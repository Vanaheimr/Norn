/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Norn <https://www.github.com/Vanaheimr/Norn>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using IPAddress = org.GraphDefined.Vanaheimr.Hermod.IPAddress;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// The measurement engine performs individual and parallel measurements
    /// against NTS servers using the Norn library.
    /// </summary>
    public class MeasurementEngine(MonitoringConfig Configuration)
    {

        #region Data

        private readonly ConcurrentDictionary<DomainName, CachedNTSKEState>  ntskeCache  = [];
        private readonly MonitoringConfig                                    config      = Configuration;

        #endregion


        #region MeasureAllServersParallel (CancellationToken)

        /// <summary>
        /// Perform a single measurement round: query all configured servers in parallel.
        /// This ensures all servers are measured at nearly the same instant,
        /// making inter-server offset comparisons meaningful.
        /// </summary>
        public async Task<MeasurementRound> MeasureAllServersParallel(DNSClient          DNSClient, CancellationToken CancellationToken = default)
        {

            var roundId          = UUIDv7.Generate();
            var roundTimestamp   = Timestamp.Now;
            var roundStopwatch   = Stopwatch.StartNew();

            // Launch all server measurements simultaneously
            var enabledServers   = config.Servers.Where(s => s.Enabled).ToList();
            var tasks            = enabledServers.Select(server => MeasureSingleServer(server, roundId, DNSClient, CancellationToken)).ToArray();
            var results          = await Task.WhenAll(tasks);

            roundStopwatch.Stop();

            var round = new MeasurementRound(
                            config.DroneId,
                            [.. results],
                            roundId,
                            roundTimestamp)
                        {
                            DroneLocation = config.DroneLocation,
                            TotalDuration = roundStopwatch.Elapsed
                        };

            return round.WithInterServerMetrics();

        }

        #endregion

        #region MeasureSingleServer       (Server, RoundId, DNSClient, CancellationToken)

        /// <summary>
        /// Complete measurement of a single NTS server:
        /// 1. DNS resolution (if due)
        /// 2. NTS-KE handshake (if cookies expired or pool exhausted)
        /// 3. NTS-authenticated NTP query with precise T1/T2/T3/T4 timing
        /// </summary>
        public async Task<NTSMeasurementResult> MeasureSingleServer(NTSServerEndpoint  Server,
                                                                    Guid               RoundId,
                                                                    DNSClient          DNSClient,
                                                                    CancellationToken  CancellationToken = default)
        {

            var totalStopwatch  = Stopwatch.StartNew();

            var result          = new NTSMeasurementResult(
                                      Server.Hostname,
                                      RoundId
                                  ) {
                                        Success = false
                                    };

            try
            {

                // ──── Step 1: DNS Resolution ────
                var dnsResult = await MeasureDNS(
                                          DNSClient,
                                          Server.Hostname
                                      );

                // ──── Step 2: NTS-KE (cached or fresh) ────
                var ntskeFromCache  = true;
                NTSKEMeasurementResult? ntskeMeasurement = null;

                var cachedState = GetOrRefreshNTSKE(Server);

                if (cachedState is null || cachedState.NeedsRefresh(config.NTSKERefreshInterval))
                {

                    ntskeFromCache   = false;
                    ntskeMeasurement = await MeasureNTSKE(Server, CancellationToken);

                    if (!ntskeMeasurement.Success)
                    {

                        totalStopwatch.Stop();

                        return new NTSMeasurementResult(Server.Hostname, RoundId) {
                                   DNS             = dnsResult,
                                   NTSKE           = ntskeMeasurement,
                                   NTSKEFromCache  = false,
                                   Success         = false,
                                   ErrorMessage    = Error.Create($"NTS-KE failed: {ntskeMeasurement.ErrorMessage}"),
                                   ErrorCategory   = ntskeMeasurement.ErrorCategory,
                                   TotalDuration   = totalStopwatch.Elapsed
                               };

                    }

                    cachedState = ntskeCache.GetValueOrDefault(Server.Hostname);

                }

                if (cachedState?.NTSKEResponse is null)
                {

                    totalStopwatch.Stop();

                    return new NTSMeasurementResult(Server.Hostname, RoundId) {
                               DNS             = dnsResult,
                               NTSKE           = ntskeMeasurement,
                               NTSKEFromCache  = ntskeFromCache,
                               Success         = false,
                               ErrorMessage    = Error.Create("No NTS-KE state available"),
                               ErrorCategory   = MonitoringErrorCategory.Cache,
                               TotalDuration   = totalStopwatch.Elapsed
                           };

                }

                // ──── Step 3: NTP Query ────
                var ntpResult = await MeasureNTP(Server, cachedState, CancellationToken);

                totalStopwatch.Stop();

                return new NTSMeasurementResult(Server.Hostname, RoundId) {
                           DNS             = dnsResult,
                           NTSKE           = ntskeMeasurement,
                           NTSKEFromCache  = ntskeFromCache,
                           NTP             = ntpResult,
                           Success         = ntpResult.Success,
                           ErrorMessage    = ntpResult.ErrorMessage,
                           ErrorCategory   = ntpResult.ErrorCategory,
                           TotalDuration   = totalStopwatch.Elapsed
                       };

            }
            catch (Exception e)
            {

                totalStopwatch.Stop();

                return new NTSMeasurementResult(Server.Hostname, RoundId) {
                           Success        = false,
                           ErrorMessage   = Error.Create(e),
                           ErrorCategory  = MonitoringErrorCategory.Exception,
                           TotalDuration  = totalStopwatch.Elapsed
                       };

            }

        }

        #endregion


        #region (private) MeasureDNS   (DNSClient, Hostname)

        /// <summary>
        /// Measure DNS resolution time and get both IPv4 and IPv6 addresses.
        /// </summary>
        private async Task<DNSResolutionResult> MeasureDNS(DNSClient   DNSClient,
                                                           DomainName  Hostname)
        {

            var sw = Stopwatch.StartNew();

            try
            {

                var addresses = (await DNSClient.Query_IPAddresses(Hostname)).ToArray();
                sw.Stop();

                return new DNSResolutionResult(
                           Success:        addresses.Length > 0,
                           Duration:       sw.Elapsed,
                           IPv4Addresses:  addresses.Where(ipAddress => ipAddress is IPv4Address).Cast<IPv4Address>(),
                           IPv6Addresses:  addresses.Where(ipAddress => ipAddress is IPv6Address).Cast<IPv6Address>()
                       );

            }
            catch (Exception e)
            {

                sw.Stop();

                return new DNSResolutionResult(
                           Success:       false,
                           Duration:      sw.Elapsed,
                           ErrorMessage:  Error.Create(e)
                       );

            }

        }

        #endregion

        #region (private) MeasureNTSKE (Server,              CancellationToken)

        /// <summary>
        /// Perform a full NTS-KE handshake and capture all timing information.
        ///
        /// NOTE: Norn exposes phase timings and TLS information directly on the
        /// NTS-KE response, so monitoring does not need a certificate-capturing
        /// validator workaround here.
        /// </summary>
        private async Task<NTSKEMeasurementResult> MeasureNTSKE(NTSServerEndpoint  Server,
                                                                CancellationToken  CancellationToken = default)
        {

            var ntsClient = new NTSClient(
                                Server.Hostname,
                                Server.NTSKEPort,
                                Server.NTPPort,
                                Timeout: config.NTSKETimeout
                            );

            var sw = Stopwatch.StartNew();

            var ntskeResult = await ntsClient.GetNTSKERecords(
                                   Timeout:            config.NTSKETimeout,
                                   CancellationToken:  CancellationToken
                               );

            sw.Stop();

            var ntskeResponse   = ntskeResult.Response;
            var timingInfo      = ntskeResult.TimingInfo;
            var tlsInfo         = ntskeResult.TLSInfo;
            var certificateInfo = BuildCertificateInfo(tlsInfo);
            var totalDuration   = timingInfo?.TotalDuration          ?? sw.Elapsed;
            var tcpDuration     = timingInfo?.TCPConnectDuration     ?? TimeSpan.Zero;
            var tlsDuration     = timingInfo?.TLSHandshakeDuration   ?? TimeSpan.Zero;
            var ntskeDuration   = timingInfo?.NTSKEProtocolDuration  ?? TimeSpan.Zero;
            var resolvedIPs     = timingInfo?.ResolvedIPAddresses.Select(ipAddress => ipAddress.ToString()) ?? [];
            var connectedIP     = timingInfo?.ConnectedIPAddress?.ToString();
            var tlsCompliance   = EvaluateTLSCompliance(certificateInfo, tlsInfo);

            if (!ntskeResult.Success ||
                ntskeResponse?.ErrorMessage is not null ||
                ntskeResponse is null)
            {

                var errorMessage  = ntskeResult.ErrorMessage ?? ntskeResponse?.ErrorMessage ?? "NTS-KE failed.";
                var errorCategory = MapNTSKEErrorCategory(ntskeResult.ErrorCategory);

                return new NTSKEMeasurementResult {
                           Success                 = false,
                           TotalDuration           = totalDuration,
                           TCPConnectDuration      = tcpDuration,
                           TLSHandshakeDuration    = tlsDuration,
                           NTSKEProtocolDuration   = ntskeDuration,
                           ErrorMessage            = Error.Create(errorMessage),
                           CertificateInfo         = certificateInfo,
                           TLSCipherSuite          = tlsInfo?.NegotiatedCipherSuite,
                           TLSVersion              = tlsInfo?.NegotiatedTLSVersion,
                           TLSApplicationProtocol  = tlsInfo?.NegotiatedApplicationProtocol,
                           TLSCompliance           = tlsCompliance,
                           ResolvedIPAddresses     = resolvedIPs,
                           ConnectedIPAddress      = connectedIP,
                           ErrorCategory           = errorCategory
                       };

            }

            ntsClient.SeedCookies(ntskeResponse);

            // Cache the NTS-KE state
            ntskeCache[Server.Hostname] = new CachedNTSKEState {
                                              NTSKEResponse     = ntskeResponse,
                                              NTSClient         = ntsClient,
                                              LastRefreshed     = Timestamp.Now,
                                              RemainingCookies  = ToByteCookieCount(ntsClient.AvailableCookieCount)
                                          };

            return new NTSKEMeasurementResult {
                       Success                 = true,
                       TotalDuration           = totalDuration,
                       TCPConnectDuration      = tcpDuration,
                       TLSHandshakeDuration    = tlsDuration,
                       NTSKEProtocolDuration   = ntskeDuration,
                       NumberOfCookies         = (UInt16) ntskeResponse.Cookies.Count(),
                       AEADAlgorithm           = "AES-SIV-CMAC-256",    // Currently only option in Norn
                       NTPServerNegotiated     = ntskeResponse.NTPv4Servers.FirstOrDefault(),
                       NTPPortNegotiated       = ntskeResponse.NTPv4Ports.  FirstOrDefault(),
                       ResolvedIPAddresses     = resolvedIPs,
                       ConnectedIPAddress      = connectedIP,
                       CookiePoolSize          = ntsClient.AvailableCookieCount,
                       CertificateInfo         = certificateInfo,
                       TLSCipherSuite          = tlsInfo?.NegotiatedCipherSuite,
                       TLSVersion              = tlsInfo?.NegotiatedTLSVersion,
                       TLSApplicationProtocol  = tlsInfo?.NegotiatedApplicationProtocol,
                       TLSCompliance           = tlsCompliance
                   };

        }

        #endregion

        #region (private static) BuildCertificateInfo(TLSInfo)

        private static TLSCertificateInfo? BuildCertificateInfo(NTSKE_TLSInfo? TLSInfo)
        {

            var certificate = TLSInfo?.ServerCertificate;

            if (certificate is null)
                return null;

            return new TLSCertificateInfo {
                       Subject                  = certificate.Subject,
                       Issuer                   = certificate.Issuer,
                       NotBefore                = certificate.NotBefore.ToUniversalTime(),
                       NotAfter                 = certificate.NotAfter. ToUniversalTime(),
                       DaysUntilExpiry          = (Int32) (certificate.NotAfter.ToUniversalTime() - Timestamp.Now).TotalDays,
                       SerialNumber             = certificate.SerialNumber,
                       Thumbprint               = certificate.Thumbprint,
                       SignatureAlgorithm       = certificate.SignatureAlgorithm.FriendlyName,
                       PublicKeyAlgorithm       = certificate.PublicKey.Oid.FriendlyName,
                       PublicKeySize            = certificate.PublicKey.GetRSAPublicKey()?.KeySize ??
                                                  certificate.PublicKey.GetECDsaPublicKey()?.KeySize,
                       SubjectAlternativeNames  = certificate.DecodeSubjectAlternativeNames(),
                       PolicyErrors             = TLSInfo?.CertificatePolicyErrors?.ToString()
                   };

        }

        #endregion

        #region (private) EvaluateTLSCompliance(CertificateInfo, TLSInfo)

        private TLSComplianceResult EvaluateTLSCompliance(TLSCertificateInfo? CertificateInfo,
                                                          NTSKE_TLSInfo?      TLSInfo)
        {

            var warnings = new List<String>();
            var errors   = new List<String>();

            if (CertificateInfo is null)
                warnings.Add("TLS server certificate information was not captured.");
            else
            {

                if (CertificateInfo.PolicyErrors.IsNotNullOrEmpty() &&
                    CertificateInfo.PolicyErrors != "None")
                    errors.Add($"TLS certificate policy errors: {CertificateInfo.PolicyErrors}");

                if (CertificateInfo.DaysUntilExpiry.HasValue)
                {

                    if (CertificateInfo.DaysUntilExpiry.Value <= config.Alerts.CertExpiryCriticalDays)
                        errors.Add($"TLS certificate expires in {CertificateInfo.DaysUntilExpiry.Value} day(s).");

                    else if (CertificateInfo.DaysUntilExpiry.Value <= config.Alerts.CertExpiryWarningDays)
                        warnings.Add($"TLS certificate expires in {CertificateInfo.DaysUntilExpiry.Value} day(s).");

                }

                if (CertificateInfo.PublicKeyAlgorithm?.Contains("RSA", StringComparison.OrdinalIgnoreCase) == true &&
                    CertificateInfo.PublicKeySize.HasValue &&
                    CertificateInfo.PublicKeySize.Value < 2048)
                    errors.Add($"RSA public key is too small: {CertificateInfo.PublicKeySize.Value} bit.");

                if (CertificateInfo.PublicKeyAlgorithm?.Contains("ECC", StringComparison.OrdinalIgnoreCase) == true &&
                    CertificateInfo.PublicKeySize.HasValue &&
                    CertificateInfo.PublicKeySize.Value < 256)
                    errors.Add($"ECDSA public key is too small: {CertificateInfo.PublicKeySize.Value} bit.");

            }

            if (TLSInfo?.NegotiatedTLSVersion != "TLS 1.3")
                errors.Add($"Unexpected TLS version: {TLSInfo?.NegotiatedTLSVersion ?? "unknown"}.");

            if (TLSInfo?.NegotiatedCipherSuite is null)
                warnings.Add("TLS cipher suite information was not captured.");

            else if (!IsRecommendedTLS13CipherSuite(TLSInfo.NegotiatedCipherSuite))
                warnings.Add($"TLS cipher suite is not in the recommended TLS 1.3 set: {TLSInfo.NegotiatedCipherSuite}.");

            return new TLSComplianceResult {
                       Status    = errors.Count   > 0 ? MonitoringStatus.Critical :
                                   warnings.Count > 0 ? MonitoringStatus.Warning  :
                                                        MonitoringStatus.OK,
                       Warnings  = warnings,
                       Errors    = errors
                   };

        }

        #endregion

        #region (private static) IsRecommendedTLS13CipherSuite(CipherSuite)

        private static Boolean IsRecommendedTLS13CipherSuite(String CipherSuite)

            => CipherSuite.Equals("TLS_AES_256_GCM_SHA384",       StringComparison.OrdinalIgnoreCase) ||
               CipherSuite.Equals("TLS_CHACHA20_POLY1305_SHA256", StringComparison.OrdinalIgnoreCase) ||
               CipherSuite.Equals("TLS_AES_128_GCM_SHA256",       StringComparison.OrdinalIgnoreCase);

        #endregion

        #region (private) MeasureNTP   (Server, CachedState, CancellationToken)

        /// <summary>
        /// Perform a single NTS-authenticated NTP query with precise T1/T2/T3/T4 timing.
        ///
        /// CRITICAL: We use Stopwatch for T1 and T4 because Timestamp.Now only has
        /// ~15ms resolution on Windows. Stopwatch uses the CPU's high-resolution
        /// performance counter.
        ///
        /// The offset and delay calculations follow RFC 5905:
        ///   offset θ = ((T2 - T1) + (T3 - T4)) / 2
        ///   delay  δ = (T4 - T1) - (T3 - T2)
        /// </summary>
        private async Task<NTPMeasurementResult> MeasureNTP(NTSServerEndpoint    Server,
                                                            CachedNTSKEState  CachedState,
                                                            CancellationToken CancellationToken = default)
        {

            var sw = Stopwatch.StartNew();

            try
            {

                // The detailed NTS query result carries the precise UDP send/receive
                // stopwatch timestamps. The outer stopwatch stays as a defensive
                // fallback around the full monitoring call path.
                var t1_stopwatch_ticks = sw.ElapsedTicks;

                var ntsClient  = CachedState.NTSClient;
                var remoteInfo = GetNTPRemoteInfo(Server, CachedState);

                if (ntsClient is null)
                    return new NTPMeasurementResult {
                               Success                 = false,
                               ErrorMessage            = Error.Create("NTS client not available from cache"),
                               ErrorCategory           = MonitoringErrorCategory.Cache,
                               RemoteHost              = remoteInfo.Host,
                               RemoteAddress           = remoteInfo.Address,
                               RemotePort              = remoteInfo.Port
                           };

                var ntsQueryResult = await ntsClient.QueryTime(
                                                 Timeout:            config.NTPTimeout,
                                                 NTSKEResponse:      CachedState.NTSKEResponse,
                                                 CancellationToken:  CancellationToken
                                             );

                var ntpResponse    = ntsQueryResult.Response;

                // Fallback T4 around the monitoring call path.
                var t4_stopwatch_ticks = sw.ElapsedTicks;

                sw.Stop();
                var stopwatchRTT = ntsQueryResult.StopwatchRoundTripTime ??
                                   StopwatchTicksToTimeSpan(t4_stopwatch_ticks - t1_stopwatch_ticks);

                var queryRemoteAddress = ntsQueryResult.RemoteEndPoint is not null
                                             ? IPAddress.FromDotNet(ntsQueryResult.RemoteEndPoint.Address)
                                             : remoteInfo.Address;

                var queryRemotePort    = ntsQueryResult.RemoteEndPoint is not null
                                             ? IPPort.Parse(ntsQueryResult.RemoteEndPoint.Port)
                                             : remoteInfo.Port;

                CachedState.RemainingCookies = ToByteCookieCount(ntsQueryResult.RemainingCookiesAfterQuery);


                if (ntpResponse is null)
                    return new NTPMeasurementResult {
                                Success                     = false,
                                StopwatchRTT                = stopwatchRTT,
                                ErrorMessage                = Error.Create(ntsQueryResult.ErrorMessage ?? "No NTP response (null)"),
                                ErrorCategory               = MapNTSQueryErrorCategory(ntsQueryResult.ErrorCategory),
                                RemoteHost                  = remoteInfo.Host,
                                RemoteAddress               = queryRemoteAddress,
                                RemotePort                  = queryRemotePort,
                                RemainingCookiesAfterQuery  = CachedState.RemainingCookies
                            };

                if (!ntsQueryResult.Success ||
                    ntpResponse.ErrorMessage is not null)
                {
                    var errorMessage = ntsQueryResult.ErrorMessage ?? ntpResponse.ErrorMessage ?? "NTP query failed!";

                    return new NTPMeasurementResult {
                                Success          = false,
                                StopwatchRTT     = stopwatchRTT,
                                ErrorMessage     = Error.Create(errorMessage),
                                KissOfDeath      = ntpResponse.Stratum == 0,
                                KissOfDeathCode  = ntpResponse.Stratum == 0
                                                       ? ntpResponse.ReferenceIdentifier.ToString(ntpResponse.Stratum)
                                                       : null,
                                ErrorCategory    = ntpResponse.Stratum == 0
                                                       ? MonitoringErrorCategory.KissOfDeath
                                                       : MapNTSQueryErrorCategory(ntsQueryResult.ErrorCategory),
                                RemoteHost       = remoteInfo.Host,
                                RemoteAddress    = queryRemoteAddress,
                                RemotePort       = queryRemotePort,
                                RemainingCookiesAfterQuery = CachedState.RemainingCookies
                            };

                }


                // ──── Extract NTP timestamps ────
                //
                // T1 = OriginateTimestamp in the RESPONSE = the server's echo of our
                //      TransmitTimestamp from the REQUEST. This is set by Norn in
                //      BuildNTSRequest() → NTPPacket.GetCurrentNTPTimestamp(), which is
                //      just before the UDP send.
                //
                // T2 = ReceiveTimestamp  = when the server received our packet
                // T3 = TransmitTimestamp = when the server sent the response
                // T4 = The receive timestamp captured by Norn while parsing the UDP
                //      response. If it is unavailable, we approximate from Stopwatch.

                var t1      = NTPPacket.NTPTimestampToDateTime(ntpResponse.OriginateTimestamp);
                var t2      = NTPPacket.NTPTimestampToDateTime(ntpResponse.ReceiveTimestamp);
                var t3      = NTPPacket.NTPTimestampToDateTime(ntpResponse.TransmitTimestamp ?? 0);
                var t4      = ntpResponse.DestinationTimestamp.HasValue
                                  ? NTPPacket.NTPTimestampToDateTime(ntpResponse.DestinationTimestamp.Value)
                                  : t1.Add(stopwatchRTT);

                // NOTE: t4 includes overhead from:
                //  - Request side:  NTS request building (AEAD encrypt, ~0.1-1ms)
                //  - Response side: NTS response parsing (AEAD decrypt, ~0.1-1ms)
                // This inflates the delay by ~0.2-2ms but has minimal effect on offset
                // since the overhead is roughly symmetric: θ_error ≈ (ε_build - ε_parse)/2

                // ──── Compute RFC 5905 offset and delay ────
                // θ = ((T2 - T1) + (T3 - T4)) / 2
                var offset  = ntpResponse.ClockOffset ??
                              TimeSpan.FromTicks(
                                  ((t2 - t1).Ticks + (t3 - t4).Ticks) / 2
                              );

                // δ = (T4 - T1) - (T3 - T2)
                var delay   = ntpResponse.RoundTripDelay ?? ((t4 - t1) - (t3 - t2));


                // ──── Check NTS extensions ────
                var uniqueIdMatched = ntpResponse.UniqueIdentifier() is not null;


                return new NTPMeasurementResult {

                           Success                     = true,
                           NTSAuthenticationValid      = true,     // If we got here, Norn validated it
                           UniqueIdMatched             = uniqueIdMatched,

                           T1_ClientSend               = t1,
                           T2_ServerReceive            = t2,
                           T3_ServerTransmit           = t3,
                           T4_ClientReceive            = t4,

                           Offset                      = offset,
                           RoundTripDelay              = delay,
                           StopwatchRTT                = stopwatchRTT,
                           RemoteHost                  = remoteInfo.Host,
                           RemoteAddress               = queryRemoteAddress,
                           RemotePort                  = queryRemotePort,

                           LeapIndicator               = ntpResponse.LI,
                           Stratum                     = ntpResponse.Stratum,
                           Poll                        = ntpResponse.Poll,
                           Precision                   = ntpResponse.Precision,
                           RootDelaySeconds            = ntpResponse.RootDelay      / 65536.0,   // 16.16 fixed-point → seconds
                           RootDispersionSeconds       = ntpResponse.RootDispersion / 65536.0,
                           ReferenceId                 = ntpResponse.ReferenceIdentifier.ToString(ntpResponse.Stratum),
                           ReferenceTimestamp          = NTPPacket.NTPTimestampToDateTime(ntpResponse.ReferenceTimestamp),

                           NewCookieReceived           = ntsQueryResult.NewCookieReceived,
                           RemainingCookiesAfterQuery  = CachedState.RemainingCookies,
                           KissOfDeath                 = false

                       };

            }
            catch (Exception e)
            {

                sw.Stop();

                return new NTPMeasurementResult {
                           Success        = false,
                           ErrorMessage   = Error.Create($"NTP exception: {e.Message}"),
                           ErrorCategory  = MonitoringErrorCategory.Exception,
                           StopwatchRTT   = sw.Elapsed
                        };

            }

        }

        #endregion


        #region (private) GetOrRefreshNTSKE (Server)

        private CachedNTSKEState? GetOrRefreshNTSKE(NTSServerEndpoint Server)
        {

            if (ntskeCache.TryGetValue(Server.Hostname, out var cached) &&
                !cached.NeedsRefresh(config.NTSKERefreshInterval))
            {
                return cached;
            }

            return null;

        }

        #endregion


        #region (private static) ToByteCookieCount(CookieCount)

        private static Byte ToByteCookieCount(Int32 CookieCount)

            => (Byte) Math.Clamp(CookieCount, Byte.MinValue, Byte.MaxValue);

        #endregion

        #region (private static) MapNTSQueryErrorCategory(ErrorCategory)

        private static MonitoringErrorCategory MapNTSQueryErrorCategory(NTSQueryErrorCategory ErrorCategory)

            => ErrorCategory switch {

                   NTSQueryErrorCategory.None               => MonitoringErrorCategory.None,
                   NTSQueryErrorCategory.NTSKE              => MonitoringErrorCategory.NTSKEProtocol,
                   NTSQueryErrorCategory.Cookie             => MonitoringErrorCategory.Cache,
                   NTSQueryErrorCategory.DNS                => MonitoringErrorCategory.DNS,
                   NTSQueryErrorCategory.NTPTimeout         => MonitoringErrorCategory.NTPTimeout,
                   NTSQueryErrorCategory.NTSAuthentication  => MonitoringErrorCategory.NTSAuthentication,
                   NTSQueryErrorCategory.KissOfDeath        => MonitoringErrorCategory.KissOfDeath,
                   NTSQueryErrorCategory.Protocol           => MonitoringErrorCategory.Unknown,
                   NTSQueryErrorCategory.Network            => MonitoringErrorCategory.NTPTimeout,
                   NTSQueryErrorCategory.Canceled           => MonitoringErrorCategory.Canceled,
                   NTSQueryErrorCategory.Exception          => MonitoringErrorCategory.Exception,
                   _                                        => MonitoringErrorCategory.Unknown

               };

        #endregion

        #region (private static) MapNTSKEErrorCategory(ErrorCategory)

        private static MonitoringErrorCategory MapNTSKEErrorCategory(NTSKEErrorCategory ErrorCategory)

            => ErrorCategory switch {

                   NTSKEErrorCategory.None            => MonitoringErrorCategory.None,
                   NTSKEErrorCategory.DNS             => MonitoringErrorCategory.DNS,
                   NTSKEErrorCategory.TCPConnect      => MonitoringErrorCategory.TCPConnect,
                   NTSKEErrorCategory.TLSHandshake    => MonitoringErrorCategory.TLSHandshake,
                   NTSKEErrorCategory.TLSCertificate  => MonitoringErrorCategory.TLSCertificate,
                   NTSKEErrorCategory.Timeout         => MonitoringErrorCategory.NTSKEProtocol,
                   NTSKEErrorCategory.Protocol        => MonitoringErrorCategory.NTSKEProtocol,
                   NTSKEErrorCategory.Canceled        => MonitoringErrorCategory.Canceled,
                   NTSKEErrorCategory.Exception       => MonitoringErrorCategory.Exception,
                   _                                  => MonitoringErrorCategory.Unknown

               };

        #endregion


        #region (private static) GetNTPRemoteInfo(Server, CachedState)

        private static (DomainName   Host,
                        IIPAddress?  Address,
                        IPPort       Port)

            GetNTPRemoteInfo(NTSServerEndpoint  Server,
                             CachedNTSKEState   CachedState)

        {

            var ntskeResponse  = CachedState.NTSKEResponse;
            var host           = ntskeResponse?.NTPv4Servers.FirstOrDefault() ?? Server.Hostname;
            var port           = ntskeResponse?.NTPv4Ports.  FirstOrDefault() ?? Server.NTPPort;
            var normalized     = host.ToString().TrimEnd('.');

            if (IPAddress.TryParse(normalized, out var ipAddress))
            { }

            else if ((ntskeResponse?.NTPv4Servers.Any() != true ||
                      String.Equals(normalized,
                                    Server.Hostname.ToString().TrimEnd('.'),
                                    StringComparison.OrdinalIgnoreCase)) &&
                            ntskeResponse?.TimingInfo?.ConnectedIPAddress is not null)
                ipAddress = ntskeResponse. TimingInfo. ConnectedIPAddress;

            return (host, ipAddress, port);

        }

        #endregion


        #region (private static) StopwatchTicksToTimeSpan(ticks)

        private static TimeSpan StopwatchTicksToTimeSpan(Int64 ticks)

            => TimeSpan.FromTicks(
                   (Int64) (ticks * ((Double) TimeSpan.TicksPerSecond / Stopwatch.Frequency))
               );

        #endregion

    }

}
