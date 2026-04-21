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
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Hermod;

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

        private readonly ConcurrentDictionary<String, CachedNTSKEState>  ntskeCache  = [];
        private readonly MonitoringConfig                                config      = Configuration;

        #endregion


        #region MeasureAllServersParallel (CancellationToken)

        /// <summary>
        /// Perform a single measurement round: query all configured servers in parallel.
        /// This ensures all servers are measured at nearly the same instant,
        /// making inter-server offset comparisons meaningful.
        /// </summary>
        public async Task<MeasurementRound> MeasureAllServersParallel(CancellationToken CancellationToken = default)
        {

            var roundId          = UUIDv7.Generate();
            var roundTimestamp   = Timestamp.Now;
            var roundStopwatch   = Stopwatch.StartNew();

            // Launch all server measurements simultaneously
            var enabledServers   = config.Servers.Where(s => s.Enabled).ToList();
            var tasks            = enabledServers.Select(server => MeasureSingleServer(server, roundId, CancellationToken)).ToArray();
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

        #region MeasureSingleServer       (Server, RoundId, CancellationToken)

        /// <summary>
        /// Complete measurement of a single NTS server:
        /// 1. DNS resolution (if due)
        /// 2. NTS-KE handshake (if cookies expired or pool exhausted)
        /// 3. NTS-authenticated NTP query with precise T1/T2/T3/T4 timing
        /// </summary>
        public async Task<NTSMeasurementResult> MeasureSingleServer(NTSServerEndpoint    Server,
                                                                    Guid              RoundId,
                                                                    CancellationToken CancellationToken = default)
        {

            var totalStopwatch = Stopwatch.StartNew();

            var result = new NTSMeasurementResult(Server.Hostname, RoundId)
            {
                Success = false
            };

            try
            {

                // ──── Step 1: DNS Resolution ────
                var dnsResult = await MeasureDNS(Server.Hostname);

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
                                   ErrorMessage    = $"NTS-KE failed: {ntskeMeasurement.ErrorMessage}",
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
                               ErrorMessage    = "No NTS-KE state available",
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
                           TotalDuration   = totalStopwatch.Elapsed
                       };

            }
            catch (Exception e)
            {

                totalStopwatch.Stop();

                return new NTSMeasurementResult(Server.Hostname, RoundId) {
                           Success        = false,
                           ErrorMessage   = $"Unhandled exception: {e.Message}",
                           TotalDuration  = totalStopwatch.Elapsed
                       };

            }

        }

        #endregion


        #region (private) MeasureDNS   (Hostname)

        /// <summary>
        /// Measure DNS resolution time and get both IPv4 and IPv6 addresses.
        /// </summary>
        private async Task<DNSResolutionResult> MeasureDNS(String Hostname)
        {

            var sw = Stopwatch.StartNew();

            try
            {

                var addresses  = await Dns.GetHostAddressesAsync(Hostname);
                sw.Stop();

                return new DNSResolutionResult {
                           Success        = addresses.Length > 0,
                           IPv4Addresses  = addresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).  Select(ipAddress => ipAddress.ToString()),
                           IPv6Addresses  = addresses.Where(a => a.AddressFamily == AddressFamily.InterNetworkV6).Select(ipAddress => ipAddress.ToString()),
                           Duration       = sw.Elapsed
                       };

            }
            catch (Exception e)
            {

                sw.Stop();

                return new DNSResolutionResult {
                           Success       = false,
                           ErrorMessage  = e. Message,
                           Duration      = sw.Elapsed
                       };

            }

        }

        #endregion

        #region (private) MeasureNTSKE (Server,              CancellationToken)

        /// <summary>
        /// Perform a full NTS-KE handshake and capture all timing information.
        ///
        /// NOTE: This wraps Norn's NTSClient.GetNTSKERecords() but adds detailed
        /// timing and certificate capture.
        ///
        /// TODO/Weakness: Norn's GetNTSKERecords() is synchronous and doesn't expose
        /// individual phase timing or certificate details. We measure the total duration
        /// externally and extract cert info via a custom RemoteCertificateValidator.
        /// Ideally Norn should be refactored to expose these phases individually.
        /// </summary>
        private async Task<NTSKEMeasurementResult> MeasureNTSKE(NTSServerEndpoint  Server,
                                                                CancellationToken  CancellationToken = default)
        {

            TLSCertificateInfo? capturedCertInfo = null;

            var ntsClient = new NTSClient(
                                Server.Hostname,
                                Server.NTSKEPort,
                                Server.NTPPort,
                                RemoteCertificateValidator: (sender, remoteCert, chain, client, sslErrors) => {

                                    // Capture certificate info during handshake
                                    if (remoteCert is not null)
                                    {

                                        var x509 = new X509Certificate2(remoteCert);

                                        capturedCertInfo = new TLSCertificateInfo {
                                                               Subject             = x509.Subject,
                                                               Issuer              = x509.Issuer,
                                                               NotBefore           = x509.NotBefore.ToUniversalTime(),
                                                               NotAfter            = x509.NotAfter. ToUniversalTime(),
                                                               DaysUntilExpiry     = (Int32) (x509.NotAfter.ToUniversalTime() - Timestamp.Now).TotalDays,
                                                               SerialNumber        = x509.SerialNumber,
                                                               Thumbprint          = x509.Thumbprint,
                                                               SignatureAlgorithm  = x509.SignatureAlgorithm.FriendlyName,
                                                               PublicKeyAlgorithm  = x509.PublicKey.Oid.FriendlyName,
                                                               PublicKeySize       = x509.PublicKey.GetRSAPublicKey()?.KeySize ??
                                                                                     x509.PublicKey.GetECDsaPublicKey()?.KeySize
                                                           };

                                    }

                                    // Accept the certificate (standard chain validation is done by Norn)
                                    // We could do custom validation here too, but for monitoring
                                    // we want to capture info even if the cert has issues.
                                    return TLSValidationResult.Success();

                                },
                                Timeout: config.NTSKETimeout
                            );

            // Currently GetNTSKERecords is synchronous (see weakness analysis).
            // Run it on a thread pool thread to avoid blocking.
            var sw = Stopwatch.StartNew();

            var ntskeResponse = await Task.Run(() => ntsClient.GetNTSKERecords(), CancellationToken);

            sw.Stop();

            if (ntskeResponse.ErrorMessage is not null)
            {
                return new NTSKEMeasurementResult {
                           Success          = false,
                           TotalDuration    = sw.Elapsed,
                           ErrorMessage     = ntskeResponse.ErrorMessage,
                           CertificateInfo  = capturedCertInfo
                       };
            }

            // Cache the NTS-KE state
            ntskeCache[Server.Hostname] = new CachedNTSKEState {
                                              NTSKEResponse     = ntskeResponse,
                                              NTSClient         = ntsClient,
                                              LastRefreshed     = Timestamp.Now,
                                              RemainingCookies  = (Byte) ntskeResponse.Cookies.Count()
                                          };

            return new NTSKEMeasurementResult {
                       Success                = true,
                       TotalDuration          = sw.Elapsed,
                       // Note: We can't distinguish TCP/TLS/NTS-KE phases with current Norn API.
                       // This is a known weakness. For now, report total only.
                       TCPConnectDuration     = TimeSpan.Zero,
                       TLSHandshakeDuration   = TimeSpan.Zero,
                       NTSKEProtocolDuration  = TimeSpan.Zero,
                       NumberOfCookies        = (UInt16) ntskeResponse.Cookies.Count(),
                       AEADAlgorithm          = "AES-SIV-CMAC-256",    // Currently only option in Norn
                       CertificateInfo        = capturedCertInfo
                   };

        }

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

                // We capture T1 externally for Stopwatch RTT, but the REAL T1
                // comes from the NTP packet's TransmitTimestamp (set inside BuildNTSRequest,
                // just before UDP send). We recover it from Response.OriginateTimestamp
                // (the server echoes our TransmitTimestamp back as OriginateTimestamp).
                var t1_stopwatch_ticks = sw.ElapsedTicks;

                var ntsClient  = CachedState.NTSClient;

                if (ntsClient is null)
                    return new NTPMeasurementResult {
                        Success      = false,
                        ErrorMessage = "NTS client not available from cache"
                    };

                var ntpResponse = await ntsClient.QueryTime(
                                            Timeout:            config.NTPTimeout,
                                            NTSKEResponse:      CachedState.NTSKEResponse,
                                            CancellationToken:  CancellationToken
                                        );

                // Record T4 (client receive time) – includes response parsing overhead
                var t4_stopwatch_ticks = sw.ElapsedTicks;

                sw.Stop();
                var stopwatchRTT = StopwatchTicksToTimeSpan(t4_stopwatch_ticks - t1_stopwatch_ticks);

                // Decrement cookie count
                if (CachedState.RemainingCookies > 0)
                    CachedState.RemainingCookies--;


                if (ntpResponse is null)
                    return new NTPMeasurementResult {
                               Success       = false,
                               StopwatchRTT  = stopwatchRTT,
                               ErrorMessage  = "No NTP response (null)"
                           };

                if (ntpResponse.ErrorMessage is not null)
                    return new NTPMeasurementResult {
                               Success          = false,
                               StopwatchRTT     = stopwatchRTT,
                               ErrorMessage     = ntpResponse.ErrorMessage,
                               KissOfDeath      = ntpResponse.Stratum == 0,
                               KissOfDeathCode  = ntpResponse.Stratum == 0
                                                      ? ntpResponse.ReferenceIdentifier.ToString()
                                                      : null
                           };


                // ──── Extract NTP timestamps ────
                //
                // T1 = OriginateTimestamp in the RESPONSE = the server's echo of our
                //      TransmitTimestamp from the REQUEST. This is set by Norn in
                //      BuildNTSRequest() → NTPPacket.GetCurrentNTPTimestamp(), which is
                //      just before the UDP send.
                //
                // T2 = ReceiveTimestamp  = when the server received our packet
                // T3 = TransmitTimestamp = when the server sent the response
                // T4 = We approximate from Stopwatch, anchored to T1.
                //      T4 ≈ T1 + stopwatchRTT (includes parse overhead on both ends)

                var t1      = NTPPacket.NTPTimestampToDateTime(ntpResponse.OriginateTimestamp);
                var t2      = NTPPacket.NTPTimestampToDateTime(ntpResponse.ReceiveTimestamp);
                var t3      = NTPPacket.NTPTimestampToDateTime(ntpResponse.TransmitTimestamp ?? 0);
                var t4      = t1.Add(stopwatchRTT);

                // NOTE: t4 includes overhead from:
                //  - Request side:  NTS request building (AEAD encrypt, ~0.1-1ms)
                //  - Response side: NTS response parsing (AEAD decrypt, ~0.1-1ms)
                // This inflates the delay by ~0.2-2ms but has minimal effect on offset
                // since the overhead is roughly symmetric: θ_error ≈ (ε_build - ε_parse)/2

                // ──── Compute RFC 5905 offset and delay ────
                // θ = ((T2 - T1) + (T3 - T4)) / 2
                var offset  = TimeSpan.FromTicks(
                                  ((t2 - t1).Ticks + (t3 - t4).Ticks) / 2
                              );

                // δ = (T4 - T1) - (T3 - T2)
                var delay   = (t4 - t1) - (t3 - t2);


                // ──── Check NTS extensions ────
                var uniqueIdMatched   = ntpResponse.UniqueIdentifier() is not null;
                var newCookieReceived = ntpResponse.Extensions.Any(e => e is NTSCookieExtension { Encrypted: true });

                // If we got a new cookie, update the cache
                if (newCookieReceived)
                    CachedState.RemainingCookies++;


                return new NTPMeasurementResult {

                           Success                 = true,
                           NTSAuthenticationValid  = true,     // If we got here, Norn validated it
                           UniqueIdMatched         = uniqueIdMatched,

                           T1_ClientSend           = t1,
                           T2_ServerReceive        = t2,
                           T3_ServerTransmit       = t3,
                           T4_ClientReceive        = t4,

                           Offset                  = offset,
                           RoundTripDelay          = delay,
                           StopwatchRTT            = stopwatchRTT,

                           LeapIndicator           = ntpResponse.LI,
                           Stratum                 = ntpResponse.Stratum,
                           Poll                    = ntpResponse.Poll,
                           Precision               = ntpResponse.Precision,
                           RootDelaySeconds        = ntpResponse.RootDelay      / 65536.0,   // 16.16 fixed-point → seconds
                           RootDispersionSeconds   = ntpResponse.RootDispersion / 65536.0,
                           ReferenceId             = ntpResponse.Stratum <= 1
                                                         ? ntpResponse.ReferenceIdentifier.AsASCII  // Stratum 0/1: always ASCII (RFC 5905, zero-padded)
                                                         : ntpResponse.ReferenceIdentifier.ToString() ?? "",
                           ReferenceTimestamp      = NTPPacket.NTPTimestampToDateTime(ntpResponse.ReferenceTimestamp),

                           NewCookieReceived       = newCookieReceived,
                           KissOfDeath             = false

                       };

            }
            catch (Exception e)
            {

                sw.Stop();

                return new NTPMeasurementResult {
                           Success       = false,
                           ErrorMessage  = $"NTP exception: {e.Message}",
                           StopwatchRTT  = sw.Elapsed
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


        #region (private static) StopwatchTicksToTimeSpan(ticks)

        private static TimeSpan StopwatchTicksToTimeSpan(Int64 ticks)

            => TimeSpan.FromTicks(
                   (Int64) (ticks * ((Double) TimeSpan.TicksPerSecond / Stopwatch.Frequency))
               );

        #endregion

    }

}
