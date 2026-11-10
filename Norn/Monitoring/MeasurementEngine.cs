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
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

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
    /// <param name="Configuration">The monitoring configuration.</param>
    /// <param name="TimeProvider">
    /// The clock this engine reads: the round timestamps, cache ageing and certificate expiry.
    /// It is also handed to every <see cref="NTSClient"/> the engine creates, so a measurement
    /// and the client that produced it agree on what time it is.
    /// </param>
    /// <param name="Random">Where the time of the next key exchange between an endpoint's MinRefresh and MaxRefresh comes from.</param>
    public class MeasurementEngine(MonitoringConfig  Configuration,
                                   TimeProvider?     TimeProvider   = null,
                                   Random?           Random         = null)
    {

        #region Data

        private readonly ConcurrentDictionary<DomainName, CachedNTSKEState>  ntskeCache    = [];
        private readonly MonitoringConfig                                    config        = Configuration;
        private readonly TimeProvider                                        timeProvider  = TimeProvider ?? System.TimeProvider.System;
        private readonly Random                                              random        = Random       ?? System.Random.Shared;

        /// <summary>
        /// What each server has told this engine about how welcome it is, per RFC 5905 § 7.4.
        /// </summary>
        private readonly ConcurrentDictionary<DomainName, NTPServerAccessState> accessStates = [];

        /// <summary>
        /// The delays of the last exchanges with each server, which the shortest
        /// of is what DelayVarAsymmetry measures a hold-up against.
        /// </summary>
        private readonly ConcurrentDictionary<DomainName, Queue<TimeSpan>>     recentDelays = [];

        /// <summary>
        /// How many of the last delays of a server its shortest delay is taken
        /// from: enough to have seen one without a hold-up, few enough that a
        /// changed path is soon what is measured against.
        /// </summary>
        public const Int32 RecentDelays = 16;

        #endregion

        #region Properties

        /// <summary>
        /// What a server has told this engine with its kiss codes: the poll rate it asked for,
        /// and whether it asked to be left alone.
        /// </summary>
        /// <remarks>
        /// Created on first sight of the server, so this never returns null and never means
        /// "nothing has happened yet" by absence — a fresh state is one that has heard nothing,
        /// which is the same thing said explicitly.
        /// </remarks>
        /// <summary>
        /// The key exchange this engine is holding for each server it has asked.
        /// </summary>
        /// <remarks>
        /// So that whoever owns this engine can say what its cookies are doing.
        /// An engine that quietly reuses exchanges is the right behaviour and a
        /// poor thing to have to take on trust - a page reporting "no key
        /// exchange has happened" while four are being reused is worse than a
        /// page reporting nothing at all.
        /// </remarks>
        public IReadOnlyDictionary<DomainName, CachedNTSKEState> KeyExchanges
            => ntskeCache;

        #endregion

        #region AccessStateFor(Hostname)

        public NTPServerAccessState AccessStateFor(DomainName Hostname)

            => accessStates.GetOrAdd(Hostname, _ => new NTPServerAccessState());

        #endregion

        #region ForgetKeyExchange(Hostname)

        /// <summary>
        /// Let go of the key exchange held for this server, so that the next
        /// round makes a new one.
        /// </summary>
        /// <remarks>
        /// For when what a key exchange was judged by has changed - the server's
        /// certificate validator, above all. An exchange is reused for as long
        /// as its cookies last, and the certificate is only looked at when one is
        /// made: without this, a server held to a fingerprint from now on would
        /// go on being asked on the strength of a handshake nobody checked it
        /// in, for as long as half an hour.
        /// </remarks>
        /// <param name="Hostname">The server whose key exchange to forget.</param>
        /// <returns>Whether there was one.</returns>
        public Boolean ForgetKeyExchange(DomainName Hostname)

            => ntskeCache.TryRemove(Hostname, out _);

        #endregion


        #region MeasureAllServersParallel (CancellationToken)

        /// <summary>
        /// Perform a single measurement round: query all configured servers in parallel.
        /// This ensures all servers are measured at nearly the same instant,
        /// making inter-server offset comparisons meaningful.
        /// </summary>
        public Task<MeasurementRound> MeasureAllServersParallel(DNSClient          DNSClient, CancellationToken CancellationToken = default)

            => MeasureServersParallel(config.Servers, DNSClient, CancellationToken);

        #endregion

        #region MeasureServersParallel    (Servers, DNSClient, CancellationToken)

        /// <summary>
        /// One round over the servers given, rather than over every server this
        /// engine is configured with.
        /// </summary>
        /// <remarks>
        /// So that a caller can measure part of its servers and decide what to
        /// do before measuring the rest - which is what asking a group of time
        /// sources in priority order amounts to. Everything else about a round
        /// is unchanged, including the inter-server metrics, which are then
        /// computed across the servers that were actually asked.
        /// </remarks>
        /// <param name="Preflight">Whether every server is first sent a packet whose answer is ignored - see <see cref="MeasureSingleServer"/>.</param>
        public async Task<MeasurementRound> MeasureServersParallel(IEnumerable<NTSServerEndpoint>  Servers,
                                                                   DNSClient                       DNSClient,
                                                                   CancellationToken               CancellationToken  = default,
                                                                   Boolean                         Preflight          = false)
        {

            var roundId          = UUIDv7.Generate();
            var roundTimestamp   = timeProvider.GetUtcNow();
            var roundStopwatch   = Stopwatch.StartNew();

            // Launch all server measurements simultaneously
            var enabledServers   = Servers.Where(s => s.Enabled).ToList();
            var tasks            = enabledServers.Select(server => MeasureSingleServer(server, roundId, DNSClient, CancellationToken, Preflight)).ToArray();
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
        /// <remarks>
        /// With Preflight, the query of step 3 is sent twice, and the answer to
        /// the first is ignored: the Preflight of the Secure Time
        /// Synchronization white paper, chrony's "presend". A server not asked
        /// for a while is reached through an ARP lookup, a firewall's new state,
        /// a tunnel being set up - delays that are not the server's, and would
        /// be measured as an asymmetric delay. The first packet takes them, and
        /// costs no cookie: its answer brings a new one, as every answer does.
        /// </remarks>
        /// <param name="Preflight">Whether to send the query a first time, whose answer is ignored.</param>
        public async Task<NTSMeasurementResult> MeasureSingleServer(NTSServerEndpoint  Server,
                                                                    Guid               RoundId,
                                                                    DNSClient          DNSClient,
                                                                    CancellationToken  CancellationToken  = default,
                                                                    Boolean            Preflight          = false)
        {

            var totalStopwatch  = Stopwatch.StartNew();

            var result          = new NTSMeasurementResult(
                                      Server.Hostname,
                                      RoundId,
                                      Timestamp: timeProvider.GetUtcNow()
                                  ) {
                                        Success = false
                                    };

            try
            {

                // ──── Step 0: Has this server asked to be left alone? ────
                //
                // Before the DNS lookup, and long before the query, because RFC 5905 § 7.4 a says
                // to "stop sending packets to that server" and § 7.4 b says to poll it less
                // often. A round that measured anyway and threw the result away would satisfy
                // neither: the packets are the thing being asked for.
                var access = AccessStateFor(Server.Hostname);

                if (config.RespectKissOfDeath &&
                    !access.MayQuery(timeProvider.GetUtcNow()))
                {

                    totalStopwatch.Stop();

                    return new NTSMeasurementResult(Server.Hostname, RoundId, Timestamp: timeProvider.GetUtcNow()) {
                               Success        = false,
                               Skipped        = true,
                               ErrorMessage   = Error.Create(
                                                    access.Demobilized
                                                        ? $"Not querying {Server.Hostname}: it answered '{access.LastKiss?.Code}' and the association is demobilized."
                                                        : $"Not querying {Server.Hostname} yet: it answered '{access.LastKiss?.Code}' and asked for a poll interval of {access.PollInterval.TotalSeconds:0} seconds."
                                                ),
                               ErrorCategory  = MonitoringErrorCategory.KissOfDeath,
                               TotalDuration  = totalStopwatch.Elapsed
                           };

                }

                // ──── Step 1: DNS Resolution ────
                var dnsResult = await MeasureDNS(
                                          DNSClient,
                                          Server.Hostname
                                      );

                // ──── Step 2: NTS-KE (cached or fresh) ────
                var ntskeFromCache  = true;
                NTSKEMeasurementResult? ntskeMeasurement = null;

                var cachedState = GetOrRefreshNTSKE(Server);

                if (cachedState is null || cachedState.NeedsRefresh(config.NTSKERefreshInterval, timeProvider))
                {

                    ntskeFromCache   = false;
                    ntskeMeasurement = await MeasureNTSKE(Server, DNSClient, CancellationToken);

                    if (!ntskeMeasurement.Success)
                    {

                        totalStopwatch.Stop();

                        return new NTSMeasurementResult(Server.Hostname, RoundId, Timestamp: timeProvider.GetUtcNow()) {
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

                    return new NTSMeasurementResult(Server.Hostname, RoundId, Timestamp: timeProvider.GetUtcNow()) {
                               DNS             = dnsResult,
                               NTSKE           = ntskeMeasurement,
                               NTSKEFromCache  = ntskeFromCache,
                               Success         = false,
                               ErrorMessage    = Error.Create("No NTS-KE state available"),
                               ErrorCategory   = MonitoringErrorCategory.Cache,
                               TotalDuration   = totalStopwatch.Elapsed
                           };

                }

                // ──── Step 3: NTP Query, a first time to be ignored where asked ────
                var preflightSent = Preflight && await SendPreflight(cachedState, CancellationToken);

                var ntpResult = await MeasureNTP(Server, cachedState, CancellationToken);

                // ──── Step 4: a signed response, where asked for, after what was measured ────
                var signedResponse = Server.SignedResponses && ntpResult.Success
                                         ? await RequestSignedResponse(cachedState, CancellationToken)
                                         : null;

                totalStopwatch.Stop();

                return new NTSMeasurementResult(Server.Hostname, RoundId, Timestamp: timeProvider.GetUtcNow()) {
                           DNS             = dnsResult,
                           NTSKE           = ntskeMeasurement,
                           NTSKEFromCache  = ntskeFromCache,
                           NTP             = ntpResult,
                           PreflightSent   = preflightSent,
                           SignedResponse  = signedResponse,
                           Success         = ntpResult.Success,
                           ErrorMessage    = ntpResult.ErrorMessage,
                           ErrorCategory   = ntpResult.ErrorCategory,
                           TotalDuration   = totalStopwatch.Elapsed
                       };

            }
            catch (Exception e)
            {

                totalStopwatch.Stop();

                return new NTSMeasurementResult(Server.Hostname, RoundId, Timestamp: timeProvider.GetUtcNow()) {
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

        #region (private) MeasureNTSKE (Server, DNSClient,   CancellationToken)

        /// <summary>
        /// Perform a full NTS-KE handshake and capture all timing information.
        ///
        /// NOTE: Norn exposes phase timings and TLS information directly on the
        /// NTS-KE response, so monitoring does not need a certificate-capturing
        /// validator workaround here.
        /// </summary>
        /// <remarks>
        /// With the DNS client the round was handed, which is the one step 1
        /// resolved the name with. The key exchange used to make a client of its
        /// own, and so asked whatever name servers the machine has - past a
        /// resolver its owner had configured, and past one it had switched off by
        /// taking its servers away.
        ///
        /// And with the server's own certificate validator, where it has one: the
        /// handshake is the only moment its certificate is seen, and a key
        /// exchange is reused for as long as its cookies last.
        ///
        /// And offering the AEAD algorithms the server's endpoint names, where it
        /// names any. They used to be read from nowhere, so an endpoint held to
        /// one algorithm was offered the client's whole list.
        /// </remarks>
        private async Task<NTSKEMeasurementResult> MeasureNTSKE(NTSServerEndpoint  Server,
                                                                DNSClient          DNSClient,
                                                                CancellationToken  CancellationToken = default)
        {

            if (Server.ConnectOverSSH is not null)
                return await MeasureNTSKEOverSSH(Server, Server.ConnectOverSSH, DNSClient, CancellationToken).ConfigureAwait(false);

            // At the endpoint's own key exchange server, where it names one, asking it for the
            // endpoint's host name as the NTP server.
            var ntsClient = new NTSClient(
                                Server.NTSKEHost ?? Server.Hostname,
                                Server.NTSKEPort,
                                Server.NTPPort,
                                RemoteCertificateValidator:  Server.RemoteCertificateValidator,
                                OfferedAEADAlgorithms:       Server.OfferedAEADAlgorithms,
                                Timeout:                     config.NTSKETimeout,
                                DNSClient:                   DNSClient,
                                TimeProvider:                timeProvider,
                                RequestedNTPServer:          Server.NTSKEHost is not null ? Server.Hostname : null
                            );

            var sw = Stopwatch.StartNew();

            // With the server's public keys, where its responses are to be
            // signed: they are what a signature is checked against.
            var ntskeResult = await ntsClient.GetNTSKERecords(
                                   RequestNTSPublicKeys:  Server.SignedResponses,
                                   Timeout:               config.NTSKETimeout,
                                   CancellationToken:     CancellationToken
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
            var cookiePoolDiagnostics = ntsClient.CookiePoolDiagnostics;

            // Cache the NTS-KE state
            var refreshed = timeProvider.GetUtcNow();

            ntskeCache[Server.Hostname] = new CachedNTSKEState {
                                              NTSKEResponse     = ntskeResponse,
                                              NTSClient         = ntsClient,
                                              LastRefreshed     = refreshed,
                                              RefreshAt         = refreshed + RefreshDelay(Server),
                                              RemainingCookies  = ToByteCookieCount(cookiePoolDiagnostics.AvailableCookieCount)
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
                       NTPPortNegotiated       = ntskeResponse.NTPv4Ports.Any()
                                                     ? ntskeResponse.NTPv4Ports.First()
                                                     : null,
                       ResolvedIPAddresses     = resolvedIPs,
                       ConnectedIPAddress      = connectedIP,
                       CookiePoolSize          = cookiePoolDiagnostics.AvailableCookieCount,
                       CookiePoolMaxSize       = cookiePoolDiagnostics.MaxCookiePoolSize,
                       CookiePoolLowWatermark  = cookiePoolDiagnostics.LowWatermark,
                       SeededCookieCount       = cookiePoolDiagnostics.SeededCookieCount,
                       CookiesReceived         = cookiePoolDiagnostics.CookiesReceived,
                       CookiesConsumed         = cookiePoolDiagnostics.CookiesConsumed,
                       DroppedCookieCount      = cookiePoolDiagnostics.DroppedCookieCount,
                       CookiePoolLow           = cookiePoolDiagnostics.IsLow,
                       CookiePoolEmpty         = cookiePoolDiagnostics.IsEmpty,
                       CertificateInfo         = certificateInfo,
                       TLSCipherSuite          = tlsInfo?.NegotiatedCipherSuite,
                       TLSVersion              = tlsInfo?.NegotiatedTLSVersion,
                       TLSApplicationProtocol  = tlsInfo?.NegotiatedApplicationProtocol,
                       TLSCompliance           = tlsCompliance
                   };

        }

        #endregion

        #region (private) MeasureNTSKEOverSSH(Server, Connect, DNSClient, CancellationToken)

        /// <summary>
        /// A key exchange over SSH - the subsystem "ntske/1@open.charging.cloud"
        /// of the white paper "NTS Key Establishment over SSH" - on a connection
        /// the endpoint makes, cached as one over TLS is.
        /// </summary>
        /// <remarks>
        /// The client offers the exporter of the connection (option A) before
        /// the transported secret (option B), and the server picks the first it
        /// can use. It never renews its cookies over TLS by itself; the next key
        /// exchange over SSH does. There is no certificate,
        /// so nothing of TLS is judged or recorded; the host key the server
        /// showed is.
        /// </remarks>
        private async Task<NTSKEMeasurementResult> MeasureNTSKEOverSSH(NTSServerEndpoint                                Server,
                                                                       Func<CancellationToken, ValueTask<SshClient>>   Connect,
                                                                       DNSClient                                        DNSClient,
                                                                       CancellationToken                                CancellationToken)
        {

            var ntsClient = new NTSClient(
                                Server.Hostname,
                                NTP_Port:                    Server.NTPPort,
                                OfferedAEADAlgorithms:       Server.OfferedAEADAlgorithms,
                                Timeout:                     config.NTSKETimeout,
                                DNSClient:                   DNSClient,
                                TimeProvider:                timeProvider,
                                CookiePoolPolicy:            new NTSCookiePoolPolicy { RenegotiateWhenExhausted = false }
                            );

            var       sw          = Stopwatch.StartNew();
            String?   hostKey     = null;
            NTSKEResult? result   = null;

            try
            {

                await using var ssh = await Connect(CancellationToken).ConfigureAwait(false);

                hostKey = SshFingerprint.Sha256(ssh.ServerHostKey);

                result  = await ntsClient.GetNTSKERecordsOverSSH(
                                    ssh,
                                    RequestNTSPublicKeys:  Server.SignedResponses,
                                    Timeout:               config.NTSKETimeout,
                                    CancellationToken:     CancellationToken
                                ).ConfigureAwait(false);

            }
            catch (OperationCanceledException) when (CancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception e)
            {

                sw.Stop();

                return new NTSKEMeasurementResult {
                           Success                 = false,
                           TotalDuration           = sw.Elapsed,
                           ErrorMessage            = Error.Create($"NTS-KE over SSH: {(hostKey is null ? "no SSH connection" : "the SSH connection failed")}: {e.Message}"),
                           SSHHostKey              = hostKey,
                           ErrorCategory           = MonitoringErrorCategory.SSH
                       };

            }

            sw.Stop();

            var ntskeResponse   = result?.Response;
            var timingInfo      = result?.TimingInfo;
            var totalDuration   = timingInfo?.TotalDuration          ?? sw.Elapsed;
            var ntskeDuration   = timingInfo?.NTSKEProtocolDuration  ?? TimeSpan.Zero;

            if (result is null         ||
                !result.Success        ||
                ntskeResponse is null  ||
                ntskeResponse.ErrorMessage is not null)
            {

                var errorMessage  = result?.ErrorMessage ?? ntskeResponse?.ErrorMessage ?? "NTS-KE over SSH failed.";

                return new NTSKEMeasurementResult {
                           Success                 = false,
                           TotalDuration           = totalDuration,
                           NTSKEProtocolDuration   = ntskeDuration,
                           ErrorMessage            = Error.Create(errorMessage),
                           SSHHostKey              = hostKey,
                           ErrorCategory           = result?.ErrorCategory == NTSKEErrorCategory.SSHSubsystem
                                                         ? MonitoringErrorCategory.SSH
                                                         : MapNTSKEErrorCategory(result?.ErrorCategory ?? NTSKEErrorCategory.Unknown)
                       };

            }

            ntsClient.SeedCookies(ntskeResponse);
            var cookiePoolDiagnostics = ntsClient.CookiePoolDiagnostics;

            var refreshed = timeProvider.GetUtcNow();

            ntskeCache[Server.Hostname] = new CachedNTSKEState {
                                              NTSKEResponse     = ntskeResponse,
                                              NTSClient         = ntsClient,
                                              LastRefreshed     = refreshed,
                                              RefreshAt         = refreshed + RefreshDelay(Server),
                                              RemainingCookies  = ToByteCookieCount(cookiePoolDiagnostics.AvailableCookieCount),
                                              SSHHostKey        = hostKey
                                          };

            return new NTSKEMeasurementResult {
                       Success                 = true,
                       TotalDuration           = totalDuration,
                       NTSKEProtocolDuration   = ntskeDuration,
                       NumberOfCookies         = (UInt16) ntskeResponse.Cookies.Count(),
                       AEADAlgorithm           = ntskeResponse.AEADAlgorithm.ToString(),
                       NTPServerNegotiated     = ntskeResponse.NTPv4Servers.FirstOrDefault(),
                       NTPPortNegotiated       = ntskeResponse.NTPv4Ports.Any()
                                                     ? ntskeResponse.NTPv4Ports.First()
                                                     : null,
                       CookiePoolSize          = cookiePoolDiagnostics.AvailableCookieCount,
                       CookiePoolMaxSize       = cookiePoolDiagnostics.MaxCookiePoolSize,
                       CookiePoolLowWatermark  = cookiePoolDiagnostics.LowWatermark,
                       SeededCookieCount       = cookiePoolDiagnostics.SeededCookieCount,
                       CookiesReceived         = cookiePoolDiagnostics.CookiesReceived,
                       CookiesConsumed         = cookiePoolDiagnostics.CookiesConsumed,
                       DroppedCookieCount      = cookiePoolDiagnostics.DroppedCookieCount,
                       CookiePoolLow           = cookiePoolDiagnostics.IsLow,
                       CookiePoolEmpty         = cookiePoolDiagnostics.IsEmpty,
                       SSHHostKey              = hostKey
                   };

        }

        #endregion

        #region (private) BuildCertificateInfo(TLSInfo)

        /// <summary>
        /// Describe the server's certificate. Not static any more: "days until expiry" is
        /// relative to a clock, and it has to be this engine's.
        /// </summary>
        private TLSCertificateInfo? BuildCertificateInfo(NTSKE_TLSInfo? TLSInfo)
        {

            var certificate = TLSInfo?.ServerCertificate;

            if (certificate is null)
                return null;

            return new TLSCertificateInfo {
                       Subject                  = certificate.Subject,
                       Issuer                   = certificate.Issuer,
                       NotBefore                = certificate.NotBefore.ToUniversalTime(),
                       NotAfter                 = certificate.NotAfter. ToUniversalTime(),
                       DaysUntilExpiry          = (Int32) (certificate.NotAfter.ToUniversalTime() - timeProvider.GetUtcNow()).TotalDays,
                       SerialNumber             = certificate.SerialNumber,
                       Thumbprint               = certificate.Thumbprint,
                       SignatureAlgorithm       = certificate.SignatureAlgorithm.FriendlyName,
                       PublicKeyAlgorithm       = certificate.PublicKey.Oid.FriendlyName,
                       PublicKeySize            = certificate.PublicKey.GetRSAPublicKey()?.KeySize ??
                                                  certificate.PublicKey.GetECDsaPublicKey()?.KeySize,
                       // Qualified because Styx and Hermod both offer this extension method,
                       // with the same signature and the same behaviour, and this file imports
                       // both namespaces. Styx's, to keep company with the GetDNSNames used for
                       // the hostname check in NTSKE_TLSClient — either would do, and picking
                       // silently is what leaves the next reader wondering whether it matters.
                       SubjectAlternativeNames  = Illias.CertificateExtensions.DecodeSubjectAlternativeNames(certificate),
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
        /// T1 and T4 come from the client's wall clock, which is the only thing they can come
        /// from: the offset is a statement about that clock, and Stopwatch has no epoch to state
        /// it against. Stopwatch appears here only to measure the round trip — as a fallback for
        /// T4 when the client did not record one, and as a diagnostic.
        ///
        /// That division is not about resolution. The comment this replaces justified it by
        /// claiming the wall clock resolves to ~15 ms on Windows, which stopped being true when
        /// .NET moved to GetSystemTimePreciseAsFileTime; measured, it is sub-microsecond here.
        /// The real reason to keep an interval on a monotonic timer is that a wall clock steps —
        /// an NTP correction landing mid-measurement would otherwise show up as network delay.
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

                var ntpResponse            = ntsQueryResult.Response;
                var cookiePoolDiagnostics  = ntsQueryResult.CookiePoolDiagnostics;

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

                CachedState.RemainingCookies = ToByteCookieCount(cookiePoolDiagnostics?.AvailableCookieCount ??
                                                                  ntsQueryResult.RemainingCookiesAfterQuery);

                // The client may have run a key exchange of its own during that call: an empty
                // cookie pool obliges it to, per RFC 8915 § 5.7, and this engine's own refresh
                // rule only pre-empts that — it keeps one cookie in reserve, which is enough
                // until a round of lost packets spends it.
                //
                // What comes back carries new keys as well as new cookies, and the two only work
                // together. A cache still holding the previous response would seal the next
                // round's request under keys the server has already replaced, and every packet
                // would be NAKed until the refresh interval elapsed.
                if (ntsClient.LastNTSKEResponse is not null &&
                    !ReferenceEquals(ntsClient.LastNTSKEResponse, CachedState.NTSKEResponse))
                {
                    CachedState.NTSKEResponse  = ntsClient.LastNTSKEResponse;
                    CachedState.LastRefreshed  = timeProvider.GetUtcNow();
                    CachedState.RefreshAt      = CachedState.LastRefreshed + RefreshDelay(Server);
                }


                if (ntpResponse is null)
                    return new NTPMeasurementResult {
                                Success                     = false,
                                StopwatchRTT                = stopwatchRTT,
                                ErrorMessage                = Error.Create(ntsQueryResult.ErrorMessage ?? "No NTP response (null)"),
                                ErrorCategory               = MapNTSQueryErrorCategory(ntsQueryResult.ErrorCategory),
                                RemoteHost                  = remoteInfo.Host,
                                 RemoteAddress               = queryRemoteAddress,
                                 RemotePort                  = queryRemotePort,
                                 RemainingCookiesAfterQuery  = CachedState.RemainingCookies,
                                 CookiePoolSize              = cookiePoolDiagnostics?.AvailableCookieCount,
                                 CookiePoolMaxSize           = cookiePoolDiagnostics?.MaxCookiePoolSize,
                                 CookiePoolLowWatermark      = cookiePoolDiagnostics?.LowWatermark,
                                 SeededCookieCount           = cookiePoolDiagnostics?.SeededCookieCount,
                                 CookiesReceived             = cookiePoolDiagnostics?.CookiesReceived,
                                 CookiesConsumed             = cookiePoolDiagnostics?.CookiesConsumed,
                                 DroppedCookieCount          = cookiePoolDiagnostics?.DroppedCookieCount,
                                 CookiePoolLow               = cookiePoolDiagnostics?.IsLow,
                                 CookiePoolEmpty             = cookiePoolDiagnostics?.IsEmpty
                             };

                if (!ntsQueryResult.Success ||
                    ntpResponse.ErrorMessage is not null)
                {

                    var errorMessage = ntsQueryResult.ErrorMessage ?? ntpResponse.ErrorMessage ?? "NTP query failed!";

                    // A kiss, and not merely a stratum-0 packet: RFC 8633 § 5.4 makes the origin
                    // timestamp the price of being believed, and NTSQueryResult.KissOfDeath is
                    // where that is checked. Reporting an unverifiable one as a kiss would let
                    // an off-path attacker decide how often this engine measures — and, with
                    // "DENY", whether it measures at all.
                    var kiss         = ntsQueryResult.KissOfDeath;

                    if (kiss is not null && config.RespectKissOfDeath)
                        AccessStateFor(Server.Hostname).Apply(kiss.Value, timeProvider.GetUtcNow());

                    return new NTPMeasurementResult {
                                Success          = false,
                                StopwatchRTT     = stopwatchRTT,
                                ErrorMessage     = Error.Create(errorMessage),
                                KissOfDeath      = kiss is not null,
                                KissOfDeathCode  = kiss?.Code,
                                ErrorCategory    = kiss is not null
                                                       ? MonitoringErrorCategory.KissOfDeath
                                                       : MapNTSQueryErrorCategory(ntsQueryResult.ErrorCategory),
                                 RemoteHost       = remoteInfo.Host,
                                 RemoteAddress    = queryRemoteAddress,
                                 RemotePort       = queryRemotePort,
                                 RemainingCookiesAfterQuery = CachedState.RemainingCookies,
                                 CookiePoolSize             = cookiePoolDiagnostics?.AvailableCookieCount,
                                 CookiePoolMaxSize          = cookiePoolDiagnostics?.MaxCookiePoolSize,
                                 CookiePoolLowWatermark     = cookiePoolDiagnostics?.LowWatermark,
                                 SeededCookieCount          = cookiePoolDiagnostics?.SeededCookieCount,
                                 CookiesReceived            = cookiePoolDiagnostics?.CookiesReceived,
                                 CookiesConsumed            = cookiePoolDiagnostics?.CookiesConsumed,
                                 DroppedCookieCount         = cookiePoolDiagnostics?.DroppedCookieCount,
                                 CookiePoolLow              = cookiePoolDiagnostics?.IsLow,
                                 CookiePoolEmpty            = cookiePoolDiagnostics?.IsEmpty
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

                // The era each timestamp belongs to is resolved against this engine's clock, not
                // an ambient one: the wire carries only the low 32 bits of the second count
                // (RFC 5905 § 6), so "roughly when" has to come from somewhere.
                var t1      = NTPPacket.NTPTimestampToDateTime(ntpResponse.OriginateTimestamp,       timeProvider);
                var t2      = NTPPacket.NTPTimestampToDateTime(ntpResponse.ReceiveTimestamp,         timeProvider);
                var t3      = NTPPacket.NTPTimestampToDateTime(ntpResponse.TransmitTimestamp ?? 0,   timeProvider);
                var t4      = ntpResponse.DestinationTimestamp.HasValue
                                  ? NTPPacket.NTPTimestampToDateTime(ntpResponse.DestinationTimestamp.Value, timeProvider)
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

                // ──── Correct it for what is known about the path ────
                var correction = OffsetCorrection(Server.DelayAsymmetry,
                                                  Server.DelayVarAsymmetry,
                                                  delay,
                                                  ShortestRecentDelay(Server.Hostname, delay));


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

                           Offset                      = offset + correction,
                           MeasuredOffset              = offset,
                           OffsetCorrection            = correction,
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
                           CookiePoolSize              = cookiePoolDiagnostics?.AvailableCookieCount,
                           CookiePoolMaxSize           = cookiePoolDiagnostics?.MaxCookiePoolSize,
                           CookiePoolLowWatermark      = cookiePoolDiagnostics?.LowWatermark,
                           SeededCookieCount           = cookiePoolDiagnostics?.SeededCookieCount,
                           CookiesReceived             = cookiePoolDiagnostics?.CookiesReceived,
                           CookiesConsumed             = cookiePoolDiagnostics?.CookiesConsumed,
                           DroppedCookieCount          = cookiePoolDiagnostics?.DroppedCookieCount,
                           CookiePoolLow               = cookiePoolDiagnostics?.IsLow,
                           CookiePoolEmpty             = cookiePoolDiagnostics?.IsEmpty,
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

        /// <summary>
        /// The key exchange held for this server, where it may be reused.
        /// </summary>
        /// <remarks>
        /// Not one that agreed on an algorithm the endpoint no longer offers:
        /// its cookies and keys are of that algorithm, so reusing it would go on
        /// with what the endpoint was changed to rule out.
        /// </remarks>
        private CachedNTSKEState? GetOrRefreshNTSKE(NTSServerEndpoint Server)
        {

            if (ntskeCache.TryGetValue(Server.Hostname, out var cached) &&
                !cached.NeedsRefresh(config.NTSKERefreshInterval, timeProvider) &&
                // Not one without the public keys signed responses are checked against.
                (!Server.SignedResponses || cached.NTSKEResponse?.PublicKeys.Any() == true) &&
                (Server.OfferedAEADAlgorithms is not { } offered ||
                 cached.NTSKEResponse is not { } response        ||
                 offered.Contains(response.AEADAlgorithm)))
            {
                return cached;
            }

            return null;

        }

        #endregion


        #region (private) RequestSignedResponse(CachedState, CancellationToken)

        /// <summary>
        /// Ask the server for a digitally signed response, as a second, scheduled
        /// one, and check its signature against the public key it names.
        /// </summary>
        /// <remarks>
        /// Costs no cookie: its answer brings a new one, as every answer does.
        /// Its timing is no measurement - the second response leaves the server
        /// once it is signed.
        /// </remarks>
        private async Task<SignedResponseResult> RequestSignedResponse(CachedNTSKEState   CachedState,
                                                                       CancellationToken  CancellationToken)
        {

            if (CachedState.NTSClient is not NTSClient ntsClient)
                return new SignedResponseResult(false, ErrorMessage: "NTS client not available from cache");

            var keys = CachedState.NTSKEResponse?.PublicKeys.ToArray() ?? [];

            try
            {

                var answer = await ntsClient.QueryTime(
                                       Timeout:              config.NTPTimeout,
                                       NTSKEResponse:        CachedState.NTSKEResponse,
                                       SignedResponseMode:   SignedResponseMode.Scheduled,
                                       SignedResponseKeyId:  keys.FirstOrDefault()?.Id ?? 1,
                                       CancellationToken:    CancellationToken
                                   );

                CachedState.RemainingCookies = ToByteCookieCount(answer.CookiePoolDiagnostics?.AvailableCookieCount ??
                                                                 answer.RemainingCookiesAfterQuery);

                if (!answer.Success || answer.Response is not NTPPacket response)
                    return new SignedResponseResult(false, ErrorMessage: answer.ErrorMessage ?? "No signed response");

                var packet    = response.ToByteArray();

                if (response.NTSSignedResponse() is not NTSSignedResponseExtension signature)
                    return new SignedResponseResult(false, packet, ErrorMessage: "The response was not signed");

                var key       = keys.FirstOrDefault(key => key.Id == signature.KeyId);

                return new SignedResponseResult(
                           true,
                           packet,
                           signature.KeyId,
                           key is not null ? signature.Verify(response, key) : null,
                           key is null ? $"The key exchange named no public key {signature.KeyId}" : null
                       );

            }
            catch (Exception e) when (!CancellationToken.IsCancellationRequested)
            {
                return new SignedResponseResult(false, ErrorMessage: e.Message);
            }

        }

        #endregion

        #region (private) SendPreflight(CachedState, CancellationToken)

        /// <summary>
        /// Send the server the query of a measurement, and ignore its answer:
        /// whether it was sent, and the cookies kept up to date.
        /// </summary>
        /// <remarks>
        /// Waiting for the answer, or the NTP timeout, before the measurement: an
        /// answer still on its way would be taken for the measurement's.
        /// </remarks>
        private async Task<Boolean> SendPreflight(CachedNTSKEState   CachedState,
                                                  CancellationToken  CancellationToken)
        {

            if (CachedState.NTSClient is not NTSClient ntsClient)
                return false;

            try
            {

                var answer = await ntsClient.QueryTime(
                                       Timeout:            config.NTPTimeout,
                                       NTSKEResponse:      CachedState.NTSKEResponse,
                                       CancellationToken:  CancellationToken
                                   );

                CachedState.RemainingCookies = ToByteCookieCount(answer.CookiePoolDiagnostics?.AvailableCookieCount ??
                                                                 answer.RemainingCookiesAfterQuery);

                return true;

            }
            catch (Exception) when (!CancellationToken.IsCancellationRequested)
            {
                // What it found is what it was sent to find out, and nothing
                // more: the measurement after it says what the server does.
                return true;
            }

        }

        #endregion

        #region (static) OffsetCorrection(DelayAsymmetry, DelayVarAsymmetry, Delay, ShortestDelay)

        /// <summary>
        /// What is added to an offset measured with a server, for what is known
        /// about the path to it: its DelayAsymmetry, and its DelayVarAsymmetry
        /// times how much longer the delay was than the shortest of the last ones.
        /// </summary>
        /// <param name="DelayAsymmetry">The fixed correction, or null for none.</param>
        /// <param name="DelayVarAsymmetry">Where a hold-up was, from -0.5 (on the way there) to +0.5 (on the way back), or null for half each.</param>
        /// <param name="Delay">The round-trip delay of the measurement.</param>
        /// <param name="ShortestDelay">The shortest round-trip delay of the last measurements with the server, this one included.</param>
        public static TimeSpan OffsetCorrection(TimeSpan?  DelayAsymmetry,
                                                Double?    DelayVarAsymmetry,
                                                TimeSpan   Delay,
                                                TimeSpan   ShortestDelay)
        {

            var correction = DelayAsymmetry ?? TimeSpan.Zero;

            if (DelayVarAsymmetry is Double asymmetry && asymmetry != 0 && Delay > ShortestDelay)
                correction += TimeSpan.FromTicks((Int64) Math.Round(Math.Clamp(asymmetry, -0.5, 0.5) * (Delay - ShortestDelay).Ticks));

            return correction;

        }

        #endregion

        #region (private) ShortestRecentDelay(Hostname, Delay)

        /// <summary>
        /// Keep the given delay as the newest of the server's, and say the
        /// shortest of the last ones, this one included.
        /// </summary>
        private TimeSpan ShortestRecentDelay(DomainName  Hostname,
                                             TimeSpan    Delay)
        {

            var delays = recentDelays.GetOrAdd(Hostname, _ => new Queue<TimeSpan>(RecentDelays));

            lock (delays)
            {

                delays.Enqueue(Delay);

                while (delays.Count > RecentDelays)
                    delays.Dequeue();

                return delays.Min();

            }

        }

        #endregion

        #region (private) RefreshDelay(Server)

        /// <summary>
        /// How long after a key exchange with the given server the next one is
        /// due: a random time between its MinRefresh and its MaxRefresh.
        /// </summary>
        /// <remarks>
        /// An endpoint that names neither has the engine's refresh interval, as
        /// before; one that names only one of them has that one. A MaxRefresh
        /// shorter than the MinRefresh is taken as the MinRefresh.
        /// </remarks>
        private TimeSpan RefreshDelay(NTSServerEndpoint Server)
        {

            var min = Server.MinRefresh ?? Server.MaxRefresh ?? config.NTSKERefreshInterval;
            var max = Server.MaxRefresh ?? min;

            if (max <= min)
                return min;

            return min + (max - min) * random.NextDouble();

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

                   NTSKEErrorCategory.None                   => MonitoringErrorCategory.None,
                   NTSKEErrorCategory.DNS                    => MonitoringErrorCategory.DNS,
                   NTSKEErrorCategory.TCPConnect             => MonitoringErrorCategory.TCPConnect,
                   NTSKEErrorCategory.TLSHandshake           => MonitoringErrorCategory.TLSHandshake,
                   NTSKEErrorCategory.TLSCertificate         => MonitoringErrorCategory.TLSCertificate,
                   NTSKEErrorCategory.SSHSubsystem           => MonitoringErrorCategory.SSH,
                   NTSKEErrorCategory.Timeout                => MonitoringErrorCategory.NTSKEProtocol,
                   NTSKEErrorCategory.Protocol               => MonitoringErrorCategory.NTSKEProtocol,
                   NTSKEErrorCategory.UnknownCriticalRecord  => MonitoringErrorCategory.NTSKEProtocol,
                   NTSKEErrorCategory.ServerError            => MonitoringErrorCategory.NTSKEProtocol,
                   NTSKEErrorCategory.ServerWarning          => MonitoringErrorCategory.NTSKEProtocol,
                   NTSKEErrorCategory.MissingRequiredRecord  => MonitoringErrorCategory.NTSKEProtocol,
                   NTSKEErrorCategory.UnsupportedProtocol    => MonitoringErrorCategory.NTSKEProtocol,
                   NTSKEErrorCategory.UnsupportedAlgorithm   => MonitoringErrorCategory.NTSKEProtocol,
                   NTSKEErrorCategory.Canceled               => MonitoringErrorCategory.Canceled,
                   NTSKEErrorCategory.Exception              => MonitoringErrorCategory.Exception,
                   _                                         => MonitoringErrorCategory.Unknown

               };

        #endregion


        #region (private static) GetNTPRemoteInfo(Server, CachedState)

        /// <remarks>
        /// Host is null when the key exchange redirected to an address rather
        /// than a name - Address carries it, and a name that was never used
        /// would be worse than nothing.
        /// </remarks>
        private static (DomainName?  Host,
                        IIPAddress?  Address,
                        IPPort       Port)

            GetNTPRemoteInfo(NTSServerEndpoint  Server,
                             CachedNTSKEState   CachedState)

        {

            var ntskeResponse  = CachedState.NTSKEResponse;

            // Where the response names no NTP server, it is the key exchange server: the
            // endpoint's own, where it names one, and its host name otherwise.
            var keyExchange    = Server.NTSKEHost ?? Server.Hostname;

            // The text and not the domain name. What the key exchange named may
            // be an address, which a DomainName cannot hold - and the check
            // below was written expecting one, so it could never have fired.
            var hostText       = NTPRemoteEndPointResolver.GetRemoteHostText(ntskeResponse, keyExchange);
            var host           = NTPRemoteEndPointResolver.GetRemoteHost    (ntskeResponse, keyExchange);
            var port           = NTPRemoteEndPointResolver.GetRemotePort    (ntskeResponse, Server.NTPPort);
            var normalized     = hostText.Trim('[', ']').TrimEnd('.');

            if (IPAddress.TryParse(normalized, out var ipAddress))
            { }

            // NTPv4ServerNames and not NTPv4Servers: the latter is the former
            // without the addresses, so an exchange that redirected to one was
            // reported at the address this client had connected to for the key
            // exchange - a different machine, and one that had done nothing
            // wrong.
            else if ((ntskeResponse?.NTPv4ServerNames.Any() != true ||
                      String.Equals(normalized,
                                    keyExchange.ToString().TrimEnd('.'),
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
