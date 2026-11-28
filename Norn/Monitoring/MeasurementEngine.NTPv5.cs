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

using System.Diagnostics;
using System.Collections.Concurrent;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;
using IPAddress = org.GraphDefined.Vanaheimr.Hermod.IPAddress;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    public partial class MeasurementEngine
    {

        #region Data

        /// <summary>
        /// The last NTPv5 probe of each server whose endpoint asks for one.
        /// </summary>
        private readonly ConcurrentDictionary<DomainName, NTPv5CapabilityResult> ntpv5Probes = [];

        #endregion

        #region Properties

        /// <summary>
        /// The last NTPv5 probe of each server whose endpoint asks for one
        /// (<see cref="NTSServerEndpoint.ProbeNTPv5"/>).
        /// </summary>
        public IReadOnlyDictionary<DomainName, NTPv5CapabilityResult> NTPv5Capabilities
            => ntpv5Probes;

        #endregion


        #region (private static) NTPVersionOf(CachedState)

        /// <summary>
        /// The version of NTP a server is asked in after the given key exchange - see
        /// <see cref="CachedNTSKEState.NTPVersion"/>.
        /// </summary>
        private static Byte NTPVersionOf(CachedNTSKEState CachedState)

            => CachedState.NTPVersion;

        #endregion

        #region (private static) NoVersionAgreed(Server, Response)

        /// <summary>
        /// Why a key exchange that agreed to none of the versions the server is asked in failed.
        /// </summary>
        private static String NoVersionAgreed(NTSServerEndpoint  Server,
                                              NTSKE_Response     Response)

            => $"The key exchange agreed to next protocol {(Response.NextProtocols.Count > 0 ? String.Join(", ", Response.NextProtocols.Select(protocol => $"0x{protocol:X4}")) : "none")}, " +
               $"and {Server.Hostname} is asked in {String.Join(" or ", Server.EffectiveNTPVersions.Select(version => $"NTPv{version}"))} alone.";

        #endregion

        #region (private) MeasureNTPv5(Server, CachedState, CancellationToken)

        /// <summary>
        /// One measurement in NTPv5 under NTS, with the cookies of a key exchange that agreed
        /// to it: the NTPv5 counterpart of MeasureNTP.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The timestamps, the offset and the delay are those of § 8: the corrected offset
        /// and delay where the network delivered corrections that pass their checks, else the
        /// plain ones. The poll field of the response is applied to the server's access state
        /// as NTPv5 has it (§ 6: 127 is "go away"), where kisses are respected.
        /// </para>
        /// <para>
        /// NTPv5 has no leap indicator. An unsynchronized server (§ 9.5) is reported as NTPv4
        /// would report it, with the leap indicator 3 of an alarm, and its time is measured, as
        /// that of an unsynchronized NTPv4 server is: whoever uses it decides. What § 9.5
        /// rules out beyond that - timestamps missing, another timescale - or a loop (§ 7.4)
        /// is a failed measurement.
        /// </para>
        /// </remarks>
        private async Task<NTPMeasurementResult> MeasureNTPv5(NTSServerEndpoint  Server,
                                                              CachedNTSKEState   CachedState,
                                                              CancellationToken  CancellationToken)
        {

            var sw          = Stopwatch.StartNew();
            var ntsClient   = CachedState.NTSClient;
            var remoteInfo  = GetNTPRemoteInfo(Server, CachedState);

            if (ntsClient is null)
                return new NTPMeasurementResult {
                           Success        = false,
                           NTPVersion     = 5,
                           ErrorMessage   = Error.Create("NTS client not available from cache"),
                           ErrorCategory  = MonitoringErrorCategory.Cache,
                           RemoteHost     = remoteInfo.Host,
                           RemoteAddress  = remoteInfo.Address,
                           RemotePort     = remoteInfo.Port
                       };

            try
            {

                var access = config.RespectKissOfDeath ? AccessStateFor(Server.Hostname) : null;

                access?.RecordQuery(timeProvider.GetUtcNow());

                var query = await ntsClient.QueryNTPv5(Timeout:            config.NTPTimeout,
                                                       NTSKEResponse:      CachedState.NTSKEResponse,
                                                       AccessState:        access,
                                                       CancellationToken:  CancellationToken).ConfigureAwait(false);

                sw.Stop();

                var roundTrip      = query.RoundTripTime ?? sw.Elapsed;
                var remoteAddress  = query.RemoteEndPoint is not null ? IPAddress.FromDotNet(query.RemoteEndPoint.Address) : remoteInfo.Address;
                var remotePort     = query.RemoteEndPoint is not null ? IPPort.Parse(query.RemoteEndPoint.Port)            : remoteInfo.Port;
                var diagnostics    = ntsClient.CookiePoolDiagnostics;

                CachedState.RemainingCookies = ToByteCookieCount(query.RemainingCookies);

                // A key exchange the client made itself, its cookies having run out: new keys
                // with new cookies, as in MeasureNTP.
                if (ntsClient.LastNTSKEResponse is not null &&
                    !ReferenceEquals(ntsClient.LastNTSKEResponse, CachedState.NTSKEResponse))
                {
                    CachedState.NTSKEResponse  = ntsClient.LastNTSKEResponse;
                    CachedState.LastRefreshed  = timeProvider.GetUtcNow();
                    CachedState.RefreshAt      = CachedState.LastRefreshed + RefreshDelay(Server);
                }

                NTPMeasurementResult Failed(String Message, MonitoringErrorCategory Category, Boolean Kiss = false)

                    => new () {
                           Success                     = false,
                           NTPVersion                  = 5,
                           StopwatchRTT                = roundTrip,
                           ErrorMessage                = Error.Create(Message),
                           ErrorCategory               = Category,
                           KissOfDeath                 = Kiss,
                           KissOfDeathCode             = Kiss ? "NTPv5 poll 127" : null,
                           RemoteHost                  = remoteInfo.Host,
                           RemoteAddress               = remoteAddress,
                           RemotePort                  = remotePort,
                           RemainingCookiesAfterQuery  = CachedState.RemainingCookies,
                           CookiePoolSize              = diagnostics.AvailableCookieCount,
                           CookiePoolMaxSize           = diagnostics.MaxCookiePoolSize,
                           CookiePoolLowWatermark      = diagnostics.LowWatermark,
                           CookiePoolLow               = diagnostics.IsLow,
                           CookiePoolEmpty             = diagnostics.IsEmpty
                       };

                if (!query.Success)
                    return Failed(query.ErrorMessage ?? "NTPv5 query failed!",
                                  query.ErrorCategory == NTSQueryErrorCategory.KissOfDeath
                                      ? MonitoringErrorCategory.KissOfDeath
                                      : MapNTSQueryErrorCategory(query.ErrorCategory),
                                  query.ErrorCategory == NTSQueryErrorCategory.KissOfDeath);

                if (query.Response is not NTPv5Packet response ||
                    query.Measurement is not NTPv5Measurement measurement)
                    return Failed($"The NTPv5 response cannot be measured with: {query.Unusable}.", MonitoringErrorCategory.Unknown);

                if (query.IsLoop)
                    return Failed("The server's reference IDs contain this client's own: a loop (§ 7.4).", MonitoringErrorCategory.Unknown);

                if (query.Unusable is NTPv5Unusable.MissingTimestamps or NTPv5Unusable.Timescale)
                    return Failed($"The NTPv5 response is not usable: {query.Unusable} (§ 9.5).", MonitoringErrorCategory.Unknown);

                // A response, its poll field applied above: one step back towards the usual
                // rate, as after an NTPv4 answer.
                if (config.RespectKissOfDeath && !response.Poll.Equals((SByte) 127))
                    AccessStateFor(Server.Hostname).RecordAnswer();

                var offset      = measurement.BestOffset;
                var delay       = measurement.BestDelay;
                var correction  = OffsetCorrection(Server.DelayAsymmetry,
                                                   Server.DelayVarAsymmetry,
                                                   delay,
                                                   ShortestRecentDelay(Server.Hostname, delay));

                return new NTPMeasurementResult {

                           Success                     = true,
                           NTPVersion                  = 5,
                           Interleaved                 = measurement.Interleaved,
                           NTSAuthenticationValid      = query.IsAuthenticated,
                           UniqueIdMatched             = query.IsAuthenticated,

                           T1_ClientSend               = measurement.T1,
                           T2_ServerReceive            = measurement.T2,
                           T3_ServerTransmit           = measurement.T3,
                           T4_ClientReceive            = measurement.T4,

                           Offset                      = offset + correction,
                           MeasuredOffset              = offset,
                           OffsetCorrection            = correction,
                           RoundTripDelay              = delay,
                           StopwatchRTT                = roundTrip,
                           RemoteHost                  = remoteInfo.Host,
                           RemoteAddress               = remoteAddress,
                           RemotePort                  = remotePort,

                           LeapIndicator               = (Byte) (response.Flags.HasFlag(NTPv5Flags.Unsynchronized) ? 3 : 0),
                           Stratum                     = response.Stratum,
                           Poll                        = (Byte) Math.Max((SByte) 0, response.Poll),
                           Precision                   = response.Precision,
                           RootDelaySeconds            = response.RootDelayTime?.TotalSeconds      ?? Double.PositiveInfinity,
                           RootDispersionSeconds       = response.RootDispersionTime?.TotalSeconds ?? Double.PositiveInfinity,

                           NewCookieReceived           = query.NewCookies > 0,
                           RemainingCookiesAfterQuery  = CachedState.RemainingCookies,
                           CookiePoolSize              = diagnostics.AvailableCookieCount,
                           CookiePoolMaxSize           = diagnostics.MaxCookiePoolSize,
                           CookiePoolLowWatermark      = diagnostics.LowWatermark,
                           SeededCookieCount           = diagnostics.SeededCookieCount,
                           CookiesReceived             = diagnostics.CookiesReceived,
                           CookiesConsumed             = diagnostics.CookiesConsumed,
                           DroppedCookieCount          = diagnostics.DroppedCookieCount,
                           CookiePoolLow               = diagnostics.IsLow,
                           CookiePoolEmpty             = diagnostics.IsEmpty,
                           KissOfDeath                 = false

                       };

            }
            catch (Exception e)
            {

                sw.Stop();

                return new NTPMeasurementResult {
                           Success        = false,
                           NTPVersion     = 5,
                           ErrorMessage   = Error.Create($"NTPv5 exception: {e.Message}"),
                           ErrorCategory  = MonitoringErrorCategory.Exception,
                           StopwatchRTT   = sw.Elapsed
                       };

            }

        }

        #endregion

        #region (private) SendPreflightNTPv5(NTSClient, CachedState, CancellationToken)

        /// <summary>
        /// The preflight of a server asked in NTPv5: one NTPv5 query whose answer is ignored.
        /// </summary>
        private async Task SendPreflightNTPv5(NTSClient          NTSClient,
                                              CachedNTSKEState   CachedState,
                                              CancellationToken  CancellationToken)
        {

            var answer = await NTSClient.QueryNTPv5(Timeout:            config.NTPTimeout,
                                                    NTSKEResponse:      CachedState.NTSKEResponse,
                                                    CancellationToken:  CancellationToken).ConfigureAwait(false);

            if (NTSClient.LastNTSKEResponse is NTSKE_Response currentKE &&
                !ReferenceEquals(CachedState.NTSKEResponse, currentKE))
            {
                CachedState.NTSKEResponse = currentKE;
                CachedState.LastRefreshed = timeProvider.GetUtcNow();
            }

            CachedState.RemainingCookies = ToByteCookieCount(answer.RemainingCookies);

        }

        #endregion

        #region (private) NTPv5CapabilityOf(Server, DNSClient, CancellationToken)

        /// <summary>
        /// The NTPv5 probe of a server: the last one while it is younger than
        /// <see cref="MonitoringConfig.NTPv5ProbeInterval"/>, a new one after that.
        /// </summary>
        private async Task<NTPv5CapabilityResult> NTPv5CapabilityOf(NTSServerEndpoint  Server,
                                                                    DNSClient          DNSClient,
                                                                    CancellationToken  CancellationToken)
        {

            if (ntpv5Probes.TryGetValue(Server.Hostname, out var last) &&
                timeProvider.GetUtcNow() - last.Timestamp < config.NTPv5ProbeInterval)
                return last with { FromCache = true };

            var probe = await ProbeNTPv5(Server, DNSClient, CancellationToken).ConfigureAwait(false);

            ntpv5Probes[Server.Hostname] = probe;

            return probe;

        }

        #endregion

        #region ProbeNTPv5(Server, DNSClient, CancellationToken)

        /// <summary>
        /// Find out what a server supports of NTPv5 (draft-ietf-ntp-ntpv5-10), now, in the
        /// three ways a client can - see <see cref="NTPv5CapabilityResult"/>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// A plain NTPv4 request with the negotiation magic of § 12; a plain NTPv5 request
        /// asking for a Server Information field (§ 7.6), and for an answer even from an
        /// unsynchronized server, because what is asked here is whether it speaks NTPv5, not
        /// whether its time is good; and, except over SSH, a key exchange of its own offering
        /// NTS for NTPv5 first (§ 11), with one NTPv5 query under it where it was agreed.
        /// </para>
        /// <para>
        /// None of it touches what the measurement holds: neither its key exchange and
        /// cookies, nor the access state its kisses are kept in. A probe is a few packets an
        /// hour, and a server's "go away" to an NTPv5 probe is reported, not obeyed for NTPv4.
        /// </para>
        /// </remarks>
        public async Task<NTPv5CapabilityResult> ProbeNTPv5(NTSServerEndpoint  Server,
                                                            DNSClient          DNSClient,
                                                            CancellationToken  CancellationToken = default)
        {

            var result = new NTPv5CapabilityResult(timeProvider.GetUtcNow());

            #region Plain: NTPv4 with the magic, then NTPv5

            using (var plain = new NTSClient(Server.Hostname,
                                             Server.NTSKEPort,
                                             Server.NTPPort,
                                             Timeout:       config.NTPTimeout,
                                             DNSClient:     DNSClient,
                                             TimeProvider:  timeProvider) { NTPv5 = NTPv5Support.Draft })
            {

                try
                {

                    var v4 = await plain.QueryTime(Timeout:            config.NTPTimeout,
                                                   AdvertiseNTPv5:     true,
                                                   CancellationToken:  CancellationToken).ConfigureAwait(false);

                    result = v4.Success
                                 ? result with { AdvertisedInNTPv4 = v4.ServerAdvertisesNTPv5 }
                                 : result with { NTPv4Error        = v4.ErrorMessage ?? v4.ErrorCategory.ToString() };

                }
                catch (Exception e) when (!CancellationToken.IsCancellationRequested)
                {
                    result = result with { NTPv4Error = e.Message };
                }

                try
                {

                    var v5 = await plain.QueryNTPv5(Timeout:               config.NTPTimeout,
                                                    AcceptUnsynchronized:  true,
                                                    ExtensionFields:       [ NTPv5ExtensionField.ServerInformation() ],
                                                    CancellationToken:     CancellationToken).ConfigureAwait(false);

                    result = v5.Success
                                 ? result with {
                                       PlainNTPv5         = true,
                                       PlainUnusable      = v5.Unusable,
                                       SupportedVersions  = v5.ServerInformation?.SupportedVersions,
                                       SupportedFlags     = v5.ServerInformation?.SupportedFlags,
                                       Stratum            = v5.Response?.Stratum,
                                       Offset             = v5.Measurement?.Offset,
                                       Delay              = v5.Measurement?.Delay
                                   }
                                 : result with { PlainNTPv5Error = v5.ErrorMessage ?? v5.ErrorCategory.ToString() };

                }
                catch (Exception e) when (!CancellationToken.IsCancellationRequested)
                {
                    result = result with { PlainNTPv5Error = e.Message };
                }

            }

            #endregion

            #region NTS for NTPv5

            if (Server.ConnectOverSSH is not null)
                return result;

            using var nts = new NTSClient(Server.NTSKEHost ?? Server.Hostname,
                                          Server.NTSKEPort,
                                          Server.NTPPort,
                                          RemoteCertificateValidator:  BuildCertificateValidator(Server),
                                          OfferedAEADAlgorithms:       Server.OfferedAEADAlgorithms,
                                          Timeout:                     config.NTSKETimeout,
                                          DNSClient:                   DNSClient,
                                          TimeProvider:                timeProvider,
                                          RequestedNTPServer:          Server.NTSKEHost is not null ? Server.Hostname : null) {
                                NTPv5 = NTPv5Support.Draft
                            };

            try
            {

                using var ke = await nts.GetNTSKERecords(Timeout:            config.NTSKETimeout,
                                                         CancellationToken:  CancellationToken).ConfigureAwait(false);

                if (!ke.Success || ke.Response is null || ke.Response.ErrorMessage is not null)
                    return result with { NTSError = ke.ErrorMessage ?? ke.Response?.ErrorMessage ?? "NTS-KE failed." };

                if (ke.Response.NextProtocol != NTPv5Draft.NTSNextProtocolId)
                    return result with { NTSNegotiated = false };

                nts.SeedCookies(ke.Response);

                var query = await nts.QueryNTPv5(Timeout:               config.NTPTimeout,
                                                 NTSKEResponse:         ke.Response,
                                                 AcceptUnsynchronized:  true,
                                                 CancellationToken:     CancellationToken).ConfigureAwait(false);

                return result with {
                           NTSNegotiated  = true,
                           NTSQuery       = query.Success && query.IsAuthenticated,
                           NTSError       = query.Success ? null : query.ErrorMessage ?? query.ErrorCategory.ToString()
                       };

            }
            catch (Exception e) when (!CancellationToken.IsCancellationRequested)
            {
                return result with { NTSError = e.Message };
            }

            #endregion

        }

        #endregion

    }

}
