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

using System.Collections.Concurrent;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

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
