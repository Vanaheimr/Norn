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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// Resolves the UDP endpoint used for NTS-protected NTP queries.
    /// </summary>
    public static class NTPRemoteEndPointResolver
    {

        #region GetRemoteHost(NTSKEResponse, FallbackHost)

        public static DomainName GetRemoteHost(NTSKE_Response?  NTSKEResponse,
                                               DomainName       FallbackHost)

            => NTSKEResponse?.NTPv4Servers.FirstOrDefault() ?? FallbackHost;

        #endregion

        #region GetRemotePort(NTSKEResponse, FallbackPort)

        public static IPPort GetRemotePort(NTSKE_Response?  NTSKEResponse,
                                           IPPort           FallbackPort)

            => NTSKEResponse?.NTPv4Ports.DefaultIfEmpty(FallbackPort).First() ?? FallbackPort;

        #endregion

        #region GetRemoteDescription(NTSKEResponse, FallbackHost, FallbackPort)

        public static String GetRemoteDescription(NTSKE_Response?  NTSKEResponse,
                                                  DomainName       FallbackHost,
                                                  IPPort           FallbackPort)
        {

            var host = GetRemoteHost(NTSKEResponse, FallbackHost);
            var port = GetRemotePort(NTSKEResponse, FallbackPort);

            return $"{host.ToString().TrimEnd('.')}:{port}";

        }

        #endregion

        #region ResolveAsync(NTSKEResponse, FallbackHost, FallbackPort, DNSClient, IPVersionPreference, Timeout, CancellationToken)

        public static async Task<System.Net.IPEndPoint?> ResolveAsync(NTSKE_Response?      NTSKEResponse,
                                                                      DomainName           FallbackHost,
                                                                      IPPort               FallbackPort,
                                                                      DNSClient            DNSClient,
                                                                      IPVersionPreference  IPVersionPreference,
                                                                      TimeSpan             Timeout,
                                                                      CancellationToken    CancellationToken = default)
        {

            var host       = GetRemoteHost(NTSKEResponse, FallbackHost);
            var port       = GetRemotePort(NTSKEResponse, FallbackPort);
            var normalized = host.ToString().TrimEnd('.');

            if ((NTSKEResponse?.NTPv4Servers.Any() != true ||
                 String.Equals(normalized,
                               FallbackHost.ToString().TrimEnd('.'),
                               StringComparison.OrdinalIgnoreCase)) &&
                NTSKEResponse?.TimingInfo?.ConnectedIPAddress is not null)
            {
                return new System.Net.IPEndPoint(
                           NTSKEResponse.TimingInfo.ConnectedIPAddress.ToDotNet(),
                           port.ToUInt16()
                       );
            }

            if (System.Net.IPAddress.TryParse(normalized, out var literalIPAddress))
                return new System.Net.IPEndPoint(
                           literalIPAddress,
                           port.ToUInt16()
                       );

            var ipAddresses = await DNSClient.Query_IPAddresses(
                                    host,
                                    Timeout:            Timeout,
                                    CancellationToken:  CancellationToken
                                ).ConfigureAwait(false);

            var orderedIPAddresses = IPVersionPreference switch {
                                         IPVersionPreference.IPv6Only    => ipAddresses.Where  (ipAddress => ipAddress is IPv6Address),
                                         IPVersionPreference.IPv4Only    => ipAddresses.Where  (ipAddress => ipAddress is IPv4Address),
                                         IPVersionPreference.PreferIPv4  => ipAddresses.OrderBy(ipAddress => ipAddress is IPv4Address ? 0 : 1),
                                         _                               => ipAddresses.OrderBy(ipAddress => ipAddress is IPv6Address ? 0 : 1)
                                     };

            var selectedIPAddress = orderedIPAddresses.FirstOrDefault();

            return selectedIPAddress is not null
                       ? new System.Net.IPEndPoint(
                             selectedIPAddress.ToDotNet(),
                             port.ToUInt16()
                         )
                       : null;

        }

        #endregion

    }

}
