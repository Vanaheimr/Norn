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

        #region GetRemoteCandidates(NTSKEResponse, FallbackHost, FallbackPort)

        public static IEnumerable<(String Host, IPPort Port)> GetRemoteCandidates(NTSKE_Response?  NTSKEResponse,
                                                                                  DomainName       FallbackHost,
                                                                                  IPPort           FallbackPort)
        {

            var hosts = (NTSKEResponse?.NTPv4ServerNames.Any() == true
                             ? NTSKEResponse.NTPv4ServerNames
                             : [ FallbackHost.ToString().TrimEnd('.') ]).
                        ToList();

            var ports = (NTSKEResponse?.NTPv4Ports.Any() == true
                             ? NTSKEResponse.NTPv4Ports
                             : [ FallbackPort ]).
                        ToList();

            for (var i = 0; i < hosts.Count; i++)
            {
                yield return (
                    hosts[i],
                    ports[Math.Min(i, ports.Count - 1)]
                );
            }

        }

        #endregion

        #region GetRemoteDescription(NTSKEResponse, FallbackHost, FallbackPort)

        public static String GetRemoteDescription(NTSKE_Response?  NTSKEResponse,
                                                  DomainName       FallbackHost,
                                                  IPPort           FallbackPort)
        {

            var (host, port) = GetRemoteCandidates(
                                   NTSKEResponse,
                                   FallbackHost,
                                   FallbackPort
                               ).First();

            return FormatEndpoint(host.TrimEnd('.'), port);

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

            var candidates = GetRemoteCandidates(
                                 NTSKEResponse,
                                 FallbackHost,
                                 FallbackPort
                             ).ToList();

            if ((NTSKEResponse?.NTPv4Servers.Any() != true ||
                 String.Equals(candidates[0].Host.TrimEnd('.'),
                               FallbackHost.ToString().TrimEnd('.'),
                               StringComparison.OrdinalIgnoreCase)) &&
                NTSKEResponse?.TimingInfo?.ConnectedIPAddress is not null)
            {
                return new System.Net.IPEndPoint(
                           NTSKEResponse.TimingInfo.ConnectedIPAddress.ToDotNet(),
                           candidates[0].Port.ToUInt16()
                       );
            }

            foreach (var (host, port) in candidates)
            {

                var normalized = host.TrimEnd('.');

                if (System.Net.IPAddress.TryParse(normalized, out var literalIPAddress))
                {
                    if (IsAllowedIPAddress(literalIPAddress, IPVersionPreference))
                    {
                        return new System.Net.IPEndPoint(
                                   literalIPAddress,
                                   port.ToUInt16()
                               );
                    }

                    continue;
                }

                IEnumerable<IIPAddress> ipAddresses;

                try
                {
                    ipAddresses = await DNSClient.Query_IPAddresses(
                                           DomainName.Parse(normalized),
                                           Timeout:            Timeout,
                                           CancellationToken:  CancellationToken
                                       ).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch
                {
                    continue;
                }

                var orderedIPAddresses = IPVersionPreference switch {
                                             IPVersionPreference.IPv6Only    => ipAddresses.Where  (ipAddress => ipAddress is IPv6Address),
                                             IPVersionPreference.IPv4Only    => ipAddresses.Where  (ipAddress => ipAddress is IPv4Address),
                                             IPVersionPreference.PreferIPv4  => ipAddresses.OrderBy(ipAddress => ipAddress is IPv4Address ? 0 : 1),
                                             _                               => ipAddresses.OrderBy(ipAddress => ipAddress is IPv6Address ? 0 : 1)
                                         };

                var selectedIPAddress = orderedIPAddresses.FirstOrDefault();

                if (selectedIPAddress is not null)
                    return new System.Net.IPEndPoint(
                               selectedIPAddress.ToDotNet(),
                               port.ToUInt16()
                           );

            }

            return null;

        }

        #endregion

        #region (private static) FormatEndpoint(Host, Port)

        private static String FormatEndpoint(String  Host,
                                             IPPort  Port)
        {

            return System.Net.IPAddress.TryParse(Host, out var ipAddress) &&
                   ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                       ? $"[{Host}]:{Port}"
                       : $"{Host}:{Port}";

        }

        #endregion

        #region (private static) IsAllowedIPAddress(IPAddress, IPVersionPreference)

        private static Boolean IsAllowedIPAddress(System.Net.IPAddress  IPAddress,
                                                  IPVersionPreference   IPVersionPreference)
        {

            if (IPVersionPreference == IPVersionPreference.IPv4Only)
                return IPAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;

            if (IPVersionPreference == IPVersionPreference.IPv6Only)
                return IPAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;

            return true;

        }

        #endregion

    }

}
