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

        #region GetRemoteHostText(NTSKEResponse, FallbackHost)

        /// <summary>
        /// Where the NTP request is going, written the way the key exchange
        /// wrote it.
        /// </summary>
        /// <remarks>
        /// Text, because that is what RFC 8915 section 4.1.7 allows: the
        /// NTPv4 Server Negotiation record "SHALL be either an IPv4 address, an
        /// IPv6 address, or a fully qualified domain name". Any caller that
        /// wants to know where a request went has to be able to hold all three,
        /// and only a string can.
        /// </remarks>
        public static String GetRemoteHostText(NTSKE_Response?  NTSKEResponse,
                                               DomainName       FallbackHost)

            => NTSKEResponse?.NTPv4ServerNames.FirstOrDefault()?.Trim() is String named && named.Length > 0
                   ? named
                   : FallbackHost.ToString().TrimEnd('.');

        #endregion

        #region GetRemoteHost(NTSKEResponse, FallbackHost)

        /// <summary>
        /// Where the NTP request is going, when that is a name; null when the
        /// key exchange named an address instead.
        /// </summary>
        /// <remarks>
        /// Null and not the fallback host. It used to answer with
        /// NTPv4Servers.FirstOrDefault() - the negotiated servers filtered down
        /// to those that parse as a domain name - falling back to the host the
        /// exchange happened on. So an exchange that redirected to an address
        /// was reported as though the request had gone to the key exchange
        /// host, and a monitoring engine that files a failure against a machine
        /// nothing was sent to is worse than one that leaves the field empty.
        ///
        /// An address is not lost by this: it is in
        /// <see cref="GetRemoteHostText"/>, which is what a caller reporting
        /// where a request went should read.
        ///
        /// IPv4 is treated the same as IPv6 here, and deliberately, although
        /// "127.0.0.2" happens to parse as a domain name - labels of digits
        /// being legal. Letting one family through as a name and not the other
        /// is how this went unnoticed in the first place.
        /// </remarks>
        public static DomainName? GetRemoteHost(NTSKE_Response?  NTSKEResponse,
                                                DomainName       FallbackHost)
        {

            var text = GetRemoteHostText(NTSKEResponse, FallbackHost).Trim('[', ']').TrimEnd('.');

            if (System.Net.IPAddress.TryParse(text, out _))
                return null;

            return DomainName.TryParse(text, out var host, out _)
                       ? host
                       : null;

        }

        #endregion

        #region GetRemotePort(NTSKEResponse, FallbackPort)

        public static IPPort GetRemotePort(NTSKE_Response?  NTSKEResponse,
                                           IPPort           FallbackPort)

            => NTSKEResponse?.NTPv4Ports.DefaultIfEmpty(FallbackPort).First() ?? FallbackPort;

        #endregion

        #region GetRemoteCandidates(NTSKEResponse, FallbackHost, FallbackPort)

/// <param name="ChosenServer">
        /// One of the servers this exchange named, to the exclusion of the
        /// others - or null to take them in the order they were named.
        /// </param>
        /// <remarks>
        /// A key exchange may name several NTP servers, and without a choice
        /// the first that resolves is used. Naming one narrows the list to it,
        /// which is what lets a caller ask each of them in turn rather than
        /// only ever reaching whichever happens to be first.
        ///
        /// A name that was not among them narrows the list to nothing, and
        /// deliberately: RFC 8915 section 4.1.7 says the negotiated server is
        /// the one "that will accept the supplied cookies", and nobody else was
        /// said to accept them. Sending them somewhere else spends a cookie on
        /// a server holding different master keys.
        /// </remarks>
        public static IEnumerable<(String Host, IPPort Port)> GetRemoteCandidates(NTSKE_Response?  NTSKEResponse,
                                                                                  DomainName       FallbackHost,
                                                                                  IPPort           FallbackPort,
                                                                                  String?          ChosenServer   = null)
        {

            var hosts = (NTSKEResponse?.NTPv4ServerNames.Any() == true
                             ? NTSKEResponse.NTPv4ServerNames
                             : [ FallbackHost.ToString().TrimEnd('.') ]).
                        ToList();

            var ports = (NTSKEResponse?.NTPv4Ports.Any() == true
                             ? NTSKEResponse.NTPv4Ports
                             : [ FallbackPort ]).
                        ToList();

            var chosen = ChosenServer?.Trim().Trim('[', ']').TrimEnd('.');

            for (var i = 0; i < hosts.Count; i++)
            {

                if (chosen is not null &&
                    !String.Equals(hosts[i].Trim('[', ']').TrimEnd('.'),
                                   chosen,
                                   StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

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

        #region QueryIPAddressesToConnect(DNSClient, Hostname, IPVersionPreference, Timeout, CancellationToken)

        /// <summary>
        /// The addresses to connect to the given name, as far as the given preference allows them: of one family
        /// only, when only one will do, asked for that family alone; else of both, with the Resolution Delay of
        /// RFC 8305 §3.
        /// </summary>
        /// <remarks>
        /// With both families, AAAA and A are asked for at once, and once one of them has answered with addresses
        /// the other is waited for 50 ms and no longer (see Hermod's Query_IPAddressesToConnect): a name server
        /// that never answers for one family costs 50 ms, and not the whole budget of the key exchange or the NTP
        /// request. Measured with a name whose A record was in the cache and whose AAAA query went to a name server
        /// that dropped it: the key exchange, with a budget of 10 s, waited for the AAAA answer until it timed out.
        /// A family that alone will do is not cut short by the other one's answer: it is the only one asked for.
        /// </remarks>
        /// <param name="DNSClient">The DNS client to ask.</param>
        /// <param name="Hostname">The name to connect to.</param>
        /// <param name="IPVersionPreference">Which address families will do, and which is preferred.</param>
        /// <param name="Timeout">The timeout of each query.</param>
        /// <param name="CancellationToken">A cancellation token.</param>
        public static async Task<IEnumerable<IIPAddress>> QueryIPAddressesToConnect(DNSClient            DNSClient,
                                                                                   DomainName           Hostname,
                                                                                   IPVersionPreference  IPVersionPreference,
                                                                                   TimeSpan             Timeout,
                                                                                   CancellationToken    CancellationToken = default)

            => IPVersionPreference switch {

                   IPVersionPreference.IPv6Only  => (await DNSClient.Query_IPv6Addresses(Hostname,
                                                                                         Timeout,
                                                                                         CancellationToken: CancellationToken).ConfigureAwait(false)).Cast<IIPAddress>(),

                   IPVersionPreference.IPv4Only  => (await DNSClient.Query_IPv4Addresses(Hostname,
                                                                                         Timeout,
                                                                                         CancellationToken: CancellationToken).ConfigureAwait(false)).Cast<IIPAddress>(),

                   _                             =>  await DNSClient.Query_IPAddressesToConnect(Hostname,
                                                                                                Timeout:            Timeout,
                                                                                                CancellationToken:  CancellationToken).ConfigureAwait(false)

               };

        #endregion

        #region ResolveAsync(NTSKEResponse, FallbackHost, FallbackPort, DNSClient, IPVersionPreference, Timeout, CancellationToken)

/// <param name="ChosenServer">
        /// One of the servers this exchange named, to the exclusion of the
        /// others; null takes them in the order they were named.
        /// </param>
        public static async Task<System.Net.IPEndPoint?> ResolveAsync(NTSKE_Response?      NTSKEResponse,
                                                                      DomainName           FallbackHost,
                                                                      IPPort               FallbackPort,
                                                                      DNSClient            DNSClient,
                                                                      IPVersionPreference  IPVersionPreference,
                                                                      TimeSpan             Timeout,
                                                                      CancellationToken    CancellationToken = default,
                                                                      String?              ChosenServer      = null)
        {

            var candidates = GetRemoteCandidates(
                                 NTSKEResponse,
                                 FallbackHost,
                                 FallbackPort,
                                 ChosenServer
                             ).ToList();

            // Which happens when a caller asked for a server this exchange did
            // not name. There is nothing to resolve and nothing to fall back
            // to: falling back would send the cookies somewhere they were never
            // said to be accepted.
            if (candidates.Count == 0)
                return null;

            // NTPv4ServerNames and not NTPv4Servers. The latter is the former
            // filtered down to what parses as a domain name, and RFC 8915
            // section 4.1.7 says the record "SHALL be either an IPv4 address,
            // an IPv6 address, or a fully qualified domain name" - so a server
            // that redirects to an address of its own had that redirect dropped
            // here and the request went to the key exchange host instead. Which
            // is precisely what the comment further down calls turning a plain
            // misconfiguration into an authentication failure reported against
            // the wrong machine, and the failure check below already used the
            // right property, so the two disagreed with each other.
            var namedSomewhereElse = NTSKEResponse?.NTPv4ServerNames.Any() == true &&
                                     !String.Equals(candidates[0].Host.Trim('[', ']').TrimEnd('.'),
                                                    FallbackHost.ToString().TrimEnd('.'),
                                                    StringComparison.OrdinalIgnoreCase);

            if (!namedSomewhereElse &&
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
                    ipAddresses = await QueryIPAddressesToConnect(
                                           DNSClient,
                                           DomainName.Parse(normalized),
                                           IPVersionPreference,
                                           Timeout,
                                           CancellationToken
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
