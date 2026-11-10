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

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// Who may query this server at all: the access list of RFC 8633 § 5.1, "Minimizing
    /// Information Leakage".
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every NTP response tells whoever asked the server's reference identifier, its reference
    /// time, its stratum and its root distance, and RFC 8633 § 5.1 recommends "Access Control
    /// Lists" to limit who learns them. An address this list does not allow is not answered at
    /// all: its NTP requests are dropped without a word - not even a kiss, which would tell it
    /// that a server is there - its NTS-KE connections are closed before the TLS handshake, and
    /// its SSH sessions are turned away once they have signed in.
    /// </para>
    /// <para>
    /// Everyone may by default. A list consists of networks that are allowed and networks that
    /// are denied, and the most specific network that contains an address decides for it, in
    /// whatever order the networks were given - as with ntpd's <c>restrict</c> and chrony's
    /// <c>allow</c> and <c>deny</c>. An address no network contains is allowed. To serve only
    /// some networks, deny all and allow those:
    /// <c>Deny: [0.0.0.0/0, ::/0], Allow: [10.0.0.0/8]</c>.
    /// </para>
    /// <para>
    /// Every network has to change something. An allowed network that nothing around it denies,
    /// or a network that is both allowed and denied, is refused when the list is made, rather
    /// than left to look as if it did what its author meant: <c>Allow: [10.0.0.0/8]</c> by
    /// itself serves everybody, not only 10.0.0.0/8.
    /// </para>
    /// </remarks>
    public sealed class NTPAccessList
    {

        #region Data

        /// <summary>
        /// The networks with what they say, the most specific first: the first that contains an
        /// address decides for it.
        /// </summary>
        private readonly (IPNetwork Network, Boolean Allowed)[] rules;

        #endregion

        #region Properties

        /// <summary>
        /// The access list that allows everyone, which a server has unless told otherwise.
        /// </summary>
        public static NTPAccessList     Everyone    { get; } = new ();

        /// <summary>
        /// The networks that are allowed, inside the ones that are denied.
        /// </summary>
        public IReadOnlyList<IPNetwork> Allowed     { get; }

        /// <summary>
        /// The networks that are denied.
        /// </summary>
        public IReadOnlyList<IPNetwork> Denied      { get; }

        /// <summary>
        /// Whether this list allows every address, as it does without networks.
        /// </summary>
        public Boolean                  IsEveryone
            => rules.Length == 0;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create an access list.
        /// </summary>
        /// <param name="Allow">The networks to allow, inside networks that are denied.</param>
        /// <param name="Deny">The networks to deny.</param>
        /// <exception cref="ArgumentException">A network changes nothing, or is IPv4 written as IPv6.</exception>
        public NTPAccessList(IEnumerable<IPNetwork>?  Allow   = null,
                             IEnumerable<IPNetwork>?  Deny    = null)
        {

            this.Allowed  = [.. (Allow ?? []).Distinct()];
            this.Denied   = [.. (Deny  ?? []).Distinct()];

            foreach (var network in Allowed.Concat(Denied))
            {

                // An IPv4 client is matched by its IPv4 address, also where a dual-stack socket
                // reported it as ::ffff:a.b.c.d - and IPNetwork.Contains never matches an IPv4
                // address against a network of such addresses.
                if (network.BaseAddress.IsIPv4MappedToIPv6)
                    throw new ArgumentException($"{network} is IPv4 written as IPv6; write it as an IPv4 network.");

                if (Allowed.Contains(network) && Denied.Contains(network))
                    throw new ArgumentException($"{network} is both allowed and denied.");

            }

            this.rules    = [.. Allowed.Select(network => (network, true)).
                                Concat(Denied.Select(network => (network, false))).
                                OrderByDescending(rule => rule.network.PrefixLength)];

            foreach (var (network, allowed) in rules)
            {

                // What the address of the network would get without it: the verdict of the most
                // specific network around it, or "allowed" where there is none.
                var around = rules.Where(rule => rule.Network.PrefixLength < network.PrefixLength &&
                                                 rule.Network.Contains(network.BaseAddress)).
                                   Select(rule => (Network: (IPNetwork?) rule.Network, rule.Allowed)).
                                   FirstOrDefault((Network: null, Allowed: true));

                if (allowed == around.Allowed)
                    throw new ArgumentException(
                              allowed
                                  ? around.Network is IPNetwork enclosing
                                        ? $"Allowing {network} changes nothing: {enclosing} around it is allowed already."
                                        : $"Allowing {network} changes nothing: everything that is not denied is allowed. " +
                                          $"To serve only {network}, deny everything else as well."
                                  : $"Denying {network} changes nothing: {around.Network} around it is denied already."
                          );

            }

        }

        #endregion


        #region Allows(Address)

        /// <summary>
        /// Whether this list allows the given address to query the server.
        /// </summary>
        /// <param name="Address">Where a request came from, or null where that could not be told.</param>
        /// <remarks>
        /// An address that cannot be told is allowed only by a list that allows everyone: a list
        /// that names networks has said that it matters where a request comes from.
        /// </remarks>
        public Boolean Allows(IPAddress? Address)
        {

            if (rules.Length == 0)
                return true;

            if (Address is null)
                return false;

            // An IPv4 client that a dual-stack socket reports as ::ffff:a.b.c.d is matched by its
            // IPv4 address: IPNetwork.Contains does that for an IPv4 network, and a test holds it
            // to it.
            foreach (var (network, allowed) in rules)
                if (network.Contains(Address))
                    return allowed;

            return true;

        }

        #endregion

        #region (static) ParseNetworks(Text)

        /// <summary>
        /// Read networks separated by commas: <c>10.0.0.0/8</c>, <c>2001:db8::/32</c>, a single
        /// address such as <c>192.0.2.7</c> for itself alone, and <c>all</c> for every IPv4 and
        /// every IPv6 address.
        /// </summary>
        /// <param name="Text">The networks, as an operator writes them.</param>
        /// <exception cref="FormatException">Something is not a network, or has bits set beyond its prefix.</exception>
        public static IReadOnlyList<IPNetwork> ParseNetworks(String Text)
        {

            var networks = new List<IPNetwork>();

            foreach (var part in Text.Split(',', StringSplitOptions.TrimEntries))
            {

                if (part.Equals("all", StringComparison.OrdinalIgnoreCase))
                {
                    networks.Add(new IPNetwork(IPAddress.Any,     0));
                    networks.Add(new IPNetwork(IPAddress.IPv6Any, 0));
                    continue;
                }

                var slash        = part.IndexOf('/');
                var addressText  = slash >= 0 ? part[..slash]        : part;
                var prefixText   = slash >= 0 ? part[(slash + 1)..]  : null;

                if (!IPAddress.TryParse(addressText, out var address) || addressText.Contains('%'))
                    throw new FormatException($"'{part}' is not a network: '{addressText}' is not an IP address.");

                var maxLength    = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
                var prefixLength = maxLength;

                if (prefixText is not null &&
                    (!Int32.TryParse(prefixText, System.Globalization.NumberStyles.None,
                                     System.Globalization.CultureInfo.InvariantCulture, out prefixLength) ||
                     prefixLength > maxLength))
                {
                    throw new FormatException($"'{part}' is not a network: the prefix length has to be a number from 0 to {maxLength}.");
                }

                // 10.1.2.3/8 is most likely a typo for one of two different things, 10.0.0.0/8 or
                // 10.1.2.3/32, and which one it is decides who is served.
                var network      = new IPNetwork(Masked(address, prefixLength), prefixLength);

                if (!network.BaseAddress.Equals(address))
                    throw new FormatException($"'{part}' has bits set beyond its prefix: the network is {network}, the address alone is {address}/{maxLength}.");

                networks.Add(network);

            }

            return networks;

        }

        #endregion

        #region (private static) Masked(Address, PrefixLength)

        private static IPAddress Masked(IPAddress  Address,
                                        Int32      PrefixLength)
        {

            var bytes = Address.GetAddressBytes();

            for (var i = 0; i < bytes.Length; i++)
            {

                var bitsInThisByte = Math.Clamp(PrefixLength - 8 * i, 0, 8);

                bytes[i] &= (Byte) (0xFF << (8 - bitsInThisByte));

            }

            return new IPAddress(bytes);

        }

        #endregion


        #region ToString()

        /// <summary>
        /// The list, as an operator would read it.
        /// </summary>
        public override String ToString()

            => IsEveryone
                   ? "everyone"
                   : String.Join("; ", new[] {
                                           Denied. Count > 0 ? $"deny {String.Join(", ", Denied)}"  : null,
                                           Allowed.Count > 0 ? $"allow {String.Join(", ", Allowed)}" : null
                                       }.OfType<String>());

        #endregion

    }

}
