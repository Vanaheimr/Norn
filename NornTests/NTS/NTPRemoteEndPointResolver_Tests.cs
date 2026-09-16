/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Norn <https://www.github.com/Vanaheimr/Norn>
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

using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// NTS/NTP remote endpoint resolver tests.
    /// </summary>
    [TestFixture]
    public class NTPRemoteEndPointResolver_Tests
    {

        #region Uses_Negotiated_IPAddress_And_Port()

        [Test]
        public async Task Uses_Negotiated_IPAddress_And_Port()
        {

            var response = new NTSKE_Response(
                               [
                                   NTSKE_Record.NTPv4ServerNegotiation(Encoding.ASCII.GetBytes("127.0.0.1")),
                                   NTSKE_Record.NTPv4PortNegotiation  ([ 0x04, 0xD2 ])
                               ],
                               [],
                               []
                           );

            var endPoint = await NTPRemoteEndPointResolver.ResolveAsync(
                                     response,
                                     DomainName.Parse("fallback.example.org"),
                                     IPPort.NTP,
                                     new DNSClient(),
                                     IPVersionPreference.IPv4Only,
                                     TimeSpan.FromSeconds(1)
                                 );

            Assert.That(endPoint,           Is.Not.Null);
            Assert.That(endPoint?.Address,  Is.EqualTo(System.Net.IPAddress.Loopback));
            Assert.That(endPoint?.Port,     Is.EqualTo(1234));

        }

        #endregion

        #region A_Negotiated_Address_Is_Not_Dropped_When_The_Key_Exchange_Connected_Somewhere()

        /// <summary>
        /// A key exchange that redirects to an address, from a connection that
        /// already has one.
        /// </summary>
        /// <remarks>
        /// The case that was wrong, and it is the ordinary one: nts.netnod.se
        /// answers its key exchange with "2a01:3f7:2:44::9" and nothing else,
        /// and RFC 8915 section 4.1.7 says the record "SHALL be either an IPv4
        /// address, an IPv6 address, or a fully qualified domain name".
        ///
        /// The redirect was dropped because the check asked NTPv4Servers -
        /// which is NTPv4ServerNames filtered down to what parses as a domain
        /// name - and an address does not. So the request went to the host the
        /// key exchange happened on, which holds different master keys, and the
        /// NAK was reported against a machine that had done nothing wrong.
        ///
        /// An IPv6 address, and that is the whole of it: "127.0.0.2" parses as
        /// a domain name perfectly well - labels of digits are legal - so an
        /// IPv4 redirect survived the filter by accident. Only the colons of an
        /// IPv6 address fail it, which is why the first version of this test
        /// passed with the fault still in place.
        ///
        /// The existing test above passes an address too and always did: it
        /// builds a response with no timing information, so the shortcut this
        /// is about is never reached either.
        /// </remarks>
        [Test]
        public async Task A_Negotiated_Address_Is_Not_Dropped_When_The_Key_Exchange_Connected_Somewhere()
        {

            var response = new NTSKE_Response(
                               [
                                   NTSKE_Record.NTPv4ServerNegotiation(Encoding.ASCII.GetBytes("2a01:3f7:2:44::9"))
                               ],
                               [],
                               [],
                               TimingInfo: new NTSKE_TimingInfo(
                                               ConnectedIPAddress: IPv6Address.Parse("2a01:3f0:1:4::29")
                                           )
                           );

            var endPoint = await NTPRemoteEndPointResolver.ResolveAsync(
                                     response,
                                     DomainName.Parse("ntske.example.org"),
                                     IPPort.NTP,
                                     new DNSClient(),
                                     IPVersionPreference.IPv6Only,
                                     TimeSpan.FromSeconds(1)
                                 );

            Assert.That(endPoint?.Address,
                        Is.EqualTo(System.Net.IPAddress.Parse("2a01:3f7:2:44::9")),
                        "The address the key exchange redirected to was dropped in favour of the host it happened on.");

        }

        #endregion

        #region The_Connected_Address_Is_Still_Reused_When_Nothing_Else_Was_Named()

        /// <summary>
        /// The shortcut the test above must not have broken.
        /// </summary>
        /// <remarks>
        /// A key exchange that names nobody else has already done the work of
        /// resolving its own host, and resolving it a second time for the NTP
        /// request would be a second lookup for an answer that is in hand.
        /// </remarks>
        [Test]
        public async Task The_Connected_Address_Is_Still_Reused_When_Nothing_Else_Was_Named()
        {

            var response = new NTSKE_Response(
                               [],
                               [],
                               [],
                               TimingInfo: new NTSKE_TimingInfo(
                                               ConnectedIPAddress: IPv4Address.Parse("127.0.0.9")
                                           )
                           );

            var endPoint = await NTPRemoteEndPointResolver.ResolveAsync(
                                     response,
                                     DomainName.Parse("ntske.example.org"),
                                     IPPort.NTP,
                                     new DNSClient(),
                                     IPVersionPreference.IPv4Only,
                                     TimeSpan.FromSeconds(1)
                                 );

            Assert.That(endPoint?.Address,
                        Is.EqualTo(System.Net.IPAddress.Parse("127.0.0.9")),
                        "A key exchange that named nobody else was resolved all over again.");

        }

        #endregion

        #region One_Of_Several_Negotiated_Servers_Can_Be_Chosen()

        /// <summary>
        /// Several servers named, and each reachable in its own right.
        /// </summary>
        /// <remarks>
        /// Without a choice only the first that resolves is ever asked, so a
        /// fault in the second is invisible until the first goes away.
        /// </remarks>
        [Test]
        public void One_Of_Several_Negotiated_Servers_Can_Be_Chosen()
        {

            var response = new NTSKE_Response(
                               [
                                   NTSKE_Record.NTPv4ServerNegotiation(Encoding.ASCII.GetBytes("first.example.org")),
                                   NTSKE_Record.NTPv4ServerNegotiation(Encoding.ASCII.GetBytes("second.example.org")),
                                   NTSKE_Record.NTPv4PortNegotiation  ([ 0x04, 0xD2 ]),
                                   NTSKE_Record.NTPv4PortNegotiation  ([ 0x11, 0x5C ])
                               ],
                               [],
                               []
                           );

            var chosen = NTPRemoteEndPointResolver.GetRemoteCandidates(
                             response,
                             DomainName.Parse("fallback.example.org"),
                             IPPort.NTP,
                             "second.example.org"
                         ).ToArray();

            Assert.Multiple(() => {
                Assert.That(chosen.Length,     Is.EqualTo(1), "Choosing one server did not narrow the list to it.");
                Assert.That(chosen[0].Host,    Is.EqualTo("second.example.org"));
                Assert.That(chosen[0].Port.ToUInt16(), Is.EqualTo(4444),
                            "The port that was negotiated alongside the chosen server was not the one taken.");
            });

        }

        #endregion

        #region A_Server_The_Exchange_Did_Not_Name_Is_Refused()

        /// <summary>
        /// Somewhere else entirely.
        /// </summary>
        /// <remarks>
        /// Refused rather than reached, and it matters more than it looks: RFC
        /// 8915 section 4.1.7 says the negotiated server is the one "that will
        /// accept the supplied cookies". A cookie is spent by sending it, so
        /// pointing it at a server holding different master keys wastes it and
        /// produces a NAK about the wrong machine.
        /// </remarks>
        [Test]
        public async Task A_Server_The_Exchange_Did_Not_Name_Is_Refused()
        {

            var response = new NTSKE_Response(
                               [
                                   NTSKE_Record.NTPv4ServerNegotiation(Encoding.ASCII.GetBytes("127.0.0.1"))
                               ],
                               [],
                               []
                           );

            var endPoint = await NTPRemoteEndPointResolver.ResolveAsync(
                                     response,
                                     DomainName.Parse("fallback.example.org"),
                                     IPPort.NTP,
                                     new DNSClient(),
                                     IPVersionPreference.IPv4Only,
                                     TimeSpan.FromSeconds(1),
                                     ChosenServer: "somewhere.else.example.org"
                                 );

            Assert.That(endPoint, Is.Null,
                        "Cookies were about to be sent to a server the key exchange never named.");

        }

        #endregion

        #region Builds_Paired_Candidates_For_Multiple_Hosts_And_Ports()

        [Test]
        public void Builds_Paired_Candidates_For_Multiple_Hosts_And_Ports()
        {

            var response = new NTSKE_Response(
                               [
                                   NTSKE_Record.NTPv4ServerNegotiation(Encoding.ASCII.GetBytes("ntp1.example.org")),
                                   NTSKE_Record.NTPv4ServerNegotiation(Encoding.ASCII.GetBytes("ntp2.example.org")),
                                   NTSKE_Record.NTPv4PortNegotiation  ([ 0x04, 0xD2 ])
                               ],
                               [],
                               []
                           );

            var candidates = NTPRemoteEndPointResolver.GetRemoteCandidates(
                                 response,
                                 DomainName.Parse("fallback.example.org"),
                                 IPPort.NTP
                             ).ToList();

            Assert.That(candidates.Count,                 Is.EqualTo(2));
            Assert.That(candidates[0].Host,               Is.EqualTo("ntp1.example.org"));
            Assert.That(candidates[0].Port,               Is.EqualTo(IPPort.Parse(1234)));
            Assert.That(candidates[1].Host,               Is.EqualTo("ntp2.example.org"));
            Assert.That(candidates[1].Port,               Is.EqualTo(IPPort.Parse(1234)));

        }

        #endregion

        #region Uses_Fallback_Host_When_Only_Port_Is_Negotiated()

        [Test]
        public void Uses_Fallback_Host_When_Only_Port_Is_Negotiated()
        {

            var response = new NTSKE_Response(
                               [
                                   NTSKE_Record.NTPv4PortNegotiation([ 0x04, 0xD2 ])
                               ],
                               [],
                               []
                           );

            var candidates = NTPRemoteEndPointResolver.GetRemoteCandidates(
                                 response,
                                 DomainName.Parse("fallback.example.org"),
                                 IPPort.NTP
                             ).ToList();

            Assert.That(candidates.Count,    Is.EqualTo(1));
            Assert.That(candidates[0].Host,  Is.EqualTo("fallback.example.org"));
            Assert.That(candidates[0].Port,  Is.EqualTo(IPPort.Parse(1234)));

        }

        #endregion

        #region Formats_IPv6_Remote_Description_With_Brackets()

        [Test]
        public void Formats_IPv6_Remote_Description_With_Brackets()
        {

            var response = new NTSKE_Response(
                               [
                                   NTSKE_Record.NTPv4ServerNegotiation(Encoding.ASCII.GetBytes("2001:db8::1")),
                                   NTSKE_Record.NTPv4PortNegotiation  ([ 0x04, 0xD2 ])
                               ],
                               [],
                               []
                           );

            Assert.That(
                NTPRemoteEndPointResolver.GetRemoteDescription(
                    response,
                    DomainName.Parse("fallback.example.org"),
                    IPPort.NTP
                ),
                Is.EqualTo("[2001:db8::1]:1234")
            );

        }

        #endregion

        #region Falls_Back_To_Client_Host_And_Port_Without_Negotiation()

        [Test]
        public void Falls_Back_To_Client_Host_And_Port_Without_Negotiation()
        {

            var host = DomainName.Parse("fallback.example.org");
            var port = IPPort.Parse(1234);

            Assert.That(NTPRemoteEndPointResolver.GetRemoteHost(null, host),        Is.EqualTo(host));
            Assert.That(NTPRemoteEndPointResolver.GetRemotePort(null, port),        Is.EqualTo(port));
            Assert.That(NTPRemoteEndPointResolver.GetRemoteDescription(null, host, port), Is.EqualTo("fallback.example.org:1234"));

        }

        #endregion

    }

}
