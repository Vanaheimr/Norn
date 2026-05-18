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
