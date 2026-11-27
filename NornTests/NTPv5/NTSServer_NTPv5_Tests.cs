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
using System.Buffers.Binary;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTPv5
{

    /// <summary>
    /// NTPv5 on the wire of a running <see cref="NTSServer"/>: answered where it is switched on,
    /// and a server that answers it says so to an NTPv4 client that asks (draft § 12).
    /// </summary>
    [TestFixture]
    [Category("LocalIntegration")]
    public class NTSServer_NTPv5_Tests
    {

        #region Data

        private NTSServer?  withNTPv5;
        private NTSServer?  withoutNTPv5;
        private NTSServer?  ntsOnly;

        #endregion

        #region Start/stop the servers

        [OneTimeSetUp]
        public async Task StartServers()
        {

            withNTPv5     = await FreePorts.Start(() => new NTSServer(NTSPort:             FreePorts.UDP(),
                                                                      MasterKeysFilePath:  null,
                                                                      NTSKEOverTLS:        false,
                                                                      Stratum:             2,
                                                                      RootDelay:           TimeSpan.FromMilliseconds(30),
                                                                      NTPv5:               NTPv5Support.Draft));

            withoutNTPv5  = await FreePorts.Start(() => new NTSServer(NTSPort:             FreePorts.UDP(),
                                                                      MasterKeysFilePath:  null,
                                                                      NTSKEOverTLS:        false));

            ntsOnly       = await FreePorts.Start(() => new NTSServer(NTSPort:             FreePorts.UDP(),
                                                                      MasterKeysFilePath:  null,
                                                                      NTSKEOverTLS:        false,
                                                                      PlainNTP:            false,
                                                                      NTPv5:               NTPv5Support.Draft));

        }

        [OneTimeTearDown]
        public async Task StopServers()
        {

            foreach (var server in new[] { withNTPv5, withoutNTPv5, ntsOnly })
                if (server is not null)
                    await server.ShutdownAsync();

        }

        #endregion


        #region NTPv5_IsOff_ByDefault()

        [Test]
        public void NTPv5_IsOff_ByDefault()
        {
            Assert.That(withoutNTPv5!.NTPv5,  Is.EqualTo(NTPv5Support.Disabled));
            Assert.That(withNTPv5!.NTPv5,     Is.EqualTo(NTPv5Support.Draft));
        }

        #endregion

        #region AnNTPv5Request_IsAnsweredInNTPv5()

        /// <summary>
        /// A request of the draft gets a response of the draft: version 5, its cookie back,
        /// the server's stratum and root delay in time32, as long as the request.
        /// </summary>
        [Test]
        public async Task AnNTPv5Request_IsAnsweredInNTPv5()
        {

            var request  = NTPv5Packet.Request(ExtensionFields: [ NTPv5ExtensionField.ServerInformation() ]);
            var answer   = await AskAsync(withNTPv5!.UDPPort, request.ToByteArray());

            Assert.That(answer, Is.Not.Null, "no answer");
            Assert.That(NTPv5Packet.TryParse(answer!, out var response, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(answer![0],                   Is.EqualTo(0x2C), "Reserved 0, VN 5, Mode 4");
                Assert.That(response!.ClientCookie,       Is.EqualTo(request.ClientCookie));
                Assert.That(response.Stratum,             Is.EqualTo(2));
                Assert.That(response.RootDelay,           Is.EqualTo(Time32.FromTimeSpan(TimeSpan.FromMilliseconds(30))));
                Assert.That(response.ReceiveTimestamp,    Is.Not.Zero);
                Assert.That(response.TransmitTimestamp,   Is.GreaterThanOrEqualTo(response.ReceiveTimestamp));
                Assert.That(answer.Length,                Is.EqualTo(request.Length));
                Assert.That(response.Find(NTPv5ExtensionTypes.ServerInformation), Is.Not.Null);
            });

        }

        #endregion

        #region AnNTPv5RequestOfAnotherDraft_GetsNoAnswer()

        [Test]
        public async Task AnNTPv5RequestOfAnotherDraft_GetsNoAnswer()
        {

            var invalidBefore = withNTPv5!.Metrics.NTPRequestsInvalid;

            Assert.That(await AskAsync(withNTPv5.UDPPort,
                                       NTPv5Packet.Request(DraftIdentification: "draft-ietf-ntp-ntpv5-09").ToByteArray()),
                        Is.Null);

            // Counted on a worker, after the datagram was taken in.
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (withNTPv5.Metrics.NTPRequestsInvalid == invalidBefore && DateTime.UtcNow < deadline)
                await Task.Delay(20);

            Assert.That(withNTPv5.Metrics.NTPRequestsInvalid, Is.GreaterThan(invalidBefore));

        }

        #endregion

        #region AServerOfNTSAlone_DoesNotAnswerNTPv5()

        /// <summary>
        /// There is no NTS for NTPv5 yet, so an NTPv5 request is a plain one, and a server of
        /// NTS alone does not answer it.
        /// </summary>
        [Test]
        public async Task AServerOfNTSAlone_DoesNotAnswerNTPv5()
        {
            Assert.That(await AskAsync(ntsOnly!.UDPPort, NTPv5Packet.Request().ToByteArray()), Is.Null);
        }

        #endregion

        #region AnNTPv4ClientAsking_IsToldNTPv5IsHere()

        /// <summary>
        /// § 12: an NTPv4 request with "NTP5DRFT" in its reference timestamp has it echoed by a
        /// server that answers NTPv5, and only by one.
        /// </summary>
        [Test]
        public async Task AnNTPv4ClientAsking_IsToldNTPv5IsHere()
        {

            var asking = PlainNTPv4Request(NTPv5Draft.NegotiationMagic);

            var yes    = await AskAsync(withNTPv5!.   UDPPort, asking);
            var no     = await AskAsync(withoutNTPv5!.UDPPort, asking);
            var plain  = await AskAsync(withNTPv5.    UDPPort, PlainNTPv4Request(0));

            Assert.That(yes,    Is.Not.Null);
            Assert.That(no,     Is.Not.Null);
            Assert.That(plain,  Is.Not.Null);

            Assert.Multiple(() => {
                Assert.That(yes![0] >> 3 & 0x07,                                     Is.EqualTo(4), "the answer to NTPv4 is NTPv4");
                Assert.That(BinaryPrimitives.ReadUInt64BigEndian(yes.AsSpan(16)),    Is.EqualTo(NTPv5Draft.NegotiationMagic), "echoed");
                Assert.That(BinaryPrimitives.ReadUInt64BigEndian(no!.AsSpan(16)),    Is.Not.EqualTo(NTPv5Draft.NegotiationMagic), "a server without NTPv5 does not claim it");
                Assert.That(BinaryPrimitives.ReadUInt64BigEndian(plain!.AsSpan(16)), Is.Not.EqualTo(NTPv5Draft.NegotiationMagic), "nor to a client that did not ask");
            });

            // The final magic asks for the RFC, which a draft server is not.
            var final = await AskAsync(withNTPv5.UDPPort, PlainNTPv4Request(NTPv5Draft.FinalNegotiationMagic));

            Assert.That(BinaryPrimitives.ReadUInt64BigEndian(final!.AsSpan(16)), Is.Not.EqualTo(NTPv5Draft.FinalNegotiationMagic));

        }

        #endregion


        #region (private static) PlainNTPv4Request(ReferenceTimestamp)

        private static Byte[] PlainNTPv4Request(UInt64 ReferenceTimestamp)
        {

            var request  = new Byte[48];
            request[0]   = 0x23;

            BinaryPrimitives.WriteUInt64BigEndian(request.AsSpan(16), ReferenceTimestamp);
            Random.Shared.NextBytes(request.AsSpan(40, 8));

            return request;

        }

        #endregion

        #region (private static) AskAsync(NTPPort, Request)

        /// <summary>
        /// The request from 127.0.0.1, and the answer, or null when none came within two seconds.
        /// </summary>
        private static async Task<Byte[]?> AskAsync(IPPort  NTPPort,
                                                    Byte[]  Request)
        {

            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            await udpClient.SendAsync(Request, new IPEndPoint(System.Net.IPAddress.Loopback, NTPPort.ToUInt16()));

            try
            {
                return (await udpClient.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(2))).Buffer;
            }
            catch (TimeoutException)
            {
                return null;
            }

        }

        #endregion

    }

}
