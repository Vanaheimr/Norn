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
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// What the NTS server does with datagrams no well-behaved client sends:
    /// other NTP modes, cookies without an authenticator, cookies it cannot
    /// unseal, and clients that are gone before their answer arrives.
    /// The datagrams are built by hand, as the client cannot be made to send them.
    /// </summary>
    [TestFixture]
    [Category("LocalIntegration")]
    public class NTSServer_RequestHandling_Tests
    {

        #region Data

        private static readonly TimeSpan   answerTimeout  = TimeSpan.FromMilliseconds(1500);

        private                 NTSServer  ntsServer      = null!;
        private                 IPEndPoint ntpEndPoint    = null!;

        #endregion

        #region Start/Stop

        [OneTimeSetUp]
        public async Task StartNTSServer()
        {

            var ntpPort = FindFreePort(SocketType.Dgram,  ProtocolType.Udp);

            ntsServer   = new NTSServer(
                              NTSKEPort:           IPPort.Parse(FindFreePort(SocketType.Stream, ProtocolType.Tcp)),
                              NTSPort:             IPPort.Parse(ntpPort),
                              MasterKeysFilePath:  null
                          );

            ntpEndPoint = new IPEndPoint(System.Net.IPAddress.Loopback, ntpPort);

            await ntsServer.Start();

        }

        [OneTimeTearDown]
        public void ShutdownNTSServer()
        {
            ntsServer.Shutdown();
        }

        #endregion


        #region OnlyClientRequestsAreAnswered()

        /// <summary>
        /// RFC 5905 § 9.2: a server answers mode 3 and nothing else. Were it to answer
        /// a server's answer (mode 4), one forged datagram would bounce between two
        /// servers without end.
        /// </summary>
        [Test]
        public async Task OnlyClientRequestsAreAnswered()
        {

            foreach (var mode in new Byte[] { 0, 1, 2, 4, 5, 6, 7 })
                Assert.That(await Ask(Header(mode)), Is.Null, $"NTP mode {mode} must not be answered.");

            var answer = await Ask(Header(3));

            Assert.That(answer,                Is.Not.Null, "A client request (mode 3) must be answered.");
            Assert.That(answer![0] & 0x07,     Is.EqualTo(4));

        }

        #endregion

        #region TheAnswerCarriesTheVersionOfTheRequest()

        /// <summary>
        /// RFC 5905 § 9.2: an NTPv3 client is answered as NTPv3.
        /// </summary>
        [Test]
        public async Task TheAnswerCarriesTheVersionOfTheRequest()
        {

            foreach (var version in new Byte[] { 3, 4 })
            {

                var request = Header(3);
                request[0]  = (Byte) ((version << 3) | 3);

                var answer  = await Ask(request);

                Assert.That(answer,                     Is.Not.Null);
                Assert.That((answer![0] >> 3) & 0x07,   Is.EqualTo(version));

            }

        }

        #endregion

        #region ACookieWithoutAuthenticatorIsRefused()

        /// <summary>
        /// RFC 8915 § 5.7: a cookie crosses the network in the clear, so sending one proves
        /// nothing. Without an authenticator the answer is an NTS NAK and carries no cookies.
        /// </summary>
        [Test]
        public async Task ACookieWithoutAuthenticatorIsRefused()
        {

            var request = Concat(
                              Header(3),
                              Extension(0x0104, new Byte[32]),
                              Extension(0x0204, FreshCookie())
                          );

            var answer  = await Ask(request);

            AssertIsNTSNAK(answer, request.Length);

        }

        #endregion

        #region AnAuthenticatorThatDoesNotVerifyIsRefused()

        /// <summary>
        /// A valid cookie together with an authenticator made without its key.
        /// </summary>
        [Test]
        public async Task AnAuthenticatorThatDoesNotVerifyIsRefused()
        {

            var request = Concat(
                              Header(3),
                              Extension(0x0104, new Byte[32]),
                              Extension(0x0204, FreshCookie()),
                              ForgedAuthenticator()
                          );

            var answer  = await Ask(request);

            AssertIsNTSNAK(answer, request.Length);

        }

        #endregion

        #region ACookieThatCannotBeUnsealedIsAnsweredWithANAK()

        /// <summary>
        /// RFC 8915 § 5.7: a client holding cookies this server can no longer unseal has
        /// to be told so, or it keeps sending them into silence instead of redoing NTS-KE.
        /// </summary>
        [Test]
        public async Task ACookieThatCannotBeUnsealedIsAnsweredWithANAK()
        {

            var cookie  = FreshCookie();
            cookie[60] ^= 0x01;

            var request = Concat(
                              Header(3),
                              Extension(0x0104, new Byte[32]),
                              Extension(0x0204, cookie),
                              ForgedAuthenticator()
                          );

            var answer  = await Ask(request);

            AssertIsNTSNAK(answer, request.Length);

        }

        #endregion

        #region AVanishedClientDoesNotStopTheServer()

        /// <summary>
        /// The answer to a client that has already closed its socket draws an ICMP
        /// "port unreachable", which Windows reports on the server's next receive.
        /// That must not end the receive loop.
        /// </summary>
        [Test]
        public async Task AVanishedClientDoesNotStopTheServer()
        {

            for (var i = 0; i < 5; i++)
            {
                using var vanishing = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));
                await vanishing.SendAsync(Header(3), 48, ntpEndPoint);
            }

            await Task.Delay(300);

            Assert.That(await Ask(Header(3)), Is.Not.Null, "The server no longer answers NTP requests.");

        }

        #endregion


        #region (private) Helpers

        private Byte[] FreshCookie()
            => ntsServer.GetServerInfos(1).First().Cookies.First();


        #region ServerInfosNeverCarryMoreCookiesThanAKeyExchange()

        /// <summary>
        /// The number of cookies of GET ~/serverInfos is the caller's "n", and it used
        /// to be taken as it came: 65535 cookies, each of them an encryption, and a
        /// response of megabytes for one small request. It is what a key exchange
        /// gives at the most, and one where none were asked for.
        /// </summary>
        [TestCase((UInt16)     0, 1)]
        [TestCase((UInt16)     1, 1)]
        [TestCase((UInt16)     7, 7)]
        [TestCase((UInt16)     8, 8)]
        [TestCase((UInt16)     9, 8)]
        [TestCase((UInt16) 65535, 8)]
        public void ServerInfosNeverCarryMoreCookiesThanAKeyExchange(UInt16 AskedFor, Int32 Given)
        {

            Assert.That(NTSServer.MaxCookiesPerResponse,                                Is.EqualTo(8));
            Assert.That(ntsServer.GetServerInfos(AskedFor).First().Cookies.Count(),     Is.EqualTo(Given));

        }

        #endregion

        private static Byte[] Header(Byte Mode)
        {
            var header = new Byte[48];
            header[0]  = (Byte) ((4 << 3) | Mode);
            return header;
        }

        private static Byte[] Extension(UInt16 Type, Byte[] Body)
        {

            var length    = 4 + ((Body.Length + 3) & ~3);
            var extension = new Byte[length];

            extension[0]  = (Byte) (Type   >> 8);
            extension[1]  = (Byte)  Type;
            extension[2]  = (Byte) (length >> 8);
            extension[3]  = (Byte)  length;

            Body.CopyTo(extension, 4);

            return extension;

        }

        /// <summary>
        /// A well-formed authenticator: a 16 octet nonce and 16 octets that are no valid tag.
        /// </summary>
        private static Byte[] ForgedAuthenticator()
            => Extension(0x0404, Concat([ 0, 16, 0, 16 ], new Byte[32]));

        private static Byte[] Concat(params Byte[][] Parts)
            => [.. Parts.SelectMany(part => part)];

        private async Task<Byte[]?> Ask(Byte[] Datagram)
        {

            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            await udpClient.SendAsync(Datagram, Datagram.Length, ntpEndPoint);

            using var timeout   = new CancellationTokenSource(answerTimeout);

            try
            {
                return (await udpClient.ReceiveAsync(timeout.Token)).Buffer;
            }
            catch (OperationCanceledException)
            {
                return null;
            }

        }

        private static void AssertIsNTSNAK(Byte[]? Answer, Int32 RequestLength)
        {

            Assert.That(Answer,                                    Is.Not.Null, "The server must answer with an NTS NAK.");
            Assert.That(Answer![1],                                Is.EqualTo(0), "An NTS NAK has stratum 0.");
            Assert.That(Encoding.ASCII.GetString(Answer, 12, 4),   Is.EqualTo("NTSN"));
            Assert.That(Answer.Length,                             Is.LessThanOrEqualTo(RequestLength), "The answer must not be larger than the request.");

            // Unique Identifier only: no authenticator, and so no cookies.
            Assert.That(Answer.Length,                             Is.EqualTo(48 + 36));

        }

        private static Int32 FindFreePort(SocketType SocketType, ProtocolType ProtocolType)
        {

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType, ProtocolType);

            socket.Bind(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            return ((IPEndPoint) socket.LocalEndPoint!).Port;

        }

        #endregion

    }

}
