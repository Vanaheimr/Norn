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
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// RFC 8915 § 5.7 from the client's side: a datagram that does not validate is
    /// discarded and the client keeps waiting, and an NTS NAK takes effect only when
    /// no valid response follows it.
    ///
    /// The forger sits where an on-path attacker would: between client and server,
    /// seeing the request, and answering from the very address the client asked.
    /// </summary>
    [TestFixture]
    [Category("LocalIntegration")]
    public class NTSClient_ForgedResponses_Tests
    {

        #region Data

        private NTSServer  ntsServer     = null!;
        private IPPort     ntsKEPort;
        private IPEndPoint ntpEndPoint   = null!;

        #endregion

        #region Start/Stop

        [OneTimeSetUp]
        public async Task StartNTSServer()
        {

            var ntpPort = FindFreePort(SocketType.Dgram, ProtocolType.Udp);

            ntsKEPort   = IPPort.Parse(FindFreePort(SocketType.Stream, ProtocolType.Tcp));
            ntpEndPoint = new IPEndPoint(System.Net.IPAddress.Loopback, ntpPort);

            ntsServer   = new NTSServer(
                              NTSKEPort:           ntsKEPort,
                              NTSPort:             IPPort.Parse(ntpPort),
                              MasterKeysFilePath:  null
                          );

            await ntsServer.Start();

        }

        [OneTimeTearDown]
        public void ShutdownNTSServer()
        {
            ntsServer.Shutdown();
        }

        #endregion


        #region AForgedNAKAheadOfTheAnswerIsPassedOver()

        /// <summary>
        /// The forged NTS NAK arrives first, the server's answer right behind it.
        /// The answer is the one that counts, and the cookies are kept.
        /// </summary>
        [Test]
        public async Task AForgedNAKAheadOfTheAnswerIsPassedOver()
        {

            using var forger   = new Forger(ntpEndPoint, ForwardToServer: true);

            var ntsClient      = ClientFor(forger.Port);
            var ntsKEResult    = await ntsClient.GetNTSKERecords();

            Assert.That(ntsKEResult.Success,                 Is.True, ntsKEResult.ErrorMessage);

            var cookiesBefore  = ntsKEResult.Response!.Cookies.Count();

            var queryResult    = await ntsClient.QueryTime(
                                           NTSKEResponse:  ntsKEResult.Response,
                                           Timeout:        TimeSpan.FromSeconds(5)
                                       );

            Assert.That(forger.ForgedDatagramsSent,          Is.EqualTo(1));
            Assert.That(queryResult.Success,                 Is.True, queryResult.ErrorMessage);

            // One cookie spent, one new cookie received: the pool was not thrown away.
            Assert.That(ntsClient.AvailableCookieCount,      Is.GreaterThanOrEqualTo(cookiesBefore));

        }

        #endregion

        #region ANAKWithNothingAfterItIsReported()

        /// <summary>
        /// The NAK is all that arrives. It is reported, once the timeout has run out,
        /// and only then are the cookies given up.
        /// </summary>
        [Test]
        public async Task ANAKWithNothingAfterItIsReported()
        {

            using var forger   = new Forger(ntpEndPoint, ForwardToServer: false);

            var ntsClient      = ClientFor(forger.Port);
            var ntsKEResult    = await ntsClient.GetNTSKERecords();

            Assert.That(ntsKEResult.Success,                 Is.True, ntsKEResult.ErrorMessage);

            var timeout        = TimeSpan.FromSeconds(1);
            var started        = System.Diagnostics.Stopwatch.GetTimestamp();

            var queryResult    = await ntsClient.QueryTime(
                                           NTSKEResponse:  ntsKEResult.Response,
                                           Timeout:        timeout
                                       );

            var elapsed        = System.Diagnostics.Stopwatch.GetElapsedTime(started);

            Assert.That(queryResult.Success,                 Is.False);
            Assert.That(queryResult.ErrorCategory,           Is.EqualTo(NTSQueryErrorCategory.KissOfDeath), queryResult.ErrorMessage);
            Assert.That(elapsed,                             Is.GreaterThanOrEqualTo(timeout - TimeSpan.FromMilliseconds(100)),
                                                             "The client must wait for a valid response until its timeout.");
            Assert.That(ntsClient.AvailableCookieCount,      Is.EqualTo(0));

        }

        #endregion

        #region ADatagramFromElsewhereIsIgnored()

        /// <summary>
        /// The same forged NAK, but sent from an address the client never asked.
        /// It is not even looked at.
        /// </summary>
        [Test]
        public async Task ADatagramFromElsewhereIsIgnored()
        {

            using var forger   = new Forger(ntpEndPoint, ForwardToServer: true, ForgeFromElsewhere: true);

            var ntsClient      = ClientFor(forger.Port);
            var ntsKEResult    = await ntsClient.GetNTSKERecords();

            Assert.That(ntsKEResult.Success,                 Is.True, ntsKEResult.ErrorMessage);

            var queryResult    = await ntsClient.QueryTime(
                                           NTSKEResponse:  ntsKEResult.Response,
                                           Timeout:        TimeSpan.FromSeconds(5)
                                       );

            Assert.That(forger.ForgedDatagramsSent,          Is.EqualTo(1));
            Assert.That(queryResult.Success,                 Is.True, queryResult.ErrorMessage);

        }

        #endregion


        #region (private) Helpers

        private NTSClient ClientFor(Int32 NTPPort)

            => new (
                   Hermod.DNS.DomainName.Localhost,
                   NTSKE_Port:                  ntsKEPort,
                   NTP_Port:                    IPPort.Parse(NTPPort),
                   IPVersionPreference:         IPVersionPreference.IPv4Only,
                   RemoteCertificateValidator:  (sender, serverCertificate, certificateChain, ntsKETLSClient, sslPolicyErrors)
                                                    => TLSValidationResult.Success()
               );

        private static Int32 FindFreePort(SocketType SocketType, ProtocolType ProtocolType)
        {

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType, ProtocolType);

            socket.Bind(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            return ((IPEndPoint) socket.LocalEndPoint!).Port;

        }

        /// <summary>
        /// Stands in for the NTP server. Each request is answered with a forged NTS NAK,
        /// and then, when asked to, passed on to the real server and its answer passed back.
        /// </summary>
        private sealed class Forger : IDisposable
        {

            private readonly UdpClient                clientSide   = new (new IPEndPoint(System.Net.IPAddress.Loopback, 0));
            private readonly UdpClient                serverSide   = new (new IPEndPoint(System.Net.IPAddress.Loopback, 0));
            private readonly UdpClient                elsewhere    = new (new IPEndPoint(System.Net.IPAddress.Loopback, 0));
            private readonly CancellationTokenSource  cts          = new ();

            private          Int32                    forgedDatagramsSent;

            public Int32 Port
                => ((IPEndPoint) clientSide.Client.LocalEndPoint!).Port;

            public Int32 ForgedDatagramsSent
                => Volatile.Read(ref forgedDatagramsSent);

            public Forger(IPEndPoint  NTPServer,
                          Boolean     ForwardToServer,
                          Boolean     ForgeFromElsewhere = false)
            {

                _ = Task.Run(async () => {

                    try
                    {
                        while (!cts.IsCancellationRequested)
                        {

                            var request = await clientSide.ReceiveAsync(cts.Token);
                            var forgery = ForgeNAK(request.Buffer);

                            await (ForgeFromElsewhere ? elsewhere : clientSide).SendAsync(forgery, forgery.Length, request.RemoteEndPoint);

                            Interlocked.Increment(ref forgedDatagramsSent);

                            if (!ForwardToServer)
                                continue;

                            // Late enough for the forgery to be the first datagram the client sees.
                            await Task.Delay(100, cts.Token);

                            await serverSide.SendAsync(request.Buffer, request.Buffer.Length, NTPServer);

                            var answer  = await serverSide.ReceiveAsync(cts.Token);

                            await clientSide.SendAsync(answer.Buffer, answer.Buffer.Length, request.RemoteEndPoint);

                        }
                    }
                    catch (OperationCanceledException)
                    { }
                    catch (ObjectDisposedException)
                    { }

                });

            }

            /// <summary>
            /// What anyone who saw the request can build: stratum 0, "NTSN",
            /// and the request's transmit timestamp as the origin.
            /// </summary>
            private static Byte[] ForgeNAK(Byte[] Request)
            {

                var nak = new Byte[48];

                nak[0]  = (4 << 3) | 4;

                Encoding.ASCII.GetBytes("NTSN").CopyTo(nak, 12);

                Buffer.BlockCopy(Request, 40, nak, 24, 8);

                return nak;

            }

            public void Dispose()
            {
                cts.Cancel();
                clientSide.Dispose();
                serverSide.Dispose();
                elsewhere. Dispose();
                cts.Dispose();
            }

        }

        #endregion

    }

}
