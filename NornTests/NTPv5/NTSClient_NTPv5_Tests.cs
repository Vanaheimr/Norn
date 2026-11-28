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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTPv5
{

    /// <summary>
    /// <see cref="NTSClient.QueryNTPv5"/> and <see cref="NTSClient.QueryNegotiated"/> against
    /// a running <see cref="NTSServer"/>, and against a scripted one for what a real server
    /// does not send: forgeries, an Authentication NAK, and "go away".
    /// </summary>
    [TestFixture]
    [Category("LocalIntegration")]
    public class NTSClient_NTPv5_Tests
    {

        #region Data

        private NTSServer?  server;
        private NTSServer?  withoutNTPv5;

        #endregion

        #region Start/stop the servers

        [OneTimeSetUp]
        public async Task StartServers()
        {

            server        = await FreePorts.Start(() => new NTSServer(NTSKEPort:           FreePorts.TCP(),
                                                                      NTSPort:             FreePorts.UDP(),
                                                                      MasterKeysFilePath:  null,
                                                                      NTPv5:               NTPv5Support.Draft));

            withoutNTPv5  = await FreePorts.Start(() => new NTSServer(NTSKEPort:           FreePorts.TCP(),
                                                                      NTSPort:             FreePorts.UDP(),
                                                                      MasterKeysFilePath:  null));

        }

        [OneTimeTearDown]
        public async Task StopServers()
        {

            foreach (var running in new[] { server, withoutNTPv5 })
                if (running is not null)
                    await running.ShutdownAsync();

        }

        #endregion


        #region APlainQuery_MeasuresTheServer()

        /// <summary>
        /// § 9: a plain NTPv5 query of a synchronized server is valid, usable, and measures an
        /// offset of about nothing to a server on the same machine; asked for, the Server
        /// Information comes along.
        /// </summary>
        [Test]
        public async Task APlainQuery_MeasuresTheServer()
        {

            using var client = ClientOf(server!.UDPPort);

            var result = await client.QueryNTPv5(ExtensionFields: [ NTPv5ExtensionField.ServerInformation() ]);

            Assert.That(result.Success, Is.True, result.ErrorMessage);

            Assert.Multiple(() => {
                Assert.That(result.IsUsable,                       Is.True, result.Unusable.ToString());
                Assert.That(result.IsAuthenticated,                Is.False);
                Assert.That(result.Measurement!.Interleaved,       Is.False);
                Assert.That(result.Measurement.Offset.Duration(),  Is.LessThan(TimeSpan.FromMilliseconds(50)));
                Assert.That(result.Measurement.Delay,              Is.LessThan(TimeSpan.FromSeconds(1)));
                Assert.That(result.Response!.Stratum,              Is.EqualTo(1));
                Assert.That(result.ServerInformation,              Is.Not.Null);
                Assert.That(result.ServerInformation!.Value.SupportedVersions & (1 << 4), Is.Not.Zero, "NTPv5 among the versions");
                Assert.That(result.Response.Length,                Is.EqualTo(result.Request!.Datagram.Length), "§ 10: as long as the request");
            });

        }

        #endregion

        #region TheInterleavedMode_DeliversTheAccurateTimestamp_OneExchangeLater()

        /// <summary>
        /// § 8: the first query of an interleaved association is in the basic mode, the second
        /// completes the first exchange with the transmit timestamp the server took after
        /// sending its response.
        /// </summary>
        [Test]
        public async Task TheInterleavedMode_DeliversTheAccurateTimestamp_OneExchangeLater()
        {

            using var client = ClientOf(server!.UDPPort, Interleaved: new NTPv5InterleavedAssociation());

            var first  = await client.QueryNTPv5();
            var second = await client.QueryNTPv5();

            Assert.That(first.Success,  Is.True, first.ErrorMessage);
            Assert.That(second.Success, Is.True, second.ErrorMessage);

            Assert.Multiple(() => {
                Assert.That(first. Measurement!.Interleaved,  Is.False);
                Assert.That(second.Response!.Flags,           Is.EqualTo(NTPv5Flags.InterleavedMode));
                Assert.That(second.Measurement!.Interleaved,  Is.True);
                Assert.That(second.Measurement.T1,            Is.EqualTo(first.Measurement.T1), "the first exchange, completed");
                Assert.That(second.Measurement.T2,            Is.EqualTo(first.Measurement.T2));
                Assert.That(second.Measurement.T3,            Is.GreaterThanOrEqualTo(first.Measurement.T2));
                Assert.That(second.Measurement.Offset.Duration(), Is.LessThan(TimeSpan.FromMilliseconds(50)));
            });

        }

        #endregion

        #region TheCorrection_ComesBack_AndIsApplied()

        /// <summary>
        /// § 7.7 and § 8: a Correction asked for comes back last, and - no switch having added
        /// anything - leaves the measurement as it was.
        /// </summary>
        [Test]
        public async Task TheCorrection_ComesBack_AndIsApplied()
        {

            using var client = ClientOf(server!.UDPPort);

            var result = await client.QueryNTPv5(RequestCorrection: true);

            Assert.That(result.Success, Is.True, result.ErrorMessage);
            Assert.That(result.Response!.ExtensionFields[^1].Type, Is.EqualTo(NTPv5ExtensionTypes.Correction));
            Assert.That(result.Measurement!.Correction,            Is.Not.Null);
            Assert.That(result.Measurement.CorrectedOffset,        Is.EqualTo(result.Measurement.Offset));
            Assert.That(result.Measurement.CorrectedDelay,         Is.EqualTo(result.Measurement.Delay));

        }

        #endregion

        #region AServerThatListsThisClient_IsReportedAsALoop()

        /// <summary>
        /// § 9: a client that serves time asks for the reference IDs, and a server that lists
        /// its own is a loop - here, the server asking itself.
        /// </summary>
        [Test]
        public async Task AServerThatListsThisClient_IsReportedAsALoop()
        {

            using var itself   = ClientOf(server!.UDPPort, OwnReferenceId: server.NTPv5ReferenceId);
            using var stranger = ClientOf(server.UDPPort,  OwnReferenceId: NTPv5ReferenceIds.NewReferenceId());

            var loop    = await itself.  QueryNTPv5();
            var noLoop  = await stranger.QueryNTPv5();

            Assert.That(loop.Success,   Is.True, loop.ErrorMessage);
            Assert.That(noLoop.Success, Is.True, noLoop.ErrorMessage);

            Assert.Multiple(() => {
                Assert.That(loop.ReferenceIds,   Has.Count.EqualTo(32));
                Assert.That(loop.IsLoop,         Is.True);
                Assert.That(loop.IsUsable,       Is.False, "a loop is not to be synchronized to");
                Assert.That(noLoop.IsLoop,       Is.False);
                Assert.That(noLoop.IsUsable,     Is.True);
            });

        }

        #endregion

        #region AnNTSQuery_IsAuthenticated_AndKeepsTheCookiesComing()

        /// <summary>
        /// § 11: after a key exchange that agreed to NTPv5, the query is authenticated, and the
        /// pool is refilled - the spent cookie and the placeholders' worth.
        /// </summary>
        [Test]
        public async Task AnNTSQuery_IsAuthenticated_AndKeepsTheCookiesComing()
        {

            using var client = ClientOf(server!.UDPPort, ServerForKeyExchange: server);

            var ke = await client.GetNTSKERecords();
            Assert.That(ke.Success, Is.True, ke.ErrorMessage);
            Assert.That(ke.Response!.NextProtocol, Is.EqualTo(NTPv5Draft.NTSNextProtocolId));

            client.SeedCookies(ke.Response);

            var poolBefore = client.AvailableCookieCount;
            Assert.That(poolBefore, Is.GreaterThan(1));

            for (var i = 0; i < 3; i++)
            {

                var result = await client.QueryNTPv5(NTSKEResponse: ke.Response, RequestCorrection: true);

                Assert.That(result.Success,          Is.True, result.ErrorMessage);
                Assert.That(result.IsAuthenticated,  Is.True);
                Assert.That(result.IsUsable,         Is.True, result.Unusable.ToString());
                Assert.That(result.NewCookies,       Is.GreaterThanOrEqualTo(1));
                Assert.That(result.Measurement!.Correction, Is.Not.Null, "unauthenticated, after the authenticator");

            }

            Assert.That(client.AvailableCookieCount, Is.GreaterThanOrEqualTo(poolBefore), "no cookie lost");

        }

        #endregion

        #region AnNTPv4KeyExchange_DoesNotServeNTPv5()

        /// <summary>
        /// § 11: the keys and cookies of a key exchange that agreed to NTPv4 are not NTPv5's, so
        /// the query is refused before anything is sent.
        /// </summary>
        [Test]
        public async Task AnNTPv4KeyExchange_DoesNotServeNTPv5()
        {

            using var client = ClientOf(withoutNTPv5!.UDPPort, ServerForKeyExchange: withoutNTPv5);

            var ke = await client.GetNTSKERecords();
            Assert.That(ke.Success, Is.True, ke.ErrorMessage);
            Assert.That(ke.Response!.NextProtocol, Is.Zero);

            var result = await client.QueryNTPv5(NTSKEResponse: ke.Response);

            Assert.That(result.Success,       Is.False);
            Assert.That(result.ErrorCategory, Is.EqualTo(NTSQueryErrorCategory.NTSKE));
            Assert.That(result.Request,       Is.Null, "nothing sent");

        }

        #endregion

        #region TheNegotiation_SwitchesToNTPv5_WhereTheServerEchoesTheMagic()

        /// <summary>
        /// § 12: NTPv4 with the magic first; a server of the draft echoes it, and the next query
        /// goes out in NTPv5; a server without NTPv5 does not, and NTPv4 stays.
        /// </summary>
        [Test]
        public async Task TheNegotiation_SwitchesToNTPv5_WhereTheServerEchoesTheMagic()
        {

            using var client     = ClientOf(server!.UDPPort);
            var negotiation      = new NTPv5VersionNegotiation();

            var first            = await client.QueryNegotiated(negotiation);

            Assert.That(first.NTPv4,                         Is.Not.Null);
            Assert.That(first.NTPv4!.Success,                Is.True, first.NTPv4.ErrorMessage);
            Assert.That(first.NTPv4.ServerAdvertisesNTPv5,   Is.True);
            Assert.That(first.NextVersion,                   Is.EqualTo(NTPv5NegotiatedVersion.NTPv5));

            var second           = await client.QueryNegotiated(negotiation);

            Assert.That(second.NTPv5,                        Is.Not.Null);
            Assert.That(second.NTPv5!.Success,               Is.True, second.NTPv5.ErrorMessage);
            Assert.That(second.NextVersion,                  Is.EqualTo(NTPv5NegotiatedVersion.NTPv5));

            using var oldClient  = ClientOf(withoutNTPv5!.UDPPort);
            var oldNegotiation   = new NTPv5VersionNegotiation();

            var old              = await oldClient.QueryNegotiated(oldNegotiation);

            Assert.That(old.NTPv4!.Success,                  Is.True, old.NTPv4.ErrorMessage);
            Assert.That(old.NTPv4.ServerAdvertisesNTPv5,     Is.False);
            Assert.That(old.NextVersion,                     Is.EqualTo(NTPv5NegotiatedVersion.NTPv4Advertising));

        }

        #endregion


        #region ForgeriesArePassedOver_AndTheFirstValidResponseCounts()

        /// <summary>
        /// § 9.4: "The client MUST ignore all invalid responses and accept only the first valid
        /// response" - a wrong client cookie and an unrequested flag first, then the answer,
        /// then a duplicate that is never read.
        /// </summary>
        [Test]
        public async Task ForgeriesArePassedOver_AndTheFirstValidResponseCounts()
        {

            await using var fake = new ScriptedServer(request => [
                                       Answer(request, ClientCookie: request.ClientCookie ^ 1, Stratum: 9),
                                       Answer(request, Flags: NTPv5Flags.InterleavedMode,      Stratum: 8),
                                       Answer(request,                                         Stratum: 2),
                                       Answer(request,                                         Stratum: 3)
                                   ]);

            using var client = ClientOf(fake.Port);

            var result = await client.QueryNTPv5();

            Assert.That(result.Success,            Is.True, result.ErrorMessage);
            Assert.That(result.Response!.Stratum,  Is.EqualTo(2), "the first valid one");

        }

        #endregion

        #region OnlyInvalidResponses_FailTheQuery_WithTheFirstOfThem()

        /// <summary>
        /// With nothing valid within the timeout, the query fails with what was wrong with the
        /// first invalid response.
        /// </summary>
        [Test]
        public async Task OnlyInvalidResponses_FailTheQuery_WithTheFirstOfThem()
        {

            await using var fake = new ScriptedServer(request => [ Answer(request, ClientCookie: 0) ]);

            using var client = ClientOf(fake.Port);

            var result = await client.QueryNTPv5(Timeout: TimeSpan.FromMilliseconds(500));

            Assert.That(result.Success,            Is.False);
            Assert.That(result.ErrorCategory,      Is.EqualTo(NTSQueryErrorCategory.Protocol));
            Assert.That(result.Validation!.Status, Is.EqualTo(NTPv5ResponseStatus.WrongClientCookie));

        }

        #endregion

        #region AnAuthenticationNAK_RetiresTheCookies()

        /// <summary>
        /// § 11: a server that cannot authenticate the request answers an Authentication NAK,
        /// echoing the Unique Identifier; with nothing valid after it, the client gives up its
        /// cookies, which the server can no longer read.
        /// </summary>
        [Test]
        public async Task AnAuthenticationNAK_RetiresTheCookies()
        {

            await using var fake = new ScriptedServer(request => [
                                       new NTPv5Packet(Mode:          NTPv5Packet.ResponseMode,
                                                       Flags:         NTPv5Flags.AuthenticationNAK,
                                                       ClientCookie:  request.ClientCookie,
                                                       ExtensionFields: [ NTPv5ExtensionField.DraftIdentification(),
                                                                          request.Find(NTPv5ExtensionTypes.UniqueIdentifier)! ]).ToByteArray()
                                   ]);

            using var client = ClientOf(fake.Port, ServerForKeyExchange: server);

            var ke = await client.GetNTSKERecords();
            Assert.That(ke.Success, Is.True, ke.ErrorMessage);

            client.SeedCookies(ke.Response!);
            Assert.That(client.AvailableCookieCount, Is.GreaterThan(1));

            var result = await client.QueryNTPv5(NTSKEResponse: ke.Response, Timeout: TimeSpan.FromMilliseconds(500));

            Assert.That(result.Success,               Is.False);
            Assert.That(result.IsAuthenticationNAK,   Is.True);
            Assert.That(result.ErrorCategory,         Is.EqualTo(NTSQueryErrorCategory.NTSAuthentication));
            Assert.That(client.AvailableCookieCount,  Is.Zero, "the pool retired");

        }

        #endregion

        #region TheServerCounts_WhatItAnsweredInNTPv5()

        /// <summary>
        /// The NTPv5 counters of the server's metrics: received and sent, NTS, interleaved and
        /// Authentication NAKs - each beside the NTPv4 counters it is also part of, so that an
        /// interop test can tell a peer that spoke NTPv5 from one that negotiated down to NTPv4.
        /// </summary>
        [Test]
        public async Task TheServerCounts_WhatItAnsweredInNTPv5()
        {

            using var plain        = ClientOf(server!.UDPPort);
            using var interleaving = ClientOf(server.UDPPort, Interleaved: new NTPv5InterleavedAssociation());
            using var secured      = ClientOf(server.UDPPort, ServerForKeyExchange: server);

            var ke = await secured.GetNTSKERecords();
            Assert.That(ke.Success, Is.True, ke.ErrorMessage);

            var before = server.Metrics;

            Assert.That((await plain.       QueryNTPv5()).Success, Is.True);
            Assert.That((await interleaving.QueryNTPv5()).Success, Is.True);
            Assert.That((await interleaving.QueryNTPv5()).Success, Is.True);
            Assert.That((await secured.     QueryNTPv5(NTSKEResponse: ke.Response)).Success, Is.True);
            Assert.That((await plain.       QueryTime()).Success, Is.True, "NTPv4, counted apart");

            // A cookie the server cannot read, sealed under the right key: a NAK, as asked for.
            var forged  = NTPv5Client.BuildRequest(NTS: new NTPv5ClientNTS(ke.Response!.C2SKey, ke.Response.S2CKey, ke.Response.AEADAlgorithm, new Byte[ke.Response.Cookies.First().Length]));

            using (var udp = new System.Net.Sockets.UdpClient(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0)))
            {
                await udp.SendAsync(forged.Datagram, new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, server.UDPPort.ToUInt16()));
                var nak = await udp.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(2));
                Assert.That(NTPv5Client.Validate(nak.Buffer, forged).Status, Is.EqualTo(NTPv5ResponseStatus.AuthenticationNAK));
            }

            var after  = server.Metrics;

            Assert.Multiple(() => {
                Assert.That(after.NTPv5RequestsReceived           - before.NTPv5RequestsReceived,           Is.EqualTo(5), after.ToString());
                Assert.That(after.NTPv5ResponsesSent              - before.NTPv5ResponsesSent,              Is.EqualTo(5));
                Assert.That(after.NTPv5AuthenticatedResponsesSent - before.NTPv5AuthenticatedResponsesSent, Is.EqualTo(1));
                Assert.That(after.NTPv5InterleavedResponsesSent   - before.NTPv5InterleavedResponsesSent,   Is.EqualTo(1));
                Assert.That(after.NTPv5AuthenticationNAKsSent     - before.NTPv5AuthenticationNAKsSent,     Is.EqualTo(1));
                Assert.That(after.NTPResponsesSent                - before.NTPResponsesSent,                Is.EqualTo(6), "the NTPv4 one too");
            });

        }

        #endregion

        #region PollGoAway_EndsTheAssociation()

        /// <summary>
        /// § 6: a poll of 127 says the server "does not want to hear from the client again".
        /// </summary>
        [Test]
        public async Task PollGoAway_EndsTheAssociation()
        {

            await using var fake = new ScriptedServer(request => [ Answer(request, Poll: NTPv5Packet.PollGoAway) ]);

            using var client = ClientOf(fake.Port);
            var accessState  = new NTPServerAccessState();

            var first  = await client.QueryNTPv5(AccessState: accessState);
            var second = await client.QueryNTPv5(AccessState: accessState);

            Assert.That(first.Success,         Is.True, first.ErrorMessage);
            Assert.That(first.MayQueryAgain,   Is.False);
            Assert.That(accessState.Demobilized, Is.True);
            Assert.That(second.Success,        Is.False);
            Assert.That(second.ErrorCategory,  Is.EqualTo(NTSQueryErrorCategory.KissOfDeath));
            Assert.That(second.Request,        Is.Null, "not sent");
            Assert.That(fake.Requests,         Is.EqualTo(1));

        }

        #endregion


        #region (private static) ClientOf(NTPPort, ...)

        private static NTSClient ClientOf(IPPort                        NTPPort,
                                          NTSServer?                    ServerForKeyExchange  = null,
                                          NTPv5InterleavedAssociation?  Interleaved           = null,
                                          UInt64?                       OwnReferenceId        = null)

            => new (Hermod.DNS.DomainName.Localhost,
                    NTSKE_Port:                  ServerForKeyExchange?.TCPPort ?? IPPort.Parse(4460),
                    NTP_Port:                    NTPPort,
                    IPVersionPreference:         IPVersionPreference.IPv4Only,
                    RemoteCertificateValidator:  (sender, serverCertificate, certificateChain, ntsKETLSClient, sslPolicyErrors) => TLSValidationResult.Success()) {
                   NTPv5                = NTPv5Support.Draft,
                   NTPv5Interleaved     = Interleaved,
                   NTPv5OwnReferenceId  = OwnReferenceId
               };

        #endregion

        #region (private static) Answer(Request, ...)

        private static Byte[] Answer(NTPv5Packet  Request,
                                     UInt64?      ClientCookie  = null,
                                     NTPv5Flags   Flags         = NTPv5Flags.None,
                                     Byte         Stratum       = 1,
                                     SByte        Poll          = 4)
        {

            var now = DateTime.UtcNow;

            return new NTPv5Packet(Mode:               NTPv5Packet.ResponseMode,
                                   Stratum:            Stratum,
                                   Poll:               Poll,
                                   Era:                NTPv5Packet.EraOf(now),
                                   Flags:              Flags,
                                   ClientCookie:       ClientCookie ?? Request.ClientCookie,
                                   ReceiveTimestamp:   NTPv5Client_Tests.Timestamp(now),
                                   TransmitTimestamp:  NTPv5Client_Tests.Timestamp(now),
                                   ExtensionFields:    [ NTPv5ExtensionField.DraftIdentification() ]).ToByteArray();

        }

        #endregion

        #region (private sealed) ScriptedServer

        /// <summary>
        /// A UDP server on the loopback that answers each NTPv5 request with what the script
        /// makes of it, datagram after datagram.
        /// </summary>
        private sealed class ScriptedServer : IAsyncDisposable
        {

            private readonly UdpClient                udpClient = new (new IPEndPoint(System.Net.IPAddress.Loopback, 0));
            private readonly CancellationTokenSource  cancel    = new ();
            private readonly Task                     loop;
            private          Int32                    requests;

            public IPPort Port
                => IPPort.Parse((UInt16) ((IPEndPoint) udpClient.Client.LocalEndPoint!).Port);

            public Int32  Requests
                => Volatile.Read(ref requests);

            public ScriptedServer(Func<NTPv5Packet, IEnumerable<Byte[]>> Script)
            {

                loop = Task.Run(async () => {

                    while (!cancel.IsCancellationRequested)
                    {

                        UdpReceiveResult received;

                        try
                        {
                            received = await udpClient.ReceiveAsync(cancel.Token);
                        }
                        catch (OperationCanceledException)
                        {
                            return;
                        }
                        catch (ObjectDisposedException)
                        {
                            return;
                        }

                        if (!NTPv5Packet.TryParse(received.Buffer, out var request, out _))
                            continue;

                        Interlocked.Increment(ref requests);

                        foreach (var datagram in Script(request))
                            await udpClient.SendAsync(datagram, received.RemoteEndPoint);

                    }

                });

            }

            public async ValueTask DisposeAsync()
            {

                cancel.Cancel();
                udpClient.Dispose();

                try { await loop; } catch { }

                cancel.Dispose();

            }

        }

        #endregion

    }

}
