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
using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTPv5
{

    /// <summary>
    /// NTS for NTPv5, draft-ietf-ntp-ntpv5-10 § 11: the key exchange agrees to NTPv5 under the
    /// draft's protocol ID, its keys come from that protocol's exporter context, its cookies are
    /// good for NTPv5 alone, and the NTS extension fields of RFC 8915 protect NTPv5 messages.
    /// </summary>
    [TestFixture]
    public class NTPv5NTS_Tests
    {

        #region KeysOfNTPv4AndNTPv5_ComeFromDifferentContexts()

        /// <summary>
        /// RFC 8915 § 5.1: the protocol ID is the first two octets of the exporter context, so
        /// the same key exchange gives NTPv5 other keys than NTPv4.
        /// </summary>
        [Test]
        public void KeysOfNTPv4AndNTPv5_ComeFromDifferentContexts()
        {

            Assert.That(NTSKE_ExportedKeys.Context(AEADAlgorithms.AES_SIV_CMAC_256, ServerToClient: true, NTPv5Draft.NTSNextProtocolId),
                        Is.EqualTo(new Byte[] { 0x80, 0x01, 0x00, 0x0F, 0x01 }));

            Assert.That(NTSKE_ExportedKeys.Context(AEADAlgorithms.AES_SIV_CMAC_256, ServerToClient: false),
                        Is.EqualTo(new Byte[] { 0x00, 0x00, 0x00, 0x0F, 0x00 }), "NTPv4 as before");

            var keys  = NTSKE_ExportedKeys.ExportAll(NTSKE_ExportedKeys.TransportedSecretExporter(RandomNumberGenerator.GetBytes(32)));

            var v4    = keys.For(AEADAlgorithms.AES_SIV_CMAC_256);
            var v5    = keys.For(AEADAlgorithms.AES_SIV_CMAC_256, NextProtocol: NTPv5Draft.NTSNextProtocolId);

            Assert.That(v5.C2SKey, Is.Not.EqualTo(v4.C2SKey));
            Assert.That(v5.S2CKey, Is.Not.EqualTo(v4.S2CKey));
            Assert.That(v5.C2SKey, Has.Length.EqualTo(v4.C2SKey.Length));

        }

        #endregion

        #region ACookie_RemembersItsProtocol_AndNTPv4CookiesStayAsTheyWere()

        /// <summary>
        /// The protocol is sealed into the cookie: two octets more for NTPv5, nothing more for
        /// NTPv4, whose cookies are exactly what they were before there was NTPv5.
        /// </summary>
        [Test]
        public void ACookie_RemembersItsProtocol_AndNTPv4CookiesStayAsTheyWere()
        {

            var masterKey  = new MasterKey(7, RandomNumberGenerator.GetBytes(32), DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1));
            var c2s        = RandomNumberGenerator.GetBytes(32);
            var s2c        = RandomNumberGenerator.GetBytes(32);

            var v4         = NTSCookie.Create(masterKey, c2s, s2c).Encrypt(masterKey);
            var v5         = NTSCookie.Create(masterKey, c2s, s2c, NextProtocol: NTPv5Draft.NTSNextProtocolId).Encrypt(masterKey);

            Assert.That(v4, Has.Length.EqualTo(8 + 2 + 32 + 16 + 8 + 2 + 32 + 32), "an NTPv4 cookie as before");
            Assert.That(v5, Has.Length.EqualTo(v4.Length + 2));

            Assert.That(NTSCookie.TryParse(v4, masterKey, out var cookie4, out var error4), Is.True, error4);
            Assert.That(NTSCookie.TryParse(v5, masterKey, out var cookie5, out var error5), Is.True, error5);

            Assert.That(cookie4!.NextProtocol, Is.Zero);
            Assert.That(cookie5!.NextProtocol, Is.EqualTo(NTPv5Draft.NTSNextProtocolId));
            Assert.That(cookie5.C2SKey,        Is.EqualTo(c2s));

            Assert.That(NTSCookie.TryParse(cookie5.ToJSON(), out var fromJSON5, out var jsonError5), Is.True, jsonError5);
            Assert.That(NTSCookie.TryParse(cookie4.ToJSON(), out var fromJSON4, out var jsonError4), Is.True, jsonError4);
            Assert.That(fromJSON5!.NextProtocol, Is.EqualTo(NTPv5Draft.NTSNextProtocolId), "kept in JSON");
            Assert.That(fromJSON4!.NextProtocol, Is.Zero);
            Assert.That(cookie4.ToJSON().ContainsKey("nextProtocol"), Is.False, "NTPv4 JSON as before");

        }

        #endregion

    }


    /// <summary>
    /// NTS for NTPv5 on the wire of a running <see cref="NTSServer"/>: key exchange over TLS,
    /// then NTPv5 over UDP.
    /// </summary>
    [TestFixture]
    [Category("LocalIntegration")]
    public class NTSServer_NTPv5NTS_Tests
    {

        #region Data

        private NTSServer?  server;
        private NTSServer?  ntsOnly;
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

            ntsOnly       = await FreePorts.Start(() => new NTSServer(NTSKEPort:           FreePorts.TCP(),
                                                                      NTSPort:             FreePorts.UDP(),
                                                                      MasterKeysFilePath:  null,
                                                                      PlainNTP:            false,
                                                                      InterleavedMode:     InterleavedModePolicy.AuthenticatedOnly,
                                                                      NTPv5:               NTPv5Support.Draft));

            withoutNTPv5  = await FreePorts.Start(() => new NTSServer(NTSKEPort:           FreePorts.TCP(),
                                                                      NTSPort:             FreePorts.UDP(),
                                                                      MasterKeysFilePath:  null));

        }

        [OneTimeTearDown]
        public async Task StopServers()
        {

            foreach (var running in new[] { server, ntsOnly, withoutNTPv5 })
                if (running is not null)
                    await running.ShutdownAsync();

        }

        #endregion


        #region TheKeyExchange_AgreesToNTPv5_WhereBothCan()

        /// <summary>
        /// § 11: offered first, NTPv5 is agreed by a server of the draft; a server without it
        /// agrees to NTPv4, which the client offered after it; and a client that does not offer
        /// NTPv5 is not given it.
        /// </summary>
        [Test]
        public async Task TheKeyExchange_AgreesToNTPv5_WhereBothCan()
        {

            var v5        = await ClientOf(server!,       NTPv5Support.Draft).   GetNTSKERecords();
            var fallback  = await ClientOf(withoutNTPv5!, NTPv5Support.Draft).   GetNTSKERecords();
            var v4        = await ClientOf(server!,       NTPv5Support.Disabled).GetNTSKERecords();

            Assert.That(v5.Success,        Is.True, v5.ErrorMessage);
            Assert.That(fallback.Success,  Is.True, fallback.ErrorMessage);
            Assert.That(v4.Success,        Is.True, v4.ErrorMessage);

            Assert.Multiple(() => {
                Assert.That(v5.Response!.      NextProtocol, Is.EqualTo(NTPv5Draft.NTSNextProtocolId));
                Assert.That(v5.Response.       Cookies,      Is.Not.Empty);
                Assert.That(fallback.Response!.NextProtocol, Is.Zero, "a server without NTPv5 agrees to NTPv4");
                Assert.That(v4.Response!.      NextProtocol, Is.Zero);
                Assert.That(v5.Response.Cookies.First().Length, Is.EqualTo(v4.Response.Cookies.First().Length + 2), "an NTPv5 cookie names its protocol");
            });

        }

        #endregion

        #region AnNTSRequest_IsAnsweredWithNTS_AndNewCookies()

        /// <summary>
        /// RFC 8915 § 5.7 over NTPv5: the response echoes the Unique Identifier, verifies under
        /// the server-to-client key, carries one new cookie for the spent one and one per
        /// placeholder - and is exactly as long as the request (§ 10).
        /// </summary>
        [Test]
        public async Task AnNTSRequest_IsAnsweredWithNTS_AndNewCookies()
        {

            var ke        = await ClientOf(server!, NTPv5Support.Draft).GetNTSKERecords();
            Assert.That(ke.Success, Is.True, ke.ErrorMessage);

            var uid       = RandomNumberGenerator.GetBytes(32);
            var request   = NTPv5Packet.Request(ExtensionFields: [ NTPv5ExtensionField.ServerInformation() ]);
            var datagram  = NTPv5NTS.BuildRequest(request, ke.Response!.C2SKey, ke.Response.AEADAlgorithm, ke.Response.Cookies.First(), uid, Placeholders: 2);

            var answer    = await AskAsync(server!.UDPPort, datagram);

            Assert.That(answer,         Is.Not.Null, "no answer");
            Assert.That(answer!.Length, Is.EqualTo(datagram.Length));

            Assert.That(NTPv5NTS.TryVerifyResponse(answer, uid, ke.Response.S2CKey, ke.Response.AEADAlgorithm, out var response, out var cookies, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(response!.Mode,          Is.EqualTo(4));
                Assert.That(response.ClientCookie,   Is.EqualTo(request.ClientCookie));
                Assert.That(response.Stratum,        Is.EqualTo(1));
                Assert.That(response.Flags,          Is.EqualTo(NTPv5Flags.None));
                Assert.That(cookies,                 Has.Count.EqualTo(3), "the spent one and two placeholders");
                Assert.That(response.Find(NTPv5ExtensionTypes.ServerInformation), Is.Not.Null);
                Assert.That(response.ExtensionFields[^1].Type, Is.EqualTo(NTPv5ExtensionTypes.NTSAuthenticator), "the authenticator last");
            });

            // A new cookie works as the first one did.
            var next      = NTPv5NTS.BuildRequest(NTPv5Packet.Request(), ke.Response.C2SKey, ke.Response.AEADAlgorithm, cookies[0], uid);
            var nextReply = await AskAsync(server.UDPPort, next);

            Assert.That(nextReply, Is.Not.Null);
            Assert.That(NTPv5NTS.TryVerifyResponse(nextReply!, uid, ke.Response.S2CKey, ke.Response.AEADAlgorithm, out _, out var nextCookies, out var nextError), Is.True, nextError);
            Assert.That(nextCookies, Has.Count.EqualTo(1));

        }

        #endregion

        #region ATamperedRequest_GetsNothing_OrANAKWhereAsked()

        /// <summary>
        /// One octet changed under the authenticator: silence, or - for a client that set the
        /// Authentication NAK flag - stratum 0 and the flag, the Unique Identifier back, nothing
        /// to synchronize to and no authenticator.
        /// </summary>
        [Test]
        public async Task ATamperedRequest_GetsNothing_OrANAKWhereAsked()
        {

            var ke        = await ClientOf(server!, NTPv5Support.Draft).GetNTSKERecords();
            Assert.That(ke.Success, Is.True, ke.ErrorMessage);

            var uid       = RandomNumberGenerator.GetBytes(32);

            Byte[] Tampered(NTPv5Flags Flags)
            {
                var datagram = NTPv5NTS.BuildRequest(NTPv5Packet.Request(Flags: Flags), ke.Response!.C2SKey, ke.Response.AEADAlgorithm, ke.Response.Cookies.First(), uid);
                datagram[30] ^= 0x01;    // in the client cookie, which the authenticator covers
                return datagram;
            }

            Assert.That(await AskAsync(server!.UDPPort, Tampered(NTPv5Flags.None)), Is.Null, "a client that did not ask is not told");

            var nakDatagram = Tampered(NTPv5Flags.AuthenticationNAK);
            var nak         = await AskAsync(server.UDPPort, nakDatagram);

            Assert.That(nak, Is.Not.Null, "a client that asked is told");
            Assert.That(NTPv5Packet.TryParse(nak!, out var response, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(response!.Flags,              Is.EqualTo(NTPv5Flags.AuthenticationNAK));
                Assert.That(response.Stratum,             Is.Zero);
                Assert.That(response.ReceiveTimestamp,    Is.Zero, "nothing to synchronize to");
                Assert.That(response.TransmitTimestamp,   Is.Zero);
                Assert.That(response.Find(NTPv5ExtensionTypes.UniqueIdentifier)!.Value, Is.EqualTo(uid));
                Assert.That(response.Find(NTPv5ExtensionTypes.NTSAuthenticator),        Is.Null);
                Assert.That(nak!.Length,                  Is.EqualTo(nakDatagram.Length));
            });

        }

        #endregion

        #region CookiesAreGoodForTheirOwnProtocolAlone()

        /// <summary>
        /// An NTPv4 cookie in an NTPv5 request is no cookie, nor is an NTPv5 cookie in an NTPv4
        /// request: their keys come from different exporter contexts.
        /// </summary>
        [Test]
        public async Task CookiesAreGoodForTheirOwnProtocolAlone()
        {

            var v4ke      = await ClientOf(server!, NTPv5Support.Disabled).GetNTSKERecords();
            Assert.That(v4ke.Success, Is.True, v4ke.ErrorMessage);

            var uid       = RandomNumberGenerator.GetBytes(32);
            var datagram  = NTPv5NTS.BuildRequest(NTPv5Packet.Request(Flags: NTPv5Flags.AuthenticationNAK), v4ke.Response!.C2SKey, v4ke.Response.AEADAlgorithm, v4ke.Response.Cookies.First(), uid);
            var nak       = await AskAsync(server!.UDPPort, datagram);

            Assert.That(nak, Is.Not.Null);
            Assert.That(NTPv5Packet.TryParse(nak!, out var response, out _), Is.True);
            Assert.That(response!.Flags, Is.EqualTo(NTPv5Flags.AuthenticationNAK), "an NTPv4 cookie in NTPv5");

            var v5client  = ClientOf(server, NTPv5Support.Draft);
            var v5ke      = await v5client.GetNTSKERecords();
            Assert.That(v5ke.Success, Is.True, v5ke.ErrorMessage);

            // The NTPv4 query of NTSClient, with the cookies and keys of NTPv5.
            var v4query   = await v5client.QueryTime(NTSKEResponse: v5ke.Response, Timeout: TimeSpan.FromSeconds(3));

            Assert.That(v4query.Success, Is.False, "an NTPv5 cookie in NTPv4");

        }

        #endregion

        #region AServerOfNTSAlone_AnswersNTSButNotPlainNTPv5_AndInterleavesWhatIsAuthenticated()

        /// <summary>
        /// PlainNTP no: a plain NTPv5 request gets no answer, an NTS one does - and under
        /// AuthenticatedOnly the interleaved mode is offered to it, its cookie good for the next.
        /// </summary>
        [Test]
        public async Task AServerOfNTSAlone_AnswersNTSButNotPlainNTPv5_AndInterleavesWhatIsAuthenticated()
        {

            Assert.That(await AskAsync(ntsOnly!.UDPPort, NTPv5Packet.Request(Flags: NTPv5Flags.InterleavedMode).ToByteArray()), Is.Null, "plain NTPv5");

            var ke        = await ClientOf(ntsOnly, NTPv5Support.Draft).GetNTSKERecords();
            Assert.That(ke.Success, Is.True, ke.ErrorMessage);

            var uid       = RandomNumberGenerator.GetBytes(32);

            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            var first     = await AskAsync(udpClient, ntsOnly.UDPPort, NTPv5NTS.BuildRequest(NTPv5Packet.Request(Flags: NTPv5Flags.InterleavedMode),
                                                                                             ke.Response!.C2SKey, ke.Response.AEADAlgorithm, ke.Response.Cookies.First(), uid));

            Assert.That(NTPv5NTS.TryVerifyResponse(first!, uid, ke.Response.S2CKey, ke.Response.AEADAlgorithm, out var firstResponse, out var cookies, out var error), Is.True, error);
            Assert.That(firstResponse!.ServerCookie, Is.Not.Zero, "a cookie for the interleaved mode");

            var second    = await AskAsync(udpClient, ntsOnly.UDPPort, NTPv5NTS.BuildRequest(NTPv5Packet.Request(Flags: NTPv5Flags.InterleavedMode, ServerCookie: firstResponse.ServerCookie),
                                                                                             ke.Response.C2SKey, ke.Response.AEADAlgorithm, cookies[0], uid));

            Assert.That(NTPv5NTS.TryVerifyResponse(second!, uid, ke.Response.S2CKey, ke.Response.AEADAlgorithm, out var secondResponse, out _, out var secondError), Is.True, secondError);
            Assert.That(secondResponse!.Flags, Is.EqualTo(NTPv5Flags.InterleavedMode));

        }

        #endregion

        #region TheCorrection_MayFollowTheAuthenticator()

        /// <summary>
        /// § 7.7: the Correction is never authenticated and goes last - after the authenticator,
        /// in request and response alike; the response verifies all the same.
        /// </summary>
        [Test]
        public async Task TheCorrection_MayFollowTheAuthenticator()
        {

            var ke        = await ClientOf(server!, NTPv5Support.Draft).GetNTSKERecords();
            Assert.That(ke.Success, Is.True, ke.ErrorMessage);

            var uid       = RandomNumberGenerator.GetBytes(32);
            var datagram  = NTPv5NTS.BuildRequest(NTPv5Packet.Request(), ke.Response!.C2SKey, ke.Response.AEADAlgorithm, ke.Response.Cookies.First(), uid,
                                                  AfterAuthenticator: [ NTPv5ExtensionField.Correction(new NTPv5Correction(0, 0, 5000 << 16, 3, 0)) ]);

            var answer    = await AskAsync(server!.UDPPort, datagram);

            Assert.That(answer, Is.Not.Null);
            Assert.That(answer!.Length, Is.EqualTo(datagram.Length));
            Assert.That(NTPv5NTS.TryVerifyResponse(answer, uid, ke.Response.S2CKey, ke.Response.AEADAlgorithm, out var response, out _, out var error), Is.True, error);
            Assert.That(response!.ExtensionFields[^1].TryReadCorrection(out var correction), Is.True, "the Correction last");
            Assert.That(correction.OriginCorrection, Is.EqualTo(5000 << 16));

        }

        #endregion


        #region (private static) ClientOf(Server, NTPv5)

        private static NTSClient ClientOf(NTSServer     Server,
                                          NTPv5Support  NTPv5)

            => new (Hermod.DNS.DomainName.Localhost,
                    NTSKE_Port:                  Server.TCPPort,
                    NTP_Port:                    Server.UDPPort,
                    IPVersionPreference:         IPVersionPreference.IPv4Only,
                    RemoteCertificateValidator:  (sender, serverCertificate, certificateChain, ntsKETLSClient, sslPolicyErrors) => TLSValidationResult.Success()) {
                   NTPv5 = NTPv5
               };

        #endregion

        #region (private static) AskAsync(...)

        private static async Task<Byte[]?> AskAsync(IPPort  NTPPort,
                                                    Byte[]  Request)
        {
            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));
            return await AskAsync(udpClient, NTPPort, Request);
        }

        private static async Task<Byte[]?> AskAsync(UdpClient  UdpClient,
                                                    IPPort     NTPPort,
                                                    Byte[]     Request)
        {

            await UdpClient.SendAsync(Request, new IPEndPoint(System.Net.IPAddress.Loopback, NTPPort.ToUInt16()));

            try
            {
                return (await UdpClient.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(2))).Buffer;
            }
            catch (TimeoutException)
            {
                return null;
            }

        }

        #endregion

    }

}
