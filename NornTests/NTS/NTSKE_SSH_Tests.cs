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

using Org.BouncyCastle.Tls;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTS.NTSKERecords;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// NTS-KE over SSH, option B: the exporter sources, the SSH Key Binding record, and key
    /// exchanges against a server with an SSH listener of its own.
    /// </summary>
    [TestFixture]
    public class NTSKE_SSH_Tests
    {

        #region Test vectors of option B

        // nts_ke_secret = 00 01 02 … 1f, and the label and contexts of RFC 8915 § 5.1. Computed
        // independently of this implementation, with Python's hmac and hashlib:
        //
        //   HKDF-Expand-SHA256(PRK = nts_ke_secret,
        //                      info = string("EXPORTER-network-time-security") || string(context),
        //                      L = key length of the algorithm)

        private static readonly Byte[] testSecret = [.. Enumerable.Range(0, 32).Select(i => (Byte) i)];

        private static readonly Object[] testVectors = [
            new Object[] { AEADAlgorithms.AES_SIV_CMAC_256, "8a9424e3fd81e14cbc9731adff3ae5b6d2fe66349b4ad384f59a1f5bd7d552ec",
                                                            "2abf8475eda5bb1798b5d3d0f2fc413d62461c0bce93707fed97366193422713" },
            new Object[] { AEADAlgorithms.AES_128_GCM_SIV,  "e7961cb8c44fcc3d44d091c8574ad0f2",
                                                            "964988be02f188bbc3c96bd86bba825d" },
            new Object[] { AEADAlgorithms.AES_256_GCM_SIV,  "5f32ede85ca7a7607baa1c2bf14057c9afb7458114e476f6a187f2f96da0aa2e",
                                                            "0b6576d8ee6e31e992f4821dac89ec44d1e575a0f1b69a4f64225dc6051ec128" }
        ];

        #endregion

        #region Data

        private static readonly IPPort       testTLSPort  = FindFreeTCPPort();
        private static readonly IPPort       testSSHPort  = FindFreeTCPPort();
        private static readonly IPPort       testNTPPort  = FindFreeUDPPort();

        private static readonly ISshHostKey  clientKey    = SshHostKey.GenerateEd25519();
        private static readonly ISshHostKey  strangerKey  = SshHostKey.GenerateEd25519();

        private NTSServer? ntsServer;

        #endregion


        #region Start/stop the NTS server

        [OneTimeSetUp]
        public async Task StartNTSServer()
        {

            ntsServer = new NTSServer(
                            NTSKEPort:           testTLSPort,
                            NTSPort:             testNTPPort,
                            MasterKeysFilePath:  null,
                            SSHPort:             testSSHPort,
                            SSHAuthenticator:    SshUserAuthenticator.ForAuthorizedKeys(clientKey.PublicKeyBlob)
                        );

            await ntsServer.Start();

        }

        [OneTimeTearDown]
        public async Task StopNTSServer()
        {
            if (ntsServer is not null)
                await ntsServer.ShutdownAsync();
        }

        #endregion


        #region Exporter sources

        [TestCaseSource(nameof(testVectors))]
        public void TransportedSecret_MatchesTheTestVectors(AEADAlgorithms  Algorithm,
                                                             String          ExpectedC2SKey,
                                                             String          ExpectedS2CKey)
        {

            var (c2sKey, s2cKey) = NTSKE_ExportedKeys.ExportAll(NTSKE_ExportedKeys.TransportedSecretExporter(testSecret)).
                                                      For(Algorithm, CompliantExporterContext: true);

            Assert.That(c2sKey.ToHexString(), Is.EqualTo(ExpectedC2SKey));
            Assert.That(s2cKey.ToHexString(), Is.EqualTo(ExpectedS2CKey));

        }

        [Test]
        public void ExporterInfo_IsTwoSSHStrings()
        {

            var info = NTSKE_ExportedKeys.ExporterInfo(
                           NTSKE_ExportedKeys.ExporterLabel,
                           NTSKE_ExportedKeys.Context(AEADAlgorithms.AES_SIV_CMAC_256, ServerToClient: false)
                       );

            Assert.That(info.ToHexString(),
                        Is.EqualTo("0000001e" + "4558504f525445522d6e6574776f726b2d74696d652d7365637572697479" +
                                   "00000005" + "0000000f00"));

        }

        [Test]
        public void TransportedSecret_OfAnotherLength_IsRefused()
        {
            Assert.That(() => NTSKE_ExportedKeys.TransportedSecretExporter(new Byte[31]), Throws.ArgumentException);
            Assert.That(() => NTSKE_ExportedKeys.TransportedSecretExporter(new Byte[33]), Throws.ArgumentException);
        }

        [Test]
        public void SSHExporter_IsTheSameExpansionUnderAnotherKey()
        {

            // Option A and option B differ only in the pseudorandom key, as long as the key
            // exchange hashes with SHA-256 — which is what lets one derivation serve both.
            var optionA = NTSKE_ExportedKeys.ExportAll(NTSKE_ExportedKeys.SSHExporter(testSecret, System.Security.Cryptography.HashAlgorithmName.SHA256)).
                                             For(AEADAlgorithms.AES_128_GCM_SIV);

            var optionB = NTSKE_ExportedKeys.ExportAll(NTSKE_ExportedKeys.TransportedSecretExporter(testSecret)).
                                             For(AEADAlgorithms.AES_128_GCM_SIV);

            Assert.That(optionA.C2SKey, Is.EqualTo(optionB.C2SKey));
            Assert.That(optionA.S2CKey, Is.EqualTo(optionB.S2CKey));

        }

        #endregion

        #region The SSH Key Binding record

        [Test]
        public void Request_RoundTrips()
        {

            var bytes = NTSKE_Record.SSHKeyBindingRequest(SSHKeyBindingMethods.Exporter,
                                                          SSHKeyBindingMethods.Transport).ToByteArray();

            // Critical bit and type 16386, four octets of body, the two method ids.
            Assert.That(bytes.ToHexString(), Is.EqualTo("c002" + "0004" + "0001" + "0002"));

            Assert.That(NTSKE_Record.TryParse(bytes, out var records, out var errorResponse), Is.True, errorResponse);

            var record = records!.Single();

            Assert.That(record,            Is.InstanceOf<SSHKeyBinding>());
            Assert.That(record.IsCritical, Is.True);
            Assert.That(record.Type,       Is.EqualTo(NTSKE_RecordTypes.SSHKeyBinding));

            Assert.That(((SSHKeyBinding) record).TryGetOfferedMethods(out var methods, out var methodError), Is.True, methodError);
            Assert.That(methods, Is.EqualTo(new UInt16[] { 0x0001, 0x0002 }));

        }

        [Test]
        public void Response_RoundTrips()
        {

            var bytes = NTSKE_Record.SSHKeyBindingResponse(SSHKeyBindingMethods.Transport, testSecret).ToByteArray();

            Assert.That(bytes.ToHexString(), Is.EqualTo("c002" + "0022" + "0002" + testSecret.ToHexString()));

            Assert.That(NTSKE_Record.TryParse(bytes, out var records, out var errorResponse), Is.True, errorResponse);

            var record = (SSHKeyBinding) records!.Single();

            Assert.That(record.TryGetSelection(out var method, out var secret, out var selectionError), Is.True, selectionError);
            Assert.That(method, Is.EqualTo(SSHKeyBindingMethods.Transport));
            Assert.That(secret, Is.EqualTo(testSecret));

        }

        [Test]
        public void Request_KeepsMethodsItDoesNotKnow()
        {

            // The server picks the first method it supports, so an unknown one before it is no
            // reason to refuse the list.
            var record = new SSHKeyBinding(true, [ 0x7f, 0xff, 0x00, 0x02 ]);

            Assert.That(record.TryGetOfferedMethods(out var methods, out var methodError), Is.True, methodError);
            Assert.That(methods, Is.EqualTo(new UInt16[] { 0x7fff, 0x0002 }));

        }

        [Test]
        public void Request_WithoutAWholeListOfMethods_IsRefused()
        {
            Assert.That(new SSHKeyBinding(true, []).                 TryGetOfferedMethods(out _, out _), Is.False);
            Assert.That(new SSHKeyBinding(true, [ 0x00, 0x02, 0x00 ]).TryGetOfferedMethods(out _, out _), Is.False);
        }

        [Test]
        public void Response_ThatCannotBeUsed_IsRefused()
        {

            // Too short for a method id.
            Assert.That(new SSHKeyBinding(true, [ 0x00 ]).                         TryGetSelection(out _, out _, out _), Is.False);

            // The transport with a secret one octet short.
            Assert.That(new SSHKeyBinding(true, [ 0x00, 0x02, .. new Byte[31] ]).  TryGetSelection(out _, out _, out _), Is.False);

            // The exporter, which carries no data, with some.
            Assert.That(new SSHKeyBinding(true, [ 0x00, 0x01, 0x00 ]).             TryGetSelection(out _, out _, out _), Is.False);

            // A method nobody offered.
            Assert.That(new SSHKeyBinding(true, [ 0x00, 0x03 ]).                   TryGetSelection(out _, out _, out _), Is.False);

        }

        [Test]
        public void Response_SelectingTheExporter_CarriesNoSecret()
        {

            var record = (SSHKeyBinding) NTSKE_Record.SSHKeyBindingResponse(SSHKeyBindingMethods.Exporter);

            Assert.That(record.TryGetSelection(out var method, out var secret, out var selectionError), Is.True, selectionError);
            Assert.That(method, Is.EqualTo(SSHKeyBindingMethods.Exporter));
            Assert.That(secret, Is.Empty);

        }

        #endregion

        #region The client's validator

        private static NTSKE_Record[] ValidResponse(params NTSKE_Record[] Extra)

            => [
                   NTSKE_Record.NextProtocolNegotiation(0),
                   NTSKE_Record.AEADAlgorithmNegotiation([ AEADAlgorithms.AES_SIV_CMAC_256 ]),
                   .. Extra,
                   new NewCookieForNTPv4(false, [ 0x01, 0x02, 0x03, 0x04 ]),
                   NTSKE_Record.EndOfMessage
               ];

        [Test]
        public void Validator_OverTLS_RefusesTheKeyBinding()
        {

            var valid = NTSKERecordValidator.ValidateServerResponse(
                            ValidResponse(NTSKE_Record.SSHKeyBindingResponse(SSHKeyBindingMethods.Transport, testSecret)),
                            out _,
                            out var errorCategory
                        );

            Assert.That(valid,         Is.False);
            Assert.That(errorCategory, Is.EqualTo(NTSKEErrorCategory.UnknownCriticalRecord));

        }

        [Test]
        public void Validator_OverSSH_RequiresExactlyOneKeyBinding()
        {

            var keyBinding = NTSKE_Record.SSHKeyBindingResponse(SSHKeyBindingMethods.Transport, testSecret);

            Assert.That(NTSKERecordValidator.ValidateServerResponse(ValidResponse(keyBinding),             out var error1, out _,     OverSSH: true), Is.True, error1);

            Assert.That(NTSKERecordValidator.ValidateServerResponse(ValidResponse(),                       out _, out var category2,  OverSSH: true), Is.False);
            Assert.That(category2, Is.EqualTo(NTSKEErrorCategory.MissingRequiredRecord));

            Assert.That(NTSKERecordValidator.ValidateServerResponse(ValidResponse(keyBinding, keyBinding), out _, out var category3,  OverSSH: true), Is.False);
            Assert.That(category3, Is.EqualTo(NTSKEErrorCategory.Protocol));

        }

        #endregion


        #region Key exchange over SSH, then NTP

        [Test]
        [Category("LocalIntegration")]
        public async Task KeyExchangeOverSSH_ThenNTP()
        {

            await using var sshClient  = await ConnectAsync(clientKey);
            var ntsClient              = NewNTSClient();

            var ntsKEResult            = await ntsClient.GetNTSKERecordsOverSSH(sshClient);

            Assert.That(ntsKEResult.Success,       Is.True, ntsKEResult.ErrorMessage);

            var ntsKEResponse          = ntsKEResult.Response!;

            Assert.That(ntsKEResponse.Cookies.Count(),  Is.EqualTo(NTSServer.MaxCookiesPerResponse));
            Assert.That(ntsKEResponse.C2SKey.Length,    Is.EqualTo(NTSAEAD.KeyLength(ntsKEResponse.AEADAlgorithm)));
            Assert.That(ntsKEResponse.S2CKey.Length,    Is.EqualTo(NTSAEAD.KeyLength(ntsKEResponse.AEADAlgorithm)));
            Assert.That(ntsKEResponse.C2SKey,           Is.Not.EqualTo(ntsKEResponse.S2CKey));
            Assert.That(ntsKEResponse.TLSInfo,          Is.Null);
            Assert.That(ntsKEResponse.NTSKERecords.OfType<SSHKeyBinding>().Count(), Is.EqualTo(1));

            // The server put the keys it derived into the cookies, and the client derived its own
            // from the transported secret. A query the server can decrypt and the client can
            // verify is the proof that both arrived at the same two keys.
            var ntsQueryResult         = await ntsClient.QueryTime(NTSKEResponse: ntsKEResponse,
                                                                   Timeout:       TimeSpan.FromSeconds(10));

            Assert.That(ntsQueryResult.Success,         Is.True, ntsQueryResult.ErrorMessage);
            Assert.That(ntsQueryResult.ErrorCategory,   Is.EqualTo(NTSQueryErrorCategory.None));

        }

        [Test]
        [Category("LocalIntegration")]
        public async Task KeyExchangeOverSSH_WithEveryAlgorithmTheServerSupports(
            [Values(AEADAlgorithms.AES_128_GCM_SIV, AEADAlgorithms.AES_SIV_CMAC_256)] AEADAlgorithms Algorithm)
        {

            await using var sshClient  = await ConnectAsync(clientKey);
            var ntsClient              = NewNTSClient([ Algorithm ]);

            var ntsKEResult            = await ntsClient.GetNTSKERecordsOverSSH(sshClient);

            Assert.That(ntsKEResult.Success,                 Is.True, ntsKEResult.ErrorMessage);
            Assert.That(ntsKEResult.Response!.AEADAlgorithm, Is.EqualTo(Algorithm));

            var ntsQueryResult         = await ntsClient.QueryTime(NTSKEResponse: ntsKEResult.Response,
                                                                   Timeout:       TimeSpan.FromSeconds(10));

            Assert.That(ntsQueryResult.Success, Is.True, ntsQueryResult.ErrorMessage);

        }

        [Test]
        [Category("LocalIntegration")]
        public async Task TwoKeyExchanges_OnOneConnection_GetTwoSecrets()
        {

            // Option B takes nothing from the connection, so it may be repeated on it — which is
            // what a station needs whose one connection carries OCPP for weeks.
            await using var sshClient  = await ConnectAsync(clientKey);
            var ntsClient              = NewNTSClient();

            var first                  = await ntsClient.GetNTSKERecordsOverSSH(sshClient);
            var second                 = await ntsClient.GetNTSKERecordsOverSSH(sshClient);

            Assert.That(first. Success, Is.True, first. ErrorMessage);
            Assert.That(second.Success, Is.True, second.ErrorMessage);
            Assert.That(second.Response!.C2SKey, Is.Not.EqualTo(first.Response!.C2SKey));

        }

        #endregion

        #region What the server refuses

        [Test]
        [Category("LocalIntegration")]
        public void AKeyTheServerDoesNotKnow_DoesNotLogIn()
        {
            Assert.That(async () => await ConnectAsync(strangerKey), Throws.Exception);
        }

        [Test]
        [Category("LocalIntegration")]
        public async Task AnotherSubsystem_IsRefused()
        {

            await using var sshClient = await ConnectAsync(clientKey);

            Assert.That(async () => await sshClient.OpenSubsystemAsync("ntske/2@open.charging.cloud"),
                        Throws.InstanceOf<SshWireException>());

        }

        [Test]
        [Category("LocalIntegration")]
        public async Task ARequestWithoutKeyBinding_IsABadRequest()
        {

            var response = await ExchangeOverSSHAsync(
                               NTSKE_Record.NTSNextProtocolNegotiation,
                               NTSKE_Record.AEADAlgorithmNegotiation([ AEADAlgorithms.AES_SIV_CMAC_256 ]),
                               NTSKE_Record.EndOfMessage
                           );

            Assert.That(ErrorCodeOf(response), Is.EqualTo(NTSKEErrorCodes.BadRequest));

        }

        [Test]
        [Category("LocalIntegration")]
        public async Task ARequestOfferingOnlyTheExporter_IsABadRequest()
        {

            var response = await ExchangeOverSSHAsync(
                               NTSKE_Record.NTSNextProtocolNegotiation,
                               NTSKE_Record.AEADAlgorithmNegotiation([ AEADAlgorithms.AES_SIV_CMAC_256 ]),
                               NTSKE_Record.SSHKeyBindingRequest(SSHKeyBindingMethods.Exporter),
                               NTSKE_Record.EndOfMessage
                           );

            Assert.That(ErrorCodeOf(response), Is.EqualTo(NTSKEErrorCodes.BadRequest));

        }

        [Test]
        [Category("LocalIntegration")]
        public async Task ARequestPreferringTheExporter_GetsTheTransport()
        {

            var response = await ExchangeOverSSHAsync(
                               NTSKE_Record.NTSNextProtocolNegotiation,
                               NTSKE_Record.AEADAlgorithmNegotiation([ AEADAlgorithms.AES_SIV_CMAC_256 ]),
                               NTSKE_Record.SSHKeyBindingRequest(SSHKeyBindingMethods.Exporter,
                                                                 SSHKeyBindingMethods.Transport),
                               NTSKE_Record.EndOfMessage
                           );

            Assert.That(ErrorCodeOf(response), Is.Null);

            var keyBinding = response.OfType<SSHKeyBinding>().Single();

            Assert.That(keyBinding.TryGetSelection(out var method, out var secret, out var selectionError), Is.True, selectionError);
            Assert.That(method,        Is.EqualTo(SSHKeyBindingMethods.Transport));
            Assert.That(secret!.Length, Is.EqualTo(NTSKE_ExportedKeys.TransportedSecretLength));

            // Never echoed over SSH, where it means nothing.
            Assert.That(response.Any(record => record.Type == NTSKE_RecordTypes.CompliantAES128GCMSIVExporterContext), Is.False);

        }

        [Test]
        [Category("LocalIntegration")]
        public async Task TheKeyBindingOverTLS_IsAnUnrecognizedCriticalRecord()
        {

            // On port 4460 the record does not occur, and a server must not hand out cookies
            // whose keys the client is about to derive from a secret it was never sent.
            using var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(System.Net.IPAddress.Loopback, testTLSPort.ToUInt16());

            var tlsClientProtocol = new TlsClientProtocol(tcpClient.GetStream());
            tlsClientProtocol.Connect(new NTSKE_TLSClient((sender, serverCertificate, certificateChain, ntsKETLSClient, sslPolicyErrors) => TLSValidationResult.Success()));

            NTSKE_Record[] request = [
                NTSKE_Record.NTSNextProtocolNegotiation,
                NTSKE_Record.AEADAlgorithmNegotiation([ AEADAlgorithms.AES_SIV_CMAC_256 ]),
                NTSKE_Record.SSHKeyBindingRequest(SSHKeyBindingMethods.Transport),
                NTSKE_Record.EndOfMessage
            ];

            await tlsClientProtocol.Stream.WriteAsync(request.ToByteArray());
            await tlsClientProtocol.Stream.FlushAsync();

            var (responseBytes, readError) = await NTSKEMessageReader.ReadAsync(tlsClientProtocol.Stream, TimeSpan.FromSeconds(10), 64 * 1024);

            Assert.That(responseBytes, Is.Not.Null, readError);
            Assert.That(NTSKE_Record.TryParse(responseBytes!, out var response, out var parseError), Is.True, parseError);
            Assert.That(ErrorCodeOf(response!), Is.EqualTo(NTSKEErrorCodes.UnrecognizedCriticalRecord));

            try { tlsClientProtocol.Close(); } catch { }

        }

        #endregion


        #region (private static) ConnectAsync(Key)

        private Task<SshClient> ConnectAsync(ISshHostKey Key)
        {

            var hostKey = ntsServer!.SSHHostKeys[0].PublicKeyBlob;

            return SshClient.ConnectAsync(
                       "127.0.0.1",
                       testSSHPort.ToUInt16(),
                       new SshClientOptions {
                           Username       = "ntske",
                           Credentials    = [ Key ],
                           // Pinned, as section 6.1 of the white paper has it: the host key is the
                           // whole of the server's authentication.
                           VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(hostKey)
                       }
                   ).AsTask();

        }

        #endregion

        #region (private static) NewNTSClient(OfferedAEADAlgorithms = null)

        private static NTSClient NewNTSClient(IEnumerable<AEADAlgorithms>? OfferedAEADAlgorithms = null)

            => new (
                   Hermod.DNS.DomainName.Localhost,
                   NTP_Port:               testNTPPort,
                   IPVersionPreference:    IPVersionPreference.IPv4Only,
                   OfferedAEADAlgorithms:  OfferedAEADAlgorithms
               );

        #endregion

        #region (private) ExchangeOverSSHAsync(Request)

        /// <summary>
        /// Send the given records in the NTS-KE subsystem, as they are, and return the answer.
        /// </summary>
        private async Task<NTSKE_Record[]> ExchangeOverSSHAsync(params NTSKE_Record[] Request)
        {

            await using var sshClient  = await ConnectAsync(clientKey);
            var channel                = await sshClient.OpenSubsystemAsync(NTSKE_SSH.SubsystemName);

            await channel.SendDataAsync(Request.ToByteArray());

            var (responseBytes, readError) = await NTSKEMessageReader.ReadAsync(channel.Input, TimeSpan.FromSeconds(10), 64 * 1024);

            Assert.That(responseBytes, Is.Not.Null, readError);
            Assert.That(NTSKE_Record.TryParse(responseBytes!, out var response, out var parseError), Is.True, parseError);

            return [.. response!];

        }

        #endregion

        #region (private static) ErrorCodeOf(Response)

        private static NTSKEErrorCodes? ErrorCodeOf(IEnumerable<NTSKE_Record> Response)
        {

            var error = Response.FirstOrDefault(record => record.Type == NTSKE_RecordTypes.Error);

            return error is not null && error.Body.Length == 2
                       ? (NTSKEErrorCodes) ((error.Body[0] << 8) | error.Body[1])
                       : null;

        }

        #endregion

        #region (private static) FindFreeTCPPort() / FindFreeUDPPort()

        private static IPPort FindFreeTCPPort()
        {

            var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();

            var port = ((IPEndPoint) listener.LocalEndpoint).Port;
            listener.Stop();

            return IPPort.Parse(port);

        }

        private static IPPort FindFreeUDPPort()
        {

            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            return IPPort.Parse(((IPEndPoint) udpClient.Client.LocalEndPoint!).Port);

        }

        #endregion

    }

}
