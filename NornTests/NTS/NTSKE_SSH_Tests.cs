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
    /// NTS-KE over SSH, options A and B: the exporter sources, the SSH Key Binding record, and key
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

        // Appendix A.3 of the specification of the SSH Key Binding record: method 0x0001 from the
        // exporter_secret on, which is 00 01 … 1f, with the nonce 20 21 … 3f and SHA-256. The
        // nonce makes the keys differ from those of option B under the same 32 octets. Checked
        // with Python's hmac as well.
        private static readonly Byte[] testExporterNonce = [.. Enumerable.Range(0x20, 32).Select(i => (Byte) i)];

        private static readonly Object[] testVectorsFromTheExporterSecret = [
            new Object[] { AEADAlgorithms.AES_SIV_CMAC_256, "dcf81015c16cb4b955624949e824e89f45cac437995a873e938ec3c7adc0218b",
                                                            "6b91d1a3ad1eb448fa5010e20dd79b280f7c303aec2252b464a4642fb70ea12d" },
            new Object[] { AEADAlgorithms.AES_128_GCM_SIV,  "fd8733d215d9d3a79f0d95b86884ed28",
                                                            "f7fe123370cdd2ed478906c34bd6d7b8" },
            new Object[] { AEADAlgorithms.AES_256_GCM_SIV,  "05d23579f0905080af0243173053808adad6d276ed0560a9fe64ef714b690554",
                                                            "d72234762b25d744d00016818b8f23ad65d1ac5c85009d1ada6215046c73ebcc" }
        ];

        [TestCaseSource(nameof(testVectorsFromTheExporterSecret))]
        public void SSHExporter_FromTheExporterSecret_MatchesTheTestVectors(AEADAlgorithms  Algorithm,
                                                                            String          ExpectedC2SKey,
                                                                            String          ExpectedS2CKey)
        {

            var (c2sKey, s2cKey) = NTSKE_ExportedKeys.ExportAll(NTSKE_ExportedKeys.SSHExporter(testSecret, testExporterNonce, System.Security.Cryptography.HashAlgorithmName.SHA256)).
                                                      For(Algorithm, CompliantExporterContext: true);

            Assert.That(c2sKey.ToHexString(), Is.EqualTo(ExpectedC2SKey));
            Assert.That(s2cKey.ToHexString(), Is.EqualTo(ExpectedS2CKey));

        }

        // Appendix A.3 of the white paper, computed independently with Python's hmac and hashlib:
        // K and H of a first key exchange, so the session id is H, the nonce 1f 1e … 00, and the
        // keys of NTS from the exporter. Hermod tests the exporter itself; this is the path of Norn
        // through it, with the context of RFC 8915 § 5.1 for AES-128-GCM-SIV.
        private static readonly Byte[] appendixA3Nonce = Convert.FromHexString("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");

        private static readonly Object[] testVectorsOfOptionA = [
            new Object[] { "SHA256", "000000204a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                                     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                                     AEADAlgorithms.AES_SIV_CMAC_256, "ea9163026944be623b625a50b8f59aa1daf843949e0f98634f178af6e248330a",
                                                                      "d9376278448d5de12b0d3ebc3c06bf26c0ccc0c85ac869b6a23d10213b7fc402" },
            new Object[] { "SHA256", "000000204a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                                     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                                     AEADAlgorithms.AES_128_GCM_SIV,  "339eabe19ea8469bbf993ac405a89417",
                                                                      "26823c8acd419d57fd901749dc6d5d76" },
            new Object[] { "SHA256", "0000002100c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
                                     "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
                                     AEADAlgorithms.AES_SIV_CMAC_256, "6d38e2ff8aaaab4842eb4cb3d66712d93d8675efc0cea721f3828f8de3fce947",
                                                                      "3a177a3612e473add6c214cbdf858b59e7012e0e68676f57692998fb5192a208" },
            new Object[] { "SHA256", "00000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
                                     "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
                                     AEADAlgorithms.AES_SIV_CMAC_256, "10f3f639e505ca255ac1a51d235bac0d0ba15b078774e0c13f7f97a15b93df05",
                                                                      "8a1e71fceb65e99f0d171f6472e8c9bd7f92f20ad8a5085d3bf9b1d7fec9c28f" },
            new Object[] { "SHA512", "00000040808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
                                     "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
                                     AEADAlgorithms.AES_128_GCM_SIV,  "891071d4dcddf3ec6a2074d58ebe5059",
                                                                      "423acfe0d50b1c0e571835f70cb4fef0" }
        ];

        [TestCaseSource(nameof(testVectorsOfOptionA))]
        public void SSHExporter_MatchesTheTestVectorsOfOptionA(String          Hash,
                                                               String          K,
                                                               String          H,
                                                               AEADAlgorithms  Algorithm,
                                                               String          C2SKey,
                                                               String          S2CKey)
        {

            var hash          = new System.Security.Cryptography.HashAlgorithmName(Hash);
            var h             = Convert.FromHexString(H);

            using var exporter = SshExporter.Create(hash, Convert.FromHexString(K), h, h);

            var fromExporter  = NTSKE_ExportedKeys.ExportAll(NTSKE_ExportedKeys.SSHExporter(exporter, appendixA3Nonce)).
                                                   For(Algorithm);

            // And from the secret alone, as a server would that is handed it with the records.
            var fromSecret    = NTSKE_ExportedKeys.ExportAll(NTSKE_ExportedKeys.SSHExporter(SshExporter.ComputeSecret(hash, Convert.FromHexString(K), h, h), appendixA3Nonce, hash)).
                                                   For(Algorithm);

            Assert.Multiple(() => {
                Assert.That(Convert.ToHexStringLower(fromExporter.C2SKey), Is.EqualTo(C2SKey));
                Assert.That(Convert.ToHexStringLower(fromExporter.S2CKey), Is.EqualTo(S2CKey));
                Assert.That(fromSecret.C2SKey, Is.EqualTo(fromExporter.C2SKey));
                Assert.That(fromSecret.S2CKey, Is.EqualTo(fromExporter.S2CKey));
            });

        }

        [Test]
        public void AnotherNonce_GivesOtherKeys()
        {

            using var exporter  = SshExporter.Create(System.Security.Cryptography.HashAlgorithmName.SHA256, new Byte[36], new Byte[32], new Byte[32]);

            var nonce           = System.Security.Cryptography.RandomNumberGenerator.GetBytes(NTSKE_ExportedKeys.ExporterNonceLength);

            var first           = NTSKE_ExportedKeys.ExportAll(NTSKE_ExportedKeys.SSHExporter(exporter, nonce)).For(AEADAlgorithms.AES_SIV_CMAC_256);
            var again           = NTSKE_ExportedKeys.ExportAll(NTSKE_ExportedKeys.SSHExporter(exporter, nonce)).For(AEADAlgorithms.AES_SIV_CMAC_256);
            var another         = NTSKE_ExportedKeys.ExportAll(NTSKE_ExportedKeys.SSHExporter(exporter, System.Security.Cryptography.RandomNumberGenerator.GetBytes(NTSKE_ExportedKeys.ExporterNonceLength))).
                                                     For(AEADAlgorithms.AES_SIV_CMAC_256);

            Assert.Multiple(() => {
                Assert.That(again.  C2SKey, Is.EqualTo    (first.C2SKey));
                Assert.That(another.C2SKey, Is.Not.EqualTo(first.C2SKey));
                Assert.That(another.S2CKey, Is.Not.EqualTo(first.S2CKey));
            });

        }

        #endregion

        #region The SSH Key Binding record

        [Test]
        public void Request_RoundTrips()
        {

            var bytes = NTSKE_Record.SSHKeyBindingRequest(SSHKeyBindingMethods.Exporter,
                                                          SSHKeyBindingMethods.Transport).ToByteArray();

            // Critical bit and type 16386, eight octets of body: each method id with the data
            // length 0 (Appendix A.2 of the white paper).
            Assert.That(bytes.ToHexString(), Is.EqualTo("c002" + "0008" + "0001" + "0000" + "0002" + "0000"));

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
            // reason to refuse the list - and its data, which the length says, is skipped, not read
            // as method ids (Appendix A.2 of the white paper: c002 000a 8001 0002 abcd 0002 0000).
            var record = new SSHKeyBinding(true, [ 0x80, 0x01, 0x00, 0x02, 0xab, 0xcd, 0x00, 0x02, 0x00, 0x00 ]);

            Assert.That(record.TryGetOfferedMethods(out var methods, out var methodError), Is.True, methodError);
            Assert.That(methods, Is.EqualTo(new UInt16[] { 0x8001, 0x0002 }));

            Assert.That(record.TryGetOffer(out var offer, out var offerError), Is.True, offerError);
            Assert.That(offer![0].Data, Is.EqualTo(new Byte[] { 0xab, 0xcd }));
            Assert.That(offer[1].Data,  Is.Empty);

        }

        [Test]
        public void Request_WithoutAWholeListOfEntries_IsRefused()
        {
            Assert.Multiple(() => {

                // No entry.
                Assert.That(new SSHKeyBinding(true, []).                                          TryGetOfferedMethods(out _, out _), Is.False);

                // An entry cut short: a method id without its data length.
                Assert.That(new SSHKeyBinding(true, [ 0x00, 0x02 ]).                              TryGetOfferedMethods(out _, out _), Is.False);
                Assert.That(new SSHKeyBinding(true, [ 0x00, 0x02, 0x00 ]).                        TryGetOfferedMethods(out _, out _), Is.False);

                // Data cut short.
                Assert.That(new SSHKeyBinding(true, [ 0x80, 0x01, 0x00, 0x05, 0xab ]).            TryGetOfferedMethods(out _, out _), Is.False);

                // Octets after the last entry.
                Assert.That(new SSHKeyBinding(true, [ 0x00, 0x02, 0x00, 0x00, 0x00 ]).            TryGetOfferedMethods(out _, out _), Is.False);

            });
        }

        [Test]
        public void Request_WithDataForTheExporterOrTheTransport_IsRefused()
        {
            Assert.Multiple(() => {
                Assert.That(new SSHKeyBinding(true, [ 0x00, 0x01, 0x00, 0x01, 0xff, 0x00, 0x02, 0x00, 0x00 ]).TryGetOfferedMethods(out _, out _), Is.False);
                Assert.That(new SSHKeyBinding(true, [ 0x00, 0x02, 0x00, 0x02, 0xaa, 0xbb ]).                  TryGetOfferedMethods(out _, out _), Is.False);
            });
        }

        [Test]
        public void Response_ThatCannotBeUsed_IsRefused()
        {

            // Too short for a method id.
            Assert.That(new SSHKeyBinding(true, [ 0x00 ]).                         TryGetSelection(out _, out _, out _), Is.False);

            // The transport with a secret one octet short.
            Assert.That(new SSHKeyBinding(true, [ 0x00, 0x02, .. new Byte[31] ]).  TryGetSelection(out _, out _, out _), Is.False);

            // The exporter without its nonce, and with a nonce one octet short.
            Assert.That(new SSHKeyBinding(true, [ 0x00, 0x01 ]).                   TryGetSelection(out _, out _, out _), Is.False);
            Assert.That(new SSHKeyBinding(true, [ 0x00, 0x01, .. new Byte[31] ]).  TryGetSelection(out _, out _, out _), Is.False);

            // A method nobody offered.
            Assert.That(new SSHKeyBinding(true, [ 0x00, 0x03 ]).                   TryGetSelection(out _, out _, out _), Is.False);

        }

        [Test]
        public void Response_SelectingTheExporter_CarriesTheNonce()
        {

            var bytes = NTSKE_Record.SSHKeyBindingResponse(SSHKeyBindingMethods.Exporter, testExporterNonce).ToByteArray();

            // Appendix B of the specification: T 0022 0001 <exporter_nonce, 32 octets>.
            Assert.That(bytes.ToHexString(), Is.EqualTo("c002" + "0022" + "0001" + testExporterNonce.ToHexString()));

            Assert.That(NTSKE_Record.TryParse(bytes, out var records, out var errorResponse), Is.True, errorResponse);

            var record = (SSHKeyBinding) records!.Single();

            Assert.That(record.TryGetSelection(out var method, out var nonce, out var selectionError), Is.True, selectionError);
            Assert.That(method, Is.EqualTo(SSHKeyBindingMethods.Exporter));
            Assert.That(nonce,  Is.EqualTo(testExporterNonce));

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
        public async Task KeyExchangeOverSSH_ThenNTP(
            [Values(SSHKeyBindingMethods.Exporter, SSHKeyBindingMethods.Transport)] SSHKeyBindingMethods Method)
        {

            await using var sshClient  = await ConnectAsync(clientKey);
            var ntsClient              = NewNTSClient();

            var ntsKEResult            = await ntsClient.GetNTSKERecordsOverSSH(sshClient,
                                                                                OfferSSHExporter: Method == SSHKeyBindingMethods.Exporter);

            Assert.That(ntsKEResult.Success,       Is.True, ntsKEResult.ErrorMessage);

            var ntsKEResponse          = ntsKEResult.Response!;

            Assert.That(ntsKEResponse.Cookies.Count(),  Is.EqualTo(NTSServer.MaxCookiesPerResponse));
            Assert.That(ntsKEResponse.C2SKey.Length,    Is.EqualTo(NTSAEAD.KeyLength(ntsKEResponse.AEADAlgorithm)));
            Assert.That(ntsKEResponse.S2CKey.Length,    Is.EqualTo(NTSAEAD.KeyLength(ntsKEResponse.AEADAlgorithm)));
            Assert.That(ntsKEResponse.C2SKey,           Is.Not.EqualTo(ntsKEResponse.S2CKey));
            Assert.That(ntsKEResponse.TLSInfo,          Is.Null);
            Assert.That(ntsKEResponse.NTSKERecords.OfType<SSHKeyBinding>().Count(), Is.EqualTo(1));
            Assert.That(SelectedMethodOf(ntsKEResponse), Is.EqualTo(Method));

            // The server put the keys it derived into the cookies, and the client derived its own
            // from the exporter of its connection or from the transported secret. A query the
            // server can decrypt and the client can verify is the proof that both arrived at the
            // same two keys.
            var ntsQueryResult         = await ntsClient.QueryTime(NTSKEResponse: ntsKEResponse,
                                                                   Timeout:       TimeSpan.FromSeconds(10));

            Assert.That(ntsQueryResult.Success,         Is.True, ntsQueryResult.ErrorMessage);
            Assert.That(ntsQueryResult.ErrorCategory,   Is.EqualTo(NTSQueryErrorCategory.None));

        }

        [Test]
        [Category("LocalIntegration")]
        public async Task KeyExchangeOverSSH_WithEveryAlgorithmTheServerSupports(
            [Values(AEADAlgorithms.AES_128_GCM_SIV, AEADAlgorithms.AES_SIV_CMAC_256)] AEADAlgorithms        Algorithm,
            [Values(SSHKeyBindingMethods.Exporter,  SSHKeyBindingMethods.Transport)]  SSHKeyBindingMethods  Method)
        {

            await using var sshClient  = await ConnectAsync(clientKey);
            var ntsClient              = NewNTSClient([ Algorithm ]);

            var ntsKEResult            = await ntsClient.GetNTSKERecordsOverSSH(sshClient,
                                                                                OfferSSHExporter: Method == SSHKeyBindingMethods.Exporter);

            Assert.That(ntsKEResult.Success,                    Is.True, ntsKEResult.ErrorMessage);
            Assert.That(ntsKEResult.Response!.AEADAlgorithm,    Is.EqualTo(Algorithm));
            Assert.That(SelectedMethodOf(ntsKEResult.Response), Is.EqualTo(Method));

            var ntsQueryResult         = await ntsClient.QueryTime(NTSKEResponse: ntsKEResult.Response,
                                                                   Timeout:       TimeSpan.FromSeconds(10));

            Assert.That(ntsQueryResult.Success, Is.True, ntsQueryResult.ErrorMessage);

        }

        [Test]
        [Category("LocalIntegration")]
        public async Task ThreeKeyExchanges_OnOneConnection_GetKeysOfTheirOwn()
        {

            // Every exchange on one connection takes the exporter, with a nonce of its own, and so
            // keys of its own — which is what a station needs whose one connection carries OCPP for
            // weeks, and which refreshes its keys on it.
            await using var sshClient  = await ConnectAsync(clientKey);
            var ntsClient              = NewNTSClient();

            var first                  = await ntsClient.GetNTSKERecordsOverSSH(sshClient);
            var second                 = await ntsClient.GetNTSKERecordsOverSSH(sshClient);
            var third                  = await ntsClient.GetNTSKERecordsOverSSH(sshClient);

            Assert.That(first. Success, Is.True, first. ErrorMessage);
            Assert.That(second.Success, Is.True, second.ErrorMessage);
            Assert.That(third. Success, Is.True, third. ErrorMessage);

            Assert.That(SelectedMethodOf(first. Response!), Is.EqualTo(SSHKeyBindingMethods.Exporter));
            Assert.That(SelectedMethodOf(second.Response!), Is.EqualTo(SSHKeyBindingMethods.Exporter));
            Assert.That(SelectedMethodOf(third. Response!), Is.EqualTo(SSHKeyBindingMethods.Exporter));

            Assert.That(second.Response!.C2SKey, Is.Not.EqualTo(first. Response!.C2SKey));
            Assert.That(third. Response!.C2SKey, Is.Not.EqualTo(second.Response!.C2SKey));
            Assert.That(third. Response!.C2SKey, Is.Not.EqualTo(first. Response!.C2SKey));

            // The keys came from the exporter the client holds and the nonce of the exchange - no
            // secret was sent.
            Assert.That(first.Response!.C2SKey,
                        Is.EqualTo(sshClient.Exporter.Export(MethodDataOf(first.Response.NTSKERecords),
                                                             NTSKE_ExportedKeys.ExporterLabel,
                                                             NTSKE_ExportedKeys.Context(first.Response.AEADAlgorithm, ServerToClient: false),
                                                             first.Response.C2SKey.Length)));

            // And the server sealed the same ones into the cookies of every exchange.
            foreach (var response in new[] { first.Response, second.Response, third.Response })
            {

                var ntsQueryResult     = await ntsClient.QueryTime(NTSKEResponse: response,
                                                                   Timeout:       TimeSpan.FromSeconds(10));

                Assert.That(ntsQueryResult.Success, Is.True, ntsQueryResult.ErrorMessage);

            }

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
        public async Task ARequestOfferingOnlyTheExporter_GetsItEveryTime()
        {

            await using var sshClient  = await ConnectAsync(clientKey);

            NTSKE_Record[] request     = [
                                             NTSKE_Record.NTSNextProtocolNegotiation,
                                             NTSKE_Record.AEADAlgorithmNegotiation([ AEADAlgorithms.AES_SIV_CMAC_256 ]),
                                             NTSKE_Record.SSHKeyBindingRequest(SSHKeyBindingMethods.Exporter),
                                             NTSKE_Record.EndOfMessage
                                         ];

            var first                  = await ExchangeOverSSHAsync(sshClient, request);
            var second                 = await ExchangeOverSSHAsync(sshClient, request);

            Assert.That(ErrorCodeOf(first),  Is.Null);
            Assert.That(ErrorCodeOf(second), Is.Null);

            Assert.That(first. OfType<SSHKeyBinding>().Single().TryGetSelection(out var firstMethod,  out var firstNonce,  out var firstError),  Is.True, firstError);
            Assert.That(second.OfType<SSHKeyBinding>().Single().TryGetSelection(out var secondMethod, out var secondNonce, out var secondError), Is.True, secondError);

            Assert.That(firstMethod,          Is.EqualTo(SSHKeyBindingMethods.Exporter));
            Assert.That(secondMethod,         Is.EqualTo(SSHKeyBindingMethods.Exporter));
            Assert.That(firstNonce!.Length,   Is.EqualTo(NTSKE_ExportedKeys.ExporterNonceLength));
            Assert.That(secondNonce,          Is.Not.EqualTo(firstNonce), "Every exchange gets a nonce of its own.");

        }

        [Test]
        [Category("LocalIntegration")]
        public async Task FourRequestsForTheExporter_AtOnce_OnOneConnection_GetNoncesOfTheirOwn()
        {

            // Four channels of one connection whose requests arrive together.
            await using var sshClient  = await ConnectAsync(clientKey);

            NTSKE_Record[] request     = [
                                             NTSKE_Record.NTSNextProtocolNegotiation,
                                             NTSKE_Record.AEADAlgorithmNegotiation([ AEADAlgorithms.AES_SIV_CMAC_256 ]),
                                             NTSKE_Record.SSHKeyBindingRequest(SSHKeyBindingMethods.Exporter),
                                             NTSKE_Record.EndOfMessage
                                         ];

            var responses              = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => ExchangeOverSSHAsync(sshClient, request)));

            Assert.That(responses.All(response => ErrorCodeOf(response) is null), Is.True);
            Assert.That(responses.Select(response => Convert.ToHexString(MethodDataOf(response))).Distinct().Count(), Is.EqualTo(4));

        }

        [Test]
        [Category("LocalIntegration")]
        public async Task ARequestPreferringTheExporter_GetsTheExporter()
        {

            await using var sshClient  = await ConnectAsync(clientKey);

            NTSKE_Record[] request     = [
                                             NTSKE_Record.NTSNextProtocolNegotiation,
                                             NTSKE_Record.AEADAlgorithmNegotiation([ AEADAlgorithms.AES_SIV_CMAC_256 ]),
                                             NTSKE_Record.SSHKeyBindingRequest(SSHKeyBindingMethods.Exporter,
                                                                               SSHKeyBindingMethods.Transport),
                                             NTSKE_Record.EndOfMessage
                                         ];

            var first                  = await ExchangeOverSSHAsync(sshClient, request);
            var second                 = await ExchangeOverSSHAsync(sshClient, request);

            Assert.That(ErrorCodeOf(first),  Is.Null);
            Assert.That(ErrorCodeOf(second), Is.Null);

            Assert.That(first. OfType<SSHKeyBinding>().Single().TryGetSelection(out var firstMethod,  out _, out var firstError),  Is.True, firstError);
            Assert.That(second.OfType<SSHKeyBinding>().Single().TryGetSelection(out var secondMethod, out _, out var secondError), Is.True, secondError);

            Assert.That(firstMethod,  Is.EqualTo(SSHKeyBindingMethods.Exporter));
            Assert.That(secondMethod, Is.EqualTo(SSHKeyBindingMethods.Exporter));

            // Never echoed over SSH, where it means nothing.
            Assert.That(first. Any(record => record.Type == NTSKE_RecordTypes.CompliantAES128GCMSIVExporterContext), Is.False);
            Assert.That(second.Any(record => record.Type == NTSKE_RecordTypes.CompliantAES128GCMSIVExporterContext), Is.False);

        }

        [Test]
        [Category("LocalIntegration")]
        public async Task ARequestPreferringTheTransport_GetsTheTransport()
        {

            // The client's order decides, not the server's preference.
            var response = await ExchangeOverSSHAsync(
                               NTSKE_Record.NTSNextProtocolNegotiation,
                               NTSKE_Record.AEADAlgorithmNegotiation([ AEADAlgorithms.AES_SIV_CMAC_256 ]),
                               NTSKE_Record.SSHKeyBindingRequest(SSHKeyBindingMethods.Transport,
                                                                 SSHKeyBindingMethods.Exporter),
                               NTSKE_Record.EndOfMessage
                           );

            Assert.That(ErrorCodeOf(response), Is.Null);
            Assert.That(response.OfType<SSHKeyBinding>().Single().TryGetSelection(out var method, out _, out var selectionError), Is.True, selectionError);
            Assert.That(method, Is.EqualTo(SSHKeyBindingMethods.Transport));

        }

        [Test]
        [Category("LocalIntegration")]
        public async Task ARequestOfferingOnlyMethodsTheServerDoesNotKnow_IsABadRequest()
        {

            var response = await ExchangeOverSSHAsync(
                               NTSKE_Record.NTSNextProtocolNegotiation,
                               NTSKE_Record.AEADAlgorithmNegotiation([ AEADAlgorithms.AES_SIV_CMAC_256 ]),
                               new SSHKeyBinding(true, [ 0x00, 0x03, 0x00, 0x00, 0x7f, 0xff, 0x00, 0x01, 0x42 ]),
                               NTSKE_Record.EndOfMessage
                           );

            Assert.That(ErrorCodeOf(response), Is.EqualTo(NTSKEErrorCodes.BadRequest));

        }

        [Test]
        [Category("LocalIntegration")]
        public async Task ARequestWithAnUnknownMethodAndItsData_GetsTheNextMethod()
        {

            // A later client's method with data of its own, before the transport: the data is
            // skipped by its length, and the transport selected.
            var response = await ExchangeOverSSHAsync(
                               NTSKE_Record.NTSNextProtocolNegotiation,
                               NTSKE_Record.AEADAlgorithmNegotiation([ AEADAlgorithms.AES_SIV_CMAC_256 ]),
                               new SSHKeyBinding(true, [ 0x80, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00 ]),
                               NTSKE_Record.EndOfMessage
                           );

            Assert.That(ErrorCodeOf(response), Is.Null);
            Assert.That(response.OfType<SSHKeyBinding>().Single().TryGetSelection(out var method, out _, out var selectionError), Is.True, selectionError);
            Assert.That(method, Is.EqualTo(SSHKeyBindingMethods.Transport));

        }

        [Test]
        [Category("LocalIntegration")]
        public async Task ARequestWithDataForTheTransport_IsABadRequest()
        {

            var response = await ExchangeOverSSHAsync(
                               NTSKE_Record.NTSNextProtocolNegotiation,
                               NTSKE_Record.AEADAlgorithmNegotiation([ AEADAlgorithms.AES_SIV_CMAC_256 ]),
                               new SSHKeyBinding(true, [ 0x00, 0x02, 0x00, 0x02, 0xaa, 0xbb ]),
                               NTSKE_Record.EndOfMessage
                           );

            Assert.That(ErrorCodeOf(response), Is.EqualTo(NTSKEErrorCodes.BadRequest));

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
        /// Send the given records in the NTS-KE subsystem of a connection of their own, as they
        /// are, and return the answer.
        /// </summary>
        private async Task<NTSKE_Record[]> ExchangeOverSSHAsync(params NTSKE_Record[] Request)
        {
            await using var sshClient = await ConnectAsync(clientKey);
            return await ExchangeOverSSHAsync(sshClient, Request);
        }

        /// <summary>
        /// Send the given records in the NTS-KE subsystem of the given connection, as they are, and
        /// return the answer.
        /// </summary>
        private static async Task<NTSKE_Record[]> ExchangeOverSSHAsync(SshClient SSHClient, params NTSKE_Record[] Request)
        {

            var channel = await SSHClient.OpenSubsystemAsync(NTSKE_SSH.SubsystemName);

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

        #region (private static) SelectedMethodOf(Response)

        /// <summary>
        /// Where the keys of a key exchange came from: the method its SSH Key Binding record selected.
        /// </summary>
        private static SSHKeyBindingMethods SelectedMethodOf(NTSKE_Response Response)
        {

            Assert.That(Response.NTSKERecords.OfType<SSHKeyBinding>().Single().TryGetSelection(out var method, out _, out var selectionError),
                        Is.True,
                        selectionError);

            return method;

        }

        #endregion

        #region (private static) MethodDataOf(Response)

        /// <summary>
        /// What the SSH Key Binding record of a response sent with the method it selected: the
        /// nonce of the exporter, or the secret of the transport.
        /// </summary>
        private static Byte[] MethodDataOf(IEnumerable<NTSKE_Record> Response)
        {

            Assert.That(Response.OfType<SSHKeyBinding>().Single().TryGetSelection(out _, out var methodData, out var selectionError),
                        Is.True,
                        selectionError);

            return methodData!;

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
