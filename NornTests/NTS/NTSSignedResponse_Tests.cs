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
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// Signed responses, and the keys they are signed and checked with.
    /// </summary>
    [TestFixture]
    public class NTSSignedResponse_Tests
    {

        #region AServerWithoutASigningKeyDoesNotAnnounceASignedResponse()

        /// <summary>
        /// Asked for a signed response it cannot give, the server answers as usual.
        /// It used to announce a second response and never send it, and the client
        /// waited for it until its timeout ran out.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task AServerWithoutASigningKeyDoesNotAnnounceASignedResponse()
        {

            var (ntsServer, ntsClient) = await Start(KeyPair: null);

            try
            {

                var ntsKEResult  = await ntsClient.GetNTSKERecords();

                Assert.That(ntsKEResult.Success,                                   Is.True, ntsKEResult.ErrorMessage);

                var started      = System.Diagnostics.Stopwatch.GetTimestamp();

                var queryResult  = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(queryResult.Success,                                   Is.True, queryResult.ErrorMessage);
                Assert.That(System.Diagnostics.Stopwatch.GetElapsedTime(started),  Is.LessThan(TimeSpan.FromSeconds(2)));
                Assert.That(queryResult.Response!.NTSSignedResponseAnnouncement(), Is.Null);
                Assert.That(queryResult.Response!.NTSSignedResponse(),             Is.Null);

                // And the query says so, instead of leaving it to be found out.
                Assert.That(queryResult.SignatureVerification,                     Is.EqualTo(NTSSignatureVerification.NotSigned));
                Assert.That(queryResult.SignatureKeyId,                            Is.Null);

            }
            finally
            {
                await ntsServer.ShutdownAsync();
            }

        }

        #endregion

        #region AQueryChecksTheSignatureItAskedFor()

        /// <summary>
        /// Whoever asks a query for a signed response is told what the signature is
        /// worth, and does not have to find the extension, the key and the check.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task AQueryChecksTheSignatureItAskedFor()
        {

            var (ntsServer, ntsClient) = await Start(KeyPair.GenerateECKeys(7));

            try
            {

                var ntsKEResult  = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);

                Assert.That(ntsKEResult.Success,                                   Is.True, ntsKEResult.ErrorMessage);

                var signed       = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             SignedResponseKeyId: 7,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(signed.Success,                                        Is.True, signed.ErrorMessage);
                Assert.That(signed.SignatureVerification,                          Is.EqualTo(NTSSignatureVerification.Verified));
                Assert.That(signed.SignatureKeyId,                                 Is.EqualTo(7));

                // Not asked for, not looked for.
                var unsigned     = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(unsigned.Success,                                      Is.True, unsigned.ErrorMessage);
                Assert.That(unsigned.SignatureVerification,                        Is.EqualTo(NTSSignatureVerification.NotRequested));
                Assert.That(unsigned.SignatureKeyId,                               Is.Null);

            }
            finally
            {
                await ntsServer.ShutdownAsync();
            }

        }

        #endregion

        #region ASignatureOfAKeyTheKeyExchangeDidNotNameIsNotVerified()

        /// <summary>
        /// A key exchange that did not ask for the public keys has none to check with.
        /// The time is still the server's, by the authenticator; of the signature
        /// nothing is known, and "verified" is not what that is called.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task ASignatureOfAKeyTheKeyExchangeDidNotNameIsNotVerified()
        {

            var (ntsServer, ntsClient) = await Start(KeyPair.GenerateECKeys(7));

            try
            {

                var ntsKEResult  = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: false);

                Assert.That(ntsKEResult.Success,                                   Is.True, ntsKEResult.ErrorMessage);
                Assert.That(ntsKEResult.Response!.PublicKeys,                      Is.Empty);

                var queryResult  = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             SignedResponseKeyId: 7,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(queryResult.Success,                                   Is.True, queryResult.ErrorMessage);
                Assert.That(queryResult.Response!.NTSSignedResponse(),             Is.Not.Null);
                Assert.That(queryResult.SignatureVerification,                     Is.EqualTo(NTSSignatureVerification.UnknownKey));
                Assert.That(queryResult.SignatureKeyId,                            Is.EqualTo(7));

            }
            finally
            {
                await ntsServer.ShutdownAsync();
            }

        }

        #endregion

        #region ASignatureThatIsNotTheNamedKeysFailsTheQuery()

        /// <summary>
        /// The key exchange named key 7, and the response is signed "with key 7" by
        /// somebody else. That is not a time with a signature missing: it is a
        /// response claiming a proof it does not have, and the query has failed.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task ASignatureThatIsNotTheNamedKeysFailsTheQuery()
        {

            var (ntsServer, ntsClient) = await Start(KeyPair.GenerateECKeys(7));

            try
            {

                var ntsKEResult  = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);

                Assert.That(ntsKEResult.Success,                                   Is.True, ntsKEResult.ErrorMessage);

                // The same key exchange, but with another key under the number 7.
                var keyExchange  = ntsKEResult.Response!;
                var otherKey     = KeyPair.GenerateECKeys(7).ToPublicKey();

                var forged       = new NTSKE_Response(
                                       keyExchange.NTSKERecords.
                                           Select(record => record.Type == NTSKE_RecordTypes.NTSPublicKey
                                                                ? NTSKE_Record.NTSPublicKey(otherKey)
                                                                : record).
                                           ToArray(),
                                       keyExchange.C2SKey,
                                       keyExchange.S2CKey
                                   );

                Assert.That(forged.PublicKeys.Single().Id,                         Is.EqualTo(7));

                var queryResult  = await ntsClient.QueryTime(
                                             NTSKEResponse:       forged,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             SignedResponseKeyId: 7,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(queryResult.Success,                                   Is.False);
                Assert.That(queryResult.SignatureVerification,                     Is.EqualTo(NTSSignatureVerification.Invalid));
                Assert.That(queryResult.SignatureKeyId,                            Is.EqualTo(7));
                Assert.That(queryResult.ErrorCategory,                             Is.EqualTo(NTSQueryErrorCategory.NTSAuthentication));
                Assert.That(queryResult.ErrorMessage,                              Does.Contain("signature"));

                // What came is still there to be looked at.
                Assert.That(queryResult.Response!.NTSSignedResponse(),             Is.Not.Null);

            }
            finally
            {
                await ntsServer.ShutdownAsync();
            }

        }

        #endregion

        #region ASignatureIsCheckedAgainstTheKeyItNames()

        /// <summary>
        /// The signature verifies under the server's key, and under nothing else.
        /// Whatever is wrong with a key, the answer is "no" and not an exception:
        /// the key comes from the server, too.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task ASignatureIsCheckedAgainstTheKeyItNames()
        {

            var keyPair                = KeyPair.GenerateECKeys(7);
            var (ntsServer, ntsClient) = await Start(keyPair);

            try
            {

                var ntsKEResult  = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);

                Assert.That(ntsKEResult.Success,                                   Is.True, ntsKEResult.ErrorMessage);

                var queryResult  = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             SignedResponseKeyId: 7,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(queryResult.Success,                                   Is.True, queryResult.ErrorMessage);

                var response     = queryResult.Response!;
                var signature    = response.NTSSignedResponse();
                var publicKey    = ntsKEResult.Response!.PublicKeys.First();

                Assert.That(signature,                                             Is.Not.Null);
                Assert.That(signature!.KeyId,                                      Is.EqualTo(7));
                Assert.That(publicKey.Id,                                          Is.EqualTo(7));

                Assert.That(signature.Verify(response, publicKey),                 Is.True);

                // The same key under another number: not the key the signature names.
                Assert.That(signature.Verify(response, new PublicKey(8, publicKey.Value)),
                            Is.False);

                // Somebody else's key.
                Assert.That(signature.Verify(response, KeyPair.GenerateECKeys(7).ToPublicKey()),
                            Is.False);

                // Not a key at all, a curve nobody knows, an algorithm nobody knows.
                Assert.That(signature.Verify(response, new PublicKey(7, RandomNumberGenerator.GetBytes(65))),
                            Is.False);

                Assert.That(signature.Verify(response, new PublicKey(7, publicKey.Value, EllipticCurve: "no-such-curve")),
                            Is.False);

                Assert.That(signature.Verify(response, new PublicKey(7, publicKey.Value, SignatureAlgorithm: "no-such-algorithm")),
                            Is.False);

            }
            finally
            {
                await ntsServer.ShutdownAsync();
            }

        }

        #endregion


        #region EqualKeysHaveEqualHashCodes()

        /// <summary>
        /// Equality is by content, so the hash code has to be as well:
        /// otherwise a dictionary holds two entries for one key.
        /// </summary>
        [Test]
        public void EqualKeysHaveEqualHashCodes()
        {

            var keyPair       = KeyPair.GenerateECKeys(1);
            var keyPairCopy   = keyPair.Clone();

            Assert.That(keyPairCopy,                                               Is.EqualTo(keyPair));
            Assert.That(keyPairCopy.GetHashCode(),                                 Is.EqualTo(keyPair.GetHashCode()));

            var publicKey     = keyPair.ToPublicKey();
            var publicKeyCopy = publicKey.Clone();

            Assert.That(publicKeyCopy,                                             Is.EqualTo(publicKey));
            Assert.That(publicKeyCopy.GetHashCode(),                               Is.EqualTo(publicKey.GetHashCode()));

            var value         = RandomNumberGenerator.GetBytes(32);
            var notBefore     = DateTimeOffset.UtcNow;
            var masterKey     = new MasterKey(1, value,                notBefore, notBefore.AddDays(1));
            var masterKeyCopy = new MasterKey(1, (Byte[]) value.Clone(), notBefore, notBefore.AddDays(1));

            Assert.That(masterKeyCopy,                                             Is.EqualTo(masterKey));
            Assert.That(masterKeyCopy.GetHashCode(),                               Is.EqualTo(masterKey.GetHashCode()));

            Assert.That(new HashSet<MasterKey> { masterKey, masterKeyCopy },       Has.Count.EqualTo(1));

        }

        #endregion

        #region AMasterKeyDoesNotPrintItself()

        /// <summary>
        /// ToString() is what a log line, an exception message or a debugger shows.
        /// </summary>
        [Test]
        public void AMasterKeyDoesNotPrintItself()
        {

            var value     = RandomNumberGenerator.GetBytes(32);
            var masterKey = new MasterKey(42, value, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

            Assert.That(masterKey.ToString(),                                      Does.StartWith("42,"));
            Assert.That(masterKey.ToString(),                                      Does.Not.Contain(Convert.ToBase64String(value)));
            Assert.That($"{masterKey}",                                            Does.Not.Contain(Convert.ToBase64String(value)));

        }

        #endregion


        #region (private) Start(KeyPair)

        private static async Task<(NTSServer, NTSClient)> Start(KeyPair? KeyPair)
        {

            var ntsKEPort = FindFreePort(SocketType.Stream, ProtocolType.Tcp);
            var ntpPort   = FindFreePort(SocketType.Dgram,  ProtocolType.Udp);

            var ntsServer = new NTSServer(
                                NTSKEPort:           IPPort.Parse(ntsKEPort),
                                NTSPort:             IPPort.Parse(ntpPort),
                                KeyPair:             KeyPair,
                                MasterKeysFilePath:  null
                            );

            await ntsServer.Start();

            var ntsClient = new NTSClient(
                                Hermod.DNS.DomainName.Localhost,
                                NTSKE_Port:                  IPPort.Parse(ntsKEPort),
                                NTP_Port:                    IPPort.Parse(ntpPort),
                                IPVersionPreference:         IPVersionPreference.IPv4Only,
                                RemoteCertificateValidator:  (sender, serverCertificate, certificateChain, ntsKETLSClient, sslPolicyErrors)
                                                                 => TLSValidationResult.Success()
                            );

            return (ntsServer, ntsClient);

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
