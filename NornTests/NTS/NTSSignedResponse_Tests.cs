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

                // Asked for no key in particular: the time stands, and the query says
                // that nothing is known about the signature.
                var queryResult  = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(queryResult.Success,                                   Is.True, queryResult.ErrorMessage);
                Assert.That(queryResult.Response!.NTSSignedResponse(),             Is.Not.Null);
                Assert.That(queryResult.SignatureVerification,                     Is.EqualTo(NTSSignatureVerification.UnknownKey));
                Assert.That(queryResult.SignatureKeyId,                            Is.EqualTo(7));

                // Asked for key 7 by its id: its word was wanted, and there is nothing
                // to check it against.
                ntsKEResult      = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: false);

                var askedFor7    = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             SignedResponseKeyId: 7,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(askedFor7.Success,                                     Is.False);
                Assert.That(askedFor7.ErrorCategory,                               Is.EqualTo(NTSQueryErrorCategory.NTSAuthentication));
                Assert.That(askedFor7.ErrorMessage,                                Does.Contain("named no such key"));
                Assert.That(askedFor7.SignatureVerification,                       Is.EqualTo(NTSSignatureVerification.UnknownKey));
                Assert.That(askedFor7.SignatureKeyId,                              Is.EqualTo(7));

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

        #region APublicKeySaysWhatItIs()

        /// <summary>
        /// The record a key exchange hands out carries the curve, the algorithm and the
        /// validity of the key. It used to carry the id and the octets, and whoever
        /// received it assumed the rest.
        /// </summary>
        [Test]
        public void APublicKeySaysWhatItIs()
        {

            var notBefore  = new DateTimeOffset(2026,  1,  1, 0, 0, 0, TimeSpan.Zero);
            var notAfter   = new DateTimeOffset(2027,  1,  1, 0, 0, 0, TimeSpan.Zero);
            var generated  = KeyPair.GenerateECKeys(7);

            var publicKey  = new PublicKey(7, generated.PublicKey, null, "secp384r1", "SHA-384withECDSA", notBefore, notAfter);
            var parsed     = PublicKey.Parse(publicKey.ToByteArray());

            Assert.That(parsed.Id,                                                 Is.EqualTo(7));
            Assert.That(parsed.Value,                                              Is.EqualTo(generated.PublicKey));
            Assert.That(parsed.EllipticCurve,                                      Is.EqualTo("secp384r1"));
            Assert.That(parsed.SignatureAlgorithm,                                 Is.EqualTo("SHA-384withECDSA"));
            Assert.That(parsed.NotBefore,                                          Is.EqualTo(notBefore));
            Assert.That(parsed.NotAfter,                                           Is.EqualTo(notAfter));
            Assert.That(parsed,                                                    Is.EqualTo(publicKey));

            // No limits, and none invented.
            var unlimited  = PublicKey.Parse(generated.ToPublicKey().ToByteArray());

            Assert.That(unlimited.NotBefore,                                       Is.Null);
            Assert.That(unlimited.NotAfter,                                        Is.Null);
            Assert.That(unlimited.EllipticCurve,                                   Is.EqualTo("secp256r1"));

            Assert.That(parsed.IsValidAt(notBefore),                               Is.True);
            Assert.That(parsed.IsValidAt(notAfter),                                Is.True);
            Assert.That(parsed.IsValidAt(notBefore.AddSeconds(-1)),                Is.False);
            Assert.That(parsed.IsValidAt(notAfter. AddSeconds( 1)),                Is.False);
            Assert.That(unlimited.IsValidAt(DateTimeOffset.MinValue),              Is.True);
            Assert.That(unlimited.IsValidAt(DateTimeOffset.MaxValue),              Is.True);

            // The key alone, as it was sent before, is not a key record any more:
            // a key that does not say what it is is not taken for what it might be.
            var bare       = new Byte[4 + generated.PublicKey.Length];
            bare[1]        = 7;
            bare[3]        = (Byte) generated.PublicKey.Length;
            generated.PublicKey.CopyTo(bare, 4);

            Assert.That(PublicKey.TryParse(bare, out _, out _),                    Is.False);

            // What is not a key record is refused, and not thrown about.
            var whole      = publicKey.ToByteArray();

            Assert.That(PublicKey.TryParse(Array.Empty<Byte>(),                  out _, out _),   Is.False);
            Assert.That(PublicKey.TryParse(new Byte[] { 0, 7, 0xff, 0xff }, out _, out _),   Is.False);
            Assert.That(PublicKey.TryParse(whole[..^1],           out _, out _),   Is.False);
            Assert.That(PublicKey.TryParse(whole.Append((Byte) 0).ToArray(), out _, out _),   Is.False);

            // An escape sequence where the name of the curve should be.
            var hostile    = (Byte[]) whole.Clone();
            hostile[4 + generated.PublicKey.Length + 1] = 0x1b;

            Assert.That(PublicKey.TryParse(hostile,               out _, out _),   Is.False);

            // A validity that ends before it begins.
            var backwards  = new PublicKey(7, generated.PublicKey, NotBefore: notAfter, NotAfter: notBefore);

            Assert.That(PublicKey.TryParse(backwards.ToByteArray(), out _, out _), Is.False);

        }

        #endregion

        #region APublicKeyReadsTheJSONItWrote()

        /// <summary>
        /// ToJSON() wrote the key as "publicKey", and Parse() looked for it as "value".
        /// </summary>
        [Test]
        public void APublicKeyReadsTheJSONItWrote()
        {

            var publicKey  = new PublicKey(
                                 7,
                                 KeyPair.GenerateECKeys(7).PublicKey,
                                 NotBefore:  new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
                                 NotAfter:   new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero)
                             );

            Assert.That(PublicKey.TryParse(publicKey.ToJSON(), out var parsed, out var errorResponse),
                                                                                   Is.True, errorResponse);

            Assert.That(parsed,                                                    Is.EqualTo(publicKey));

        }

        #endregion

        #region AServerSignsWithTheKeyThatWasAskedFor()

        /// <summary>
        /// Asked for a key it does not have, the server does not sign with the one it
        /// has: the client would hold a signature it did not ask for. Asked for no
        /// key in particular, it signs with its own, and the query says which.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task AServerSignsWithTheKeyThatWasAskedFor()
        {

            var (ntsServer, ntsClient) = await Start(KeyPair.GenerateECKeys(7));

            try
            {

                var ntsKEResult  = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);

                Assert.That(ntsKEResult.Success,                                   Is.True, ntsKEResult.ErrorMessage);

                var started      = System.Diagnostics.Stopwatch.GetTimestamp();

                var otherKey     = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             SignedResponseKeyId: 8,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(otherKey.Success,                                      Is.True, otherKey.ErrorMessage);
                Assert.That(otherKey.SignatureVerification,                        Is.EqualTo(NTSSignatureVerification.NotSigned));
                Assert.That(otherKey.Response!.NTSSignedResponseAnnouncement(),    Is.Null);
                Assert.That(System.Diagnostics.Stopwatch.GetElapsedTime(started),  Is.LessThan(TimeSpan.FromSeconds(2)));

                var anyKey       = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(anyKey.Success,                                        Is.True, anyKey.ErrorMessage);
                Assert.That(anyKey.SignatureVerification,                          Is.EqualTo(NTSSignatureVerification.Verified));
                Assert.That(anyKey.SignatureKeyId,                                 Is.EqualTo(7));

            }
            finally
            {
                await ntsServer.ShutdownAsync();
            }

        }

        #endregion

        #region AServerDoesNotSignWithAKeyThatIsNotValid(DaysFromNow)

        /// <summary>
        /// A key past its last day, and one before its first: neither signs. The one
        /// that is past is not handed out by the key exchange either; the one to come
        /// is, so that it is known by the time it is used.
        /// </summary>
        [TestCase(-30, -1, false, TestName = "AServerDoesNotSignWithAKeyThatHasExpired")]
        [TestCase(  1, 30, true,  TestName = "AServerDoesNotSignWithAKeyThatIsNotValidYet")]
        [Category("LocalIntegration")]
        public async Task AServerDoesNotSignWithAKeyThatIsNotValid(Int32 FromDays, Int32 ToDays, Boolean HandedOut)
        {

            var generated              = KeyPair.GenerateECKeys(7);
            var now                    = DateTimeOffset.UtcNow;

            var (ntsServer, ntsClient) = await Start(
                                                   new KeyPair(
                                                       7,
                                                       generated.PrivateKey,
                                                       generated.PublicKey,
                                                       NotBefore:  now.AddDays(FromDays),
                                                       NotAfter:   now.AddDays(ToDays)
                                                   )
                                               );

            try
            {

                var ntsKEResult  = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);

                Assert.That(ntsKEResult.Success,                                   Is.True, ntsKEResult.ErrorMessage);
                Assert.That(ntsKEResult.Response!.PublicKeys.Any(),                Is.EqualTo(HandedOut));

                var queryResult  = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             SignedResponseKeyId: 7,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(queryResult.Success,                                   Is.True, queryResult.ErrorMessage);
                Assert.That(queryResult.SignatureVerification,                     Is.EqualTo(NTSSignatureVerification.NotSigned));
                Assert.That(queryResult.Response!.NTSSignedResponse(),             Is.Null);

            }
            finally
            {
                await ntsServer.ShutdownAsync();
            }

        }

        #endregion

        #region ASignatureOfAKeyThatWasNotValidFailsTheQuery()

        /// <summary>
        /// The signature is the key's, and the key exchange said that key ended last
        /// year. A server that signs with a key it has retired, or somebody who got
        /// hold of one: either way not a proof of anything.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task ASignatureOfAKeyThatWasNotValidFailsTheQuery()
        {

            var (ntsServer, ntsClient) = await Start(KeyPair.GenerateECKeys(7));

            try
            {

                var ntsKEResult  = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);

                Assert.That(ntsKEResult.Success,                                   Is.True, ntsKEResult.ErrorMessage);

                // The same key exchange and the same key, with a validity that is over.
                var keyExchange  = ntsKEResult.Response!;
                var serverKey    = keyExchange.PublicKeys.Single();

                var retired      = new PublicKey(
                                       serverKey.Id,
                                       serverKey.Value,
                                       NotBefore:  DateTimeOffset.UtcNow.AddDays(-400),
                                       NotAfter:   DateTimeOffset.UtcNow.AddDays(-35)
                                   );

                var outdated     = new NTSKE_Response(
                                       keyExchange.NTSKERecords.
                                           Select(record => record.Type == NTSKE_RecordTypes.NTSPublicKey
                                                                ? NTSKE_Record.NTSPublicKey(retired)
                                                                : record).
                                           ToArray(),
                                       keyExchange.C2SKey,
                                       keyExchange.S2CKey
                                   );

                var queryResult  = await ntsClient.QueryTime(
                                             NTSKEResponse:       outdated,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             SignedResponseKeyId: 7,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(queryResult.Success,                                   Is.False);
                Assert.That(queryResult.SignatureVerification,                     Is.EqualTo(NTSSignatureVerification.KeyNotValid));
                Assert.That(queryResult.SignatureKeyId,                            Is.EqualTo(7));
                Assert.That(queryResult.ErrorCategory,                             Is.EqualTo(NTSQueryErrorCategory.NTSAuthentication));
                Assert.That(queryResult.ErrorMessage,                              Does.Contain("not valid"));

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


        #region ASuccessorTakesOverOnItsFirstDay()

        /// <summary>
        /// A server with several keys signs with the valid one that began last, and
        /// nobody has to switch it. The key exchange tells of every key a response may
        /// be signed with before the client asks again: the valid ones, and the one
        /// whose first day is near - not yet the one that is ten days off.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task ASuccessorTakesOverOnItsFirstDay()
        {

            var now                    = DateTimeOffset.UtcNow;

            static KeyPair Dated(UInt16 Id, DateTimeOffset? NotBefore)
            {
                var generated = KeyPair.GenerateECKeys(Id);
                return new KeyPair(Id, generated.PrivateKey, generated.PublicKey, NotBefore: NotBefore);
            }

            var (ntsServer, ntsClient) = await Start(
                                                   Dated( 7, null),
                                                   Dated(10, now.AddDays (10)),
                                                   Dated( 9, now.AddHours(12)),
                                                   Dated( 8, now.AddHours(-1))
                                               );

            try
            {

                Assert.That(ntsServer.CurrentKeyId,                                Is.EqualTo(8));
                Assert.That(ntsServer.PublicKeys.Select(key => key.Id),            Is.EqualTo(new UInt16[] { 7, 8, 9, 10 }));

                var ntsKEResult  = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);

                Assert.That(ntsKEResult.Success,                                   Is.True, ntsKEResult.ErrorMessage);

                // The one in use first, then as they began.
                Assert.That(ntsKEResult.Response!.PublicKeys.Select(key => key.Id), Is.EqualTo(new UInt16[] { 8, 7, 9 }));

                // Asked for no key in particular: the one in use.
                var anyKey       = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(anyKey.Success,                                        Is.True, anyKey.ErrorMessage);
                Assert.That(anyKey.SignatureVerification,                          Is.EqualTo(NTSSignatureVerification.Verified));
                Assert.That(anyKey.SignatureKeyId,                                 Is.EqualTo(8));

                // Asked for its predecessor, which is still valid: that one.
                ntsKEResult      = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);

                var predecessor  = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             SignedResponseKeyId: 7,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(predecessor.Success,                                   Is.True, predecessor.ErrorMessage);
                Assert.That(predecessor.SignatureVerification,                     Is.EqualTo(NTSSignatureVerification.Verified));
                Assert.That(predecessor.SignatureKeyId,                            Is.EqualTo(7));

                // Asked for its successor, whose day has not come: not signed.
                ntsKEResult      = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);

                var successor    = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             SignedResponseKeyId: 9,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(successor.Success,                                     Is.True, successor.ErrorMessage);
                Assert.That(successor.SignatureVerification,                       Is.EqualTo(NTSSignatureVerification.NotSigned));

            }
            finally
            {
                await ntsServer.ShutdownAsync();
            }

        }

        #endregion

        #region AKeyIsAddedAndRemovedWhileTheServerRuns()

        /// <summary>
        /// A running server is given its next key and has a key taken from it, and
        /// signs accordingly at once - with no restart, and with nothing to switch.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task AKeyIsAddedAndRemovedWhileTheServerRuns()
        {

            var now                    = DateTimeOffset.UtcNow;
            var first                  = KeyPair.GenerateECKeys(7);
            var generated              = KeyPair.GenerateECKeys(8);
            var second                 = new KeyPair(8, generated.PrivateKey, generated.PublicKey, NotBefore: now.AddMinutes(-1));

            var (ntsServer, ntsClient) = await Start(first);

            try
            {

                Assert.That(ntsServer.CurrentKeyId,                                Is.EqualTo(7));

                Assert.That(ntsServer.AddKeyPair(second),                          Is.True);
                Assert.That(ntsServer.AddKeyPair(KeyPair.GenerateECKeys(8)),       Is.False, "a second key of the same id was taken");
                Assert.That(() => ntsServer.AddKeyPair(KeyPair.GenerateECKeys(0)), Throws.ArgumentException, "0 asks for no key in particular");
                Assert.That(ntsServer.CurrentKeyId,                                Is.EqualTo(8));

                var ntsKEResult  = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);

                Assert.That(ntsKEResult.Success,                                   Is.True, ntsKEResult.ErrorMessage);
                Assert.That(ntsKEResult.Response!.PublicKeys.Select(key => key.Id), Is.EqualTo(new UInt16[] { 8, 7 }));

                var added        = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(added.Success,                                         Is.True, added.ErrorMessage);
                Assert.That(added.SignatureVerification,                           Is.EqualTo(NTSSignatureVerification.Verified));
                Assert.That(added.SignatureKeyId,                                  Is.EqualTo(8));

                Assert.That(ntsServer.RemoveKeyPair(8),                            Is.True);
                Assert.That(ntsServer.RemoveKeyPair(8),                            Is.False);
                Assert.That(ntsServer.CurrentKeyId,                                Is.EqualTo(7));

                ntsKEResult      = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);

                Assert.That(ntsKEResult.Success,                                   Is.True, ntsKEResult.ErrorMessage);
                Assert.That(ntsKEResult.Response!.PublicKeys.Select(key => key.Id), Is.EqualTo(new UInt16[] { 7 }));

                var removed      = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(removed.Success,                                       Is.True, removed.ErrorMessage);
                Assert.That(removed.SignatureVerification,                         Is.EqualTo(NTSSignatureVerification.Verified));
                Assert.That(removed.SignatureKeyId,                                Is.EqualTo(7));

            }
            finally
            {
                await ntsServer.ShutdownAsync();
            }

        }

        #endregion

        #region AServerRefusesTwoKeysOfOneId()

        /// <summary>
        /// Two keys of one id cannot be told apart by a request or by a signature, and
        /// a key of the id 0 cannot be asked for at all.
        /// </summary>
        [Test]
        public void AServerRefusesTwoKeysOfOneId()
        {

            Assert.That(() => new NTSServer(
                                  KeyPair:             KeyPair.GenerateECKeys(7),
                                  KeyPairs:            [ KeyPair.GenerateECKeys(7) ],
                                  MasterKeysFilePath:  null
                              ),
                        Throws.ArgumentException);

            Assert.That(() => new NTSServer(
                                  KeyPair:             KeyPair.GenerateECKeys(0),
                                  MasterKeysFilePath:  null
                              ),
                        Throws.ArgumentException);

        }

        #endregion


        #region AResponseSignedWithAnotherKeyThanAskedForIsNotTheProof()

        /// <summary>
        /// A server that signs with another key than the one the query asked for.
        /// </summary>
        private sealed class SignsWithItsFirstKey(IPPort NTSKEPort, IPPort NTSPort, params KeyPair[] KeyPairs)

            : NTSServer(NTSKEPort:           NTSKEPort,
                        NTSPort:             NTSPort,
                        KeyPairs:            KeyPairs,
                        MasterKeysFilePath:  null)

        {

            private readonly KeyPair first = KeyPairs[0];

            protected override KeyPair? SigningKeyFor(UInt16 KeyId)
                => first;

        }

        /// <summary>
        /// The query asked for key 8 and the response is signed with key 7 - a key the
        /// key exchange named, and a signature that is good. It is still not what was
        /// asked for: whoever names a key wants that key's word, and the query fails
        /// and says that it is another's, and whose, without looking at the signature
        /// further.
        ///
        /// Asked for no key in particular, the same response is verified.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task AResponseSignedWithAnotherKeyThanAskedForIsNotTheProof()
        {

            var (ntsServer, ntsClient) = await Start(
                                                   (ntsKEPort, ntpPort) => new SignsWithItsFirstKey(
                                                                               ntsKEPort,
                                                                               ntpPort,
                                                                               KeyPair.GenerateECKeys(7),
                                                                               KeyPair.GenerateECKeys(8)
                                                                           )
                                               );

            try
            {

                var ntsKEResult  = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);

                Assert.That(ntsKEResult.Success,                                   Is.True, ntsKEResult.ErrorMessage);
                Assert.That(ntsKEResult.Response!.PublicKeys.Select(key => key.Id), Is.EquivalentTo(new UInt16[] { 7, 8 }));

                var askedFor8    = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             SignedResponseKeyId: 8,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                // Key 8's word was asked for, and this is not it: the query has failed,
                // and says whose word it got.
                Assert.That(askedFor8.Success,                                     Is.False);
                Assert.That(askedFor8.ErrorCategory,                               Is.EqualTo(NTSQueryErrorCategory.NTSAuthentication));
                Assert.That(askedFor8.ErrorMessage,                                Does.Contain("not with the public key 8"));
                Assert.That(askedFor8.SignatureVerification,                       Is.EqualTo(NTSSignatureVerification.WrongKey));
                Assert.That(askedFor8.SignatureKeyId,                              Is.EqualTo(7));

                ntsKEResult      = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);

                var askedForAny  = await ntsClient.QueryTime(
                                             NTSKEResponse:       ntsKEResult.Response,
                                             SignedResponseMode:  SignedResponseMode.Scheduled,
                                             Timeout:             TimeSpan.FromSeconds(5)
                                         );

                Assert.That(askedForAny.Success,                                   Is.True, askedForAny.ErrorMessage);
                Assert.That(askedForAny.SignatureVerification,                     Is.EqualTo(NTSSignatureVerification.Verified));
                Assert.That(askedForAny.SignatureKeyId,                            Is.EqualTo(7));

            }
            finally
            {
                await ntsServer.ShutdownAsync();
            }

        }

        #endregion


        #region (private) Start(KeyPair, params KeyPairs)

        private static Task<(NTSServer, NTSClient)> Start(KeyPair? KeyPair, params KeyPair[] KeyPairs)

            => Start((ntsKEPort, ntpPort) => new NTSServer(
                                                 NTSKEPort:           ntsKEPort,
                                                 NTSPort:             ntpPort,
                                                 KeyPair:             KeyPair,
                                                 KeyPairs:            KeyPairs,
                                                 MasterKeysFilePath:  null
                                             ));

        private static async Task<(NTSServer, NTSClient)> Start(Func<IPPort, IPPort, NTSServer> Create)
        {

            var ntsKEPort = FindFreePort(SocketType.Stream, ProtocolType.Tcp);
            var ntpPort   = FindFreePort(SocketType.Dgram,  ProtocolType.Udp);

            var ntsServer = Create(IPPort.Parse(ntsKEPort), IPPort.Parse(ntpPort));

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
