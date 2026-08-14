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

using NUnit.Framework;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// The key serialization of the NTS server key pairs.
    ///
    /// A private key is a FIXED-WIDTH unsigned magnitude whose leading zero
    /// octets are part of the encoding. A signed two's complement encoding is
    /// neither: it strips those zeroes on the way out, and on the way in it
    /// reads every key whose leading bit is set - roughly one in two - as a
    /// negative number, and thus as a different key.
    ///
    /// Key pairs written before this was corrected must keep working, since
    /// they are persisted as base64 within the key pair JSON.
    /// </summary>
    [TestFixture]
    public class KeyPair_Tests
    {

        #region (private static) DomainParameters(Name = "secp256r1")

        /// <summary>
        /// The elliptic curve domain parameters of the given named curve.
        /// </summary>
        private static ECDomainParameters DomainParameters(String Name = "secp256r1")
        {

            var ellipticCurve = SecNamedCurves.GetByName(Name);

            return new ECDomainParameters(
                       ellipticCurve.Curve,
                       ellipticCurve.G,
                       ellipticCurve.N,
                       ellipticCurve.H
                   );

        }

        #endregion


        #region Private_keys_keep_their_leading_zeroes()

        [Test]
        public void Private_keys_keep_their_leading_zeroes()
        {

            var domainParameters  = DomainParameters();

            // The private key 1 is the sharpest case of the padding rule:
            // 31 zero bytes followed by a single 1.
            var serialized        = KeyPair.SerializePrivateKey(
                                        new ECPrivateKeyParameters("ECDSA", BigInteger.One, domainParameters)
                                    );

            Assert.That(serialized.Length,  Is.EqualTo(32));
            Assert.That(serialized[..31],   Is.EqualTo(new Byte[31]));
            Assert.That(serialized[31],     Is.EqualTo(1));

            Assert.That(KeyPair.ParsePrivateKey(domainParameters, serialized).D,  Is.EqualTo(BigInteger.One));

            // What the previous serialization would have produced, so that
            // this test can not quietly start passing for the wrong reason.
            Assert.That(BigInteger.One.ToByteArray().Length,  Is.EqualTo(1));

        }

        #endregion

        #region Private_keys_with_a_leading_bit_set_are_not_read_as_negative()

        [Test]
        public void Private_keys_with_a_leading_bit_set_are_not_read_as_negative()
        {

            var domainParameters  = DomainParameters();

            // The group order of secp256r1 begins with 0xFF, so n-1 is the
            // largest valid private key AND has its leading bit set.
            var d                 = domainParameters.N.Subtract(BigInteger.One);

            var serialized        = KeyPair.SerializePrivateKey(
                                        new ECPrivateKeyParameters("ECDSA", d, domainParameters)
                                    );

            Assert.That(serialized.Length,  Is.EqualTo(32));
            Assert.That(serialized[0],      Is.GreaterThanOrEqualTo(0x80),  "The test vector must have its leading bit set!");

            var parsed            = KeyPair.ParsePrivateKey(domainParameters, serialized);

            Assert.That(parsed.D.SignValue,  Is.EqualTo(1));
            Assert.That(parsed.D,            Is.EqualTo(d));
            Assert.That(parsed.D,            Is.LessThan(domainParameters.N));

            // The very same bytes read as signed two's complement really are
            // a negative number - the unsigned reading is doing actual work.
            Assert.That(new BigInteger(serialized).SignValue,  Is.EqualTo(-1));

        }

        #endregion

        #region Key_pairs_written_by_earlier_versions_still_parse()

        [Test]
        public void Key_pairs_written_by_earlier_versions_still_parse()
        {

            var domainParameters = DomainParameters();

            // Earlier versions wrote the two's complement of a positive
            // number: leading zeroes stripped, and a 0x00 prepended whenever
            // the leading bit was set. Every one of those encodings must
            // still yield the very same key, otherwise every key pair ever
            // stored would be lost.
            foreach (var d in new[] {
                                  BigInteger.One,
                                  BigInteger.ValueOf(255),
                                  BigInteger.ValueOf(256),
                                  domainParameters.N.Subtract(BigInteger.One),
                                  new BigInteger("57C92077664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3", 16),
                                  new BigInteger("00000000664146E876760C9520D054AA93C3AFB04E306705DB6090308507B4D3", 16)
                              })
            {

                var legacyBytes = d.ToByteArray();

                Assert.That(KeyPair.ParsePrivateKey(domainParameters, legacyBytes).D,
                            Is.EqualTo(d),
                            d.ToString(16));

                // ...and the new encoding of the same key is the fixed-width
                // one, which parses to the same value as well.
                var currentBytes = KeyPair.SerializePrivateKey(
                                       new ECPrivateKeyParameters("ECDSA", d, domainParameters)
                                   );

                Assert.That(currentBytes.Length,  Is.EqualTo(32),  d.ToString(16));

                Assert.That(KeyPair.ParsePrivateKey(domainParameters, currentBytes).D,
                            Is.EqualTo(d),
                            d.ToString(16));

            }

        }

        #endregion

        #region A_generated_key_pair_signs_and_verifies()

        [Test]
        public void A_generated_key_pair_signs_and_verifies()
        {

            var domainParameters  = DomainParameters();
            var data              = "NTS signed response".ToUTF8Bytes();

            // Generating, storing and reloading a key pair must yield the very
            // same keys - for every key, not merely for those whose leading
            // bit happens to be clear.
            for (var i = 0; i < 16; i++)
            {

                var keyPair     = KeyPair.GenerateECKeys((UInt16) i);

                Assert.That(keyPair.PrivateKey.Length,  Is.EqualTo(32),  $"key {i}");
                Assert.That(keyPair.PublicKey. Length,  Is.EqualTo(65),  $"key {i}");
                Assert.That(keyPair.PublicKey[0],       Is.EqualTo(0x04), $"key {i}");

                var privateKey  = KeyPair.ParsePrivateKey(domainParameters, keyPair.PrivateKey);
                var publicKey   = KeyPair.ParsePublicKey (domainParameters, keyPair.PublicKey);

                // The public key that was stored must be the one belonging to
                // the private key that was stored.
                Assert.That(domainParameters.G.Multiply(privateKey.D).Normalize(),
                            Is.EqualTo(publicKey.Q.Normalize()),
                            $"key {i}");

                var signer      = SignerUtilities.GetSigner(keyPair.SignatureAlgorithm);
                signer.Init(true, privateKey);
                signer.BlockUpdate(data, 0, data.Length);
                var signature   = signer.GenerateSignature();

                var verifier    = SignerUtilities.GetSigner(keyPair.SignatureAlgorithm);
                verifier.Init(false, publicKey);
                verifier.BlockUpdate(data, 0, data.Length);

                Assert.That(verifier.VerifySignature(signature),  Is.True,  $"key {i}");

            }

        }

        #endregion

        #region A_key_pair_survives_its_JSON_representation()

        [Test]
        public void A_key_pair_survives_its_JSON_representation()
        {

            var domainParameters  = DomainParameters();
            var data              = "NTS signed response".ToUTF8Bytes();

            for (var i = 0; i < 8; i++)
            {

                var keyPair   = KeyPair.GenerateECKeys((UInt16) i);
                var reloaded  = KeyPair.Parse(keyPair.ToJSON());

                Assert.That(reloaded.Id,          Is.EqualTo(keyPair.Id));
                Assert.That(reloaded.PrivateKey,  Is.EqualTo(keyPair.PrivateKey),  $"key {i}");
                Assert.That(reloaded.PublicKey,   Is.EqualTo(keyPair.PublicKey),   $"key {i}");

                // ...and the reloaded private key still signs what the
                // reloaded public key verifies.
                var signer    = SignerUtilities.GetSigner(reloaded.SignatureAlgorithm);
                signer.Init(true, KeyPair.ParsePrivateKey(domainParameters, reloaded.PrivateKey));
                signer.BlockUpdate(data, 0, data.Length);

                var verifier  = SignerUtilities.GetSigner(reloaded.SignatureAlgorithm);
                verifier.Init(false, KeyPair.ParsePublicKey(domainParameters, reloaded.PublicKey));
                verifier.BlockUpdate(data, 0, data.Length);

                Assert.That(verifier.VerifySignature(signer.GenerateSignature()),  Is.True,  $"key {i}");

            }

        }

        #endregion

    }

}
