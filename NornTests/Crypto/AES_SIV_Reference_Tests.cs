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

using System.Security.Cryptography;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.Crypto
{

    /// <summary>
    /// AES-SIV does its own CMAC and its own counter mode, over one block cipher and on
    /// the stack. These tests hold it to another implementation of the same RFC 5297:
    /// the one it replaced, written with the CMAC and the counter mode of BouncyCastle
    /// and with the AES of its tables, array by array as the RFC reads.
    /// </summary>
    public class AES_SIV_Reference_Tests
    {

        #region Reference: RFC 5297 with the CMAC and the counter mode of BouncyCastle

        private static Byte[] ReferenceCMAC(Byte[] Key, Byte[] Message)
        {

            var cmac = new CMac(new AesEngine());
            cmac.Init(new KeyParameter(Key));
            cmac.BlockUpdate(Message, 0, Message.Length);

            var output = new Byte[cmac.GetMacSize()];
            cmac.DoFinal(output, 0);

            return output;

        }

        private static Byte[] ReferenceDouble(Byte[] Block)
        {

            var output = new Byte[16];
            var carry  = 0;

            for (var i = 15; i >= 0; i--)
            {
                output[i]  = (Byte) ((Block[i] << 1) | carry);
                carry      = (Block[i] & 0x80) != 0 ? 1 : 0;
            }

            if (carry != 0)
                output[15] ^= 0x87;

            return output;

        }

        private static Byte[] ReferenceXOR(Byte[] A, Byte[] B)
            => [.. A.Zip(B, (a, b) => (Byte) (a ^ b))];

        private static Byte[] ReferenceS2V(Byte[] Key, IEnumerable<Byte[]> AssociatedData, Byte[] Nonce, Byte[] Plaintext)
        {

            var D       = ReferenceCMAC(Key, new Byte[16]);
            var vector  = AssociatedData.ToList();

            if (Nonce.Length > 0)
                vector.Add(Nonce);

            foreach (var element in vector)
                D = ReferenceXOR(ReferenceDouble(D), ReferenceCMAC(Key, element));

            Byte[] T;

            if (Plaintext.Length >= 16)
            {
                T = (Byte[]) Plaintext.Clone();
                for (var i = 0; i < 16; i++)
                    T[Plaintext.Length - 16 + i] ^= D[i];
            }
            else
            {
                var padded = new Byte[16];
                Plaintext.CopyTo(padded, 0);
                padded[Plaintext.Length] = 0x80;
                T = ReferenceXOR(ReferenceDouble(D), padded);
            }

            return ReferenceCMAC(Key, T);

        }

        private static Byte[] ReferenceCTR(Byte[] Key, Byte[] SyntheticIV, Byte[] Input)
        {

            var counter = (Byte[]) SyntheticIV.Clone();
            counter[ 8] &= 0x7F;
            counter[12] &= 0x7F;

            var cipher = new SicBlockCipher(new AesEngine());
            cipher.Init(true, new ParametersWithIV(new KeyParameter(Key), counter));

            var padded     = new Byte[(Input.Length + 15) / 16 * 16];
            var encrypted  = new Byte[padded.Length];
            Input.CopyTo(padded, 0);

            for (var i = 0; i < padded.Length; i += 16)
                cipher.ProcessBlock(padded, i, encrypted, i);

            return encrypted[..Input.Length];

        }

        private static Byte[] ReferenceEncrypt(Byte[] Key, IEnumerable<Byte[]> AssociatedData, Byte[] Nonce, Byte[] Plaintext)
        {

            var half  = Key.Length / 2;
            var siv   = ReferenceS2V(Key[..half], AssociatedData, Nonce, Plaintext);

            return [.. siv, .. ReferenceCTR(Key[half..], siv, Plaintext)];

        }

        #endregion


        #region EveryLengthEncryptsAsTheReferenceDoes()

        /// <summary>
        /// Every length of plaintext from nothing to five blocks, with every length of
        /// the one associated data from nothing to three: all the places where a block
        /// ends, where the last one is whole or is not, and where the plaintext is too
        /// short to have the D XORed onto its end.
        /// </summary>
        [TestCase(32)]
        [TestCase(64)]
        public void EveryLengthEncryptsAsTheReferenceDoes(Int32 KeyLength)
        {

            var key    = RandomNumberGenerator.GetBytes(KeyLength);
            var siv    = new AES_SIV(key);
            var nonce  = RandomNumberGenerator.GetBytes(16);

            for (var plaintextLength = 0; plaintextLength <= 80; plaintextLength++)
            for (var associatedLength = 0; associatedLength <= 48; associatedLength++)
            {

                var plaintext   = RandomNumberGenerator.GetBytes(plaintextLength);
                var associated  = RandomNumberGenerator.GetBytes(associatedLength);

                var expected    = ReferenceEncrypt(key, [ associated ], nonce, plaintext);
                var encrypted   = siv.Encrypt([ associated ], nonce, plaintext);

                Assert.That(encrypted,                                      Is.EqualTo(expected),  $"plaintext of {plaintextLength}, associated data of {associatedLength}");
                Assert.That(siv.Decrypt([ associated ], nonce, encrypted),  Is.EqualTo(plaintext), $"plaintext of {plaintextLength}, associated data of {associatedLength}");

            }

        }

        #endregion

        #region AnyVectorEncryptsAsTheReferenceDoes()

        /// <summary>
        /// Whatever the vector of S2V is made of: no associated data, one or several,
        /// with a nonce and without, short and long.
        /// </summary>
        [Test]
        public void AnyVectorEncryptsAsTheReferenceDoes()
        {

            var random = new Random(8915);

            for (var round = 0; round < 3000; round++)
            {

                var key         = RandomNumberGenerator.GetBytes(random.Next(2) == 0 ? 32 : 64);
                var associated  = Enumerable.Range(0, random.Next(4)).
                                             Select(_ => RandomNumberGenerator.GetBytes(random.Next(300))).
                                             ToArray();
                var nonce       = RandomNumberGenerator.GetBytes(random.Next(3) == 0 ? 0 : random.Next(1, 40));
                var plaintext   = RandomNumberGenerator.GetBytes(random.Next(1200));

                var siv         = new AES_SIV(key);
                var expected    = ReferenceEncrypt(key, associated, nonce, plaintext);
                var encrypted   = siv.Encrypt(associated, nonce, plaintext);

                Assert.That(encrypted,                                  Is.EqualTo(expected),  $"round {round}");
                Assert.That(siv.Decrypt(associated, nonce, encrypted),  Is.EqualTo(plaintext), $"round {round}");

            }

        }

        #endregion

        #region TheCounterCarriesAcrossAllItsBytes()

        /// <summary>
        /// The counter is one number of 128 bits. A synthetic IV that ends in 0xff bytes
        /// makes it carry, further than a counter of 32 or 64 bits would.
        /// </summary>
        [Test]
        public void TheCounterCarriesAcrossAllItsBytes()
        {

            var key     = RandomNumberGenerator.GetBytes(32);
            var input   = RandomNumberGenerator.GetBytes(16 * 5 + 3);

            foreach (var ffBytes in new[] { 1, 4, 5, 8, 9, 15, 16 })
            {

                var iv = RandomNumberGenerator.GetBytes(16);

                for (var i = 16 - ffBytes; i < 16; i++)
                    iv[i] = 0xff;

                Assert.That(AES_SIV.AES_CTR_Encrypt(input, iv, key),
                            Is.EqualTo(ReferenceCTR(key, iv, input)),
                            $"{ffBytes} byte(s) of 0xff at the end of the counter");

            }

        }

        #endregion

        #region ACMACOfEveryLengthIsTheReferences()

        [Test]
        public void ACMACOfEveryLengthIsTheReferences()
        {

            foreach (var keyLength in new[] { 16, 32 })
            {

                var key = RandomNumberGenerator.GetBytes(keyLength);

                for (var length = 0; length <= 100; length++)
                {

                    var message = RandomNumberGenerator.GetBytes(length);

                    Assert.That(AES_SIV.CMAC(key, message),
                                Is.EqualTo(ReferenceCMAC(key, message)),
                                $"a message of {length} under a key of {keyLength}");

                }

            }

        }

        #endregion

        #region AChangedBitIsRefusedWhereverItIs()

        /// <summary>
        /// One bit changed in the synthetic IV, in the ciphertext, in the associated
        /// data or in the nonce: not this message, and no plaintext comes back.
        /// </summary>
        [Test]
        public void AChangedBitIsRefusedWhereverItIs()
        {

            var siv         = new AES_SIV(RandomNumberGenerator.GetBytes(32));
            var associated  = RandomNumberGenerator.GetBytes(40);
            var nonce       = RandomNumberGenerator.GetBytes(16);
            var plaintext   = RandomNumberGenerator.GetBytes(50);
            var encrypted   = siv.Encrypt([ associated ], nonce, plaintext);

            for (var i = 0; i < encrypted.Length; i++)
            {

                var changed = (Byte[]) encrypted.Clone();
                changed[i] ^= 0x01;

                Assert.That(() => siv.Decrypt([ associated ], nonce, changed),
                            Throws.InstanceOf<CryptographicException>(),
                            $"byte {i} of the message");

            }

            var otherAssociated = (Byte[]) associated.Clone();
            otherAssociated[7] ^= 0x80;

            var otherNonce = (Byte[]) nonce.Clone();
            otherNonce[0] ^= 0x01;

            Assert.That(() => siv.Decrypt([ otherAssociated ], nonce,      encrypted), Throws.InstanceOf<CryptographicException>());
            Assert.That(() => siv.Decrypt([ associated ],      otherNonce, encrypted), Throws.InstanceOf<CryptographicException>());
            Assert.That(siv.Decrypt([ associated ], nonce, encrypted),                 Is.EqualTo(plaintext));

        }

        #endregion

        #region OneInstanceServesManyThreads()

        /// <summary>
        /// An instance keeps bytes and no cipher, so that the one a server holds for a
        /// key may be used by every request at once.
        /// </summary>
        [Test]
        public void OneInstanceServesManyThreads()
        {

            var key   = RandomNumberGenerator.GetBytes(32);
            var siv   = new AES_SIV(key);
            var wrong = 0;

            Parallel.For(0, 64, _ => {

                var random = new Random();

                for (var round = 0; round < 500; round++)
                {

                    var associated  = RandomNumberGenerator.GetBytes(random.Next(200));
                    var nonce       = RandomNumberGenerator.GetBytes(16);
                    var plaintext   = RandomNumberGenerator.GetBytes(random.Next(400));
                    var encrypted   = siv.Encrypt([ associated ], nonce, plaintext);

                    if (!encrypted.AsSpan().SequenceEqual(ReferenceEncrypt(key, [ associated ], nonce, plaintext)) ||
                        !siv.Decrypt([ associated ], nonce, encrypted).AsSpan().SequenceEqual(plaintext))
                    {
                        Interlocked.Increment(ref wrong);
                    }

                }

            });

            Assert.That(wrong, Is.Zero);

        }

        #endregion

    }

}
