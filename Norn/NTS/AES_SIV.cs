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

using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// AES Synthetic Initialization Vector Encryption (AES-SIV-CMAC-256)
    /// </summary>
    /// <remarks>
    /// Four of these run for every NTS request a server answers - the cookie is opened,
    /// the request verified, a new cookie sealed and the response authenticated - so what
    /// one costs is what a request costs. It used to be seven microseconds and eight
    /// kilobytes of garbage: every CMAC of S2V made its own cipher and expanded the key
    /// again, AES was done in tables although the processor has an instruction for it,
    /// and every intermediate value was an array of its own.
    ///
    /// Now the two keys are expanded once per operation, AES is the processor's where it
    /// has it (<see cref="AesUtilities.CreateEngine"/>), and CMAC and the counter mode
    /// are done here, over that one block cipher, on the stack. What depends on the key
    /// alone - the two CMAC subkeys and CMAC(K, 0), which S2V starts from - is computed
    /// when the key is given and kept.
    ///
    /// An instance may be used by several threads at once: it keeps bytes, and no cipher.
    /// </remarks>
    public class AES_SIV
    {

        #region Data

        private const    Int32   BlockSize = 16;

        /// <summary>
        /// The two subkeys of CMAC under Key1, RFC 4493 § 2.3: K1 and K2, 16 bytes each.
        /// </summary>
        private readonly Byte[]  cmacSubkeys;

        /// <summary>
        /// CMAC(Key1, 0^128): what S2V starts from, RFC 5297 § 2.4.
        /// </summary>
        private readonly Byte[]  cmacOfZero;

        #endregion

        #region Properties

        /// <summary>
        /// Key1 for CMAC (S2V).
        /// </summary>
        public Byte[]  Key1_CMAC      { get; }

        /// <summary>
        /// Key2 for AES-Counter Mode.
        /// </summary>
        public Byte[]  Key2_AESCTR    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new AES Synthetic Initialization Vector (AES-SIV) encryption.
        /// </summary>
        public AES_SIV(Byte[] Key)
        {

            if (Key.Length != 32 && Key.Length != 64)
                throw new ArgumentException("Key length must be either 32 or 64 Bytes for AES-SIV", nameof(Key));

            var half = Key.Length / 2;

            Key1_CMAC    = new Byte[half];
            Key2_AESCTR  = new Byte[half];

            Array.Copy(Key,    0, Key1_CMAC,   0, half);
            Array.Copy(Key, half, Key2_AESCTR, 0, half);

            var aes      = Keyed(Key1_CMAC);

            cmacSubkeys  = new Byte[2 * BlockSize];
            cmacOfZero   = new Byte[BlockSize];

            Subkeys(aes, cmacSubkeys);

            Span<Byte> zero = stackalloc Byte[BlockSize];
            zero.Clear();

            CMAC(aes, cmacSubkeys, zero, [], cmacOfZero);

        }

        #endregion


        #region Encrypt (AssociatedData, Nonce, Plaintext)

        /// <summary>
        /// Encrypts the given plaintext message considering the associated data using AES Counter Mode (AES-CTR)
        /// with a synthetic initialization vector based on plaintext and associated data, and the second part of the key.
        ///
        /// It will return the synthetic initialization vector (SIV) concatenated with the ciphertext: SIV|Ciphertext
        /// </summary>
        public Byte[] Encrypt(IEnumerable<Byte[]>  AssociatedData,
                              Byte[]               Nonce,
                              Byte[]               Plaintext)
        {

            // Nothing is logged here on purpose: this runs for every NTS request and every NTS
            // response, and both halves of the split key pass through it. Logging them once is
            // enough to compromise every association the process has served.

            var result       = new Byte[BlockSize + Plaintext.Length];
            var syntheticIV  = result.AsSpan(0, BlockSize);

            String2InitializationVector(AssociatedData, Nonce, Plaintext, syntheticIV);

            CTR(Keyed(Key2_AESCTR), syntheticIV, Plaintext, result.AsSpan(BlockSize));

            return result;

        }

        #endregion

        #region Decrypt (AssociatedData, Nonce, SyntheticIVAndCiphertext)

        /// <summary>
        /// Decrypts an encrypted message of the form syntheticIV || ciphertext.
        /// Recomputes the expected synthetic IV using the associated data and nonce (which may be a salt)
        /// and verifies that it matches the one embedded in the message.
        /// Throws CryptographicException if authentication fails.
        /// </summary>
        public Byte[] Decrypt(IEnumerable<Byte[]>  AssociatedData,
                              Byte[]               Nonce,
                              Byte[]               SyntheticIVAndCiphertext)
        {

            if (SyntheticIVAndCiphertext.Length < BlockSize)
                throw new ArgumentException("Encrypted message too short.");

            var syntheticIV  = SyntheticIVAndCiphertext.AsSpan(0, BlockSize);
            var plaintext    = new Byte[SyntheticIVAndCiphertext.Length - BlockSize];

            // AES-CTR decryption is the same as encryption:
            CTR(Keyed(Key2_AESCTR), syntheticIV, SyntheticIVAndCiphertext.AsSpan(BlockSize), plaintext);

            // Recompute the synthetic IV from associated data, nonce, and the decrypted plaintext:
            Span<Byte> computedSIV = stackalloc Byte[BlockSize];

            String2InitializationVector(AssociatedData, Nonce, plaintext, computedSIV);

            // Compared in constant time: a data-dependent early exit would leak how much of a
            // forged synthetic IV was correct, letting an attacker construct one byte at a time.
            if (!CryptographicOperations.FixedTimeEquals(syntheticIV, computedSIV))
            {

                // What was decrypted with a synthetic IV that is not this message's is not
                // this message, and is nobody's business.
                CryptographicOperations.ZeroMemory(plaintext);

                throw new CryptographicException("Authentication failed: SIV mismatch!");

            }

            return plaintext;

        }

        #endregion


        #region (private) String2InitializationVector (AssociatedData, Nonce, Plaintext, SyntheticIV)

        /// <summary>
        /// Implements the "String to Initialization Vector" (S2V) function according to RFC 5297.
        /// https://www.rfc-editor.org/rfc/rfc5297.html#section-2.4
        /// </summary>
        private void String2InitializationVector(IEnumerable<Byte[]>  AssociatedData,
                                                 Byte[]               Nonce,
                                                 ReadOnlySpan<Byte>   Plaintext,
                                                 Span<Byte>           SyntheticIV)
        {

            // There is deliberately no "empty vector" special case here.
            //
            // RFC 5297 §2.4 returns CMAC(K, <one>) only when S2V is called with an empty
            // vector, and §2.6 always appends the plaintext to that vector:
            //
            //     V = S2V(K1, AD1, ..., ADn, P)
            //
            // So even with no associated data and an empty plaintext the vector is ("") —
            // one element, length zero — which falls through to the padded-last-block branch
            // below. The empty vector is unreachable from SIV-ENCRYPT, and short-cutting to
            // CMAC(<one>) on "no associated data and no plaintext" produced a different
            // synthetic IV than any conformant implementation.

            var aes = Keyed(Key1_CMAC);

            // Step 1: D = CMAC(K, <zero>), which the constructor has computed.
            Span<Byte> D    = stackalloc Byte[BlockSize];
            Span<Byte> cmac = stackalloc Byte[BlockSize];

            cmacOfZero.CopyTo(D);

            // Step 2: every element but the last - the associated data, and the nonce
            // where there is one. The plaintext is always the last, even when it is empty.
            foreach (var associatedData in AssociatedData)
            {
                DoubleBlock(D);
                CMAC(aes, cmacSubkeys, associatedData, [], cmac);
                XOR(D, cmac);
            }

            if (Nonce.Length > 0)
            {
                DoubleBlock(D);
                CMAC(aes, cmacSubkeys, Nonce, [], cmac);
                XOR(D, cmac);
            }

            // Step 3 and 4: V = CMAC(K, T)
            if (Plaintext.Length >= BlockSize)
            {

                // T = Sn xorend D: the plaintext, its last 16 bytes XORed with D. CMAC
                // takes it in two parts, so that it need not be put together anywhere.
                Span<Byte> end = stackalloc Byte[BlockSize];

                Plaintext[^BlockSize..].CopyTo(end);
                XOR(end, D);

                CMAC(aes, cmacSubkeys, Plaintext[..^BlockSize], end, SyntheticIV);

            }
            else
            {

                // T = dbl(D) xor pad(Sn)
                Span<Byte> padded = stackalloc Byte[BlockSize];

                padded.Clear();
                Plaintext.CopyTo(padded);
                padded[Plaintext.Length] = 0x80;

                DoubleBlock(D);
                XOR(padded, D);

                CMAC(aes, cmacSubkeys, padded, [], SyntheticIV);

            }

        }

        #endregion


        #region (private static) Keyed      (Key)

        /// <summary>
        /// AES under the given key, for encrypting single blocks: the processor's own
        /// where it has one, tables otherwise.
        /// </summary>
        /// <remarks>
        /// One per operation, and never kept: a cipher is not promised to be safe for two
        /// threads at once, and expanding a key is a small part of what it used to cost
        /// to do so for every CMAC.
        /// </remarks>
        private static IBlockCipher Keyed(Byte[] Key)
        {

            var aes = AesUtilities.CreateEngine();

            aes.Init(true, new KeyParameter(Key));

            return aes;

        }

        #endregion

        #region (private static) Subkeys    (AES, Subkeys)

        /// <summary>
        /// The subkeys of CMAC, RFC 4493 § 2.3: K1 = dbl(AES(K, 0)), K2 = dbl(K1).
        /// </summary>
        /// <param name="AES">AES under the CMAC key.</param>
        /// <param name="Subkeys">32 bytes: K1, then K2.</param>
        private static void Subkeys(IBlockCipher AES, Span<Byte> Subkeys)
        {

            var k1 = Subkeys[..BlockSize];
            var k2 = Subkeys[BlockSize..];

            k1.Clear();
            AES.ProcessBlock(k1, k1);
            DoubleBlock(k1);

            k1.CopyTo(k2);
            DoubleBlock(k2);

        }

        #endregion

        #region (private static) CMAC       (AES, Subkeys, Message, MessageEnd, MAC)

        /// <summary>
        /// AES-CMAC, RFC 4493 § 2.4, over a message that comes in two parts.
        /// </summary>
        /// <param name="AES">AES under the CMAC key.</param>
        /// <param name="Subkeys">The subkeys of that key: K1, then K2.</param>
        /// <param name="Message">The message, or its beginning.</param>
        /// <param name="MessageEnd">What follows it: nothing, or exactly one block.</param>
        /// <param name="MAC">Where the 16 bytes of the MAC go.</param>
        private static void CMAC(IBlockCipher        AES,
                                 ReadOnlySpan<Byte>  Subkeys,
                                 ReadOnlySpan<Byte>  Message,
                                 ReadOnlySpan<Byte>  MessageEnd,
                                 Span<Byte>          MAC)
        {

            Span<Byte> x     = stackalloc Byte[BlockSize];
            Span<Byte> last  = stackalloc Byte[BlockSize];

            x.Clear();

            var length = Message.Length + MessageEnd.Length;

            // Every block but the last one. The last one is kept back even when it is a
            // whole block, because it is treated differently.
            var before = length == 0
                             ? 0
                             : (length - 1) / BlockSize * BlockSize;

            // MessageEnd is nothing or one whole block, so the blocks before the last
            // one lie in Message entirely, unless MessageEnd is the last block itself.
            var inMessage = Math.Min(before, Message.Length / BlockSize * BlockSize);

            for (var offset = 0; offset < inMessage; offset += BlockSize)
            {
                XOR(x, Message.Slice(offset, BlockSize));
                AES.ProcessBlock(x, x);
            }

            // A block that lies across the two parts: the rest of Message and the
            // beginning of MessageEnd. With MessageEnd being one block, there is at most
            // one such block before the last.
            var done = inMessage;

            if (done < before)
            {

                Span<Byte> across = stackalloc Byte[BlockSize];

                Take(Message, MessageEnd, done, across);

                XOR(x, across);
                AES.ProcessBlock(x, x);

                done += BlockSize;

            }

            var remaining = length - done;

            if (remaining == BlockSize)
            {
                Take(Message, MessageEnd, done, last);
                XOR(last, Subkeys[..BlockSize]);
            }
            else
            {

                last.Clear();
                Take(Message, MessageEnd, done, last[..remaining]);
                last[remaining] = 0x80;

                XOR(last, Subkeys[BlockSize..]);

            }

            XOR(x, last);
            AES.ProcessBlock(x, MAC);

        }

        /// <summary>
        /// Copy from the two parts of a message, as if they were one.
        /// </summary>
        private static void Take(ReadOnlySpan<Byte>  Message,
                                 ReadOnlySpan<Byte>  MessageEnd,
                                 Int32               Offset,
                                 Span<Byte>          Destination)
        {

            var fromMessage = Math.Clamp(Message.Length - Offset, 0, Destination.Length);

            if (fromMessage > 0)
                Message.Slice(Offset, fromMessage).CopyTo(Destination);

            if (fromMessage < Destination.Length)
                MessageEnd.Slice(Offset + fromMessage - Message.Length, Destination.Length - fromMessage).
                           CopyTo(Destination[fromMessage..]);

        }

        #endregion

        #region (private static) CTR        (AES, SyntheticIV, Input, Output)

        /// <summary>
        /// AES in counter mode as RFC 5297 § 2.6 has it: the counter starts at the
        /// synthetic IV with two of its bits cleared, and is one 128 bit number.
        /// </summary>
        /// <param name="AES">AES under the encryption key.</param>
        /// <param name="SyntheticIV">The synthetic IV, which is left as it is.</param>
        /// <param name="Input">What to encrypt, or to decrypt.</param>
        /// <param name="Output">Where it goes: as long as the input.</param>
        private static void CTR(IBlockCipher        AES,
                                ReadOnlySpan<Byte>  SyntheticIV,
                                ReadOnlySpan<Byte>  Input,
                                Span<Byte>          Output)
        {

            Span<Byte> counter    = stackalloc Byte[BlockSize];
            Span<Byte> keystream  = stackalloc Byte[BlockSize];

            SyntheticIV.CopyTo(counter);

            // rfc5297 Section 2.5: Clear the 31st and 63rd bit (rightmost bit = 0th)
            counter[ 8] &= 0x7F;
            counter[12] &= 0x7F;

            for (var offset = 0; offset < Input.Length; offset += BlockSize)
            {

                AES.ProcessBlock(counter, keystream);

                var count = Math.Min(BlockSize, Input.Length - offset);

                for (var i = 0; i < count; i++)
                    Output[offset + i] = (Byte) (Input[offset + i] ^ keystream[i]);

                // The next counter: one more, as a big-endian number of 128 bits.
                for (var i = BlockSize - 1; i >= 0 && ++counter[i] == 0; i--)
                { }

            }

            CryptographicOperations.ZeroMemory(keystream);

        }

        #endregion

        #region (private static) DoubleBlock(Block), XOR(Block, With)

        /// <summary>
        /// Double a 16 byte block in GF(2^128), in place: dbl() of RFC 5297 § 2.3.
        /// </summary>
        private static void DoubleBlock(Span<Byte> Block)
        {

            var carry = 0;

            for (var i = BlockSize - 1; i >= 0; i--)
            {
                var b     = Block[i];
                Block[i]  = (Byte) ((b << 1) | carry);
                carry     = b >> 7;
            }

            // The polynomial x^128 + x^7 + x^2 + x + 1, R = 0x87 - and without a branch
            // on the bit that fell out, which is a bit of a secret.
            Block[BlockSize - 1] ^= (Byte) (0x87 & -carry);

        }

        /// <summary>
        /// XOR a block into another, in place.
        /// </summary>
        private static void XOR(Span<Byte> Block, ReadOnlySpan<Byte> With)
        {
            for (var i = 0; i < Block.Length; i++)
                Block[i] ^= With[i];
        }

        #endregion


        #region (static)  CMAC                        (Key, Message)

        /// <summary>
        /// Calculate the AES Cipher-based Message Authentication Code (AES-CMAC)
        /// over the message using the given key.
        /// </summary>
        /// <param name="Key">The key to use.</param>
        /// <param name="Message">The message to calculate the CMAC for.</param>
        public static Byte[] CMAC(Byte[] Key,
                                  Byte[] Message)
        {

            var aes = Keyed(Key);

            Span<Byte> subkeys = stackalloc Byte[2 * BlockSize];
            Subkeys(aes, subkeys);

            var output = new Byte[BlockSize];
            CMAC(aes, subkeys, Message, [], output);

            return output;

        }

        #endregion

        #region (static)  DoubleBlock                 (Block)

        /// <summary>
        /// Double a 16 byte block in GF(2^128): dbl() of RFC 5297 § 2.3.
        /// </summary>
        /// <param name="Block">A 16-Byte block.</param>
        public static Byte[] DoubleBlock(Byte[] Block)
        {

            if (Block.Length != BlockSize)
                throw new ArgumentException("Block must be 16 Bytes", nameof(Block));

            var output = (Byte[]) Block.Clone();

            DoubleBlock(output.AsSpan());

            return output;

        }

        #endregion

        #region (static)  XOR_Blocks                  (BlockA, BlockB)

        /// <summary>
        /// XOR two equally long byte arrays.
        /// </summary>
        /// <param name="BlockA">The first byte array.</param>
        /// <param name="BlockB">The second byte array.</param>
        public static Byte[] XOR_Blocks(Byte[] BlockA,
                                        Byte[] BlockB)
        {

            if (BlockA.Length != BlockB.Length)
                throw new ArgumentException("Arrays must have same length");

            var result = (Byte[]) BlockA.Clone();

            XOR(result, BlockB);

            return result;

        }

        #endregion

        #region (static)  Pad                         (Data)

        public static Byte[] Pad(Byte[] Data)
        {

            // https://www.rfc-editor.org/rfc/rfc5297.html
            // 2. Specification of SIV
            // 2.1. Notation
            // pad(X)
            // indicates padding of string X, len(X) < 128, out to 128 bits by
            // the concatenation of a single bit of 1 followed by as many 0 bits
            // as are necessary.
            //
            // pad(data) = data || 0x80 || 0^j, till the total length is 16 Bytes.

            // The RFC defines pad() only for len(X) < 128 bits. A full or overlong block has
            // nothing to pad, and writing the 0x80 marker at Data.Length would run past the
            // end of the block.
            if (Data.Length >= BlockSize)
                throw new ArgumentException($"pad() is defined for inputs shorter than 16 bytes; got {Data.Length}!",
                                            nameof(Data));

            var padded = new Byte[BlockSize];
            Buffer.BlockCopy(Data, 0, padded, 0, Data.Length);
            padded[Data.Length] = 0x80;

            return padded;

        }

        #endregion

        #region (static)  AES_CTR_Encrypt             (Plaintext, InitializationVector, SharedKey)

        /// <summary>
        /// Encrypts the given plaintext message using AES Counter Mode (AES-CTR)
        /// with the given initialization vector and shared key.
        /// </summary>
        public static Byte[] AES_CTR_Encrypt(Byte[] Plaintext,
                                             Byte[] InitializationVector,
                                             Byte[] SharedKey)
        {

            if (InitializationVector.Length != BlockSize)
                throw new ArgumentException("The initialization vector must be 16 Bytes", nameof(InitializationVector));

            var ciphertext = new Byte[Plaintext.Length];

            CTR(Keyed(SharedKey), InitializationVector, Plaintext, ciphertext);

            return ciphertext;

        }

        #endregion


    }

}
