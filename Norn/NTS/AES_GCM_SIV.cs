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

using System.Runtime.CompilerServices;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// AES-GCM-SIV (RFC 8452), the nonce-misuse-resistant AEAD behind
    /// <see cref="AEADAlgorithms.AES_128_GCM_SIV"/> and <see cref="AEADAlgorithms.AES_256_GCM_SIV"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The same property AES-SIV has — repeating a nonce leaks only whether two messages were
    /// identical, rather than destroying the key — reached by a different route: POLYVAL and
    /// AES-CTR instead of CMAC and AES-CTR. The practical difference is speed, because POLYVAL
    /// is a carry-less multiply and every processor that runs TLS well has an instruction for
    /// it. That is why chrony offers this one first.
    /// </para>
    /// <para>
    /// Two things about it are visible on the NTS wire and matter more than the speed.
    /// The nonce is exactly twelve octets, where AES-SIV takes any length — so the Authenticator
    /// extension field is shaped differently. And the key is sixteen octets for the 128-bit
    /// variant against AES-SIV-CMAC-256's thirty-two, which halves what a cookie has to carry
    /// for each of the two directions.
    /// </para>
    /// <para>
    /// The primitive itself is BouncyCastle's. Writing a second POLYVAL would be writing the
    /// interesting half of a cryptographic primitive twice in the same process, and the value of
    /// an independent implementation comes from it being in a different codebase — which is
    /// where the conformance suite's is.
    /// </para>
    /// </remarks>
    public class AES_GCM_SIV
    {

        #region Data

        /// <summary>
        /// The tag length in bits. RFC 8452 § 6 fixes it; there is no truncated variant.
        /// </summary>
        private const Int32 TagLengthBits = 128;

        private readonly KeyParameter  keyParameter;
        private readonly Int32         keyLength;

        #endregion

        #region Properties

        /// <summary>
        /// The nonce length in octets. RFC 8452 § 6: "N_MIN and N_MAX are 12" — not a
        /// recommendation but the only length the construction defines.
        /// </summary>
        public const Int32 NonceLength = 12;

        /// <summary>
        /// Which of the two AEADs this key selects.
        /// </summary>
        public AEADAlgorithms Algorithm

            => keyLength == 16
                   ? AEADAlgorithms.AES_128_GCM_SIV
                   : AEADAlgorithms.AES_256_GCM_SIV;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create an AES-GCM-SIV context.
        /// </summary>
        /// <param name="Key">
        /// The key-generating key: sixteen octets for AEAD_AES_128_GCM_SIV, thirty-two for
        /// AEAD_AES_256_GCM_SIV.
        /// </param>
        /// <remarks>
        /// "Key-generating" is RFC 8452's own term and worth keeping: this key never encrypts
        /// anything. Per message it derives a fresh authentication key and encryption key from
        /// the nonce, which is what lets the same key be used far past the birthday bound that
        /// limits AES-GCM.
        /// </remarks>
        public AES_GCM_SIV(Byte[] Key)
        {

            if (Key is null || (Key.Length != 16 && Key.Length != 32))
                throw new ArgumentException("An AES-GCM-SIV key must be 16 or 32 bytes long!",
                                            nameof(Key));

            this.keyLength     = Key.Length;
            this.keyParameter  = new KeyParameter(Key);

        }

        #endregion


        #region Encrypt(AssociatedData, Nonce, Plaintext)

        /// <summary>
        /// Seal the plaintext, returning the ciphertext with the sixteen-octet tag appended.
        /// </summary>
        /// <param name="AssociatedData">Authenticated but not encrypted.</param>
        /// <param name="Nonce">Exactly <see cref="NonceLength"/> octets.</param>
        /// <param name="Plaintext">The plaintext, which may be empty.</param>
        public Byte[] Encrypt(Byte[]  AssociatedData,
                              Byte[]  Nonce,
                              Byte[]  Plaintext)
        {

            if (Nonce is null || Nonce.Length != NonceLength)
                throw new ArgumentException($"An AES-GCM-SIV nonce must be exactly {NonceLength} bytes long (RFC 8452 § 6)!",
                                            nameof(Nonce));

            return Process(true, AssociatedData.AsSpan(), Nonce, Plaintext.AsSpan());

        }

        /// <summary>
        /// Seal the plaintext without allocating intermediate buffers for associated data or input.
        /// </summary>
        [OverloadResolutionPriority(-1)]
        public Byte[] Encrypt(ReadOnlySpan<Byte>  AssociatedData,
                              ReadOnlySpan<Byte>  Nonce,
                              ReadOnlySpan<Byte>  Plaintext)
        {

            if (Nonce.Length != NonceLength)
                throw new ArgumentException($"An AES-GCM-SIV nonce must be exactly {NonceLength} bytes long (RFC 8452 § 6)!",
                                            nameof(Nonce));

            return Process(true, AssociatedData, Nonce.ToArray(), Plaintext);

        }

        #endregion

        #region Decrypt(AssociatedData, Nonce, Ciphertext)

        /// <summary>
        /// Open the ciphertext, or throw if the tag does not verify.
        /// </summary>
        /// <remarks>
        /// Throws rather than returning a failure, matching <see cref="AES_SIV"/>: callers here
        /// treat an unopenable packet as unparseable, and a decrypt that returns something on
        /// failure is the shape that invites a caller to use it anyway.
        /// </remarks>
        public Byte[] Decrypt(Byte[]  AssociatedData,
                              Byte[]  Nonce,
                              Byte[]  Ciphertext)
        {

            if (Nonce is null || Nonce.Length != NonceLength)
                throw new ArgumentException($"An AES-GCM-SIV nonce must be exactly {NonceLength} bytes long (RFC 8452 § 6)!",
                                            nameof(Nonce));

            return Process(false, AssociatedData.AsSpan(), Nonce, Ciphertext.AsSpan());

        }

        /// <summary>
        /// Open the ciphertext without allocating intermediate buffers for associated data or input.
        /// </summary>
        [OverloadResolutionPriority(-1)]
        public Byte[] Decrypt(ReadOnlySpan<Byte>  AssociatedData,
                              ReadOnlySpan<Byte>  Nonce,
                              ReadOnlySpan<Byte>  Ciphertext)
        {

            if (Nonce.Length != NonceLength)
                throw new ArgumentException($"An AES-GCM-SIV nonce must be exactly {NonceLength} bytes long (RFC 8452 § 6)!",
                                            nameof(Nonce));

            return Process(false, AssociatedData, Nonce.ToArray(), Ciphertext);

        }

        #endregion

        #region (private) Process(ForEncryption, AssociatedData, Nonce, Input)

        private Byte[] Process(Boolean             ForEncryption,
                               ReadOnlySpan<Byte>  AssociatedData,
                               Byte[]              Nonce,
                               ReadOnlySpan<Byte>  Input)
        {

            var cipher = new GcmSivBlockCipher(AesUtilities.CreateEngine());

            cipher.Init(
                ForEncryption,
                new AeadParameters(
                    keyParameter,
                    TagLengthBits,
                    Nonce
                )
            );

            if (!AssociatedData.IsEmpty)
                cipher.ProcessAadBytes(AssociatedData);

            var outputSize = cipher.GetOutputSize(Input.Length);
            var output     = outputSize == 0 ? [] : new Byte[outputSize];

            Int32 written;

            try
            {
                written  = Input.IsEmpty ? 0 : cipher.ProcessBytes(Input, output);
                written += cipher.DoFinal(output.AsSpan(written));
            }
            catch (InvalidCipherTextException e)
            {
                CryptographicOperations.ZeroMemory(output);
                throw new CryptographicException("AES-GCM-SIV authentication failed: tag mismatch!", e);
            }

            if (written == output.Length)
                return output;

            var trimmed = new Byte[written];
            Buffer.BlockCopy(output, 0, trimmed, 0, written);

            return trimmed;

        }

        #endregion

    }

}
