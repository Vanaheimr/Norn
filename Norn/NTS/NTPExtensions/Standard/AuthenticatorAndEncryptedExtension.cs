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

using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Diagnostics.CodeAnalysis;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Norn.NTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// A NTP extension containing an authenticator and encrypted extension fields.
    /// </summary>
    public class AuthenticatorAndEncryptedExtension : NTPExtension
    {

        #region Properties

        /// <summary>
        /// The nonce.
        /// </summary>
        public Byte[]                     Nonce                  { get; }

        /// <summary>
        /// The ciphertext.
        /// </summary>
        public Byte[]                     Ciphertext             { get; }

        /// <summary>
        /// Optional encrypted extensions.
        /// </summary>
        public IEnumerable<NTPExtension>  EncryptedExtensions    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new Authenticator and Encrypted extension.
        /// </summary>
        /// <param name="Nonce">The nonce.</param>
        /// <param name="Ciphertext">The ciphertext.</param>
        /// <param name="EncryptedExtensions">Optional encrypted extensions.</param>
        /// <param name="Authenticated">Whether the extension is/was authenticated.</param>
        /// <param name="Encrypted">Whether the extension is/was encrypted.</param>
        public AuthenticatorAndEncryptedExtension(Byte[]                      Nonce,
                                                  Byte[]                      Ciphertext,
                                                  IEnumerable<NTPExtension>?  EncryptedExtensions   = null,
                                                  Boolean                     Authenticated         = false,
                                                  Boolean                     Encrypted             = false)

            : base(ExtensionTypes.AuthenticatorAndEncrypted,
                   new Byte[4 + ((Nonce.Length + 3) & ~3) + ((Ciphertext.Length + 3) & ~3)],
                   Authenticated,
                   Encrypted)

        {

            this.Nonce                  = Nonce;
            this.Ciphertext             = Ciphertext;
            this.EncryptedExtensions    = EncryptedExtensions ?? [];

            var nonceLength             = Nonce.Length;
            var ciphertextLength        = Ciphertext.Length;// Math.Max(Ciphertext.Length - 16, 16);

            var paddedNonceLength       = (nonceLength      + 3) & ~3;
            //var paddedciphertextLength  = (ciphertextLength + 3) & ~3;

            Value[0] = (Byte) ((nonceLength      >> 8) & 0xff);
            Value[1] = (Byte)  (nonceLength            & 0xff);

            Value[2] = (Byte) ((ciphertextLength >> 8) & 0xff);
            Value[3] = (Byte)  (ciphertextLength       & 0xff);

            Buffer.BlockCopy(Nonce,      0, Value, 4,                     nonceLength);
            Buffer.BlockCopy(Ciphertext, 0, Value, 4 + paddedNonceLength, ciphertextLength);

        }

        #endregion


        public static Boolean TryParse(Byte[]                                                        ReceivedValue,
                                       IEnumerable<Byte[]>                                           AssociatedData,
                                       ref List<NTPExtension>                                        AuthenticatedExtensions,
                                       Byte[]                                                        Key, // S2C or C2S key!
                                       [NotNullWhen(true)]  out AuthenticatorAndEncryptedExtension?  AuthExtension,
                                       [NotNullWhen(false)] out String?                              ErrorResponse,
                                       AEADAlgorithms                                                AEADAlgorithm = NTSAEAD.Default)
        {

            if (ReceivedValue is null || ReceivedValue.Length < 16)
            {
                ErrorResponse = "NTS Authenticator and Encrypted extension value is null or too short!";
                AuthExtension = null;
                return false;
            }

            return TryParse(
                       ReceivedValue.AsSpan(),
                       AssociatedData.Aggregate().AsSpan(),
                       ref AuthenticatedExtensions,
                       Key,
                       out AuthExtension,
                       out ErrorResponse,
                       AEADAlgorithm
                   );

        }


        /// <summary>
        /// Verify and open an NTS Authenticator and Encrypted Extension Fields value directly
        /// from wire spans, without copying the associated data or intermediate slices.
        /// </summary>
        [OverloadResolutionPriority(-1)]
        public static Boolean TryParse(ReadOnlySpan<Byte>                                            ReceivedValue,
                                       ReadOnlySpan<Byte>                                            AssociatedData,
                                       ref List<NTPExtension>                                        AuthenticatedExtensions,
                                       Byte[]                                                        Key, // S2C or C2S key!
                                       [NotNullWhen(true)]  out AuthenticatorAndEncryptedExtension?  AuthExtension,
                                       [NotNullWhen(false)] out String?                              ErrorResponse,
                                       AEADAlgorithms                                                AEADAlgorithm = NTSAEAD.Default)
        {

            try
            {

                ErrorResponse = null;
                AuthExtension = null;

                if (Key is null || Key.Length == 0)
                {
                    ErrorResponse = "Missing NTS key!";
                    return false;
                }

                if (ReceivedValue.Length < 16)
                {
                    ErrorResponse = "NTS Authenticator and Encrypted extension value is null or too short!";
                    return false;
                }

                var nonceLength                  = BinaryPrimitives.ReadUInt16BigEndian(ReceivedValue.Slice(0, 2));
                var ciphertextLength             = BinaryPrimitives.ReadUInt16BigEndian(ReceivedValue.Slice(2, 2));

                if (nonceLength == 0)
                {
                    ErrorResponse = "NTS Authenticator and Encrypted extension nonce must not be empty (RFC 8915 § 5.6)!";
                    return false;
                }

                var paddedNonceLength            = (nonceLength      + 3) & ~3;
                var paddedCiphertextLength       = (ciphertextLength + 3) & ~3;

                var expectedTotalLength          = 4 + paddedNonceLength + paddedCiphertextLength;
                if (ReceivedValue.Length < expectedTotalLength)
                {
                    ErrorResponse = "NTS Authenticator and Encrypted extension value has unexpected length!";
                    return false;
                }

                // RFC 8915 § 5.6: any additional padding octets appended to meet minimum extension
                // length requirements MUST be zero.
                for (var i = expectedTotalLength; i < ReceivedValue.Length; i++)
                {
                    if (ReceivedValue[i] != 0)
                    {
                        ErrorResponse = "NTS Authenticator and Encrypted extension contains non-zero trailing padding!";
                        return false;
                    }
                }

                var receivedNonceSpan         = ReceivedValue.Slice(4, nonceLength);
                var receivedCiphertextSpan    = ciphertextLength > 0
                                                    ? ReceivedValue.Slice(4 + paddedNonceLength, ciphertextLength)
                                                    : ReadOnlySpan<Byte>.Empty;

                // Opened with the algorithm the key exchange agreed on, not with a fixed one:
                // the sender chose it, and the ciphertext is unreadable under any other.
                var aead                      = NTSAEAD.Create(AEADAlgorithm, Key);
                var computedOutput            = aead.Decrypt(AssociatedData, receivedNonceSpan, receivedCiphertextSpan);

                List<NTPExtension>? extensions = null;

                var offset = 0;
                while (offset + 4 <= computedOutput.Length)
                {

                    var type   = (ExtensionTypes) BinaryPrimitives.ReadUInt16BigEndian(computedOutput.AsSpan(offset,     2));
                    var length =                  BinaryPrimitives.ReadUInt16BigEndian(computedOutput.AsSpan(offset + 2, 2));

                    if (length < 4 || (length & 3) != 0)
                    {
                        ErrorResponse = $"Illegal length of encrypted extension {length} at offset {offset}!";
                        return false;
                    }

                    if (offset + length > computedOutput.Length)
                    {
                        ErrorResponse = $"Truncated encrypted extension of length {length} at offset {offset}!";
                        return false;
                    }

                    switch (type)
                    {

                        case ExtensionTypes.UniqueIdentifier:
                        case ExtensionTypes.NTSCookiePlaceholder:
                        case ExtensionTypes.AuthenticatorAndEncrypted:
                            break;

                        case ExtensionTypes.NTSCookie:
                            extensions ??= new List<NTPExtension>(2);
                            extensions.Add(
                                new NTSCookieExtension(
                                    computedOutput.AsSpan(offset + 4, length - 4).ToArray(),
                                    Authenticated: true,
                                    Encrypted:     true
                                )
                            );
                            break;

                        case ExtensionTypes.Debug:
                            if (!DebugExtension.TryParse(computedOutput.AsSpan(offset + 4, length - 4).ToArray(),
                                                         out var debugExtension,
                                                         out     ErrorResponse,
                                                         Authenticated: true,
                                                         Encrypted:     true))
                            {
                                return false;
                            }
                            extensions ??= new List<NTPExtension>(2);
                            extensions.Add(debugExtension);
                            break;

                        default:
                            extensions ??= new List<NTPExtension>(2);
                            extensions.Add(
                                new NTPExtension(
                                    type,
                                    computedOutput.AsSpan(offset + 4, length - 4).ToArray(),
                                    Authenticated: true,
                                    Encrypted:     true
                                )
                            );
                            break;

                    }

                    offset += length;

                }

                if (offset != computedOutput.Length)
                {
                    ErrorResponse = $"Encrypted extension plaintext has {computedOutput.Length - offset} trailing byte(s)!";
                    return false;
                }

                for (var i = 0; i < AuthenticatedExtensions.Count; i++)
                    AuthenticatedExtensions[i].Authenticated = true;

                AuthExtension = new AuthenticatorAndEncryptedExtension(
                                    receivedNonceSpan.ToArray(),
                                    ciphertextLength > 0 ? receivedCiphertextSpan.ToArray() : [],
                                    extensions ?? (IEnumerable<NTPExtension>) []
                                );

                return true;

            }
            catch (Exception e)
            {
                ErrorResponse = e.Message;
                AuthExtension = null;
                return false;
            }

        }


        #region Create(NTSKEResponse, AssociatedData, Plainttext = null, Nonce = null)

        /// <summary>
        /// Create a "NTS Authenticator and Encrypted Extension Fields" extension (type=0x0404)
        /// </summary>
        /// <param name="NTSKEResponse">A Network Time Security Key Establishment (NTS-KE) response containing the C2S key.</param>
        /// <param name="AssociatedData">An array of byte arrays to be authenticated but not encrypted.</param>
        /// <param name="Plaintext">The optional plaintext to be encrypted (e.g. internal extension fields).</param>
        /// <param name="Nonce">The optional nonce to be used for encryption.</param>
        public static AuthenticatorAndEncryptedExtension

            Create(NTSKE_Response       NTSKEResponse,
                   IEnumerable<Byte[]>  AssociatedData,
                   Byte[]?              Plaintext   = null,
                   Byte[]?              Nonce       = null)

            => Create(
                   NTSKEResponse.C2SKey,
                   AssociatedData,
                   Plaintext,
                   Nonce,
                   NTSKEResponse.AEADAlgorithm
               );

        /// <summary>
        /// Create a "NTS Authenticator and Encrypted Extension Fields" extension (type=0x0404)
        /// from contiguous read-only spans without copying associated data or plaintext.
        /// </summary>
        [OverloadResolutionPriority(-1)]
        public static AuthenticatorAndEncryptedExtension

            Create(NTSKE_Response      NTSKEResponse,
                   ReadOnlySpan<Byte>  AssociatedData,
                   ReadOnlySpan<Byte>  Plaintext   = default,
                   Byte[]?             Nonce       = null)

            => Create(
                   NTSKEResponse.C2SKey,
                   AssociatedData,
                   Plaintext,
                   Nonce,
                   NTSKEResponse.AEADAlgorithm
               );

        #endregion

        #region Create(NTSKey,        AssociatedData, Plainttext = null, Nonce = null)

        /// <summary>
        /// Create a "NTS Authenticator and Encrypted Extension Fields" extension (type=0x0404)
        /// </summary>
        /// <param name="NTSKey">The C2S or S2C key from the Network Time Security Key Establishment (NTS-KE) response.</param>
        /// <param name="AssociatedData">An array of byte arrays to be authenticated but not encrypted.</param>
        /// <param name="Plaintext">The optional plaintext to be encrypted (e.g. internal extension fields).</param>
        /// <param name="Nonce">The optional nonce to be used for encryption.</param>
        /// <param name="AEADAlgorithm">
        /// The algorithm agreed by the key exchange. It decides both how the plaintext is sealed
        /// and how long the nonce is — twelve octets for AES-GCM-SIV, sixteen for AES-SIV — so a
        /// caller that gets it wrong produces a field the peer cannot even frame, let alone open.
        /// </param>
        public static AuthenticatorAndEncryptedExtension

            Create(Byte[]               NTSKey,
                   IEnumerable<Byte[]>  AssociatedData,
                   Byte[]?              Plaintext      = null,
                   Byte[]?              Nonce          = null,
                   AEADAlgorithms       AEADAlgorithm  = NTSAEAD.Default)

            => Create(
                   NTSKey,
                   AssociatedData.Aggregate().AsSpan(),
                   Plaintext.AsSpan(),
                   Nonce,
                   AEADAlgorithm
               );

        /// <summary>
        /// Create a "NTS Authenticator and Encrypted Extension Fields" extension (type=0x0404)
        /// from contiguous read-only spans without copying associated data or plaintext.
        /// </summary>
        [OverloadResolutionPriority(-1)]
        public static AuthenticatorAndEncryptedExtension

            Create(Byte[]              NTSKey,
                   ReadOnlySpan<Byte>  AssociatedData,
                   ReadOnlySpan<Byte>  Plaintext      = default,
                   Byte[]?             Nonce          = null,
                   AEADAlgorithms      AEADAlgorithm  = NTSAEAD.Default)

        {

            var aead   = NTSAEAD.Create(AEADAlgorithm, NTSKey);
            var nonce  = Nonce ?? RandomNumberGenerator.GetBytes(aead.NonceLength);

            return new AuthenticatorAndEncryptedExtension(
                       nonce,
                       aead.Encrypt(
                           AssociatedData,
                           nonce,
                           Plaintext
                       )
                   );

        }

        #endregion


    }

}
