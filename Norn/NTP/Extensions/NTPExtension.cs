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
using System.Security.Cryptography;
using System.Diagnostics.CodeAnalysis;

using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTP
{

    /// <summary>
    /// A NTP Extension.
    /// 
    /// Network Time Security for the Network Time Protocol: https://datatracker.ietf.org/doc/html/rfc8915
    /// 5. NTS Extension Fields for NTPv4
    /// 
    /// Network Time Protocol Version 4: Protocol and Algorithms Specification: https://datatracker.ietf.org/doc/html/rfc5905
    /// Network Time Protocol Version 4 (NTPv4) Extension Fields:               https://datatracker.ietf.org/doc/html/rfc7822
    /// 
    /// </summary>
    public class NTPExtension
    {

        #region Properties

        /// <summary>
        /// The extension type.
        /// </summary>
        public ExtensionTypes  Type             { get; }

        /// <summary>
        /// The text representation of the extension type.
        /// </summary>
        public String          Name

            => Type switch {
                   ExtensionTypes.UniqueIdentifier           => "Unique Identifier",
                   ExtensionTypes.NTSCookie                  => "NTS Cookie",
                   ExtensionTypes.NTSCookiePlaceholder       => "NTS Cookie Placeholder",
                   ExtensionTypes.AuthenticatorAndEncrypted  => "Authenticator and Encrypted",
                   ExtensionTypes.Debug                      => "Debug",
                   _                                         => "<unknown>"
               };

        /// <summary>
        /// The overall length of the extension (including the 4-byte header).
        /// </summary>
        public UInt16          Length           { get; }

        /// <summary>
        /// The data within the extension.
        /// </summary>
        public Byte[]          Value            { get; }

        /// <summary>
        /// Whether the extension is/was authenticated.
        /// </summary>
        public Boolean         Authenticated    { get; internal set; }

        /// <summary>
        /// Whether the extension is/was encrypted.
        /// </summary>
        public Boolean         Encrypted        { get; internal set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new NTP extension.
        /// </summary>
        /// <param name="Type">The extension type.</param>
        /// <param name="Value">The data within the extension.</param>
        /// <param name="Authenticated">Whether the extension is/was authenticated.</param>
        /// <param name="Encrypted">Whether the extension is/was encrypted.</param>
        public NTPExtension(ExtensionTypes  Type,
                            Byte[]          Value,
                            Boolean         Authenticated = false,
                            Boolean         Encrypted     = false)
        {

            #region Inital checks

            if (Value is null)
                throw new ArgumentNullException(nameof(Value));

            // RFC 7822 § 7.5.1.4 sets a 16-octet minimum for unencrypted extension fields
            // (4-octet header + at least 12 octets of value). RFC 8915 § 5.6 explicitly lifts
            // that minimum for encrypted extension fields inside the Authenticator, where only
            // the 4-octet header and 4-octet alignment apply.
            var minValueLength = Encrypted ? 0 : 12;

            if (Value.Length < minValueLength)
                throw new ArgumentOutOfRangeException(
                              nameof(Value),
                              Encrypted
                                  ? "The encrypted extension value must not be null!"
                                  : "The value must be at least 12 bytes long (16 bytes including header)! See RFC 5905 § 7.5 and RFC 7822 § 7.5.1.4!"
                          );

            if (Value.Length > UInt16.MaxValue - 7)
                throw new ArgumentOutOfRangeException(
                              nameof(Value),
                              $"The extension value length ({Value.Length}) exceeds the 16-bit NTP extension length limit!"
                          );

            #endregion

            this.Type           = Type;
            this.Value          = Value;
            this.Length         = (UInt16) ((4 + Value.Length + 3) & ~3);
            this.Authenticated  = Authenticated;
            this.Encrypted      = Encrypted;

        }

        #endregion


        #region TryParse(ByteArray, out NTPExtension, out ErrorResponse)

        /// <summary>
        /// Try to parse the given binary representation of a NTP extension.
        /// </summary>
        /// <param name="ByteArray">The binary representation of a NTP extension to be parsed.</param>
        /// <param name="NTPExtension">The parsed NTP extension.</param>
        /// <param name="ErrorResponse">An optional error message.</param>
        public static Boolean TryParse(Byte[]                                  ByteArray,
                                       [NotNullWhen(true)]  out NTPExtension?  NTPExtension,
                                       [NotNullWhen(false)] out String?        ErrorResponse)
        {

            ErrorResponse  = null;
            NTPExtension   = null;

            if (ByteArray.Length < 4)
            {
                ErrorResponse = "The packet is too short!";
                return false;
            }

            var type   = BinaryPrimitives.ReadUInt16BigEndian(ByteArray.AsSpan(0, 2));
            var length = BinaryPrimitives.ReadUInt16BigEndian(ByteArray.AsSpan(2, 2));

            if (length < 16 || (length & 3) != 0)
            {
                ErrorResponse = "Extension field length must be at least 16 bytes and a multiple of 4!";
                return false;
            }

            if (length > ByteArray.Length)
            {
                ErrorResponse = "Extension field too long!";
                return false;
            }

            var value = new Byte[length - 4];
            Buffer.BlockCopy(ByteArray, 4, value, 0, length - 4);

            NTPExtension = new NTPExtension(
                               (ExtensionTypes) type,
                               value
                           );

            return true;

        }

        #endregion

        #region WriteTo(Destination)

        /// <summary>
        /// Write the wire representation of this extension directly into the given span
        /// without allocating an intermediate byte array.
        /// </summary>
        /// <param name="Destination">A destination span of at least <see cref="Length"/> bytes.</param>
        public void WriteTo(Span<Byte> Destination)
        {

            if (Destination.Length < Length)
                throw new ArgumentException($"Destination span ({Destination.Length} bytes) is shorter than extension length ({Length} bytes)!",
                                            nameof(Destination));

            BinaryPrimitives.WriteUInt16BigEndian(Destination,              (UInt16) Type);
            BinaryPrimitives.WriteUInt16BigEndian(Destination.Slice(2, 2),  Length);

            if (Value.Length > 0)
                Value.AsSpan().CopyTo(Destination.Slice(4, Value.Length));

            var padding = Length - 4 - Value.Length;
            if (padding > 0)
                Destination.Slice(4 + Value.Length, padding).Clear();

        }

        #endregion

        #region ToByteArray()

        /// <summary>
        /// Return a binary representation of this object.
        /// </summary>
        public Byte[] ToByteArray()
        {

            var result = new Byte[Length];
            WriteTo(result);
            return result;

        }

        #endregion


        #region Static methods

        #region (static) UniqueIdentifier(UniqueId = null)

        /// <summary>
        /// Create a new Unique Identifier extension.
        /// </summary>
        /// <param name="UniqueId">The unique identifier.</param>
        public static NTPExtension UniqueIdentifier(Byte[]? UniqueId = null)

            => new UniqueIdentifierExtension(
                   UniqueId is not null
                       ? UniqueId
                       : RandomNumberGenerator.GetBytes(32)
               );

        #endregion

        #region (static) NTSCookie(Value)

        /// <summary>
        /// Create a new NTS Cookie extension.
        /// </summary>
        /// <param name="Value">The NTS cookie.</param>
        public static NTPExtension NTSCookie(Byte[] Value)

            => new NTSCookieExtension(
                   Value
               );

        #endregion

        #region (static) NTSCookiePlaceholder(Length)

        /// <summary>
        /// Create a new NTS Cookie Placeholder extension.
        /// </summary>
        /// <param name="Length">The length of the expected NTS cookie.</param>
        public static NTPExtension NTSCookiePlaceholder(UInt16 Length)

            => new NTSCookiePlaceholderExtension(
                   Length
               );

        #endregion

        #region (static) AuthenticatorAndEncrypted(Nonce, Ciphertext, EncryptedExtensions = null)

        /// <summary>
        /// Create a new Authenticator and Encrypted extension.
        /// </summary>
        /// <param name="Nonce">The nonce.</param>
        /// <param name="Ciphertext">The ciphertext.</param>
        /// <param name="EncryptedExtensions">Optional encrypted extensions.</param>
        public static NTPExtension AuthenticatorAndEncrypted(Byte[]                      Nonce,
                                                             Byte[]                      Ciphertext,
                                                             IEnumerable<NTPExtension>?  EncryptedExtensions   = null)

            => new AuthenticatorAndEncryptedExtension(
                   Nonce,
                   Ciphertext,
                   EncryptedExtensions
               );

        #endregion

        #region (static) NTSRequestSignedResponse(KeyId)

        /// <summary>
        /// Create a new NTS Request Signed Response extension.
        /// </summary>
        /// <param name="KeyId">The key used to sign the response.</param>
        public static NTPExtension NTSRequestSignedResponse(UInt16 KeyId)

            => new NTSRequestSignedResponseExtension(
                   KeyId
               );

        #endregion

        #region (static) NTSSignedResponseAnnouncement(IsScheduled)

        /// <summary>
        /// Create a new NTS Signed Response Announcement extension.
        /// </summary>
        /// <param name="IsScheduled">Whether a 2nd signed response is scheduled.</param>
        public static NTPExtension NTSSignedResponseAnnouncement(Boolean IsScheduled)

            => new NTSSignedResponseAnnouncementExtension(
                   IsScheduled
               );

        #endregion

        #region (static) NTSSignedResponse(KeyId, Signature)

        /// <summary>
        /// Create a new NTS Signed Response extension.
        /// </summary>
        /// <param name="KeyId">The key used to sign the response.</param>
        /// <param name="Signature">The signature of the response.</param>
        public static NTPExtension NTSSignedResponse(UInt16   KeyId,
                                                     Byte[]   Signature)

            => new NTSSignedResponseExtension(
                   KeyId,
                   Signature
               );

        #endregion

        #endregion


        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"Type: {Type}, Length: {Length}, Data: {BitConverter.ToString(Value ?? [])}";

        #endregion


    }

}
