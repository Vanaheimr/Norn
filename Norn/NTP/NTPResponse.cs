/*
 * Copyright (c) 2010-2025 GraphDefined GmbH <achim.friedland@graphdefined.com>
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

using System.Diagnostics.CodeAnalysis;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTP
{

    public static class NTPResponseExtensions
    {

        /// <summary>
        /// The value of an optional UniqueIdentifier extension.
        /// </summary>
        public static Byte[]?                                  UniqueIdentifier              (this NTPResponse NTPResponse)
            => NTPResponse.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.UniqueIdentifier)?.Value;

        /// <summary>
        /// The value of an optional UniqueIdentifier extension.
        /// </summary>
        public static UniqueIdentifierExtension?               UniqueIdentifierExtension     (this NTPResponse NTPResponse)
            => NTPResponse.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.UniqueIdentifier)              as UniqueIdentifierExtension;

        /// <summary>
        /// The value of an optional NTS Cookie extension.
        /// </summary>
        public static NTSCookieExtension?                      NTSCookieExtension            (this NTPResponse NTPResponse)
            => NTPResponse.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.NTSCookie)                     as NTSCookieExtension;

        /// <summary>
        /// The value of an optional NTS Request Signed Response extension.
        /// </summary>
        public static NTSRequestSignedResponseExtension?       NTSRequestSignedResponse      (this NTPResponse NTPResponse)
            => NTPResponse.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.NTSRequestSignedResponse)      as NTSRequestSignedResponseExtension;

        /// <summary>
        /// The value of an optional NTS Signed Response Announcement extension.
        /// </summary>
        public static NTSSignedResponseAnnouncementExtension?  NTSSignedResponseAnnouncement (this NTPResponse NTPResponse)
            => NTPResponse.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.NTSSignedResponseAnnouncement) as NTSSignedResponseAnnouncementExtension;

        /// <summary>
        /// The value of an optional NTS Signed Response extension.
        /// </summary>
        public static NTSSignedResponseExtension?              NTSSignedResponse             (this NTPResponse NTPResponse)
            => NTPResponse.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.NTSSignedResponse)             as NTSSignedResponseExtension;

    }


    /// <summary>
    /// The NTP request (RFC 5905).
    /// </summary>
    public class NTPResponse : NTPPacket
    {

        #region Constructor(s)

        #region NTPResponse(LI = null, ...)

        public NTPResponse(Byte?                       LI                     = null,
                           Byte?                       VN                     = null,
                           Byte?                       Mode                   = null,
                           Byte?                       Stratum                = null,
                           Byte?                       Poll                   = null,
                           SByte?                      Precision              = null,
                           UInt32?                     RootDelay              = null,
                           UInt32?                     RootDispersion         = null,
                           ReferenceIdentifier?        ReferenceIdentifier    = null,
                           UInt64?                     ReferenceTimestamp     = null,
                           UInt64?                     OriginateTimestamp     = null,
                           UInt64?                     ReceiveTimestamp       = null,
                           UInt64?                     TransmitTimestamp      = null,
                           IEnumerable<NTPExtension>?  Extensions             = null,
                           Int32?                      KeyId                  = null,
                           Byte[]?                     MessageDigest          = null,
                           UInt64?                     DestinationTimestamp   = null,

                           NTPRequest?                 Request                = null,
                           Byte[]?                     ResponseBytes          = null,
                           String?                     ErrorMessage           = null)

            : base(LI,
                    VN,
                    Mode,
                    Stratum,
                    Poll,
                    Precision,
                    RootDelay,
                    RootDispersion,
                    ReferenceIdentifier,
                    ReferenceTimestamp,
                    OriginateTimestamp,
                    ReceiveTimestamp,
                    TransmitTimestamp,
                    Extensions,
                    KeyId,
                    MessageDigest,
                    DestinationTimestamp,

                    Request,
                    ResponseBytes,
                    ErrorMessage)

        { }

        #endregion

        #region NTPResponse(NTPPacket,    Extensions = null)

        public NTPResponse(NTPPacket                   NTPPacket,
                           IEnumerable<NTPExtension>?  Extensions   = null)

            : this(NTPPacket.LI,
                   NTPPacket.VN,
                   NTPPacket.Mode,
                   NTPPacket.Stratum,
                   NTPPacket.Poll,
                   NTPPacket.Precision,
                   NTPPacket.RootDelay,
                   NTPPacket.RootDispersion,
                   NTPPacket.ReferenceIdentifier,
                   NTPPacket.ReferenceTimestamp,
                   NTPPacket.OriginateTimestamp,
                   NTPPacket.ReceiveTimestamp,
                   NTPPacket.TransmitTimestamp,
                   Extensions)

        {

        }

        #endregion

        #region NTPResponse(ErrorMessage, Extensions = null)

        public NTPResponse(String ErrorMessage)

            : base(ErrorMessage)

        { }

        #endregion

        #endregion


        #region TryParse(Buffer, out NTPResponse, out ErrorResponse, Request = null, NTSKey = null, ExptectedUniqueId = null)

        public static Boolean TryParse(Byte[]                                 Buffer,
                                       [NotNullWhen(true)]  out NTPResponse?  NTPResponse,
                                       [NotNullWhen(false)] out String?       ErrorResponse,
                                       NTPRequest?                            Request            = null,
                                       Byte[]?                                NTSKey             = null,
                                       Byte[]?                                ExpectedUniqueId   = null)
        {

            #region Initial checks

            ErrorResponse = null;
            NTPResponse   = null;

            if (Buffer.Length < 48)
            {
                ErrorResponse = "The NTP response is too short!";
                NTPResponse     = null;
                return false;
            }

            #endregion

            var ntpPacketBytes = new Byte[48];
            Array.Copy(Buffer, ntpPacketBytes, 48);
            var things         = new List<Byte[]>() { ntpPacketBytes };

            #region Parse Extensions

            var offset     = 48;
            var extensions = new List<NTPExtension>();

            while (offset + 4 <= Buffer.Length)
            {

                var type   = (ExtensionTypes) ((Buffer[offset]     << 8) | Buffer[offset + 1]);
                var length = (UInt16)         ((Buffer[offset + 2] << 8) | Buffer[offset + 3]);

                if (length < 4)
                {
                    ErrorResponse  = $"Illegal length of extension {length} at offset {offset}!";
                    NTPResponse      = null;
                    return false;
                }

                if (offset + length > Buffer.Length)
                    break;

                var copy = new Byte[length];
                Array.Copy(Buffer, offset, copy, 0, length);
                things.Add(copy);

                var data = new Byte[length - 4];
                Array.Copy(Buffer, offset + 4, data, 0, length - 4);

                switch (type)
                {

                    case ExtensionTypes.UniqueIdentifier:

                        if (!UniqueIdentifierExtension.TryParse(data, out var uniqueIdentifierExtension, out ErrorResponse))
                            return false;

                        var r1  = Request?.UniqueIdentifier();

                        if (r1 is not null && !uniqueIdentifierExtension.Value.SequenceEqual(r1))
                        {
                            ErrorResponse = $"Unexpected UniqueIdentifier '{uniqueIdentifierExtension.Value}' != '{r1}'!";
                            return false;
                        }

                        if (ExpectedUniqueId is not null &&
                            !uniqueIdentifierExtension.Value.SequenceEqual(ExpectedUniqueId))
                        {
                            ErrorResponse = $"Unexpected UniqueIdentifier '{uniqueIdentifierExtension.Value}' != '{ExpectedUniqueId}'!";
                            return false;
                        }

                        extensions.Add(uniqueIdentifierExtension);

                        break;


                    case ExtensionTypes.NTSCookie:
                        extensions.Add(
                            new NTSCookieExtension(data)
                        );
                        break;


                    case ExtensionTypes.NTSCookiePlaceholder:
                        extensions.Add(
                            new NTSCookiePlaceholderExtension(100) // Nonsense!
                        );
                        break;


                    case ExtensionTypes.AuthenticatorAndEncrypted:

                        if (NTSKey is null)
                        {
                            ErrorResponse = "Missing NTS key for the AuthenticatorAndEncrypted extension!";
                            return false;
                        }

                        if (!AuthenticatorAndEncryptedExtension.TryParse(data,
                                                                         things.Take(things.Count-1),
                                                                         ref extensions,
                                                                         NTSKey,
                                                                         out var authenticatorAndEncryptedExtension,
                                                                         out ErrorResponse))
                        {
                            return false;
                        }

                        extensions.Add(authenticatorAndEncryptedExtension);

                        if (authenticatorAndEncryptedExtension.EncryptedExtensions.Any())
                            extensions.AddRange(authenticatorAndEncryptedExtension.EncryptedExtensions);

                        break;


                    case ExtensionTypes.Debug:

                        if (!DebugExtension.TryParse(data, out var debugExtension, out ErrorResponse))
                            return false;

                        extensions.Add(debugExtension);

                        break;


                    case ExtensionTypes.NTSSignedResponseAnnouncement:

                        if (!NTSSignedResponseAnnouncementExtension.TryParse(data, out var signedResponseAnnouncementExtension, out ErrorResponse))
                            return false;

                        extensions.Add(signedResponseAnnouncementExtension);

                        break;


                    case ExtensionTypes.NTSSignedResponse:

                        if (!NTSSignedResponseExtension.TryParse(data, out var signedResponseExtension, out ErrorResponse))
                            return false;

                        extensions.Add(signedResponseExtension);

                        break;


                    default:
                        extensions.Add(
                            new NTPExtension(
                                type,
                                data
                            )
                        );
                        break;

                }

                offset += length;

            }

            #endregion

            #region Parse NTP packet

            NTPResponse = new NTPResponse(

                            LI:                     (Byte) ((Buffer[0] >> 6) & 0x03),
                            VN:                     (Byte) ((Buffer[0] >> 3) & 0x07),
                            Mode:                   (Byte)  (Buffer[0]       & 0x07),
                            Stratum:                Buffer[1],
                            Poll:                   Buffer[2],
                            Precision:              (SByte) Buffer[3],
                            RootDelay:              (UInt32) ((Buffer[4]  << 24) | (Buffer[5]  << 16) | (Buffer[6]  << 8) | Buffer[7]),
                            RootDispersion:         (UInt32) ((Buffer[8]  << 24) | (Buffer[9]  << 16) | (Buffer[10] << 8) | Buffer[11]),
                            ReferenceIdentifier:    ReferenceIdentifier.From(Buffer[12], Buffer[13], Buffer[14], Buffer[15]),
                            ReferenceTimestamp:     ReadUInt64(Buffer, 16),
                            OriginateTimestamp:     ReadUInt64(Buffer, 24),
                            ReceiveTimestamp:       ReadUInt64(Buffer, 32),
                            TransmitTimestamp:      ReadUInt64(Buffer, 40),

                            Extensions:             extensions,
                            KeyId:                  null,
                            MessageDigest:          null,
                            DestinationTimestamp:   null,

                            Request:                Request,
                            ResponseBytes:          Buffer

                        );

            #endregion

            #region Parse Kiss-o'-Death

            if (NTPResponse.Stratum == 0)
            {
                ErrorResponse = NTPResponse.ReferenceIdentifier.ErrorString ?? "ERR";
                return false;
            }

            #endregion

            return true;

        }

        #endregion


    }

}
