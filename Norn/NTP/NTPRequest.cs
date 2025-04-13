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

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTP
{

    public static class NTPRequestExtensions
    {

        /// <summary>
        /// The value of an optional UniqueIdentifier extension.
        /// </summary>
        public static Byte[]?                                  UniqueIdentifier              (this NTPRequest NTPRequest)
            => NTPRequest.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.UniqueIdentifier)?.Value;

        /// <summary>
        /// The value of an optional UniqueIdentifier extension.
        /// </summary>
        public static UniqueIdentifierExtension?               UniqueIdentifierExtension     (this NTPRequest NTPRequest)
            => NTPRequest.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.UniqueIdentifier)              as UniqueIdentifierExtension;

        /// <summary>
        /// The value of an optional NTS Cookie extension.
        /// </summary>
        public static NTSCookieExtension?                      NTSCookieExtension            (this NTPRequest NTPRequest)
            => NTPRequest.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.NTSCookie)                     as NTSCookieExtension;

        /// <summary>
        /// The value of an optional NTS Request Signed Response extension.
        /// </summary>
        public static NTSRequestSignedResponseExtension?       NTSRequestSignedResponse      (this NTPRequest NTPRequest)
            => NTPRequest.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.NTSRequestSignedResponse)      as NTSRequestSignedResponseExtension;

        /// <summary>
        /// The value of an optional NTS Signed Response Announcement extension.
        /// </summary>
        public static NTSSignedResponseAnnouncementExtension?  NTSSignedResponseAnnouncement (this NTPRequest NTPRequest)
            => NTPRequest.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.NTSSignedResponseAnnouncement) as NTSSignedResponseAnnouncementExtension;

        /// <summary>
        /// The value of an optional NTS Signed Response extension.
        /// </summary>
        public static NTSSignedResponseExtension?              NTSSignedResponse             (this NTPRequest NTPRequest)
            => NTPRequest.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.NTSSignedResponse)             as NTSSignedResponseExtension;

    }


    /// <summary>
    /// The NTP request (RFC 5905).
    /// </summary>
    public class NTPRequest : NTPPacket
    {

        #region Constructor(s)

        #region NTPRequest(LI = null, ...)

        public NTPRequest(Byte?                       LI                     = null,
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

                   null,
                   ResponseBytes,
                   ErrorMessage)

        { }

        #endregion

        #region NTPRequest(NTPPacket,    Extensions = null)

        public NTPRequest(NTPPacket                   NTPPacket,
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

        #region NTPRequest(ErrorMessage, Extensions = null)

        public NTPRequest(String ErrorMessage)

            : base(ErrorMessage)

        { }

        #endregion

        #endregion


        #region TryParse(Buffer, out NTPRequest, out ErrorResponse, NTSKey = null)

        public static Boolean TryParse(Byte[]                                    Buffer,
                                       [NotNullWhen(true)]  out NTPRequest?      NTPRequest,
                                       [NotNullWhen(false)] out String?          ErrorResponse,
                                       Byte[]?                                   NTSKey       = null,
                                       ConcurrentDictionary<UInt64, MasterKey>?  MasterKeys   = null)
        {

            #region Initial checks

            ErrorResponse = null;
            NTPRequest     = null;

            if (Buffer.Length < 48)
            {
                ErrorResponse = "The NTP request is too short!";
                NTPRequest     = null;
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
                    NTPRequest      = null;
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

                        extensions.Add(uniqueIdentifierExtension);

                        break;


                    case ExtensionTypes.NTSCookie:

                        var ntsCookieExtension = new NTSCookieExtension(data);

                        if (NTSCookie.TryParse(ntsCookieExtension.Value, out var encryptedCookie, out var err) &&
                            encryptedCookie.MasterKeyId.HasValue &&
                            MasterKeys is not null &&
                            MasterKeys.TryGetValue(encryptedCookie.MasterKeyId.Value, out var masterKey) &&
                            encryptedCookie.Timestamp >= masterKey.NotBefore &&
                            encryptedCookie.Timestamp <  masterKey.NotAfter)
                        {

                            var ntsCookie = encryptedCookie.Decrypt(masterKey);
                            NTSKey = ntsCookie.C2SKey;

                            extensions.Add(
                                new NTSCookieExtension(
                                    data,
                                    ntsCookie
                                )
                            );

                        }
                        else
                        {
                            extensions.Add(ntsCookieExtension);
                        }

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


                    case ExtensionTypes.NTSRequestSignedResponse:

                        if (!NTSRequestSignedResponseExtension.TryParse(data, out var requestSignedResponseExtension, out ErrorResponse))
                            return false;

                        extensions.Add(requestSignedResponseExtension);

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

            NTPRequest = new NTPRequest(

                            LI:                    (Byte) ((Buffer[0] >> 6) & 0x03),
                            VN:                    (Byte) ((Buffer[0] >> 3) & 0x07),
                            Mode:                  (Byte)  (Buffer[0]       & 0x07),
                            Stratum:               Buffer[1],
                            Poll:                  Buffer[2],
                            Precision:             (SByte) Buffer[3],
                            RootDelay:             (UInt32) ((Buffer[4]  << 24) | (Buffer[5]  << 16) | (Buffer[6]  << 8) | Buffer[7]),
                            RootDispersion:        (UInt32) ((Buffer[8]  << 24) | (Buffer[9]  << 16) | (Buffer[10] << 8) | Buffer[11]),
                            ReferenceIdentifier:   ReferenceIdentifier.From(Buffer[12], Buffer[13], Buffer[14], Buffer[15]),
                            ReferenceTimestamp:    ReadUInt64(Buffer, 16),
                            OriginateTimestamp:    ReadUInt64(Buffer, 24),
                            ReceiveTimestamp:      ReadUInt64(Buffer, 32),
                            TransmitTimestamp:     ReadUInt64(Buffer, 40),

                            Extensions:            extensions

                        );

            #endregion

            return true;

        }

        #endregion


    }

}
