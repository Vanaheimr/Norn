﻿/*
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

    public static class NTPPacketExtensions
    {

        /// <summary>
        /// The value of an optional UniqueIdentifier extension.
        /// </summary>
        public static Byte[]?                                  UniqueIdentifier              (this NTPPacket NTPPacket)
            => NTPPacket.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.UniqueIdentifier)?.Value;

        /// <summary>
        /// The value of an optional UniqueIdentifier extension.
        /// </summary>
        public static UniqueIdentifierExtension?               UniqueIdentifierExtension     (this NTPPacket NTPPacket)
            => NTPPacket.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.UniqueIdentifier)              as UniqueIdentifierExtension;

        /// <summary>
        /// The value of an optional NTS Cookie extension.
        /// </summary>
        public static NTSCookieExtension?                      NTSCookieExtension            (this NTPPacket NTPPacket)
            => NTPPacket.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.NTSCookie)                     as NTSCookieExtension;

        /// <summary>
        /// The value of an optional NTS Request Signed Response extension.
        /// </summary>
        public static NTSRequestSignedResponseExtension?       NTSRequestSignedResponse      (this NTPPacket NTPPacket)
            => NTPPacket.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.NTSRequestSignedResponse)      as NTSRequestSignedResponseExtension;

        /// <summary>
        /// The value of an optional NTS Signed Response Announcement extension.
        /// </summary>
        public static NTSSignedResponseAnnouncementExtension?  NTSSignedResponseAnnouncement (this NTPPacket NTPPacket)
            => NTPPacket.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.NTSSignedResponseAnnouncement) as NTSSignedResponseAnnouncementExtension;

        /// <summary>
        /// The value of an optional NTS Signed Response extension.
        /// </summary>
        public static NTSSignedResponseExtension?              NTSSignedResponse             (this NTPPacket NTPPacket)
            => NTPPacket.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.NTSSignedResponse)             as NTSSignedResponseExtension;

    }


    // Stratum  Meaning
    //   ----------------------------------------------
    //   0        kiss-o'-death message (see below)
    //   1        primary reference (e.g., synchronized by radio clock)
    //   2-15     secondary reference (synchronized by NTP or SNTP)
    //   16-255   reserved


    /// <summary>
    /// The NTP request (RFC 5905).
    /// </summary>
    /// <param name="LI"></param>
    /// <param name="VN"></param>
    /// <param name="Mode"></param>
    /// <param name="Stratum"></param>
    /// <param name="Poll"></param>
    /// <param name="Precision"></param>
    /// <param name="RootDelay"></param>
    /// <param name="RootDispersion"></param>
    /// <param name="ReferenceIdentifier"></param>
    /// <param name="ReferenceTimestamp"></param>
    /// <param name="OriginateTimestamp"></param>
    /// <param name="ReceiveTimestamp"></param>
    /// <param name="TransmitTimestamp"></param>
    /// <param name="Extensions"></param>
    /// 
    /// <param name="Request"></param>
    /// <param name="ResponseBytes"></param>
    public class NTPPacket(Byte?                       LI                     = null,
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

                           NTPPacket?                  Request                = null,
                           Byte[]?                     ResponseBytes          = null,
                           String?                     ErrorMessage           = null)

    {

        #region Properties

        /// <summary>
        /// Leap Indicator (2 Bit, default: 0)
        /// </summary>
        public Byte                        LI                     { get; } = LI                  ?? 0;

        /// <summary>
        /// Version Number (3 Bit, default: 4)
        /// </summary>
        public Byte                        VN                     { get; } = VN                  ?? 4;

        /// <summary>
        /// Mode (3 Bit, client default: 3)
        /// </summary>
        public Byte                        Mode                   { get; } = Mode                ?? 3;

        /// <summary>
        /// Stratum (client default: 0)
        /// </summary>
        public Byte                        Stratum                { get; } = Stratum             ?? 0;

        /// <summary>
        /// Poll (2^n exponential value, e.g. 4 for 16 seconds)
        /// </summary>
        public Byte                        Poll                   { get; } = Poll                ?? 4;

        /// <summary>
        /// Precision (as two's complement, e.g. -6)
        /// </summary>
        public SByte                       Precision              { get; } = Precision           ?? -6;

        /// <summary>
        /// Root Delay (16.16 fixed point format)
        /// </summary>
        public UInt32                      RootDelay              { get; } = RootDelay           ?? 0;

        /// <summary>
        /// Root Dispersion (16.16 fixed point format)
        /// </summary>
        public UInt32                      RootDispersion         { get; } = RootDispersion      ?? 0;

        /// <summary>
        /// Reference Identifier
        /// </summary>
        public ReferenceIdentifier         ReferenceIdentifier    { get; } = ReferenceIdentifier ?? NTP.ReferenceIdentifier.Zero;

        /// <summary>
        /// Reference Timestamp (64 Bit)
        /// Default for clients: 0
        /// </summary>
        public UInt64                      ReferenceTimestamp     { get; } = ReferenceTimestamp  ?? 0;

        /// <summary>
        /// Originate Timestamp (64 Bit)
        /// Default for clients: 0
        /// </summary>
        public UInt64                      OriginateTimestamp     { get; } = OriginateTimestamp  ?? 0;

        /// <summary>
        /// Receive Timestamp (64 Bit)
        /// Default for clients: 0
        /// </summary>
        public UInt64                      ReceiveTimestamp       { get; } = ReceiveTimestamp    ?? 0;

        /// <summary>
        /// Transmit Timestamp (64 Bit)
        /// Will normally be set to the current time when the request is sent.
        /// </summary>
        public UInt64?                     TransmitTimestamp      { get; } = TransmitTimestamp;

        /// <summary>
        /// The optional enumeration of NTP extensions.
        /// </summary>
        public IEnumerable<NTPExtension>   Extensions             { get; } = Extensions          ?? [];

        /// <summary>
        /// Optional 4 byte key identification
        /// </summary>
        public Int32?                      KeyId                  { get; } = KeyId;

        /// <summary>
        /// Optional 16 byte message digest
        /// </summary>
        public Byte[]?                     MessageDigest          { get; } = MessageDigest;

        /// <summary>
        /// Optional 64 bit destination timestamp
        /// Note: This timestamp is not part of the packet itself!
        /// It is captured upon arrival and returned in the receive buffer along with the buffer length and data.
        /// </summary>
        public UInt64?                     DestinationTimestamp   { get; } = DestinationTimestamp;

        /// <summary>
        /// The optional NTP request that led to this response.
        /// </summary>
        public NTPPacket?                  Request                { get; } = Request;

        /// <summary>
        /// The optional byte representation of the response.
        /// </summary>
        public Byte[]?                     ResponseBytes          { get; } = ResponseBytes;

        /// <summary>
        /// An optional error message.
        /// </summary>
        public String?                     ErrorMessage           { get; } = ErrorMessage;

        #endregion

        #region Constructor(s)

        #region NTPPacket(NTPPacket,    Extensions = null)

        public NTPPacket(NTPPacket                   NTPPacket,
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

        #region NTPPacket(ErrorMessage, Extensions = null)

        public NTPPacket(String ErrorMessage)

            : this(0,
                   0,
                   0,
                   0,
                   0,
                   0,
                   0,
                   0,
                   ReferenceIdentifier.Zero,
                   0,
                   0,
                   0,
                   0,
                   [])

        {

            this.ErrorMessage = ErrorMessage;

        }

        #endregion

        #endregion


        #region ToByteArray(SkipExtensions = false)

        /// <summary>
        /// Get a binary of the NTP request (big-endian).
        /// </summary>
        public Byte[] ToByteArray(Boolean SkipExtensions = false)
        {

            var buffer = new Byte[48];

            // Byte 0: LI (2 Bit), VN (3 Bit), Mode (3 Bit)
            buffer[0] = (Byte) (((LI & 0x03) << 6) | ((VN & 0x07) << 3) | (Mode & 0x07));
            buffer[1] = Stratum;
            buffer[2] = Poll;
            buffer[3] = (Byte) Precision;

            WriteUInt32BigEndian(buffer,  4, RootDelay);
            WriteUInt32BigEndian(buffer,  8, RootDispersion);
            WriteUInt32BigEndian(buffer, 12, ReferenceIdentifier.Integer);
            WriteUInt64BigEndian(buffer, 16, ReferenceTimestamp);
            WriteUInt64BigEndian(buffer, 24, OriginateTimestamp);
            WriteUInt64BigEndian(buffer, 32, ReceiveTimestamp);

            if (TransmitTimestamp.HasValue)
                WriteUInt64BigEndian(buffer, 40, TransmitTimestamp.Value);

            else
            {

                var ntpTimestamp = GetCurrentNTPTimestamp();

                // Bytes 40-47:  Transmit Timestamp as big-endian
                for (var i = 0; i < 8; i++)
                    buffer[40 + i] = (Byte) (ntpTimestamp >> (56 - i * 8));

            }

            if (Extensions.Any() && !SkipExtensions)
            {

                var bufferLength = buffer.Length;

                Array.Resize(ref buffer, bufferLength + Extensions.Sum(extension => extension.Length));
                var offset       = bufferLength;

                foreach (var extension in Extensions)
                {
                    Buffer.BlockCopy(extension.ToByteArray(), 0, buffer, offset, extension.Length);
                    offset += extension.Length;
                }

            }

            return buffer;

        }

        #endregion

        #region (static) WriteUInt32BigEndian(buffer, offset, value)

        /// <summary>
        /// Schreibt eine 32-Bit-Zahl im big-endian Format in den Buffer.
        /// </summary>
        private static void WriteUInt32BigEndian(byte[] buffer, int offset, uint value)
        {
            buffer[offset]     = (byte)((value >> 24) & 0xFF);
            buffer[offset + 1] = (byte)((value >> 16) & 0xFF);
            buffer[offset + 2] = (byte)((value >> 8) & 0xFF);
            buffer[offset + 3] = (byte)(value & 0xFF);
        }

        #endregion

        #region (static) WriteUInt64BigEndian(buffer, offset, value)

        /// <summary>
        /// Schreibt eine 64-Bit-Zahl im big-endian Format in den Buffer.
        /// </summary>
        private static void WriteUInt64BigEndian(byte[] buffer, int offset, ulong value)
        {
            buffer[offset]     = (byte)((value >> 56) & 0xFF);
            buffer[offset + 1] = (byte)((value >> 48) & 0xFF);
            buffer[offset + 2] = (byte)((value >> 40) & 0xFF);
            buffer[offset + 3] = (byte)((value >> 32) & 0xFF);
            buffer[offset + 4] = (byte)((value >> 24) & 0xFF);
            buffer[offset + 5] = (byte)((value >> 16) & 0xFF);
            buffer[offset + 6] = (byte)((value >> 8) & 0xFF);
            buffer[offset + 7] = (byte)(value & 0xFF);
        }

        #endregion

        #region (static) GetCurrentNTPTimestamp(Timestamp = null)

        /// <summary>
        /// Converts DateTime.UtcNow to a 64-bit NTP time format (seconds since 1900).
        /// The upper 32 bits contain the seconds, the lower 32 bits the fraction of a second as 32-bit fixed-point (2^32 is 1 second).
        /// </summary>
        /// <param name="Timestamp">An optional timestamp (UTC) to be converted to a NTP timestamp.</param>
        public static UInt64 GetCurrentNTPTimestamp(DateTime? Timestamp = null)
        {

            var ntpEpoch  = new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var now       = Timestamp ?? DateTime.UtcNow;
            var ts        = now - ntpEpoch;

            var seconds   = (UInt64) ts.TotalSeconds;
            var fraction  = (UInt64) ((ts.TotalSeconds - seconds) * 0x100000000L);

            return (seconds << 32) | fraction;

        }

        #endregion


        #region (protected) ReadUInt64(Buffer, Offset)

        protected static UInt64 ReadUInt64(Byte[] Buffer, Int32 Offset)

            => ((UInt64) Buffer[Offset]     << 56) |
               ((UInt64) Buffer[Offset + 1] << 48) |
               ((UInt64) Buffer[Offset + 2] << 40) |
               ((UInt64) Buffer[Offset + 3] << 32) |
               ((UInt64) Buffer[Offset + 4] << 24) |
               ((UInt64) Buffer[Offset + 5] << 16) |
               ((UInt64) Buffer[Offset + 6] <<  8) |
                         Buffer[Offset + 7];

        #endregion


        #region NTPTimestampToDateTime(ntpTimestamp)

        /// <summary>
        /// Converts a 64-bit NTP timestamp to a DateTime (UTC).
        /// </summary>
        public static DateTime NTPTimestampToDateTime(UInt64 NTPTimestamp)
        {

            var secondsSinceEpoch  = (UInt32) (NTPTimestamp >> 32);
            var fraction           = (UInt32) (NTPTimestamp & 0xFFFFFFFF);
            var fractionSeconds    = fraction / (Double) 0x100000000L; // 2^32

            return new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc).
                       AddSeconds(secondsSinceEpoch + fractionSeconds);

        }

        #endregion


        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => ErrorMessage is not null
                   ? ErrorMessage
                   : $"{TransmitTimestamp}, stratum: {Stratum}";

        #endregion

    }

}
