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
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using org.GraphDefined.Vanaheimr.Norn.NTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTPv5
{

    /// <summary>
    /// An NTPv5 message, draft-ietf-ntp-ntpv5-10 § 6: the 48-octet header and the extension
    /// fields after it.
    /// </summary>
    /// <remarks>
    /// A type of its own rather than an <see cref="NTPPacket"/> with another version number.
    /// The header shares only its first octet's layout with NTPv4: there is no leap indicator,
    /// no reference identifier and no origin or reference timestamp, and in their place are a
    /// timescale, an era, flags and two cookies. Read as an NTPv4 packet, the client cookie
    /// would pass for a reference timestamp and the server cookie for half the root delay.
    /// </remarks>
    public sealed class NTPv5Packet
    {

        #region Data

        /// <summary>
        /// The header, and the shortest valid message (§ 6).
        /// </summary>
        public const Int32  HeaderLength    = 48;

        /// <summary>
        /// The Version Number of NTPv5.
        /// </summary>
        public const Byte   VersionNumber   = 5;

        /// <summary>
        /// The Mode of a request.
        /// </summary>
        public const Byte   RequestMode     = 3;

        /// <summary>
        /// The Mode of a response.
        /// </summary>
        public const Byte   ResponseMode    = 4;

        /// <summary>
        /// § 6: a Poll of 127 tells the client the server does not want to hear from it again.
        /// </summary>
        public const SByte  PollGoAway      = 127;

        #endregion

        #region Properties

        /// <summary>
        /// The two Reserved bits that were the leap indicator of NTPv4. Sent as zero and, by
        /// § 6, ignored on receipt; kept only to show what was received.
        /// </summary>
        public Byte                                Reserved             { get; }

        /// <summary>
        /// The Mode: 3 for a request, 4 for a response.
        /// </summary>
        public Byte                                Mode                 { get; }

        /// <summary>
        /// The Stratum: 0 for unknown, or a server that cannot or will not tell the time; 1 for
        /// a primary server. Zero in a request.
        /// </summary>
        public Byte                                Stratum              { get; }

        /// <summary>
        /// The shortest poll interval the server allows, as a power of two in seconds;
        /// <see cref="PollGoAway"/> to send no more. Zero in a request.
        /// </summary>
        public SByte                               Poll                 { get; }

        /// <summary>
        /// The precision of the server's timestamps, as a power of two in seconds. Zero in a request.
        /// </summary>
        public SByte                               Precision            { get; }

        /// <summary>
        /// The Root Delay in <see cref="Time32"/>. Zero in a request.
        /// </summary>
        public UInt32                              RootDelay            { get; }

        /// <summary>
        /// The Root Dispersion in <see cref="Time32"/>. Zero in a request.
        /// </summary>
        public UInt32                              RootDispersion       { get; }

        /// <summary>
        /// In a request the timescale asked for, in a response the one its timestamps are in.
        /// </summary>
        public NTPv5Timescale                      Timescale            { get; }

        /// <summary>
        /// The NTP era of the receive timestamp. Zero in a request.
        /// </summary>
        public Byte                                Era                  { get; }

        /// <summary>
        /// The Flags.
        /// </summary>
        public NTPv5Flags                          Flags                { get; }

        /// <summary>
        /// The Server Cookie of the interleaved mode: zero, or in a request a copy of the one
        /// of the last response.
        /// </summary>
        public UInt64                              ServerCookie         { get; }

        /// <summary>
        /// The Client Cookie: random in a request, echoed in its response.
        /// </summary>
        public UInt64                              ClientCookie         { get; }

        /// <summary>
        /// The server's receive timestamp. Zero in a request.
        /// </summary>
        public UInt64                              ReceiveTimestamp     { get; }

        /// <summary>
        /// The server's transmit timestamp. Zero in a request.
        /// </summary>
        public UInt64                              TransmitTimestamp    { get; }

        /// <summary>
        /// The extension fields, in the order of the message.
        /// </summary>
        public IReadOnlyList<NTPv5ExtensionField>  ExtensionFields      { get; }

        /// <summary>
        /// The octets of the whole message.
        /// </summary>
        public Int32                               Length
            => HeaderLength + ExtensionFields.Sum(extensionField => extensionField.PaddedLength);

        /// <summary>
        /// The Root Delay as a duration, or null for infinity.
        /// </summary>
        public TimeSpan?                           RootDelayTime
            => Time32.ToTimeSpan(RootDelay);

        /// <summary>
        /// The Root Dispersion as a duration, or null for infinity.
        /// </summary>
        public TimeSpan?                           RootDispersionTime
            => Time32.ToTimeSpan(RootDispersion);

        /// <summary>
        /// The octets of the Draft Identification field, or null without one.
        /// </summary>
        public Byte[]?                             DraftIdentification
            => Find(NTPv5ExtensionTypes.DraftIdentification)?.Value;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// An NTPv5 message of the given fields; every field left out is zero.
        /// </summary>
        public NTPv5Packet(Byte                               Mode,
                           Byte                               Stratum             = 0,
                           SByte                              Poll                = 0,
                           SByte                              Precision           = 0,
                           UInt32                             RootDelay           = 0,
                           UInt32                             RootDispersion      = 0,
                           NTPv5Timescale                     Timescale           = NTPv5Timescale.UTC,
                           Byte                               Era                 = 0,
                           NTPv5Flags                         Flags               = NTPv5Flags.None,
                           UInt64                             ServerCookie        = 0,
                           UInt64                             ClientCookie        = 0,
                           UInt64                             ReceiveTimestamp    = 0,
                           UInt64                             TransmitTimestamp   = 0,
                           IEnumerable<NTPv5ExtensionField>?  ExtensionFields     = null,
                           Byte                               Reserved            = 0)
        {

            if (Mode > 7)
                throw new ArgumentOutOfRangeException(nameof(Mode),     Mode,     "The Mode is 3 bits.");

            if (Reserved > 3)
                throw new ArgumentOutOfRangeException(nameof(Reserved), Reserved, "The Reserved field is 2 bits.");

            this.Reserved           = Reserved;
            this.Mode               = Mode;
            this.Stratum            = Stratum;
            this.Poll               = Poll;
            this.Precision          = Precision;
            this.RootDelay          = RootDelay;
            this.RootDispersion     = RootDispersion;
            this.Timescale          = Timescale;
            this.Era                = Era;
            this.Flags              = Flags;
            this.ServerCookie       = ServerCookie;
            this.ClientCookie       = ClientCookie;
            this.ReceiveTimestamp   = ReceiveTimestamp;
            this.TransmitTimestamp  = TransmitTimestamp;
            this.ExtensionFields    = ExtensionFields?.ToArray() ?? [];

        }

        #endregion


        #region (static) Request(...)

        /// <summary>
        /// A client request as § 9 builds it: every header field zero but the version, the
        /// mode, the timescale, the flags, the server cookie and a fresh random client cookie,
        /// and the Draft Identification first among the extension fields, which § 7.1 asks of
        /// every request of a draft implementation.
        /// </summary>
        /// <param name="ClientCookie">The client cookie, by default a new random one.</param>
        /// <param name="Timescale">The timescale asked for (default: UTC).</param>
        /// <param name="Flags">The flags of the request.</param>
        /// <param name="ServerCookie">The server cookie of the last response, for the interleaved mode.</param>
        /// <param name="ExtensionFields">Further extension fields.</param>
        /// <param name="DraftIdentification">The draft to name, by default <see cref="NTPv5Draft.Identification"/>; the empty string for none.</param>
        public static NTPv5Packet Request(UInt64?                            ClientCookie         = null,
                                          NTPv5Timescale                     Timescale            = NTPv5Timescale.UTC,
                                          NTPv5Flags                         Flags                = NTPv5Flags.None,
                                          UInt64                             ServerCookie         = 0,
                                          IEnumerable<NTPv5ExtensionField>?  ExtensionFields      = null,
                                          String?                            DraftIdentification  = null)
        {

            var fields = new List<NTPv5ExtensionField>();

            if (DraftIdentification != String.Empty)
                fields.Add(NTPv5ExtensionField.DraftIdentification(DraftIdentification));

            fields.AddRange(ExtensionFields ?? []);

            return new (Mode:             RequestMode,
                        Timescale:        Timescale,
                        Flags:            Flags,
                        ServerCookie:     ServerCookie,
                        ClientCookie:     ClientCookie ?? NewClientCookie(),
                        ExtensionFields:  fields);

        }

        #endregion

        #region (static) NewClientCookie()

        /// <summary>
        /// A random client cookie from a cryptographic generator, never zero: § 12 has a
        /// client drop a response with a zero client cookie, as an NTPv4 server's answer.
        /// </summary>
        public static UInt64 NewClientCookie()
        {

            Span<Byte> cookie = stackalloc Byte[8];

            UInt64 value;

            do
            {
                RandomNumberGenerator.Fill(cookie);
                value = BinaryPrimitives.ReadUInt64BigEndian(cookie);
            }
            while (value == 0);

            return value;

        }

        #endregion

        #region (static) IsNTPv5(Datagram)

        /// <summary>
        /// Whether the version number of the given datagram is 5. Says nothing about whether
        /// the rest is a valid message.
        /// </summary>
        public static Boolean IsNTPv5(ReadOnlySpan<Byte> Datagram)

            => Datagram.Length > 0 &&
               ((Datagram[0] >> 3) & 0x07) == VersionNumber;

        #endregion

        #region (static) EraOf(Timestamp)

        /// <summary>
        /// The NTP era the given instant falls in, as the Era field carries it: 0 from 1900 to
        /// 2036-02-07T06:28:16Z, 1 for the 136 years after that, and so on.
        /// </summary>
        public static Byte EraOf(DateTime Timestamp)
        {

            // In integers: a Double holds 53 bits, and the ticks of 2036 need 56, so a division
            // in floating point lands a few ticks either side of the rollover.
            var ticks         = (Timestamp - NTPPacket.NTPEpoch).Ticks;
            var ticksPerEra   = NTPPacket.SecondsPerEra * TimeSpan.TicksPerSecond;
            var era           = ticks / ticksPerEra;

            if (ticks % ticksPerEra < 0)
                era--;

            return unchecked((Byte) era);

        }

        #endregion


        #region (static) ToTimestamp64(Elapsed)

        /// <summary>
        /// A duration in the timestamp64 format of § 5, 32.32 fixed point in seconds - for a
        /// clock that counts from an epoch of its own, as the monotonic one of § 7.9 does.
        /// Truncated to 32 bits of seconds, as an NTP timestamp is.
        /// </summary>
        public static UInt64 ToTimestamp64(TimeSpan Elapsed)
        {

            if (Elapsed <= TimeSpan.Zero)
                return 0;

            var seconds   = Elapsed.Ticks / TimeSpan.TicksPerSecond;
            var remainder = Elapsed.Ticks % TimeSpan.TicksPerSecond;

            return ((UInt64) (UInt32) seconds << 32) |
                   (UInt32) ((UInt64) remainder * 0x100000000UL / (UInt64) TimeSpan.TicksPerSecond);

        }

        #endregion


        #region (static) TryParse(Buffer, out Packet, out ErrorResponse)

        /// <summary>
        /// Parse an NTPv5 message, checking the framing of § 6 and § 7: at least the header, a
        /// whole number of 4 octets, version 5, and every extension field within the message,
        /// padded to 4 octets. What the fields mean is the business of whoever reads them.
        /// </summary>
        /// <param name="Buffer">The datagram.</param>
        /// <param name="Packet">The message, when it is one.</param>
        /// <param name="ErrorResponse">Why it is not, when it is not.</param>
        public static Boolean TryParse(ReadOnlySpan<Byte>                     Buffer,
                                       [NotNullWhen(true)]  out NTPv5Packet?  Packet,
                                       [NotNullWhen(false)] out String?       ErrorResponse)
        {

            Packet         = null;
            ErrorResponse  = null;

            if (Buffer.Length < HeaderLength)
            {
                ErrorResponse = $"An NTPv5 message is at least {HeaderLength} octets long, got {Buffer.Length}!";
                return false;
            }

            // § 6: "The maximum length is not specified, but the length MUST be divisible by 4
            // octets." Which is also what makes the walk below safe: every field starts on a
            // 4-octet boundary, so whatever is left there is a whole header or nothing.
            if ((Buffer.Length & 3) != 0)
            {
                ErrorResponse = $"An NTPv5 message is a whole number of 4 octets, got {Buffer.Length}!";
                return false;
            }

            var version = (Byte) ((Buffer[0] >> 3) & 0x07);

            if (version != VersionNumber)
            {
                ErrorResponse = $"Not an NTPv5 message, but version {version}!";
                return false;
            }

            var fields  = new List<NTPv5ExtensionField>();
            var offset  = HeaderLength;

            while (offset < Buffer.Length)
            {

                var type    = (NTPv5ExtensionTypes) BinaryPrimitives.ReadUInt16BigEndian(Buffer.Slice(offset,     2));
                var length  =                       BinaryPrimitives.ReadUInt16BigEndian(Buffer.Slice(offset + 2, 2));

                if (length < 4)
                {
                    ErrorResponse = $"The extension field at offset {offset} declares a length of {length} octets, " +
                                     "but its Type and Length fields alone occupy 4!";
                    return false;
                }

                // § 7: the Length leaves out the zeros that pad the field to the next 4 octets,
                // and they belong to the message all the same.
                var padded  = (length + 3) & ~3;

                if (offset + padded > Buffer.Length)
                {
                    ErrorResponse = $"The extension field at offset {offset} declares a length of {length} octets, " +
                                    $"which runs {offset + padded - Buffer.Length} octet(s) past the end of the " +
                                    $"{Buffer.Length}-octet message!";
                    return false;
                }

                fields.Add(new NTPv5ExtensionField(type, Buffer.Slice(offset + 4, length - 4).ToArray()));

                offset += padded;

            }

            Packet = new NTPv5Packet(
                         Reserved:           (Byte) (Buffer[0] >> 6),
                         Mode:               (Byte) (Buffer[0] & 0x07),
                         Stratum:                    Buffer[1],
                         Poll:               (SByte) Buffer[2],
                         Precision:          (SByte) Buffer[3],
                         RootDelay:          BinaryPrimitives.ReadUInt32BigEndian(Buffer.Slice( 4, 4)),
                         RootDispersion:     BinaryPrimitives.ReadUInt32BigEndian(Buffer.Slice( 8, 4)),
                         Timescale:          (NTPv5Timescale) Buffer[12],
                         Era:                Buffer[13],
                         Flags:              (NTPv5Flags) BinaryPrimitives.ReadUInt16BigEndian(Buffer.Slice(14, 2)),
                         ServerCookie:       BinaryPrimitives.ReadUInt64BigEndian(Buffer.Slice(16, 8)),
                         ClientCookie:       BinaryPrimitives.ReadUInt64BigEndian(Buffer.Slice(24, 8)),
                         ReceiveTimestamp:   BinaryPrimitives.ReadUInt64BigEndian(Buffer.Slice(32, 8)),
                         TransmitTimestamp:  BinaryPrimitives.ReadUInt64BigEndian(Buffer.Slice(40, 8)),
                         ExtensionFields:    fields
                     );

            return true;

        }

        #endregion

        #region Find(Type)

        /// <summary>
        /// The first extension field of the given type, or null.
        /// </summary>
        public NTPv5ExtensionField? Find(NTPv5ExtensionTypes Type)

            => ExtensionFields.FirstOrDefault(field => field.Type == Type);

        #endregion

        #region ToByteArray() / WriteTo(Destination)

        /// <summary>
        /// The message as it goes on the wire.
        /// </summary>
        public Byte[] ToByteArray()
        {

            var bytes = new Byte[Length];

            WriteTo(bytes);

            return bytes;

        }

        /// <summary>
        /// Write the message, <see cref="Length"/> octets.
        /// </summary>
        public void WriteTo(Span<Byte> Destination)
        {

            Destination[0] = (Byte) ((Reserved << 6) | (VersionNumber << 3) | (Mode & 0x07));
            Destination[1] = Stratum;
            Destination[2] = (Byte) Poll;
            Destination[3] = (Byte) Precision;

            BinaryPrimitives.WriteUInt32BigEndian(Destination.Slice( 4, 4), RootDelay);
            BinaryPrimitives.WriteUInt32BigEndian(Destination.Slice( 8, 4), RootDispersion);

            Destination[12] = (Byte) Timescale;
            Destination[13] = Era;

            BinaryPrimitives.WriteUInt16BigEndian(Destination.Slice(14, 2), (UInt16) Flags);
            BinaryPrimitives.WriteUInt64BigEndian(Destination.Slice(16, 8), ServerCookie);
            BinaryPrimitives.WriteUInt64BigEndian(Destination.Slice(24, 8), ClientCookie);
            BinaryPrimitives.WriteUInt64BigEndian(Destination.Slice(32, 8), ReceiveTimestamp);
            BinaryPrimitives.WriteUInt64BigEndian(Destination.Slice(40, 8), TransmitTimestamp);

            var offset = HeaderLength;

            foreach (var field in ExtensionFields)
            {
                field.WriteTo(Destination.Slice(offset, field.PaddedLength));
                offset += field.PaddedLength;
            }

        }

        #endregion

        #region (override) ToString()

        /// <inheritdoc/>
        public override String ToString()

            => $"NTPv5 mode {Mode}, stratum {Stratum}, {Timescale}, era {Era}, flags {Flags}, " +
               $"{ExtensionFields.Count} extension field(s), {Length} octets";

        #endregion

    }

}
