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

using System.Text;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTPv5
{

    /// <summary>
    /// Everything of NTPv5 that belongs to one revision of the draft and will change before it
    /// is an RFC: the name of the draft, the codepoints it uses in place of the IANA ones still
    /// marked [[TBD]], and the magic of the version negotiation.
    /// </summary>
    /// <remarks>
    /// Kept in one place on purpose. The draft is still moving - -10 alone dropped leap
    /// seconds and replaced the reference-ID Bloom filter - and following it to the next
    /// revision should be a change of this file and of <see cref="NTPv5ExtensionTypes"/>, not
    /// a search through the code.
    /// </remarks>
    public static class NTPv5Draft
    {

        /// <summary>
        /// The draft this implementation follows, as the Draft Identification extension field
        /// of § 7.1 carries it: ASCII, the full name with its revision, no terminating zero.
        /// </summary>
        public const String  Identification        = "draft-ietf-ntp-ntpv5-10";

        /// <summary>
        /// <see cref="Identification"/> as the octets on the wire.
        /// </summary>
        public static ReadOnlySpan<Byte> IdentificationBytes
            => "draft-ietf-ntp-ntpv5-10"u8;

        /// <summary>
        /// § 12: the reference timestamp an NTPv4 client request carries to ask whether the
        /// server speaks NTPv5, and the server echoes to say yes. The draft-only value,
        /// "NTP5DRFT" in ASCII; the final one will be "NTP5NTP5" (<see cref="FinalNegotiationMagic"/>).
        /// </summary>
        public const UInt64  NegotiationMagic       = 0x4E54503544524654UL;

        /// <summary>
        /// § 12: the reference timestamp of the negotiation once NTPv5 is an RFC, "NTP5NTP5".
        /// A draft implementation must not answer it, since what it would agree to is not the
        /// draft it implements.
        /// </summary>
        public const UInt64  FinalNegotiationMagic  = 0x4E5450354E545035UL;

        /// <summary>
        /// § 11: the NTS Next Protocol ID of NTPv5 in drafts, for IANA to replace.
        /// </summary>
        public const UInt16  NTSNextProtocolId      = 0x8001;

        /// <summary>
        /// § 11: the NTS-KE record type in which a draft client names its draft (non-critical,
        /// ASCII, no trailing zeros).
        /// </summary>
        public const UInt16  NTSKEDraftRecordType   = 0x4001;

        /// <summary>
        /// Whether the given octets are exactly <see cref="Identification"/>. § 7.1 compares
        /// over the full length, so a longer or shorter name is another draft.
        /// </summary>
        public static Boolean IsThisDraft(ReadOnlySpan<Byte> Identification)
            => Identification.SequenceEqual(IdentificationBytes);

        /// <summary>
        /// The given Draft Identification as text, for logs.
        /// </summary>
        public static String Describe(ReadOnlySpan<Byte> Identification)
            => Encoding.ASCII.GetString(Identification);

    }


    /// <summary>
    /// The extension field types of draft-ietf-ntp-ntpv5-10 § 7, by their draft codepoints.
    /// IANA has assigned none of them yet ([[TBD]] in § 13).
    /// </summary>
    public enum NTPv5ExtensionTypes : UInt16
    {

        /// <summary>§ 7.2, any length, ignored by the receiver.</summary>
        Padding                     = 0xF501,

        /// <summary>§ 7.3, a MAC over everything before it.</summary>
        MessageAuthenticationCode   = 0xF502,

        /// <summary>§ 7.4, which reference IDs of the server's sources a client asks for.</summary>
        ReferenceIDsRequest         = 0xF503,

        /// <summary>§ 7.4, the reference IDs with their shares.</summary>
        ReferenceIDsResponse        = 0xF504,

        /// <summary>§ 7.6, the versions and flags a server supports.</summary>
        ServerInformation           = 0xF505,

        /// <summary>§ 7.7, delay corrections of transparent network devices.</summary>
        Correction                  = 0xF506,

        /// <summary>§ 7.8, when the server's clock was last set.</summary>
        ReferenceTimestamp          = 0xF507,

        /// <summary>§ 7.9, a receive timestamp of a clock free of steps.</summary>
        MonotonicReceiveTimestamp   = 0xF508,

        /// <summary>§ 7.10, the receive timestamp in another timescale.</summary>
        SecondaryReceiveTimestamp   = 0xF509,

        /// <summary>§ 7.5, which of the server's sources a client asks for.</summary>
        TimeSourcesRequest          = 0xF50A,

        /// <summary>§ 7.5, the server's sources.</summary>
        TimeSourcesResponse         = 0xF50B,

        /// <summary>§ 7.1, the draft a draft implementation follows. Gone in the RFC.</summary>
        DraftIdentification         = 0xF5FF

    }


    /// <summary>
    /// The Flags field of the NTPv5 header, § 6.
    /// </summary>
    [Flags]
    public enum NTPv5Flags : UInt16
    {

        /// <summary>No flag.</summary>
        None                = 0x0000,

        /// <summary>
        /// In a request: answer even when the timestamps are not fit to synchronize to.
        /// In a response: they are not.
        /// </summary>
        Unsynchronized      = 0x0001,

        /// <summary>
        /// In a request: interleaved mode, please. In a response: this one is interleaved.
        /// </summary>
        InterleavedMode     = 0x0002,

        /// <summary>
        /// In a request: answer even when the request fails to authenticate. In a response:
        /// it did.
        /// </summary>
        AuthenticationNAK   = 0x0004

    }


    /// <summary>
    /// The Timescale field of the NTPv5 header and of the Secondary Receive Timestamp, § 6.
    /// </summary>
    public enum NTPv5Timescale : Byte
    {

        /// <summary>Coordinated Universal Time.</summary>
        UTC  = 0,

        /// <summary>International Atomic Time.</summary>
        TAI  = 1,

        /// <summary>Universal Time 1.</summary>
        UT1  = 2

    }


    /// <summary>
    /// Whether a server answers NTPv5.
    /// </summary>
    public enum NTPv5Support
    {

        /// <summary>
        /// Not at all: an NTPv5 request is handled as before, by the NTPv4 code.
        /// </summary>
        Disabled,

        /// <summary>
        /// The draft of <see cref="NTPv5Draft.Identification"/>, and only to clients that name
        /// that draft (§ 7.1, § 11).
        /// </summary>
        Draft

    }

}
