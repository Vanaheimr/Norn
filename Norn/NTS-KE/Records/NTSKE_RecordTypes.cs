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

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    public static class NTSKE_RecordTypesExtensions
    {

        /// <summary>
        /// The type description of the NTS-KE record.
        /// </summary>
        /// <remarks>
        /// Switched on the full sixteen bits, not on a byte. The record type is a 15-bit field
        /// and IANA's registry reaches 32767, so a cast to Byte silently folds every type above
        /// 255 onto another one — record 1024 would have described itself as "End of Message".
        /// </remarks>
        public static String Description(this NTSKE_RecordTypes Type)

            => (UInt16) Type switch {

                   0 => "End of Message",
                   1 => "NTS Next Protocol Negotiation",
                   2 => "Error",
                   3 => "Warning",
                   4 => "AEAD Algorithm Negotiation",
                   5 => "New Cookie for NTPv4",
                   6 => "NTPv4 Server Negotiation (ASCII address?)",
                   7 => "NTPv4 Port Negotiation",

              0x4E00 => "NTS Request PublicKey",
              0x4E01 => "NTS PublicKey",
              0x4E02 => "SSH Key Binding",

                1024 => "Compliant AES-128-GCM-SIV Exporter Context",

                   _ => "Unknown or custom record type!"

               };

    }


    /// <summary>
    /// NTS-KE Record Types
    /// </summary>
    public enum NTSKE_RecordTypes : UInt16
    {

        /// <summary>
        /// The end of the message
        /// </summary>
        EndOfMessage                = 0,

        /// <summary>
        /// The NTS-KE protocol negotiation
        /// </summary>
        NTSNextProtocolNegotiation  = 1,

        /// <summary>
        /// The error message
        /// </summary>
        Error                       = 2,

        /// <summary>
        /// The warning message
        /// </summary>
        Warning                     = 3,

        /// <summary>
        /// The AEAD algorithm negotiation
        /// </summary>
        AEADAlgorithmNegotiation    = 4,

        /// <summary>
        /// The new cookie for NTPv4
        /// </summary>
        NewCookieForNTPv4           = 5,

        /// <summary>
        /// The NTPv4 server negotiation
        /// </summary>
        NTPv4ServerNegotiation      = 6,

        /// <summary>
        /// The NTPv4 port negotiation
        /// </summary>
        NTPv4PortNegotiation        = 7,


        // Vendor extensions, in IANA's Private or Experimental Use range.
        //
        // 16384 to 32767 is the only part of the registry an implementation may take values from
        // without asking. These used to sit at 32 and 33, inside 0-1023 - the range reserved for
        // IETF Review, where an implementation has no claim at all and where the pool draft has
        // since been assigned 8 to 14 - and then at 0x4000 to 0x4002, the very first values of
        // the private range and so the ones everybody else takes first: draft-ietf-ntp-ntpv5-10
        // § 11 has every client of the draft send its Draft Identification in record 0x4001, and
        // draft-venhoek-nts-pool used 0x4000 to 0x4005 before it was renumbered.
        //
        // 0x4E00 ('N') to 0x4E02 is used by nothing known: not the NTPv5 draft, not the pool
        // drafts, not ntpd-rs, not chrony, and IANA has nothing in the range. Collisions are still
        // possible by construction, nothing coordinates the private range; they matter only
        // between two implementations that both take values from it and then talk to each other.
        // The two public-key records go out non-critical, so a peer that has never heard of them
        // ignores them either way.


        /// <summary>
        /// NTS Request Public Key — a Norn extension, not an RFC 8915 record.
        /// </summary>
        NTSRequestPublicKey        = 0x4E00,

        /// <summary>
        /// NTS Public Key — a Norn extension, not an RFC 8915 record.
        /// </summary>
        NTSPublicKey               = 0x4E01,

        /// <summary>
        /// SSH Key Binding — NTS-KE over SSH, not an RFC 8915 record: where the keys come from
        /// when there is no TLS exporter, and the secret of option B.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Section 5 of the white paper "NTS Key Establishment over SSH". Provisional, from the
        /// same private range as the two records above; a coordinated value would be one from the
        /// "Specification Required" range 1024 to 16383.
        /// </para>
        /// <para>
        /// Unlike the two above it always goes out critical. It only ever travels over the SSH
        /// subsystem, whose name already says that the server knows it, and a server reached over
        /// TLS on port 4460 must refuse it rather than hand out keys the client cannot derive.
        /// </para>
        /// </remarks>
        SSHKeyBinding              = 0x4E02,


        /// <summary>
        /// Compliant AES-128-GCM-SIV Exporter Context: both peers can derive keys the way
        /// RFC 8915 § 5.1 says, rather than the way chrony does.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Registered with IANA as record type 1024 — reference chrony-project.org, in the range
        /// that requires a specification rather than the private-use range — and carried with an
        /// empty body and the critical bit clear, so that a peer which has never heard of it
        /// simply ignores it.
        /// </para>
        /// <para>
        /// It exists because chrony writes algorithm id 15 into the § 5.1 exporter context for
        /// sessions running on algorithm 30. A client that can do it properly sends this record;
        /// a server that agrees echoes it; and only then does either side use the compliant
        /// context. See <see cref="NTSKE_ExportedKeys.ExporterAlgorithmFor"/>, which is where the
        /// decision is actually made.
        /// </para>
        /// </remarks>
        CompliantAES128GCMSIVExporterContext = 1024


    }

}
