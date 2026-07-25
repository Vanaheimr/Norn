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

using System.Diagnostics.CodeAnalysis;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTP
{

    /// <summary>
    /// Validates the extension field framing of an NTP packet against RFC 7822 before
    /// anything is decoded from it.
    ///
    /// Running as a single pass up front means the decoders that follow can assume every
    /// field is well framed, and — because the whole chain is checked before any field is
    /// interpreted — a malformed tail cannot be silently dropped while the rest of the
    /// packet is accepted.
    /// </summary>
    public static class NTPExtensionFieldValidator
    {

        /// <summary>The fixed NTP header, RFC 5905 § 7.3.</summary>
        public const Int32 HeaderLength = 48;

        /// <summary>
        /// RFC 7822 § 7.5.1.4: absent a MAC, the last extension field is at least 28 octets.
        /// </summary>
        public const Int32 MinimumLastFieldLength = 28;

        /// <summary>
        /// RFC 7822 § 7.5.1.4: absent a MAC, every field other than the last is at least
        /// 16 octets.
        /// </summary>
        public const Int32 MinimumFieldLength = 16;


        /// <summary>
        /// Check the extension field chain that follows the header.
        /// </summary>
        /// <param name="Buffer">The whole packet.</param>
        /// <param name="ErrorResponse">Why the framing is invalid, when it is.</param>
        public static Boolean TryValidate(Byte[]                            Buffer,
                                          [NotNullWhen(false)] out String?  ErrorResponse)
        {

            ErrorResponse = null;

            if (Buffer.Length < HeaderLength)
            {
                ErrorResponse = $"An NTP packet is at least {HeaderLength} octets long, got {Buffer.Length}!";
                return false;
            }

            // No extension fields at all is valid: a plain NTPv4 packet is just the header.
            if (Buffer.Length == HeaderLength)
                return true;

            var offset  = HeaderLength;
            var lengths = new List<Int32>();
            var counts  = new Dictionary<ExtensionTypes, Int32>();

            while (offset < Buffer.Length)
            {

                var remaining = Buffer.Length - offset;

                if (remaining < 4)
                {
                    ErrorResponse = $"{remaining} octet(s) of trailing data after the last extension field at offset {offset}: " +
                                     "an extension field header is 4 octets and RFC 7822 leaves no room for anything else!";
                    return false;
                }

                var length = (Buffer[offset + 2] << 8) | Buffer[offset + 3];

                if (length < 4)
                {
                    ErrorResponse = $"The extension field at offset {offset} declares a length of {length} octets, " +
                                     "but the Field Type and Length fields alone occupy 4!";
                    return false;
                }

                if (length % 4 != 0)
                {
                    ErrorResponse = $"The extension field at offset {offset} declares a length of {length} octets, " +
                                     "which is not a multiple of 4 (RFC 7822: fields are zero-padded to a four-octet boundary)!";
                    return false;
                }

                if (offset + length > Buffer.Length)
                {
                    ErrorResponse = $"The extension field at offset {offset} declares a length of {length} octets, " +
                                    $"which runs {offset + length - Buffer.Length} octet(s) past the end of the " +
                                    $"{Buffer.Length}-octet packet!";
                    return false;
                }

                var type      = (ExtensionTypes) ((Buffer[offset] << 8) | Buffer[offset + 1]);
                counts[type]  = counts.TryGetValue(type, out var seen) ? seen + 1 : 1;

                lengths.Add(length);
                offset += length;

            }

            // RFC 8915 § 5.7 allows exactly one Unique Identifier and exactly one
            // Authenticator field in an NTS-protected packet. Accepting two would leave it
            // undefined which one a peer is meant to match against, and would let an
            // attacker append a second one to change how the packet is read.
            foreach (var singleton in new[] { ExtensionTypes.UniqueIdentifier,
                                              ExtensionTypes.AuthenticatorAndEncrypted })
            {
                if (counts.TryGetValue(singleton, out var count) && count > 1)
                {
                    ErrorResponse = $"The packet carries {count} {singleton} extension fields; " +
                                     "RFC 8915 § 5.7 permits at most one!";
                    return false;
                }
            }

            for (var i = 0; i < lengths.Count; i++)
            {

                var isLast   = i == lengths.Count - 1;
                var minimum  = isLast ? MinimumLastFieldLength : MinimumFieldLength;

                if (lengths[i] < minimum)
                {
                    ErrorResponse = $"The {(isLast ? "last" : $"#{i + 1}")} extension field is {lengths[i]} octets; " +
                                    $"RFC 7822 § 7.5.1.4 requires at least {minimum} in a packet without a MAC!";
                    return false;
                }

            }

            return true;

        }

    }

}
