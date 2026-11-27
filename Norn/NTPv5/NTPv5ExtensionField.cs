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
using System.Text;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTPv5
{

    /// <summary>
    /// An extension field of an NTPv5 message, draft-ietf-ntp-ntpv5-10 § 7.
    /// </summary>
    /// <remarks>
    /// Not an <see cref="NTP.NTPExtension"/>: RFC 7822's minimum of 16 octets does not hold in
    /// NTPv5, where a field is as short as its 4-octet header and the Server Information field
    /// is 8 octets in all. And the Length of § 7 counts the field without the zeros that pad it
    /// to the next 4 octets of the message, so a field's length need not be a multiple of 4 -
    /// the Draft Identification is the one that usually is not.
    /// </remarks>
    public sealed partial class NTPv5ExtensionField
    {

        #region Properties

        /// <summary>
        /// The Type field. A type this implementation does not know keeps its value.
        /// </summary>
        public NTPv5ExtensionTypes  Type            { get; }

        /// <summary>
        /// The octets after the 4-octet header, up to the declared Length.
        /// </summary>
        public Byte[]               Value           { get; }

        /// <summary>
        /// The Length field: the header and <see cref="Value"/>, without the message-level padding.
        /// </summary>
        public Int32                Length
            => 4 + Value.Length;

        /// <summary>
        /// The octets the field takes in the message, padded to a multiple of 4.
        /// </summary>
        public Int32                PaddedLength
            => (Length + 3) & ~3;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// An extension field of the given type and value.
        /// </summary>
        public NTPv5ExtensionField(NTPv5ExtensionTypes  Type,
                                   Byte[]               Value)
        {

            ArgumentNullException.ThrowIfNull(Value);

            if (Value.Length > UInt16.MaxValue - 4)
                throw new ArgumentOutOfRangeException(nameof(Value), Value.Length, "An extension field is at most 65535 octets, header included.");

            this.Type   = Type;
            this.Value  = Value;

        }

        #endregion


        #region Padding(Length)

        /// <summary>
        /// § 7.2: a Padding field of the given length, header included, its data all zeros.
        /// </summary>
        public static NTPv5ExtensionField Padding(Int32 Length)
        {

            if (Length < 4)
                throw new ArgumentOutOfRangeException(nameof(Length), Length, "A Padding field is at least its 4-octet header.");

            return new (NTPv5ExtensionTypes.Padding, new Byte[Length - 4]);

        }

        #endregion

        #region DraftIdentification(Identification = NTPv5Draft.Identification)

        /// <summary>
        /// § 7.1: the Draft Identification of the given draft, by default the one Norn follows.
        /// </summary>
        public static NTPv5ExtensionField DraftIdentification(String? Identification = null)

            => new (NTPv5ExtensionTypes.DraftIdentification,
                    Encoding.ASCII.GetBytes(Identification ?? NTPv5Draft.Identification));

        #endregion

        #region ServerInformation(SupportedVersions = 0, SupportedFlags = None)

        /// <summary>
        /// § 7.6: the Server Information field, 8 octets. A request sends it with both values
        /// zero; a response says in them which versions (bit 0 for version 1) and which
        /// header flags the server supports.
        /// </summary>
        public static NTPv5ExtensionField ServerInformation(UInt16      SupportedVersions  = 0,
                                                            NTPv5Flags  SupportedFlags     = NTPv5Flags.None)
        {

            var value = new Byte[4];

            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(0, 2), SupportedVersions);
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(2, 2), (UInt16) SupportedFlags);

            return new (NTPv5ExtensionTypes.ServerInformation, value);

        }

        #endregion

        #region TryReadServerInformation(out SupportedVersions, out SupportedFlags)

        /// <summary>
        /// The two values of a Server Information field, when this is one of its fixed length.
        /// </summary>
        public Boolean TryReadServerInformation(out UInt16      SupportedVersions,
                                                out NTPv5Flags  SupportedFlags)
        {

            SupportedVersions  = 0;
            SupportedFlags     = NTPv5Flags.None;

            if (Type != NTPv5ExtensionTypes.ServerInformation || Value.Length != 4)
                return false;

            SupportedVersions  =               BinaryPrimitives.ReadUInt16BigEndian(Value.AsSpan(0, 2));
            SupportedFlags     = (NTPv5Flags)  BinaryPrimitives.ReadUInt16BigEndian(Value.AsSpan(2, 2));

            return true;

        }

        #endregion


        #region WriteTo(Destination)

        /// <summary>
        /// Write the field and its padding, <see cref="PaddedLength"/> octets.
        /// </summary>
        public void WriteTo(Span<Byte> Destination)
        {

            BinaryPrimitives.WriteUInt16BigEndian(Destination[..2],    (UInt16) Type);
            BinaryPrimitives.WriteUInt16BigEndian(Destination.Slice(2, 2), (UInt16) Length);

            Value.CopyTo(Destination[4..]);

            Destination[Length..PaddedLength].Clear();

        }

        #endregion

        #region (override) ToString()

        /// <inheritdoc/>
        public override String ToString()

            => Enum.IsDefined(Type)
                   ? $"{Type} ({Length} octets)"
                   : $"0x{(UInt16) Type:X4} ({Length} octets)";

        #endregion

    }

}
