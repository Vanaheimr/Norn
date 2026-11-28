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
using System.Net.Sockets;
using System.Text;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTPv5
{

    #region NTPv5TimeSourceIdType

    /// <summary>
    /// What kind of identifier a time source of draft-ietf-ntp-ntpv5-10 § 7.5 has.
    /// </summary>
    public enum NTPv5TimeSourceIdType : Byte
    {

        /// <summary>
        /// A source no other identifier describes; no identifier.
        /// </summary>
        None                 = 0,

        /// <summary>
        /// An NTP server or peer, or a source of another protocol, over IPv4: 4 octets.
        /// </summary>
        IPv4Address          = 1,

        /// <summary>
        /// An NTP server or peer, or a source of another protocol, over IPv6: 16 octets.
        /// </summary>
        IPv6Address          = 2,

        /// <summary>
        /// A reference clock, by its code from the IANA NTP Reference Identifier Codes
        /// registry: 4 octets.
        /// </summary>
        ReferenceIdentifier  = 3

    }

    #endregion

    #region NTPv5TimeSourceFlags

    /// <summary>
    /// The flags of a time source of § 7.5.
    /// </summary>
    [Flags]
    public enum NTPv5TimeSourceFlags : Byte
    {

        /// <summary>
        /// No flag.
        /// </summary>
        None           = 0,

        /// <summary>
        /// The source is authenticated, by a MAC or by NTS.
        /// </summary>
        Authenticated  = 0x1

    }

    #endregion

    #region NTPv5TimeSource

    /// <summary>
    /// One time source of a server, as § 7.5 lists it: its share in the server's clock,
    /// encoded as for the reference IDs of § 7.4, its flags, and its identifier.
    /// </summary>
    /// <param name="Share">The share, encoded as -16 log2 s rounded up: 0 for all of it, 255 for the least.</param>
    /// <param name="Flags">The flags.</param>
    /// <param name="IdType">The kind of identifier.</param>
    /// <param name="Identifier">The identifier, as many octets as its kind has.</param>
    public sealed record NTPv5TimeSource(Byte                   Share,
                                         NTPv5TimeSourceFlags   Flags,
                                         NTPv5TimeSourceIdType  IdType,
                                         Byte[]                 Identifier)
    {

        #region Properties

        /// <summary>
        /// The octets the source takes in a Time Sources Response: four, and its identifier.
        /// </summary>
        public Int32                   Length
            => 4 + Identifier.Length;

        /// <summary>
        /// Whether the source is authenticated.
        /// </summary>
        public Boolean                 IsAuthenticated
            => Flags.HasFlag(NTPv5TimeSourceFlags.Authenticated);

        /// <summary>
        /// The share, decoded: from 1 for all of it down to about 0.0016 %.
        /// </summary>
        public Double                  DecodedShare
            => NTPv5ReferenceIds.DecodeShare(Share);

        /// <summary>
        /// The address of a source identified by one.
        /// </summary>
        public System.Net.IPAddress?   IPAddress
            => IdType is NTPv5TimeSourceIdType.IPv4Address or NTPv5TimeSourceIdType.IPv6Address
                   ? new System.Net.IPAddress(Identifier)
                   : null;

        /// <summary>
        /// The code of a reference clock, such as "GPS" or "PPS", without its trailing zeros.
        /// </summary>
        public String?                 ReferenceIdentifierCode
            => IdType == NTPv5TimeSourceIdType.ReferenceIdentifier
                   ? Encoding.ASCII.GetString(Identifier).TrimEnd('\0')
                   : null;

        #endregion


        #region (static) Of(Address, Share, Authenticated = false)

        /// <summary>
        /// A source identified by its IPv4 or IPv6 address - an IPv4 address mapped to IPv6 as
        /// the IPv4 address it is.
        /// </summary>
        /// <param name="Address">The address.</param>
        /// <param name="Share">The share of the source, from 0 to 1.</param>
        /// <param name="Authenticated">Whether it is authenticated.</param>
        public static NTPv5TimeSource Of(System.Net.IPAddress  Address,
                                         Double                Share,
                                         Boolean               Authenticated = false)
        {

            if (Address.IsIPv4MappedToIPv6)
                Address = Address.MapToIPv4();

            return new (NTPv5ReferenceIds.EncodeShare(Share),
                        Authenticated ? NTPv5TimeSourceFlags.Authenticated : NTPv5TimeSourceFlags.None,
                        Address.AddressFamily == AddressFamily.InterNetworkV6
                            ? NTPv5TimeSourceIdType.IPv6Address
                            : NTPv5TimeSourceIdType.IPv4Address,
                        Address.GetAddressBytes());

        }

        #endregion

        #region (static) OfReferenceClock(Code, Share, Authenticated = false)

        /// <summary>
        /// A reference clock by its code of the IANA NTP Reference Identifier Codes registry,
        /// one to four ASCII characters, padded with zeros.
        /// </summary>
        /// <param name="Code">The code, such as "GPS".</param>
        /// <param name="Share">The share of the source, from 0 to 1.</param>
        /// <param name="Authenticated">Whether it is authenticated.</param>
        public static NTPv5TimeSource OfReferenceClock(String   Code,
                                                       Double   Share,
                                                       Boolean  Authenticated = false)
        {

            if (String.IsNullOrEmpty(Code) || Code.Length > 4 || Code.Any(c => c > 0x7F))
                throw new ArgumentException("A reference identifier is one to four ASCII characters.", nameof(Code));

            var identifier = new Byte[4];
            Encoding.ASCII.GetBytes(Code, identifier);

            return new (NTPv5ReferenceIds.EncodeShare(Share),
                        Authenticated ? NTPv5TimeSourceFlags.Authenticated : NTPv5TimeSourceFlags.None,
                        NTPv5TimeSourceIdType.ReferenceIdentifier,
                        identifier);

        }

        #endregion

        #region (static) Unidentified(Share, Authenticated = false)

        /// <summary>
        /// A source no other identifier describes.
        /// </summary>
        /// <param name="Share">The share of the source, from 0 to 1.</param>
        /// <param name="Authenticated">Whether it is authenticated.</param>
        public static NTPv5TimeSource Unidentified(Double   Share,
                                                   Boolean  Authenticated = false)

            => new (NTPv5ReferenceIds.EncodeShare(Share),
                    Authenticated ? NTPv5TimeSourceFlags.Authenticated : NTPv5TimeSourceFlags.None,
                    NTPv5TimeSourceIdType.None,
                    []);

        #endregion


        #region Equals / GetHashCode

        /// <inheritdoc/>
        public Boolean Equals(NTPv5TimeSource? Other)

            => Other is not null &&
               Share  == Other.Share  &&
               Flags  == Other.Flags  &&
               IdType == Other.IdType &&
               Identifier.AsSpan().SequenceEqual(Other.Identifier);

        /// <inheritdoc/>
        public override Int32 GetHashCode()

            => HashCode.Combine(Share, Flags, IdType, Convert.ToHexString(Identifier));

        #endregion

        /// <inheritdoc/>
        public override String ToString()

            => $"{IPAddress?.ToString() ?? ReferenceIdentifierCode ?? IdType.ToString()} ({DecodedShare:P1}{(IsAuthenticated ? ", authenticated" : "")})";

    }

    #endregion


    /// <summary>
    /// The Time Sources Request and Response of draft-ietf-ntp-ntpv5-10 § 7.5: a server's
    /// current time sources, for monitoring and debugging.
    /// </summary>
    /// <remarks>
    /// A list of where a server gets its time from is something an operator may not want to
    /// hand to anyone who asks, which is why § 7.5 speaks of the field as "supported and
    /// enabled": Norn's server answers it only where it was given a list.
    /// </remarks>
    public static class NTPv5TimeSources
    {

        #region Data

        /// <summary>
        /// § 7.5: the data of a request - the index and its padding - is at least 20 octets,
        /// room for one source of the longest kind, an IPv6 address, in the response.
        /// </summary>
        public const Int32 MinimumRequestDataLength = 20;

        #endregion


        #region Request(Index = 0, DataLength = MinimumRequestDataLength)

        /// <summary>
        /// A Time Sources Request for the sources from the given index on, with room for the
        /// given number of octets of them in the response.
        /// </summary>
        /// <param name="Index">The index of the first source, from 0.</param>
        /// <param name="DataLength">The data length of the request, at least 20 and a multiple of 4, which bounds the response.</param>
        public static NTPv5ExtensionField Request(Byte   Index       = 0,
                                                  Int32  DataLength  = MinimumRequestDataLength)
        {

            if (DataLength < MinimumRequestDataLength || DataLength % 4 != 0)
                throw new ArgumentOutOfRangeException(nameof(DataLength), DataLength, "The data of a Time Sources Request is at least 20 octets and a multiple of 4.");

            var value = new Byte[DataLength];
            value[0]  = Index;

            return new (NTPv5ExtensionTypes.TimeSourcesRequest, value);

        }

        #endregion

        #region TryAnswer(Sources, Request, out Response)

        /// <summary>
        /// § 7.5: the response to a Time Sources Request - the sources from its index on, as
        /// many as fit in the length of its data, none skipped to fit a shorter one in; empty
        /// where the index is not one of a source. False for a request that is none: data
        /// shorter than 20 octets or not a multiple of 4, which is ignored.
        /// </summary>
        /// <param name="Sources">The server's current sources.</param>
        /// <param name="Request">The request field.</param>
        /// <param name="Response">The response field.</param>
        public static Boolean TryAnswer(IReadOnlyList<NTPv5TimeSource>                   Sources,
                                        NTPv5ExtensionField                              Request,
                                        [NotNullWhen(true)] out NTPv5ExtensionField?     Response)
        {

            Response = null;

            if (Request.Type != NTPv5ExtensionTypes.TimeSourcesRequest ||
                Request.Value.Length < MinimumRequestDataLength       ||
                Request.Value.Length % 4 != 0)
                return false;

            var index    = Request.Value[0];
            var room     = Request.Value.Length;
            var answered = new List<NTPv5TimeSource>();
            var length   = 0;

            // "MUST NOT skip sources in its list": the first that does not fit ends the list.
            for (var i = (Int32) index; i < Sources.Count; i++)
            {

                if (length + Sources[i].Length > room)
                    break;

                answered.Add(Sources[i]);
                length += Sources[i].Length;

            }

            var value    = new Byte[length];
            var offset   = 0;

            foreach (var source in answered)
            {
                value[offset++] = source.Share;
                value[offset++] = (Byte) source.Flags;
                value[offset++] = (Byte) source.IdType;
                value[offset++] = (Byte) source.Identifier.Length;
                source.Identifier.CopyTo(value, offset);
                offset += source.Identifier.Length;
            }

            Response = new NTPv5ExtensionField(NTPv5ExtensionTypes.TimeSourcesResponse, value);
            return true;

        }

        #endregion

        #region TryRead(Value, out Sources)

        /// <summary>
        /// The sources of the value of a Time Sources Response. An identifier of a kind this
        /// reader does not know is kept as it came, by its length.
        /// </summary>
        public static Boolean TryRead(ReadOnlySpan<Byte>                    Value,
                                      out IReadOnlyList<NTPv5TimeSource>    Sources)
        {

            var sources = new List<NTPv5TimeSource>();
            Sources     = sources;

            var offset  = 0;

            while (offset < Value.Length)
            {

                if (offset + 4 > Value.Length)
                    return false;

                var share   = Value[offset];
                var flags   = (NTPv5TimeSourceFlags)  Value[offset + 1];
                var idType  = (NTPv5TimeSourceIdType) Value[offset + 2];
                var length  = Value[offset + 3];

                if (offset + 4 + length > Value.Length)
                    return false;

                if (ExpectedLength(idType) is Int32 expected && expected != length)
                    return false;

                sources.Add(new NTPv5TimeSource(share, flags, idType, Value.Slice(offset + 4, length).ToArray()));

                offset += 4 + length;

            }

            return true;

        }

        #endregion

        #region (private static) ExpectedLength(IdType)

        private static Int32? ExpectedLength(NTPv5TimeSourceIdType IdType)

            => IdType switch {
                   NTPv5TimeSourceIdType.None                 => 0,
                   NTPv5TimeSourceIdType.IPv4Address          => 4,
                   NTPv5TimeSourceIdType.IPv6Address          => 16,
                   NTPv5TimeSourceIdType.ReferenceIdentifier  => 4,
                   _                                          => null
               };

        #endregion

    }

}
