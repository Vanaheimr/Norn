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

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTPv5
{

    /// <summary>
    /// One entry of a list of reference IDs, draft-ietf-ntp-ntpv5-10 § 7.4: a 56-bit
    /// reference ID and the share of the server's time it stands for, encoded in 8 bits.
    /// </summary>
    /// <param name="Share">The encoded share: 0 for 100 %, 255 for the least there is.</param>
    /// <param name="ReferenceId">The reference ID, 56 bits; 0 for an unused entry.</param>
    public readonly record struct NTPv5ReferenceIdEntry(Byte    Share,
                                                        UInt64  ReferenceId)
    {

        /// <summary>
        /// An unused entry: the minimum share and a zero reference ID.
        /// </summary>
        public static NTPv5ReferenceIdEntry Unused
            => new (NTPv5ReferenceIds.MinimumShare, 0);

        /// <summary>
        /// Whether this is an unused entry.
        /// </summary>
        public Boolean IsUnused
            => ReferenceId == 0;

    }


    /// <summary>
    /// A source of a server, as far as its reference IDs go: how much it weighs in the
    /// server's time, and the list of reference IDs it reported in its last Reference IDs
    /// Response - empty for one that does not speak NTPv5, a reference clock or an NTPv4
    /// server, which § 7.4 has contribute nothing.
    /// </summary>
    /// <param name="Weight">The weight of the source; only its ratio to the others counts.</param>
    /// <param name="ReferenceIds">The source's list, its own ID first.</param>
    public sealed record NTPv5ReferenceIdSource(Double                              Weight,
                                                IReadOnlyList<NTPv5ReferenceIdEntry> ReferenceIds);


    /// <summary>
    /// The list of reference IDs a server answers a Reference IDs Request with,
    /// draft-ietf-ntp-ntpv5-10 § 7.4: 32 entries, its own first with a share of 100 %, then
    /// its direct and indirect sources by decreasing share, the rest unused.
    /// </summary>
    /// <remarks>
    /// It replaced the Bloom filter of the drafts before -10. A client that serves time
    /// itself finds its own ID in the list of a server that takes time from it, and stops
    /// taking time from that server: a loop is seen before it closes.
    /// </remarks>
    public sealed class NTPv5ReferenceIds
    {

        #region Data

        /// <summary>
        /// The entries of a full list.
        /// </summary>
        public const Int32  Capacity      = 32;

        /// <summary>
        /// The octets of one entry: the share and 7 octets of reference ID.
        /// </summary>
        public const Int32  EntryLength   = 8;

        /// <summary>
        /// The encoded share of 100 %.
        /// </summary>
        public const Byte   FullShare     = 0;

        /// <summary>
        /// The encoded share of the least there is, about 0.0016 %, and of an unused entry.
        /// </summary>
        public const Byte   MinimumShare  = 255;

        /// <summary>
        /// The 56 bits of a reference ID.
        /// </summary>
        public const UInt64 ReferenceIdMask = 0x00FF_FFFF_FFFF_FFFFUL;

        private readonly NTPv5ReferenceIdEntry[] entries;

        #endregion

        #region Properties

        /// <summary>
        /// The server's own reference ID, the first entry.
        /// </summary>
        public UInt64                               OwnReferenceId
            => entries[0].ReferenceId;

        /// <summary>
        /// All 32 entries, unused ones included.
        /// </summary>
        public IReadOnlyList<NTPv5ReferenceIdEntry>  Entries
            => entries;

        #endregion

        #region Constructor(s)

        private NTPv5ReferenceIds(NTPv5ReferenceIdEntry[] Entries)
        {
            this.entries = Entries;
        }

        #endregion


        #region (static) NewReferenceId()

        /// <summary>
        /// § 10: a randomly generated, non-zero 56-bit reference ID.
        /// </summary>
        public static UInt64 NewReferenceId()
        {

            Span<Byte> random = stackalloc Byte[8];

            UInt64 id;

            do
            {
                RandomNumberGenerator.Fill(random);
                id = BinaryPrimitives.ReadUInt64BigEndian(random) & ReferenceIdMask;
            }
            while (id == 0);

            return id;

        }

        #endregion

        #region (static) EncodeShare(Share) / DecodeShare(Share)

        /// <summary>
        /// § 7.4: the share s, from 0 to 1, as -16 log2 s rounded up and limited to 0 to 255 -
        /// so that what is encoded is never more than it was.
        /// </summary>
        public static Byte EncodeShare(Double Share)
        {

            if (Double.IsNaN(Share) || Share <= 0)
                return MinimumShare;

            if (Share >= 1)
                return FullShare;

            // The product of a share that is an exact power of two is an exact integer, and
            // must not be pushed to the next one by the last bit of the logarithm.
            var encoded = Math.Ceiling(Math.Round(-16 * Math.Log2(Share), 9));

            return (Byte) Math.Clamp(encoded, FullShare, MinimumShare);

        }

        /// <summary>
        /// § 7.4: the encoded share v as 2^(-v/16).
        /// </summary>
        public static Double DecodeShare(Byte Share)

            => Math.Pow(2, -Share / 16.0);

        #endregion

        #region (static) Of(OwnReferenceId, Sources = null)

        /// <summary>
        /// § 7.4: the list of a server with the given reference ID and sources. Each source's
        /// shares, decoded, are scaled by one half and by the source's part of the total
        /// weight; an ID reported by more than one source has the sum. The 31 largest follow
        /// the server's own ID.
        /// </summary>
        public static NTPv5ReferenceIds Of(UInt64                                OwnReferenceId,
                                           IEnumerable<NTPv5ReferenceIdSource>?  Sources = null)
        {

            OwnReferenceId &= ReferenceIdMask;

            if (OwnReferenceId == 0)
                throw new ArgumentOutOfRangeException(nameof(OwnReferenceId), "A reference ID is not zero.");

            var sources      = Sources?.Where(source => source.Weight > 0 && !Double.IsNaN(source.Weight)).ToArray() ?? [];
            var totalWeight  = sources.Sum(source => source.Weight);
            var shares       = new Dictionary<UInt64, Double>();

            foreach (var source in sources)
            {

                var weight = source.Weight / totalWeight;

                foreach (var entry in source.ReferenceIds)
                {

                    var id = entry.ReferenceId & ReferenceIdMask;

                    // Unused entries, and this server's own ID: a loop it is part of is its
                    // sources' to see, not a share of its own time to report back to them.
                    if (id == 0 || id == OwnReferenceId)
                        continue;

                    shares[id] = shares.GetValueOrDefault(id) + 0.5 * weight * DecodeShare(entry.Share);

                }

            }

            var entries = new NTPv5ReferenceIdEntry[Capacity];

            entries[0] = new (FullShare, OwnReferenceId);

            var index = 1;

            // By decreasing share, and among equal shares by ID, so that the same sources
            // always give the same list.
            foreach (var (id, share) in shares.OrderByDescending(pair => pair.Value).
                                               ThenBy          (pair => pair.Key).
                                               Take            (Capacity - 1))
            {
                entries[index++] = new (EncodeShare(share), id);
            }

            for (; index < Capacity; index++)
                entries[index] = NTPv5ReferenceIdEntry.Unused;

            return new (entries);

        }

        #endregion

        #region (static) TryRead(Value, out Entries)

        /// <summary>
        /// The entries of the value of a Reference IDs Response.
        /// </summary>
        public static Boolean TryRead(ReadOnlySpan<Byte>                                Value,
                                      out IReadOnlyList<NTPv5ReferenceIdEntry>          Entries)
        {

            if (Value.Length % EntryLength != 0)
            {
                Entries = [];
                return false;
            }

            var entries = new NTPv5ReferenceIdEntry[Value.Length / EntryLength];

            for (var i = 0; i < entries.Length; i++)
            {
                var octets = BinaryPrimitives.ReadUInt64BigEndian(Value.Slice(i * EntryLength, EntryLength));
                entries[i] = new ((Byte) (octets >> 56), octets & ReferenceIdMask);
            }

            Entries = entries;
            return true;

        }

        #endregion

        #region TryAnswer(Request, out Response)

        /// <summary>
        /// § 7.4: the Reference IDs Response to a Reference IDs Request - as long as the
        /// request, the entries from its index on - or none, where the request is not one
        /// this server can answer and "MUST be ignored".
        /// </summary>
        /// <remarks>
        /// The length the draft speaks of, at least 8 and a multiple of 8, is that of the data
        /// after the 4-octet header: so read, a response of the same length holds a whole
        /// number of 8-octet entries, as it must. An index is valid for that length when the
        /// entries it asks for are all in the list of 32.
        /// </remarks>
        public Boolean TryAnswer(NTPv5ExtensionField                           Request,
                                 [System.Diagnostics.CodeAnalysis.NotNullWhen(true)]
                                 out NTPv5ExtensionField?                      Response)
        {

            Response = null;

            if (Request.Type != NTPv5ExtensionTypes.ReferenceIDsRequest ||
                Request.Value.Length < EntryLength ||
                Request.Value.Length % EntryLength != 0)
                return false;

            var first  = (Int32) Request.Value[0];
            var count  = Request.Value.Length / EntryLength;

            if (first + count > Capacity)
                return false;

            var value  = new Byte[Request.Value.Length];

            for (var i = 0; i < count; i++)
            {
                var entry = entries[first + i];
                BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(i * EntryLength, EntryLength),
                                                      ((UInt64) entry.Share << 56) | (entry.ReferenceId & ReferenceIdMask));
            }

            Response = new NTPv5ExtensionField(NTPv5ExtensionTypes.ReferenceIDsResponse, value);
            return true;

        }

        #endregion

        #region (static) Request(Index = 0, Entries = Capacity)

        /// <summary>
        /// § 7.4: a Reference IDs Request for the given number of entries from the given index,
        /// by default the whole list in one.
        /// </summary>
        public static NTPv5ExtensionField Request(Byte   Index    = 0,
                                                  Int32  Entries  = Capacity)
        {

            if (Entries is < 1 or > Capacity)
                throw new ArgumentOutOfRangeException(nameof(Entries), Entries, "A request is for 1 to 32 entries.");

            var value  = new Byte[Entries * EntryLength];
            value[0]   = Index;

            return new (NTPv5ExtensionTypes.ReferenceIDsRequest, value);

        }

        #endregion

    }

}
