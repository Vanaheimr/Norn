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

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTPv5
{

    /// <summary>
    /// The values of a Correction field, draft-ietf-ntp-ntpv5-10 § 7.7.
    /// </summary>
    /// <param name="OriginCorrection">The Delay Correction of the request, copied by the server.</param>
    /// <param name="OriginPathId">The Path ID of the request, copied by the server.</param>
    /// <param name="DelayCorrection">The delay added by network devices, signed 48.16 fixed point in nanoseconds.</param>
    /// <param name="PathId">The sum of the port IDs of those devices.</param>
    /// <param name="ChecksumComplement">What a device changes to keep the UDP checksum valid.</param>
    public readonly record struct NTPv5Correction(Int64   OriginCorrection,
                                                  UInt16  OriginPathId,
                                                  Int64   DelayCorrection,
                                                  UInt16  PathId,
                                                  UInt16  ChecksumComplement);


    public sealed partial class NTPv5ExtensionField
    {

        #region Data

        /// <summary>
        /// § 7.7: the Correction field is 28 octets.
        /// </summary>
        public const Int32 CorrectionLength                 = 28;

        /// <summary>
        /// § 7.8: the Reference Timestamp field is 12 octets.
        /// </summary>
        public const Int32 ReferenceTimestampLength         = 12;

        /// <summary>
        /// § 7.9: the Monotonic Receive Timestamp field is 16 octets.
        /// </summary>
        public const Int32 MonotonicReceiveTimestampLength  = 16;

        #endregion


        #region Correction(Correction = default)

        /// <summary>
        /// § 7.7: a Correction field, all zeros by default, as a client sends it.
        /// </summary>
        public static NTPv5ExtensionField Correction(NTPv5Correction Correction = default)
        {

            var value = new Byte[CorrectionLength - 4];

            BinaryPrimitives.WriteInt64BigEndian (value.AsSpan( 0, 8), Correction.OriginCorrection);
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan( 8, 2), Correction.OriginPathId);
            // Octets 10 and 11 are Reserved, sent as zero.
            BinaryPrimitives.WriteInt64BigEndian (value.AsSpan(12, 8), Correction.DelayCorrection);
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(20, 2), Correction.PathId);
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(22, 2), Correction.ChecksumComplement);

            return new (NTPv5ExtensionTypes.Correction, value);

        }

        #endregion

        #region TryReadCorrection(out Correction)

        /// <summary>
        /// The values of a Correction field of its fixed length.
        /// </summary>
        public Boolean TryReadCorrection(out NTPv5Correction Correction)
        {

            Correction = default;

            if (Type != NTPv5ExtensionTypes.Correction || Length != CorrectionLength)
                return false;

            Correction = new (OriginCorrection:    BinaryPrimitives.ReadInt64BigEndian (Value.AsSpan( 0, 8)),
                              OriginPathId:        BinaryPrimitives.ReadUInt16BigEndian(Value.AsSpan( 8, 2)),
                              DelayCorrection:     BinaryPrimitives.ReadInt64BigEndian (Value.AsSpan(12, 8)),
                              PathId:              BinaryPrimitives.ReadUInt16BigEndian(Value.AsSpan(20, 2)),
                              ChecksumComplement:  BinaryPrimitives.ReadUInt16BigEndian(Value.AsSpan(22, 2)));

            return true;

        }

        #endregion


        #region ReferenceTimestamp(Timestamp = 0)

        /// <summary>
        /// § 7.8: a Reference Timestamp field - zero in a request, in a response when the
        /// server's clock was last set.
        /// </summary>
        public static NTPv5ExtensionField ReferenceTimestamp(UInt64 Timestamp = 0)
        {

            var value = new Byte[ReferenceTimestampLength - 4];

            BinaryPrimitives.WriteUInt64BigEndian(value, Timestamp);

            return new (NTPv5ExtensionTypes.ReferenceTimestamp, value);

        }

        #endregion

        #region TryReadReferenceTimestamp(out Timestamp)

        /// <summary>
        /// The timestamp of a Reference Timestamp field of its fixed length.
        /// </summary>
        public Boolean TryReadReferenceTimestamp(out UInt64 Timestamp)
        {

            Timestamp = 0;

            if (Type != NTPv5ExtensionTypes.ReferenceTimestamp || Length != ReferenceTimestampLength)
                return false;

            Timestamp = BinaryPrimitives.ReadUInt64BigEndian(Value);
            return true;

        }

        #endregion


        #region MonotonicReceiveTimestamp(EpochId = 0, Timestamp = 0)

        /// <summary>
        /// § 7.9: a Monotonic Receive Timestamp field - both zero in a request, in a response
        /// the epoch of the server's monotonic clock and its reading at reception.
        /// </summary>
        public static NTPv5ExtensionField MonotonicReceiveTimestamp(UInt32  EpochId    = 0,
                                                                    UInt64  Timestamp  = 0)
        {

            var value = new Byte[MonotonicReceiveTimestampLength - 4];

            BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(0, 4), EpochId);
            BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(4, 8), Timestamp);

            return new (NTPv5ExtensionTypes.MonotonicReceiveTimestamp, value);

        }

        #endregion

        #region TryReadMonotonicReceiveTimestamp(out EpochId, out Timestamp)

        /// <summary>
        /// The values of a Monotonic Receive Timestamp field of its fixed length.
        /// </summary>
        public Boolean TryReadMonotonicReceiveTimestamp(out UInt32  EpochId,
                                                        out UInt64  Timestamp)
        {

            EpochId    = 0;
            Timestamp  = 0;

            if (Type != NTPv5ExtensionTypes.MonotonicReceiveTimestamp || Length != MonotonicReceiveTimestampLength)
                return false;

            EpochId    = BinaryPrimitives.ReadUInt32BigEndian(Value.AsSpan(0, 4));
            Timestamp  = BinaryPrimitives.ReadUInt64BigEndian(Value.AsSpan(4, 8));

            return true;

        }

        #endregion

    }

}
