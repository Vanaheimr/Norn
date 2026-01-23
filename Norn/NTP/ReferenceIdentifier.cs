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
using System.Runtime.InteropServices;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTP
{

    /// <summary>
    /// The NTP Reference Identifier.
    /// 
    /// This is a 32-bit bitstring identifying the particular reference source.
    /// 
    /// This field is significant only in server messages, where for stratum 0
    /// (kiss-o'-death message) and 1 (primary server), the value is a
    /// four-character ASCII string, left justified and zero padded to 32 bits.
    /// 
    /// For IPv4 secondary servers, the value is the 32-bit IPv4 address of
    /// the synchronization source.
    /// 
    /// For IPv6 and OSI secondary servers, the value is the first 32 bits of
    /// the MD5 hash of the IPv6 or NSAP address of the synchronization source.
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    public readonly struct ReferenceIdentifier : IId,
                                                 IComparable<ReferenceIdentifier>,
                                                 IEquatable<ReferenceIdentifier>
    {

        #region Data

        [FieldOffset(0)]
        private readonly UInt32  rawValue;

        [FieldOffset(0)]
        private readonly Byte    byte0;

        [FieldOffset(1)]
        private readonly Byte    byte1;

        [FieldOffset(2)]
        private readonly Byte    byte2;

        [FieldOffset(3)]
        private readonly Byte    byte3;

        #endregion

        #region Properties

        /// <summary>
        /// Indicates whether this identification is null or empty.
        /// </summary>
        public readonly Boolean  IsNullOrEmpty
            => false;

        /// <summary>
        /// Indicates whether this identification is NOT null or empty.
        /// </summary>
        public readonly Boolean  IsNotNullOrEmpty
            => true;

        /// <summary>
        /// The length of the reference identifier.
        /// </summary>
        public readonly UInt64   Length
            => (UInt64) AsASCII.Length;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new reference identifier based on the given bytes.
        /// </summary>
        /// <param name="Byte0">Byte 0</param>
        /// <param name="Byte1">Byte 1</param>
        /// <param name="Byte2">Byte 2</param>
        /// <param name="Byte3">Byte 3</param>
        private ReferenceIdentifier(Byte  Byte0,
                                    Byte  Byte1,
                                    Byte  Byte2,
                                    Byte  Byte3)
        {

            byte0 = Byte0;
            byte1 = Byte1;
            byte2 = Byte2;
            byte3 = Byte3;

        }

        #endregion


        #region Bytes

        /// <summary>
        /// The reference identifier as an array of bytes.
        /// </summary>
        public readonly Byte[] AsBytes
            => [ byte0, byte1, byte2, byte3 ];

        #endregion

        #region Integer

        /// <summary>
        /// The reference identifier as an integer.
        /// </summary>
        public readonly UInt32 Integer
            => rawValue;

        #endregion

        #region ASCII

        /// <summary>
        /// Whether the reference identifier is an ASCII string.
        /// </summary>
        public readonly Boolean IsASCII

            => byte0 >= 32 && byte0 <= 126 &&
               byte1 >= 32 && byte1 <= 126 &&
               byte2 >= 32 && byte2 <= 126 &&
               byte3 >= 32 && byte3 <= 126;

        /// <summary>
        /// The reference identifier as an ASCII string.
        /// </summary>
        public readonly String AsASCII
            => Encoding.ASCII.GetString([byte0, byte1, byte2, byte3]).TrimEnd('\0');

        #endregion

        #region ErrorString

        /// <summary>
        /// The reference identifier as an error string.
        /// </summary>
        public String? ErrorString
        {
            get
            {

                var ascii = AsASCII;

                return IsASCII

                           ? ascii switch {

                                 // https://datatracker.ietf.org/doc/html/rfc5905
                                 // 7.4. The Kiss-o'-Death Packet
                                 "ACST" => $"'{ascii}' The association belongs to a unicast server",
                                 "AUTH" => $"'{ascii}' Server authentication failed",
                                 "AUTO" => $"'{ascii}' Autokey sequence failed",
                                 "BCST" => $"'{ascii}' The association belongs to a broadcast server",
                                 "CRYP" => $"'{ascii}' Cryptographic authentication or identification failed",
                                 "DENY" => $"'{ascii}' Access denied by remote server",
                                 "DROP" => $"'{ascii}' Lost peer in symmetric mode",
                                 "RSTR" => $"'{ascii}' Access denied due to local policy",
                                 "INIT" => $"'{ascii}' The association has not yet synchronized for the first time",
                                 "MCST" => $"'{ascii}' The association belongs to a dynamically discovered server",
                                 "NKEY" => $"'{ascii}' No key found.Either the key was never installed or is not trusted",
                                 "RATE" => $"'{ascii}' Rate exceeded.The server has temporarily denied access because the client exceeded the rate threshold",
                                 "RMOT" => $"'{ascii}' Alteration of association from a remote host running ntpdc",
                                 "STEP" => $"'{ascii}' A step change in system time has occurred, but the association has not yet resynchronized",

                                 // https://datatracker.ietf.org/doc/html/rfc8915
                                 // 5.7. Protocol Details
                                 "NTSN" => $"'{ascii}' NTS Negative Acknowledgment (NAK)",

                                 _      => ascii

                             }

                           : null;

            }

        }

        #endregion

        #region TimeSource

        /// <summary>
        /// The reference identifier as time source.
        /// </summary>
        public String? TimeSource
        {
            get
            {

                var ascii = AsASCII;

                return IsASCII

                           ? ascii switch {

                              // https://datatracker.ietf.org/doc/html/rfc4330

                              // Code                 External Reference Source
                              // ---------------------------------------------------------------------------------
                                "LOCL" => $"'{ascii}' uncalibrated local clock",
                                "CESM" => $"'{ascii}' calibrated Cesium clock",
                                "RBDM" => $"'{ascii}' calibrated Rubidium clock",
                                "PPS"  => $"'{ascii}' calibrated quartz clock or other pulse-per-second source",
                                "IRIG" => $"'{ascii}' Inter-Range Instrumentation Group",
                                "ACTS" => $"'{ascii}' NIST telephone modem service",
                                "USNO" => $"'{ascii}' USNO telephone modem service",
                                "PTB"  => $"'{ascii}' PTB (Germany) telephone modem service",
                                "TDF"  => $"'{ascii}' Allouis (France) Radio 164 kHz",
                                "DCF"  => $"'{ascii}' Mainflingen (Germany) Radio 77.5 kHz",
                                "MSF"  => $"'{ascii}' Rugby (UK) Radio 60 kHz",
                                "WWV"  => $"'{ascii}' Ft. Collins (US) Radio 2.5, 5, 10, 15, 20 MHz",
                                "WWVB" => $"'{ascii}' Boulder (US) Radio 60 kHz",
                                "WWVH" => $"'{ascii}' Kauai Hawaii (US) Radio 2.5, 5, 10, 15 MHz",
                                "CHU"  => $"'{ascii}' Ottawa (Canada) Radio 3330, 7335, 14670 kHz",
                                "LORC" => $"'{ascii}' LORAN-C radionavigation system",
                                "OMEG" => $"'{ascii}' OMEGA radionavigation system",
                                "GPS"  => $"'{ascii}' Global Positioning Service",
                                 _     => ascii

                             }

                           : null;

            }

        }

        #endregion

        #region IPv4Address

        /// <summary>
        /// The reference identifier as an IPv4 address.
        /// </summary>
        public readonly IPv4Address? AsIPv4Address
            => new IPv4Address([ byte0, byte1, byte2, byte3 ]);

        #endregion


        #region (static) Zero

        public static ReferenceIdentifier Zero

            => new (0,0,0,0);

        #endregion

        #region (static) From (Text)

        public static ReferenceIdentifier From(String Text)
        {

            if (Text.Length > 4)
                throw new ArgumentException("Text must be less or equals 4 characters.", nameof(Text));

            return From(Encoding.ASCII.GetBytes(Text));

        }

        #endregion

        #region (static) From (Integer)

        public static ReferenceIdentifier From(UInt32 Integer)

                   => new (
                          (Byte)  (Integer >> 24),
                          (Byte) ((Integer >> 16) & 0xFF),
                          (Byte) ((Integer >>  8) & 0xFF),
                          (Byte)  (Integer        & 0xFF)
                       );

        #endregion

        #region (static) From (ByteArray)

        public static ReferenceIdentifier From(Byte[] ByteArray)
        {

            if (ByteArray.Length > 4)
                throw new ArgumentException("Byte array must be less or equals 4 bytes.", nameof(ByteArray));

            Span<Byte> buffer = stackalloc Byte[4];
            ByteArray.CopyTo(buffer);

            return new (
                       buffer[0],
                       buffer[1],
                       buffer[2],
                       buffer[3]
                   );

        }

        #endregion

        #region (static) From (Byte0, Byte1, Byte2, Byte3)

        public static ReferenceIdentifier From(Byte  Byte0,
                                               Byte  Byte1,
                                               Byte  Byte2,
                                               Byte  Byte3)

            => new (
                   Byte0,
                   Byte1,
                   Byte2,
                   Byte3
               );

        #endregion


        #region Operator overloading

        #region Operator == (ReferenceIdentifier1, ReferenceIdentifier2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ReferenceIdentifier1">A charging profile identification.</param>
        /// <param name="ReferenceIdentifier2">Another charging profile identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (ReferenceIdentifier ReferenceIdentifier1,
                                           ReferenceIdentifier ReferenceIdentifier2)

            => ReferenceIdentifier1.Equals(ReferenceIdentifier2);

        #endregion

        #region Operator != (ReferenceIdentifier1, ReferenceIdentifier2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ReferenceIdentifier1">A charging profile identification.</param>
        /// <param name="ReferenceIdentifier2">Another charging profile identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (ReferenceIdentifier ReferenceIdentifier1,
                                           ReferenceIdentifier ReferenceIdentifier2)

            => !ReferenceIdentifier1.Equals(ReferenceIdentifier2);

        #endregion

        #region Operator <  (ReferenceIdentifier1, ReferenceIdentifier2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ReferenceIdentifier1">A charging profile identification.</param>
        /// <param name="ReferenceIdentifier2">Another charging profile identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (ReferenceIdentifier ReferenceIdentifier1,
                                          ReferenceIdentifier ReferenceIdentifier2)

            => ReferenceIdentifier1.rawValue < ReferenceIdentifier2.rawValue;

        #endregion

        #region Operator <= (ReferenceIdentifier1, ReferenceIdentifier2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ReferenceIdentifier1">A charging profile identification.</param>
        /// <param name="ReferenceIdentifier2">Another charging profile identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (ReferenceIdentifier ReferenceIdentifier1,
                                           ReferenceIdentifier ReferenceIdentifier2)

            => ReferenceIdentifier1.rawValue <= ReferenceIdentifier2.rawValue;

        #endregion

        #region Operator >  (ReferenceIdentifier1, ReferenceIdentifier2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ReferenceIdentifier1">A charging profile identification.</param>
        /// <param name="ReferenceIdentifier2">Another charging profile identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (ReferenceIdentifier ReferenceIdentifier1,
                                          ReferenceIdentifier ReferenceIdentifier2)

            => ReferenceIdentifier1.rawValue > ReferenceIdentifier2.rawValue;

        #endregion

        #region Operator >= (ReferenceIdentifier1, ReferenceIdentifier2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="ReferenceIdentifier1">A charging profile identification.</param>
        /// <param name="ReferenceIdentifier2">Another charging profile identification.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (ReferenceIdentifier ReferenceIdentifier1,
                                           ReferenceIdentifier ReferenceIdentifier2)

            => ReferenceIdentifier1.rawValue >= ReferenceIdentifier2.rawValue;

        #endregion

        #endregion

        #region IComparable<ReferenceIdentifier> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two reference identifiers.
        /// </summary>
        /// <param name="Object">A reference identifier to compare with.</param>
        public readonly Int32 CompareTo(Object? Object)

            => Object is ReferenceIdentifier referenceIdentifier
                   ? CompareTo(referenceIdentifier)
                   : throw new ArgumentException("The given object is not a reference identifier!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(ReferenceIdentifier)

        /// <summary>
        /// Compares two reference identifiers.
        /// </summary>
        /// <param name="ReferenceIdentifier">A reference identifier to compare with.</param>
        public readonly Int32 CompareTo(ReferenceIdentifier other)

            => rawValue.CompareTo(other.rawValue);

        #endregion

        #endregion

        #region IEquatable<ReferenceIdentifier> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two reference identifiers for equality.
        /// </summary>
        /// <param name="Object">A reference identifier to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is ReferenceIdentifier referenceIdentifier &&
                   Equals(referenceIdentifier);

        #endregion

        #region Equals(ReferenceIdentifier)

        /// <summary>
        /// Compares two reference identifiers for equality.
        /// </summary>
        /// <param name="ReferenceIdentifier">A reference identifier to compare with.</param>
        public readonly Boolean Equals(ReferenceIdentifier ReferenceIdentifier)

            => rawValue == ReferenceIdentifier.rawValue;

        #endregion

        #endregion

        #region (override) GetHashCode()

        /// <summary>
        /// Return the HashCode of this object.
        /// </summary>
        public override Int32 GetHashCode()

            => rawValue.GetHashCode();

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override readonly String ToString()
        {

            if (IsASCII)
            {

                if (ErrorString?.Length > 4)
                    return $"Error: \"{ErrorString}\"";

                return $"ASCII: \"{AsASCII}\"";

            }

            return $"IPv4/Raw: {AsIPv4Address} (0x{rawValue:X8})";

        }

        #endregion


    }

}
