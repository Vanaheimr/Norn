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

using System.Security.Cryptography;
using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// A NTS cookie as used by the NTS server.
    /// </summary>
    public class NTSCookie : IEquatable<NTSCookie>,
                             IComparable<NTSCookie>
    {

        #region Data

        /// <summary>
        /// The JSON-LD context of this object.
        /// </summary>
        public readonly static JSONLDContext DefaultJSONLDContext = JSONLDContext.Parse("https://graphdefined.org/context/vanaheimr/norn/nts/cookie");


        private const Byte    NonceLength         = 32;

        private const UInt16  OffsetTimestamp     =                     0;
        private const UInt16  OffsetMasterKeyId   = OffsetTimestamp   + 8;
        private const UInt16  OffsetNonce         = OffsetMasterKeyId + 8;
        private const UInt16  OffsetAlgorithmId   = OffsetNonce       + NonceLength;
        private const UInt16  OffsetC2SKey        = OffsetAlgorithmId + 2;
        // OffsetS2CKey variable!

        #endregion

        #region Properties

        public UInt64          MasterKeyId      { get; } = 0;
        public Byte[]          C2SKey           { get; } = [];
        public Byte[]          S2CKey           { get; } = [];
        public AEADAlgorithms  AEADAlgorithm    { get; } = AEADAlgorithms.AES_SIV_CMAC_256;
        public DateTimeOffset  Timestamp        { get; } = Illias.Timestamp.Now;
        public Byte[]          Nonce            { get; } = [];

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new NTS cookie.
        /// </summary>
        private NTSCookie(UInt64           MasterKeyId,
                          Byte[]           C2SKey,
                          Byte[]           S2CKey,
                          DateTimeOffset?  Timestamp       = null,
                          AEADAlgorithms?  AEADAlgorithm   = null,
                          Byte[]?          Nonce           = null)
        {

            #region Initial checks

            if (C2SKey.Length == 0)
                throw new ArgumentException("The C2SKey must not be empty!", nameof(C2SKey));

            if (S2CKey.Length == 0)
                throw new ArgumentException("The S2CKey must not be empty!", nameof(S2CKey));

            if (C2SKey.Length != S2CKey.Length)
                throw new ArgumentException("The C2SKey and S2CKey must be of the same length!");

            #endregion

            this.C2SKey         = C2SKey;
            this.S2CKey         = S2CKey;
            this.MasterKeyId    = MasterKeyId;
            this.AEADAlgorithm  = AEADAlgorithm ?? AEADAlgorithms.AES_SIV_CMAC_256;
            this.Timestamp      = Timestamp     ?? Illias.Timestamp.Now;
            this.Nonce          = Nonce         ?? RandomNumberGenerator.GetBytes(32);

            unchecked
            {

                hashCode = this.C2SKey.       GetHashCode() * 13 ^
                           this.S2CKey.       GetHashCode() * 11 ^
                           this.MasterKeyId.  GetHashCode() *  7 ^
                           this.AEADAlgorithm.GetHashCode() *  5 ^
                           this.Timestamp.    GetHashCode() *  3 ^
                           this.Nonce.        GetHashCode();

            }

        }

        #endregion


        public static NTSCookie Create(MasterKey        MasterKey,
                                       Byte[]           C2SKey,
                                       Byte[]           S2CKey,
                                       AEADAlgorithms?  AEADAlgorithm   = null)
        {

            return new (
                       C2SKey:          C2SKey,
                       S2CKey:          S2CKey,
                       MasterKeyId:     MasterKey.Id,
                       AEADAlgorithm:   AEADAlgorithm,
                       Timestamp:       Illias.Timestamp.Now,
                       Nonce:           RandomNumberGenerator.GetBytes(32)
                   );

        }


        #region (static) Parse    (JSON,  ...)

        /// <summary>
        /// Parse the given JSON representation of a NTS cookie.
        /// </summary>
        /// <param name="CustomNTSCookieParser">A delegate to parse custom NTSCookie JSON objects.</param>
        public static NTSCookie Parse(JObject                                  JSON,
                                      CustomJObjectParserDelegate<NTSCookie>?  CustomNTSCookieParser   = null)
        {

            if (TryParse(JSON,
                         out var ntsCookie,
                         out var errorResponse,
                         CustomNTSCookieParser))
            {
                return ntsCookie;
            }

            throw new ArgumentException("The given JSON representation of a NTS cookie is invalid: " + errorResponse,
                                        nameof(JSON));

        }

        #endregion

        #region (static) Parse    (Bytes, ...)

        /// <summary>
        /// Parse the given binary representation of a NTS cookie.
        /// </summary>
        public static NTSCookie Parse(Byte[] Bytes)
        {

            if (TryParse(Bytes,
                         out var ntsCookie,
                         out var errorResponse))
            {
                return ntsCookie;
            }

            throw new ArgumentException("The given binary representation of a NTS cookie is invalid: " + errorResponse,
                                        nameof(Bytes));

        }

        #endregion

        #region (static) TryParse (JSON,  out NTSCookie, out ErrorResponse, ...)

        // Note: The following is needed to satisfy pattern matching delegates! Do not refactor it!

        /// <summary>
        /// Try to parse the given JSON representation of a NTS cookie.
        /// </summary>
        /// <param name="JSON">The JSON to be parsed.</param>
        /// <param name="NTSCookie">The parsed NTS cookie.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(JObject                              JSON,
                                       [NotNullWhen(true)]  out NTSCookie?  NTSCookie,
                                       [NotNullWhen(false)] out String?     ErrorResponse)

            => TryParse(JSON,
                        out NTSCookie,
                        out ErrorResponse,
                        null);


        /// <summary>
        /// Try to parse the given JSON representation of a NTS cookie.
        /// </summary>
        /// <param name="JSON">The JSON to be parsed.</param>
        /// <param name="NTSCookie">The parsed NTS cookie.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        /// <param name="CustomNTSCookieParser">A delegate to parse custom NTSCookie JSON objects.</param>
        public static Boolean TryParse(JObject                                  JSON,
                                       [NotNullWhen(true)]  out NTSCookie?      NTSCookie,
                                       [NotNullWhen(false)] out String?         ErrorResponse,
                                       CustomJObjectParserDelegate<NTSCookie>?  CustomNTSCookieParser)
        {
            try
            {

                NTSCookie = null;

                #region MasterKeyId      [mandatory]

                if (!JSON.ParseMandatory("masterKeyId",
                                         "master key identification",
                                         out UInt64 masterKeyId,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region C2SKey           [mandatory]

                if (!JSON.ParseMandatoryText("c2sKey",
                                             "C2S key",
                                             out String? c2sKeyBASE64,
                                             out ErrorResponse))
                {
                    return false;
                }

                var c2sKey = c2sKeyBASE64.FromBASE64();

                #endregion

                #region S2CKey           [mandatory]

                if (!JSON.ParseMandatoryText("s2cKey",
                                             "S2C key",
                                             out String? s2cKeyBASE64,
                                             out ErrorResponse))
                {
                    return false;
                }

                var s2cKey = s2cKeyBASE64.FromBASE64();

                #endregion

                #region Timestamp        [mandatory]

                if (!JSON.ParseMandatory("timestamp",
                                         "NTS cookie timestamp",
                                         out DateTimeOffset timestamp,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region AEADAlgorithm    [optional]

                if (JSON.ParseOptional("aeadAlgorithm",
                                       "AEAD algorithm",
                                       AEADAlgorithmsExtensions.TryParse,
                                       out AEADAlgorithms? aeadAlgorithm,
                                       out ErrorResponse))
                {
                    if (ErrorResponse is not null)
                        return false;
                }

                #endregion

                #region Nonce            [mandatory]

                if (!JSON.ParseMandatoryText("nonce",
                                             "cryptographic nonce",
                                             out String? nonceBASE64,
                                             out ErrorResponse))
                {
                    return false;
                }

                var nonce = nonceBASE64.FromBASE64();

                #endregion


                NTSCookie = new NTSCookie(
                                masterKeyId,
                                c2sKey,
                                s2cKey,
                                timestamp,
                                aeadAlgorithm,
                                nonce
                            );

                if (CustomNTSCookieParser is not null)
                    NTSCookie = CustomNTSCookieParser(JSON,
                                                      NTSCookie);

                return true;

            }
            catch (Exception e)
            {
                NTSCookie      = default;
                ErrorResponse  = "The given JSON representation of a NTS cookie is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region (static) TryParse (Bytes, out NTSCookie, out ErrorResponse, ...)

        /// <summary>
        /// Try to parse the given binary representation of a NTS cookie.
        /// </summary>
        /// <param name="Bytes">The array of bytes to be parsed.</param>
        /// <param name="NTSCookie">The parsed NTS cookie.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(Byte[]                               Bytes,
                                       [NotNullWhen(true)]  out NTSCookie?  NTSCookie,
                                       [NotNullWhen(false)] out String?     ErrorResponse)
        {
            try
            {

                NTSCookie      = null;
                ErrorResponse  = null;


                Int64 timestampInt64   = 0;
                for (var j = 0; j < 8; j++)
                    timestampInt64   |= (Int64) (Bytes[OffsetTimestamp   + j] << (56 - 8 * j));

                Int64 masterKeyIdInt64 = 0;
                for (var j = 0; j < 8; j++)
                    masterKeyIdInt64 |= (Int64) (Bytes[OffsetMasterKeyId + j] << (56 - 8 * j));


                // The following should be **encrypted**!!!

                var nonce = new Byte[32];
                Array.Copy(Bytes, OffsetNonce, nonce, 0, nonce.Length);

                // AlgorithmId (Big-Endian)
                UInt16 algorithmIdUInt16 = 0;
                algorithmIdUInt16 |= (UInt16) (Bytes[OffsetAlgorithmId + 0] << 8);
                algorithmIdUInt16 |= (UInt16) (Bytes[OffsetAlgorithmId + 1] & 0xFF);
                var algorithmId = (AEADAlgorithms) algorithmIdUInt16;

                // Key length
                var keyLength = algorithmId switch {
                                    AEADAlgorithms.AES_SIV_CMAC_256 => 32,
                                    _ => 0
                                };

                // C2S key
                var c2sKey = new Byte[keyLength];
                Array.Copy(Bytes, OffsetC2SKey,           c2sKey, 0, c2sKey.Length);

                // S2C key
                var s2cKey = new Byte[keyLength];
                Array.Copy(Bytes, OffsetC2SKey+keyLength, s2cKey, 0, s2cKey.Length);


                NTSCookie = new NTSCookie(
                                (UInt64) masterKeyIdInt64,
                                c2sKey,
                                s2cKey,
                                DateTimeOffsetExtensions.FromUnixTimestamp(timestampInt64),
                                algorithmId,
                                nonce
                            );

                return true;

            }
            catch (Exception e)
            {
                NTSCookie      = default;
                ErrorResponse  = "The given JSON representation of a NTS cookie is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON      (IncludeJSONLDContext = false, CustomNTSCookieSerializer = null)

        /// <summary>
        /// Return a JSON representation of this NTS cookie.
        /// </summary>
        /// <param name="IncludeJSONLDContext">Whether to include the JSON-LD context or not.</param>
        /// <param name="CustomNTSCookieSerializer">A delegate to serialize custom NTSCookie objects.</param>
        public JObject ToJSON(Boolean                                      IncludeJSONLDContext        = false,
                              CustomJObjectSerializerDelegate<NTSCookie>?  CustomNTSCookieSerializer   = null)
        {

            var json = JSONObject.Create(

                           IncludeJSONLDContext
                               ? new JProperty("@context",        DefaultJSONLDContext.ToString())
                               : null,

                                 new JProperty("masterKeyId",     MasterKeyId),
                                 new JProperty("c2sKey",          C2SKey.              ToBase64()),
                                 new JProperty("s2cKey",          S2CKey.              ToBase64()),
                                 new JProperty("timestamp",       Timestamp.           ToISO8601()),

                           AEADAlgorithm != AEADAlgorithms.AES_SIV_CMAC_256
                               ? new JProperty("aeadAlgorithm",   AEADAlgorithm.       ToString())
                               : null,

                                 new JProperty("nonce",           Nonce.               ToBase64())

                       );

            return CustomNTSCookieSerializer is not null
                       ? CustomNTSCookieSerializer(this, json)
                       : json;

        }

        #endregion

        #region ToByteArray ()

        /// <summary>
        /// Return a binary representation of this NTS cookie.
        /// </summary>
        public Byte[] ToByteArray()
        {

            #region Data

            var OffsetS2CKey   = (UInt16) (OffsetC2SKey + C2SKey.Length);
            var totalLength    = OffsetS2CKey + S2CKey.Length;

            var unixTimestamp  = (UInt64) Timestamp.ToUnixTimestamp();

            #endregion

            // NOTE: This is a vendor specific implementation of the NTS cookie format!
            // rfc8915 Section 6 https://datatracker.ietf.org/doc/html/rfc8915#name-suggested-format-for-nts-co
            // gives just some general hints about the cookie format!

            var cookie = new Byte[totalLength];

            // Timestamp (Big-Endian)
            for (var i = 0; i < 8; i++)
                cookie[OffsetTimestamp + i] = (Byte) (unixTimestamp >> (56 - 8 * i));

            // MasterKeyId (Big-Endian)
            //if (MasterKeyId.HasValue)
                for (var i = 0; i < 8; i++)
                    cookie[OffsetMasterKeyId + i] = (Byte) (MasterKeyId >> (56 - 8 * i));


            // The following should be **encrypted**!!!
            // ToDo: AEAD-Encrypt `cookie` with master key

            // Nonce (32 bytes)
            var nonce = RandomNumberGenerator.GetBytes(32);
            Buffer.BlockCopy(nonce, 0, cookie, OffsetNonce, nonce.Length);

            // AlgorithmId (Big-Endian)
            var algorithmBytes = AEADAlgorithm.GetBytes();
            cookie[OffsetAlgorithmId]     = algorithmBytes[0];
            cookie[OffsetAlgorithmId + 1] = algorithmBytes[1];

            // C2S/S2C keys
            Buffer.BlockCopy(C2SKey, 0, cookie, OffsetC2SKey,                 C2SKey.Length);
            Buffer.BlockCopy(S2CKey, 0, cookie, OffsetC2SKey + C2SKey.Length, S2CKey.Length);

            return cookie;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this NTS cookie.
        /// </summary>
        public NTSCookie Clone()

            => new (
                   MasterKeyId,
                   C2SKey.ToHexString().FromHEX(),
                   S2CKey.ToHexString().FromHEX(),
                   Timestamp,
                   AEADAlgorithm,
                   Nonce. ToHexString().FromHEX()
               );

        #endregion


        public Byte[] Encrypt(MasterKey MasterKey)
        {

            var ntsCookie  = MasterKey.Id != this.MasterKeyId

                                 ? new NTSCookie(
                                       MasterKey.Id,
                                       C2SKey,
                                       S2CKey,
                                       Timestamp,
                                       AEADAlgorithm,
                                       Nonce
                                 )

                                 : this;

            var bytes      = ntsCookie.ToByteArray();

            //// Timestamp (Big-Endian)
            //for (var j = 0; j < 8; j++)
            //    bytes[OffsetMasterKeyId + j] = (Byte) (MasterKey.Id >> (56 - 8 * j));


            // TODO: AEAD-Encrypt `cookie` with master key

            return bytes;

        }

        public NTSCookie Decrypt(MasterKey masterKey)
        {
            return this;
        }


        #region Operator overloading

        #region Operator == (NTSCookie1, NTSCookie2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="NTSCookie1">A NTS cookie.</param>
        /// <param name="NTSCookie2">Another NTS cookie.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (NTSCookie NTSCookie1,
                                           NTSCookie NTSCookie2)

            => NTSCookie1.Equals(NTSCookie2);

        #endregion

        #region Operator != (NTSCookie1, NTSCookie2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="NTSCookie1">A NTS cookie.</param>
        /// <param name="NTSCookie2">Another NTS cookie.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (NTSCookie NTSCookie1,
                                           NTSCookie NTSCookie2)

            => !NTSCookie1.Equals(NTSCookie2);

        #endregion

        #region Operator <  (NTSCookie1, NTSCookie2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="NTSCookie1">A NTS cookie.</param>
        /// <param name="NTSCookie2">Another NTS cookie.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (NTSCookie NTSCookie1,
                                          NTSCookie NTSCookie2)

            => NTSCookie1.CompareTo(NTSCookie2) < 0;

        #endregion

        #region Operator <= (NTSCookie1, NTSCookie2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="NTSCookie1">A NTS cookie.</param>
        /// <param name="NTSCookie2">Another NTS cookie.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (NTSCookie NTSCookie1,
                                           NTSCookie NTSCookie2)

            => NTSCookie1.CompareTo(NTSCookie2) <= 0;

        #endregion

        #region Operator >  (NTSCookie1, NTSCookie2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="NTSCookie1">A NTS cookie.</param>
        /// <param name="NTSCookie2">Another NTS cookie.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (NTSCookie NTSCookie1,
                                          NTSCookie NTSCookie2)

            => NTSCookie1.CompareTo(NTSCookie2) > 0;

        #endregion

        #region Operator >= (NTSCookie1, NTSCookie2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="NTSCookie1">A NTS cookie.</param>
        /// <param name="NTSCookie2">Another NTS cookie.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (NTSCookie NTSCookie1,
                                           NTSCookie NTSCookie2)

            => NTSCookie1.CompareTo(NTSCookie2) >= 0;

        #endregion

        #endregion

        #region IComparable<NTSCookie> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two NTS cookies.
        /// </summary>
        /// <param name="Object">A NTS cookie to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is NTSCookie ntsCookie
                   ? CompareTo(ntsCookie)
                   : throw new ArgumentException("The given object is not a NTS cookie!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(NTSCookie)

        /// <summary>
        /// Compares two NTS cookies.
        /// </summary>
        /// <param name="NTSCookie">A NTS cookie to compare with.</param>
        public Int32 CompareTo(NTSCookie? NTSCookie)
        {

            if (NTSCookie is null)
                throw new ArgumentNullException(nameof(NTSCookie), "The given NTS cookie must not be null!");

            var c = C2SKey.    ToHexString().CompareTo(NTSCookie.C2SKey.    ToHexString());

            if (c == 0)
                c = S2CKey.    ToHexString().CompareTo(NTSCookie.S2CKey.    ToHexString());

            // MasterKeyId

            if (c == 0)
                c = AEADAlgorithm.  CompareTo(NTSCookie.AEADAlgorithm);

            if (c == 0)
                c = Timestamp. ToISO8601().  CompareTo(NTSCookie.Timestamp. ToISO8601());

            if (c == 0)
                c = Nonce.     ToHexString().CompareTo(NTSCookie.Nonce.     ToHexString());

            return c;

        }

        #endregion

        #endregion

        #region IEquatable<NTSCookie> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two NTS cookies for equality.
        /// </summary>
        /// <param name="Object">A NTS cookie to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is NTSCookie ntsCookie &&
                   Equals(ntsCookie);

        #endregion

        #region Equals(NTSCookie)

        /// <summary>
        /// Compares two NTS cookies for equality.
        /// </summary>
        /// <param name="NTSCookie">A NTS cookie to compare with.</param>
        public Boolean Equals(NTSCookie? NTSCookie)

            => NTSCookie is not null &&
               C2SKey.               SequenceEqual(NTSCookie.C2SKey)                 &&
               S2CKey.               SequenceEqual(NTSCookie.S2CKey)                 &&
               //MasterKeyId.Equals(NTSCookie.MasterKeyId) &&
               AEADAlgorithm.        Equals       (NTSCookie.AEADAlgorithm)          &&
               Timestamp.ToISO8601().Equals       (NTSCookie.Timestamp.ToISO8601()) &&
               Nonce.                SequenceEqual(NTSCookie.Nonce);

        #endregion

        #endregion

        #region (override) GetHashCode()

        private readonly Int32 hashCode;

        /// <summary>
        /// Return the hash code of this object.
        /// </summary>
        public override Int32 GetHashCode()
            => hashCode;

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"{AEADAlgorithm} / '{Nonce.ToBase64()[12..]}' @ {Timestamp}";

        #endregion


    }

}
