/*
 * Copyright (c) 2010-2025 GraphDefined GmbH <achim.friedland@graphdefined.com>
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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// A NTS Public Key,
    /// which is e.g. used to sign NTS responses by a NTS server.
    /// </summary>
    public class PublicKey : IEquatable<PublicKey>,
                             IComparable<PublicKey>
    {

        #region Data

        /// <summary>
        /// The JSON-LD context of this object.
        /// </summary>
        public readonly static JSONLDContext DefaultJSONLDContext = JSONLDContext.Parse("https://graphdefined.org/context/vanaheimr/norn/nts/server/publicKey");

        #endregion

        #region Properties

        /// <summary>
        /// The key identification.
        /// </summary>
        public UInt16           Id                    { get; }

        /// <summary>
        /// The key value.
        /// </summary>
        public Byte[]           Value                 { get; }

        /// <summary>
        /// The optional multi-language description of the key.
        /// </summary>
        public I18NString?      Description           { get; }

        /// <summary>
        /// Elliptic curve used for the key.
        /// </summary>
        public String           EllipticCurve         { get; }

        /// <summary>
        /// Signature algorithm used with the key.
        /// </summary>
        public String           SignatureAlgorithm    { get; }

        /// <summary>
        /// The optional date/time from which the key is valid.
        /// </summary>
        public DateTimeOffset?  NotBefore             { get; }

        /// <summary>
        /// The optional date/time until which the key is valid.
        /// </summary>
        public DateTimeOffset?  NotAfter              { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new NTS server Public Key.
        /// </summary>
        /// <param name="Id">The key identification.</param>
        /// <param name="Value">The key value.</param>
        /// <param name="Description">An optional multi-language description of the key.</param>
        /// <param name="EllipticCurve">The optional elliptic curve used for the key (default: "secp256r1").</param>
        /// <param name="SignatureAlgorithm">The optional signature algorithm used with the key (default: "SHA-256withECDSA").</param>
        /// <param name="NotBefore">An optional date/time from which the key is valid.</param>
        /// <param name="NotAfter">An optional date/time until which the key is valid.</param>
        public PublicKey(UInt16           Id,
                         Byte[]           Value,
                         I18NString?      Description          = null,
                         String?          EllipticCurve        = null,
                         String?          SignatureAlgorithm   = null,
                         DateTimeOffset?  NotBefore            = null,
                         DateTimeOffset?  NotAfter             = null)

        {

            this.Id                  = Id;
            this.Value               = Value;
            this.Description         = Description;
            this.EllipticCurve       = EllipticCurve      ?? "secp256r1";
            this.SignatureAlgorithm  = SignatureAlgorithm ?? "SHA-256withECDSA";
            this.NotBefore           = NotBefore;
            this.NotAfter            = NotAfter;

            unchecked
            {

                hashCode = this.Id.                GetHashCode()       * 17 ^
                           this.Value.             GetHashCode()       * 13 ^
                          (this.Description?.      GetHashCode() ?? 0) * 11 ^
                           this.EllipticCurve.     GetHashCode()       *  7 ^
                           this.SignatureAlgorithm.GetHashCode()       *  5 ^
                          (this.NotBefore?.        GetHashCode() ?? 0) *  3 ^
                           this.NotAfter?.         GetHashCode() ?? 0;

            }

        }

        #endregion


        #region (static) Parse    (JSON, ...)

        /// <summary>
        /// Parse the given JSON representation of a public key.
        /// </summary>
        /// <param name="CustomPublicKeyParser">A delegate to parse custom PublicKey JSON objects.</param>
        public static PublicKey Parse(JObject                                  JSON,
                                      CustomJObjectParserDelegate<PublicKey>?  CustomPublicKeyParser   = null)
        {

            if (TryParse(JSON,
                         out var publicKey,
                         out var errorResponse,
                         CustomPublicKeyParser))
            {
                return publicKey;
            }

            throw new ArgumentException("The given JSON representation of a public key is invalid: " + errorResponse,
                                        nameof(JSON));

        }

        #endregion

        #region (static) Parse    (ByteArray, ...)

        /// <summary>
        /// Parse the given binary representation of a public key.
        /// </summary>
        public static PublicKey Parse(Byte[] ByteArray)
        {

            if (TryParse(ByteArray,
                         out var publicKey,
                         out var errorResponse))
            {
                return publicKey;
            }

            throw new ArgumentException("The given JSON representation of a binary public key is invalid: " + errorResponse,
                                        nameof(ByteArray));

        }

        #endregion

        #region (static) TryParse (JSON,      out PublicKey, out ErrorResponse, ...)

        // Note: The following is needed to satisfy pattern matching delegates! Do not refactor it!

        /// <summary>
        /// Try to parse the given JSON representation of a public key.
        /// </summary>
        /// <param name="JSON">The JSON to be parsed.</param>
        /// <param name="PublicKey">The parsed public key.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(JObject                              JSON,
                                       [NotNullWhen(true)]  out PublicKey?  PublicKey,
                                       [NotNullWhen(false)] out String?     ErrorResponse)

            => TryParse(JSON,
                        out PublicKey,
                        out ErrorResponse,
                        null);


        /// <summary>
        /// Try to parse the given JSON representation of a public key.
        /// </summary>
        /// <param name="JSON">The JSON to be parsed.</param>
        /// <param name="PublicKey">The parsed public key.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        /// <param name="CustomPublicKeyParser">A delegate to parse custom PublicKey JSON objects.</param>
        public static Boolean TryParse(JObject                                  JSON,
                                       [NotNullWhen(true)]  out PublicKey?      PublicKey,
                                       [NotNullWhen(false)] out String?         ErrorResponse,
                                       CustomJObjectParserDelegate<PublicKey>?  CustomPublicKeyParser)
        {
            try
            {

                PublicKey = null;

                #region Id                    [mandatory]

                if (!JSON.ParseMandatory("id",
                                         "key identification",
                                         out UInt16 id,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region Value                 [mandatory]

                if (!JSON.ParseMandatoryText("value",
                                             "public key value",
                                             out String? valueBase64,
                                             out ErrorResponse))
                {
                    return false;
                }

                if (valueBase64.IsNullOrEmpty())
                {
                    ErrorResponse = "The given public key must not be null or empty!";
                    return false;
                }

                if (!StringExtensions.TryParseBASE64(valueBase64, out var value, out var errorResponse))
                {
                    ErrorResponse = "The given public key is not a valid BASE64 string: " + errorResponse;
                    return false;
                }

                #endregion

                #region Description           [optional]

                if (JSON.ParseOptionalJSON("description",
                                           "not after",
                                           I18NString.TryParse,
                                           out I18NString? description,
                                           out ErrorResponse))
                {
                    if (ErrorResponse is not null)
                        return false;
                }

                #endregion

                #region EllipticCurve         [optional]

                var ellipticCurve       = JSON.GetString("ellipticCurve");

                #endregion

                #region SignatureAlgorithm    [optional]

                var signatureAlgorithm  = JSON.GetString("signatureAlgorithm");

                #endregion

                #region NotBefore             [optional]

                if (JSON.ParseOptional("notBefore",
                                       "not before",
                                       out DateTimeOffset? notBefore,
                                       out ErrorResponse))
                {
                    if (ErrorResponse is not null)
                        return false;
                }

                #endregion

                #region NotAfter              [optional]

                if (JSON.ParseOptional("notAfter",
                                       "not after",
                                       out DateTimeOffset? notAfter,
                                       out ErrorResponse))
                {
                    if (ErrorResponse is not null)
                        return false;
                }

                #endregion


                PublicKey = new PublicKey(
                                id,
                                value,
                                description,
                                ellipticCurve,
                                signatureAlgorithm,
                                notBefore,
                                notAfter
                            );

                if (CustomPublicKeyParser is not null)
                    PublicKey = CustomPublicKeyParser(JSON,
                                                      PublicKey);

                return true;

            }
            catch (Exception e)
            {
                PublicKey      = default;
                ErrorResponse  = "The given JSON representation of a public key is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region (static) TryParse (ByteArray, out PublicKey, out ErrorResponse, ...)

        /// <summary>
        /// Try to parse the given binary representation of a public key.
        /// </summary>
        /// <param name="ByteArray">The byte array to be parsed.</param>
        /// <param name="PublicKey">The parsed public key.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(Byte[]                               ByteArray,
                                       [NotNullWhen(true)]  out PublicKey?  PublicKey,
                                       [NotNullWhen(false)] out String?     ErrorResponse)
        {
            try
            {

                PublicKey      = null;
                ErrorResponse  = null;

                var id      = (UInt16) ((ByteArray[0] << 8) | ByteArray[1]);
                var length  = (UInt16) ((ByteArray[2] << 8) | ByteArray[3]);
                var value   = new Byte[length];

                if (length > ByteArray.Length - 4)
                {
                    ErrorResponse = "The given key value is too long!";
                    return false;
                }

                Buffer.BlockCopy(ByteArray, 4, value, 0, length);


                PublicKey = new PublicKey(
                                id,
                                value
                                //description,
                                //ellipticCurve,
                                //signatureAlgorithm,
                                //notBefore,
                                //notAfter
                            );

                return true;

            }
            catch (Exception e)
            {
                PublicKey      = default;
                ErrorResponse  = "The given JSON representation of a public key is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON      (IncludeJSONLDContext = false, CustomPublicKeySerializer = null)

        /// <summary>
        /// Return a JSON representation of this public key.
        /// </summary>
        /// <param name="IncludeJSONLDContext">Whether to include the JSON-LD context or not.</param>
        /// <param name="CustomPublicKeySerializer">A delegate to serialize custom PublicKey objects.</param>
        public JObject ToJSON(Boolean                                      IncludeJSONLDContext        = false,
                              CustomJObjectSerializerDelegate<PublicKey>?  CustomPublicKeySerializer   = null)
        {

            var json = JSONObject.Create(

                           IncludeJSONLDContext
                               ? new JProperty("@context",             DefaultJSONLDContext.ToString())
                               : null,

                                 new JProperty("id",                   Id),
                                 new JProperty("publicKey",            Value.               ToBase64()),

                           Description is not null
                               ? new JProperty("description",          Description.         ToJSON())
                               : null,

                                 new JProperty("ellipticCurve",        EllipticCurve),
                                 new JProperty("signatureAlgorithm",   SignatureAlgorithm),

                           NotBefore.HasValue
                               ? new JProperty("notBefore",            NotBefore.Value.     ToISO8601())
                               : null,

                           NotAfter. HasValue
                               ? new JProperty("notAfter",             NotAfter. Value.     ToISO8601())
                               : null

                       );

            return CustomPublicKeySerializer is not null
                       ? CustomPublicKeySerializer(this, json)
                       : json;

        }

        #endregion

        #region ToByteArray ()

        /// <summary>
        /// Return a binary representation of this public key.
        /// </summary>
        public Byte[] ToByteArray()
        {

            var bytes = new Byte[2 + 2 + Value.Length];

            bytes[0] = (Byte) ((Id >> 8) & 0xFF);
            bytes[1] = (Byte)  (Id       & 0xFF);

            var length = (UInt16) Value.Length;
            bytes[2] = (Byte) ((length       >> 8) & 0xFF);
            bytes[3] = (Byte)  (length             & 0xFF);

            Buffer.BlockCopy(Value, 0, bytes, 4, length);

            //ToDo: Add additional public key meta data!

            return bytes;

        }

        #endregion


        #region Clone()

        /// <summary>
        /// Clone this NTS server public key.
        /// </summary>
        public PublicKey Clone()

            => new (
                   Id,
                   Value.ToHexString().FromHEX(),
                   Description?.      Clone(),
                   EllipticCurve.     CloneString(),
                   SignatureAlgorithm.CloneString(),
                   NotBefore,
                   NotAfter
               );

        #endregion


        #region Operator overloading

        #region Operator == (PublicKey1, PublicKey2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="PublicKey1">A public key.</param>
        /// <param name="PublicKey2">Another public key.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (PublicKey PublicKey1,
                                           PublicKey PublicKey2)

            => PublicKey1.Equals(PublicKey2);

        #endregion

        #region Operator != (PublicKey1, PublicKey2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="PublicKey1">A public key.</param>
        /// <param name="PublicKey2">Another public key.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (PublicKey PublicKey1,
                                           PublicKey PublicKey2)

            => !PublicKey1.Equals(PublicKey2);

        #endregion

        #region Operator <  (PublicKey1, PublicKey2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="PublicKey1">A public key.</param>
        /// <param name="PublicKey2">Another public key.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (PublicKey PublicKey1,
                                          PublicKey PublicKey2)

            => PublicKey1.CompareTo(PublicKey2) < 0;

        #endregion

        #region Operator <= (PublicKey1, PublicKey2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="PublicKey1">A public key.</param>
        /// <param name="PublicKey2">Another public key.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (PublicKey PublicKey1,
                                           PublicKey PublicKey2)

            => PublicKey1.CompareTo(PublicKey2) <= 0;

        #endregion

        #region Operator >  (PublicKey1, PublicKey2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="PublicKey1">A public key.</param>
        /// <param name="PublicKey2">Another public key.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (PublicKey PublicKey1,
                                          PublicKey PublicKey2)

            => PublicKey1.CompareTo(PublicKey2) > 0;

        #endregion

        #region Operator >= (PublicKey1, PublicKey2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="PublicKey1">A public key.</param>
        /// <param name="PublicKey2">Another public key.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (PublicKey PublicKey1,
                                           PublicKey PublicKey2)

            => PublicKey1.CompareTo(PublicKey2) >= 0;

        #endregion

        #endregion

        #region IComparable<PublicKey> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two public keys.
        /// </summary>
        /// <param name="Object">A public key to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is PublicKey publicKey
                   ? CompareTo(publicKey)
                   : throw new ArgumentException("The given object is not a public key!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(PublicKey)

        /// <summary>
        /// Compares two public keys.
        /// </summary>
        /// <param name="PublicKey">A public key to compare with.</param>
        public Int32 CompareTo(PublicKey? PublicKey)
        {

            if (PublicKey is null)
                throw new ArgumentNullException(nameof(PublicKey), "The given public key must not be null!");

            var c = Id.                           CompareTo(PublicKey.Id);

            if (c == 0)
                c = Value.          ToHexString().CompareTo(PublicKey.Value.          ToHexString());

            if (c == 0 && NotBefore.HasValue && PublicKey.NotBefore.HasValue)
                c = NotBefore.Value.ToISO8601().  CompareTo(PublicKey.NotBefore.Value.ToISO8601());

            if (c == 0 && NotAfter. HasValue && PublicKey.NotAfter. HasValue)
                c = NotAfter. Value.ToISO8601().  CompareTo(PublicKey.NotAfter. Value.ToISO8601());

            return c;

        }

        #endregion

        #endregion

        #region IEquatable<PublicKey> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two public keys for equality.
        /// </summary>
        /// <param name="Object">A public key to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is PublicKey publicKey &&
                   Equals(publicKey);

        #endregion

        #region Equals(PublicKey)

        /// <summary>
        /// Compares two public keys for equality.
        /// </summary>
        /// <param name="PublicKey">A public key to compare with.</param>
        public Boolean Equals(PublicKey? PublicKey)

            => PublicKey is not null &&
               Id.                   Equals       (PublicKey.Id)                                            &&
               Value.                SequenceEqual(PublicKey.Value)                                         &&
              (Description?.         Equals       (PublicKey.Description) ?? PublicKey.Description is null) &&
               EllipticCurve.        Equals       (PublicKey.EllipticCurve)                                 &&
               SignatureAlgorithm.   Equals       (PublicKey.SignatureAlgorithm)                            &&
               NotBefore.            Equals       (PublicKey.NotBefore)                                     &&
               NotAfter.             Equals       (PublicKey.NotAfter);

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

            => $"{Id}: {Value.ToBase64()}, not before: {NotBefore}, not after: {NotAfter}";

        #endregion


    }

}
