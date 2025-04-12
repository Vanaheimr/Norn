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
    /// A NTS server key pair.
    /// </summary>
    public class KeyPair : IEquatable<KeyPair>,
                           IComparable<KeyPair>
    {

        #region Data

        /// <summary>
        /// The JSON-LD context of this object.
        /// </summary>
        public readonly static JSONLDContext DefaultJSONLDContext = JSONLDContext.Parse("https://graphdefined.org/context/vanaheimr/norn/nts/server/keyPair");

        #endregion

        #region Properties

        /// <summary>
        /// The key identification.
        /// </summary>
        public UInt16           Id                    { get; }

        /// <summary>
        /// The private key value.
        /// </summary>
        public Byte[]           PrivateKey            { get; }

        /// <summary>
        /// The public key value.
        /// </summary>
        public Byte[]           PublicKey             { get; }

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
        /// Create a new NTS server key pair.
        /// </summary>
        /// <param name="Id">The key identification.</param>
        /// <param name="PrivateKey">The private key value.</param>
        /// <param name="PublicKey">The public key value.</param>
        /// <param name="Description">An optional multi-language description of the key.</param>
        /// <param name="EllipticCurve">The optional elliptic curve used for the key (default: "secp256r1").</param>
        /// <param name="SignatureAlgorithm">The optional signature algorithm used with the key (default: "SHA-256withECDSA").</param>
        /// <param name="NotBefore">An optional date/time from which the key is valid.</param>
        /// <param name="NotAfter">An optional date/time until which the key is valid.</param>
        public KeyPair(UInt16           Id,
                       Byte[]           PrivateKey,
                       Byte[]           PublicKey,
                       I18NString?      Description          = null,
                       String?          EllipticCurve        = null,
                       String?          SignatureAlgorithm   = null,
                       DateTimeOffset?  NotBefore            = null,
                       DateTimeOffset?  NotAfter             = null)

        {

            this.Id                  = Id;
            this.PrivateKey          = PrivateKey;
            this.PublicKey           = PublicKey;
            this.Description         = Description;
            this.EllipticCurve       = EllipticCurve      ?? "secp256r1";
            this.SignatureAlgorithm  = SignatureAlgorithm ?? "SHA-256withECDSA";
            this.NotBefore           = NotBefore;
            this.NotAfter            = NotAfter;

            unchecked
            {

                hashCode = this.Id.                GetHashCode()       * 23 ^
                           this.PrivateKey.        GetHashCode()       * 17 ^
                           this.PublicKey.         GetHashCode()       * 13 ^
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
        /// Parse the given JSON representation of a key pair.
        /// </summary>
        /// <param name="CustomKeyPairParser">A delegate to parse custom key pair JSON objects.</param>
        public static KeyPair Parse(JObject                                JSON,
                                    CustomJObjectParserDelegate<KeyPair>?  CustomKeyPairParser   = null)
        {

            if (TryParse(JSON,
                         out var keyPair,
                         out var errorResponse,
                         CustomKeyPairParser))
            {
                return keyPair;
            }

            throw new ArgumentException("The given JSON representation of a key pair is invalid: " + errorResponse,
                                        nameof(JSON));

        }

        #endregion

        #region (static) TryParse (JSON, out KeyPair, out ErrorResponse, ...)

        // Note: The following is needed to satisfy pattern matching delegates! Do not refactor it!

        /// <summary>
        /// Try to parse the given JSON representation of a key pair.
        /// </summary>
        /// <param name="JSON">The JSON to be parsed.</param>
        /// <param name="KeyPair">The parsed key pair.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(JObject                            JSON,
                                       [NotNullWhen(true)]  out KeyPair?  KeyPair,
                                       [NotNullWhen(false)] out String?   ErrorResponse)

            => TryParse(JSON,
                        out KeyPair,
                        out ErrorResponse,
                        null);


        /// <summary>
        /// Try to parse the given JSON representation of a key pair.
        /// </summary>
        /// <param name="JSON">The JSON to be parsed.</param>
        /// <param name="KeyPair">The parsed key pair.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        /// <param name="CustomKeyPairParser">A delegate to parse custom KeyPair JSON objects.</param>
        public static Boolean TryParse(JObject                                JSON,
                                       [NotNullWhen(true)]  out KeyPair?      KeyPair,
                                       [NotNullWhen(false)] out String?       ErrorResponse,
                                       CustomJObjectParserDelegate<KeyPair>?  CustomKeyPairParser)
        {
            try
            {

                KeyPair = null;

                #region Id                    [mandatory]

                if (!JSON.ParseMandatory("id",
                                         "key identification",
                                         out UInt16 id,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region PrivateKey            [mandatory]

                if (!JSON.ParseMandatoryText("privateKey",
                                             "private key",
                                             out String? privateKeyBase64,
                                             out ErrorResponse))
                {
                    return false;
                }

                if (privateKeyBase64.IsNullOrEmpty())
                {
                    ErrorResponse = "The given private key must not be null or empty!";
                    return false;
                }

                if (!StringExtensions.TryParseBASE64(privateKeyBase64, out var privateKey, out var errorResponse1))
                {
                    ErrorResponse = "The given private key is not a valid BASE64 string: " + errorResponse1;
                    return false;
                }

                #endregion

                #region PublicKey            [mandatory]

                if (!JSON.ParseMandatoryText("publicKey",
                                             "public key",
                                             out String? publicKeyBase64,
                                             out ErrorResponse))
                {
                    return false;
                }

                if (publicKeyBase64.IsNullOrEmpty())
                {
                    ErrorResponse = "The given public key must not be null or empty!";
                    return false;
                }

                if (!StringExtensions.TryParseBASE64(publicKeyBase64, out var publicKey, out var errorResponse2))
                {
                    ErrorResponse = "The given public key is not a valid BASE64 string: " + errorResponse2;
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


                KeyPair = new KeyPair(
                              id,
                              privateKey,
                              publicKey,
                              description,
                              ellipticCurve,
                              signatureAlgorithm,
                              notBefore,
                              notAfter
                          );

                if (CustomKeyPairParser is not null)
                    KeyPair = CustomKeyPairParser(JSON,
                                                  KeyPair);

                return true;

            }
            catch (Exception e)
            {
                KeyPair        = default;
                ErrorResponse  = "The given JSON representation of a key pair is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON (IncludeJSONLDContext = false, CustomKeyPairSerializer = null)

        /// <summary>
        /// Return a JSON representation of this key pair.
        /// </summary>
        /// <param name="IncludeJSONLDContext">Whether to include the JSON-LD context or not.</param>
        /// <param name="CustomKeyPairSerializer">A delegate to serialize custom KeyPair objects.</param>
        public JObject ToJSON(Boolean                                    IncludeJSONLDContext      = false,
                              CustomJObjectSerializerDelegate<KeyPair>?  CustomKeyPairSerializer   = null)
        {

            var json = JSONObject.Create(

                           IncludeJSONLDContext
                               ? new JProperty("@context",             DefaultJSONLDContext.ToString())
                               : null,

                                 new JProperty("id",                   Id),
                                 new JProperty("privateKey",           PrivateKey.          ToBase64()),
                                 new JProperty("publicKey",            PublicKey.           ToBase64()),

                           Description is not null
                               ? new JProperty("description",          Description.         ToJSON())
                               : null,

                                 new JProperty("ellipticCurve",        EllipticCurve),
                                 new JProperty("signatureAlgorithm",   SignatureAlgorithm),

                           NotBefore.HasValue
                               ? new JProperty("notBefore",            NotBefore.Value.     ToIso8601())
                               : null,

                           NotAfter. HasValue
                               ? new JProperty("notAfter",             NotAfter. Value.     ToIso8601())
                               : null

                       );

            return CustomKeyPairSerializer is not null
                       ? CustomKeyPairSerializer(this, json)
                       : json;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this NTS server key pair.
        /// </summary>
        public KeyPair Clone()

            => new (
                   Id,
                   PrivateKey.ToHexString().FromHEX(),
                   PublicKey. ToHexString().FromHEX(),
                   Description?.      Clone(),
                   EllipticCurve.     CloneString(),
                   SignatureAlgorithm.CloneString(),
                   NotBefore,
                   NotAfter
               );

        #endregion


        #region ToPublicKey()

        /// <summary>
        /// Convert this NTS server key pair into a NTS public key.
        /// </summary>
        public PublicKey ToPublicKey()

            => new (
                   Id,
                   PublicKey.ToHexString().FromHEX(),
                   Description?.      Clone(),
                   EllipticCurve.     CloneString(),
                   SignatureAlgorithm.CloneString(),
                   NotBefore,
                   NotAfter
               );

        #endregion


        #region Operator overloading

        #region Operator == (KeyPair1, KeyPair2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="KeyPair1">A key pair.</param>
        /// <param name="KeyPair2">Another key pair.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (KeyPair KeyPair1,
                                           KeyPair KeyPair2)

            => KeyPair1.Equals(KeyPair2);

        #endregion

        #region Operator != (KeyPair1, KeyPair2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="KeyPair1">A key pair.</param>
        /// <param name="KeyPair2">Another key pair.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (KeyPair KeyPair1,
                                           KeyPair KeyPair2)

            => !KeyPair1.Equals(KeyPair2);

        #endregion

        #region Operator <  (KeyPair1, KeyPair2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="KeyPair1">A key pair.</param>
        /// <param name="KeyPair2">Another key pair.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (KeyPair KeyPair1,
                                          KeyPair KeyPair2)

            => KeyPair1.CompareTo(KeyPair2) < 0;

        #endregion

        #region Operator <= (KeyPair1, KeyPair2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="KeyPair1">A key pair.</param>
        /// <param name="KeyPair2">Another key pair.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (KeyPair KeyPair1,
                                           KeyPair KeyPair2)

            => KeyPair1.CompareTo(KeyPair2) <= 0;

        #endregion

        #region Operator >  (KeyPair1, KeyPair2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="KeyPair1">A key pair.</param>
        /// <param name="KeyPair2">Another key pair.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (KeyPair KeyPair1,
                                          KeyPair KeyPair2)

            => KeyPair1.CompareTo(KeyPair2) > 0;

        #endregion

        #region Operator >= (KeyPair1, KeyPair2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="KeyPair1">A key pair.</param>
        /// <param name="KeyPair2">Another key pair.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (KeyPair KeyPair1,
                                           KeyPair KeyPair2)

            => KeyPair1.CompareTo(KeyPair2) >= 0;

        #endregion

        #endregion

        #region IComparable<KeyPair> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two key pairs.
        /// </summary>
        /// <param name="Object">A key pair to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is KeyPair keyPair
                   ? CompareTo(keyPair)
                   : throw new ArgumentException("The given object is not a key pair!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(KeyPair)

        /// <summary>
        /// Compares two key pairs.
        /// </summary>
        /// <param name="KeyPair">A key pair to compare with.</param>
        public Int32 CompareTo(KeyPair? KeyPair)
        {

            if (KeyPair is null)
                throw new ArgumentNullException(nameof(KeyPair), "The given key pair must not be null!");

            var c = Id.                           CompareTo(KeyPair.Id);

            if (c == 0)
                c = PublicKey.          ToHexString().CompareTo(KeyPair.PublicKey.          ToHexString());

            if (c == 0 && NotBefore.HasValue && KeyPair.NotBefore.HasValue)
                c = NotBefore.Value.ToIso8601().  CompareTo(KeyPair.NotBefore.Value.ToIso8601());

            if (c == 0 && NotAfter. HasValue && KeyPair.NotAfter. HasValue)
                c = NotAfter. Value.ToIso8601().  CompareTo(KeyPair.NotAfter. Value.ToIso8601());

            return c;

        }

        #endregion

        #endregion

        #region IEquatable<KeyPair> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two key pairs for equality.
        /// </summary>
        /// <param name="Object">A key pair to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is KeyPair keyPair &&
                   Equals(keyPair);

        #endregion

        #region Equals(KeyPair)

        /// <summary>
        /// Compares two key pairs for equality.
        /// </summary>
        /// <param name="KeyPair">A key pair to compare with.</param>
        public Boolean Equals(KeyPair? KeyPair)

            => KeyPair is not null &&
               Id.                   Equals       (KeyPair.Id)                                            &&
               PublicKey.                SequenceEqual(KeyPair.PublicKey)                                         &&
              (Description?.         Equals       (KeyPair.Description) ?? KeyPair.Description is null) &&
               EllipticCurve.        Equals       (KeyPair.EllipticCurve)                                 &&
               SignatureAlgorithm.   Equals       (KeyPair.SignatureAlgorithm)                            &&
               NotBefore.            Equals       (KeyPair.NotBefore)                                     &&
               NotAfter.             Equals       (KeyPair.NotAfter);

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

            => $"{Id}: {PublicKey.ToBase64()}, not before: {NotBefore}, not after: {NotAfter}";

        #endregion


    }

}
