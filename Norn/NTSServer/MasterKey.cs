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
    /// A NTS server master key.
    /// </summary>
    public readonly struct MasterKey : IEquatable<MasterKey>,
                                       IComparable<MasterKey>
    {

        #region Data

        /// <summary>
        /// The JSON-LD context of this object.
        /// </summary>
        public readonly static JSONLDContext DefaultJSONLDContext = JSONLDContext.Parse("https://graphdefined.org/context/vanaheimr/norn/nts/server/masterKey");

        #endregion

        #region Properties

        /// <summary>
        /// The key identification.
        /// </summary>
        public UInt64          KeyId        { get; }

        /// <summary>
        /// The key value.
        /// </summary>
        public Byte[]          Value        { get; }

        /// <summary>
        /// The key is valid from this date/time.
        /// </summary>
        public DateTimeOffset  NotBefore    { get; }

        /// <summary>
        /// The key is valid until this date/time.
        /// </summary>
        public DateTimeOffset  NotAfter     { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new NTS server master key.
        /// </summary>
        /// <param name="KeyId">The key identification.</param>
        /// <param name="Value">The key value.</param>
        /// <param name="NotBefore">The key is valid from this date/time.</param>
        /// <param name="NotAfter">The key is valid until this date/time.</param>
        public MasterKey(UInt64          KeyId,
                         Byte[]          Value,
                         DateTimeOffset  NotBefore,
                         DateTimeOffset  NotAfter)

        {

            this.KeyId      = KeyId;
            this.Value      = Value;
            this.NotBefore  = NotBefore;
            this.NotAfter   = NotAfter;

            unchecked
            {

                hashCode = this.KeyId.    GetHashCode() * 7 ^
                           this.Value.    GetHashCode() * 5 ^
                           this.NotBefore.GetHashCode() * 3 ^
                           this.NotAfter. GetHashCode();

            }

        }

        #endregion


        #region (static) Parse   (Text, ...)

        /// <summary>
        /// Parse the given text representation of a NTS server master key.
        /// </summary>
        /// <param name="CustomMasterKeyParser">A delegate to parse custom MasterKey JSON objects.</param>
        public static MasterKey Parse(String                                   Text,
                                      CustomJObjectParserDelegate<MasterKey>?  CustomMasterKeyParser   = null)
        {

            if (TryParse(Text,
                         out var masterKey,
                         out var errorResponse,
                         CustomMasterKeyParser))
            {
                return masterKey;
            }

            throw new ArgumentException("The given text representation of a NTS server master key is invalid: " + errorResponse,
                                        nameof(Text));

        }

        #endregion

        #region (static) Parse   (JSON, ...)

        /// <summary>
        /// Parse the given JSON representation of a NTS server master key.
        /// </summary>
        /// <param name="CustomMasterKeyParser">A delegate to parse custom MasterKey JSON objects.</param>
        public static MasterKey Parse(JObject                                  JSON,
                                      CustomJObjectParserDelegate<MasterKey>?  CustomMasterKeyParser   = null)
        {

            if (TryParse(JSON,
                         out var masterKey,
                         out var errorResponse,
                         CustomMasterKeyParser))
            {
                return masterKey;
            }

            throw new ArgumentException("The given JSON representation of a NTS server master key is invalid: " + errorResponse,
                                        nameof(JSON));

        }

        #endregion

        #region TryParse(Text, out MasterKey, out ErrorResponse, ...)

        // Note: The following is needed to satisfy pattern matching delegates! Do not refactor it!

        /// <summary>
        /// Try to parse the given JSON representation of a NTS server master key.
        /// </summary>
        /// <param name="Text">The text to be parsed.</param>
        /// <param name="MasterKey">The parsed NTS server master key.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(String                              Text,
                                                            out MasterKey  MasterKey,
                                       [NotNullWhen(false)] out String?    ErrorResponse)

            => TryParse(Text,
                        out MasterKey,
                        out ErrorResponse,
                        null);


        /// <summary>
        /// Try to parse the given text representation of a NTS server master key.
        /// </summary>
        /// <param name="JSON">The text to be parsed.</param>
        /// <param name="MasterKey">The parsed NTS server master key.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        /// <param name="CustomMasterKeyParser">A delegate to parse custom MasterKey JSON objects.</param>
        public static Boolean TryParse(String                                   Text,
                                                            out MasterKey       MasterKey,
                                       [NotNullWhen(false)] out String?         ErrorResponse,
                                       CustomJObjectParserDelegate<MasterKey>?  CustomMasterKeyParser)
        {
            try
            {

                var json = JObject.Parse(Text);

                if (TryParse(json, out MasterKey, out ErrorResponse, CustomMasterKeyParser))
                    return true;

                return false;

            }
            catch (Exception e)
            {
                MasterKey      = default;
                ErrorResponse  = "The given text representation of a MasterKey is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region TryParse(JSON, out MasterKey, out ErrorResponse, ...)

        // Note: The following is needed to satisfy pattern matching delegates! Do not refactor it!

        /// <summary>
        /// Try to parse the given JSON representation of a NTS server master key.
        /// </summary>
        /// <param name="JSON">The JSON to be parsed.</param>
        /// <param name="MasterKey">The parsed NTS server master key.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(JObject                             JSON,
                                                            out MasterKey  MasterKey,
                                       [NotNullWhen(false)] out String?    ErrorResponse)

            => TryParse(JSON,
                        out MasterKey,
                        out ErrorResponse,
                        null);


        /// <summary>
        /// Try to parse the given JSON representation of a NTS server master key.
        /// </summary>
        /// <param name="JSON">The JSON to be parsed.</param>
        /// <param name="MasterKey">The parsed NTS server master key.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        /// <param name="CustomMasterKeyParser">A delegate to parse custom MasterKey JSON objects.</param>
        public static Boolean TryParse(JObject                                  JSON,
                                                            out MasterKey       MasterKey,
                                       [NotNullWhen(false)] out String?         ErrorResponse,
                                       CustomJObjectParserDelegate<MasterKey>?  CustomMasterKeyParser)
        {
            try
            {

                MasterKey = default;

                #region KeyId        [mandatory]

                if (!JSON.ParseMandatory("keyId",
                                         "key identification",
                                         out UInt64 keyId,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region Value        [mandatory]

                if (!JSON.ParseMandatoryText("value",
                                             "key value",
                                             out String? valueBase64,
                                             out ErrorResponse))
                {
                    return false;
                }

                if (valueBase64.IsNullOrEmpty())
                {
                    ErrorResponse = "The given key value must not be null or empty!";
                    return false;
                }

                if (!StringExtensions.TryParseBASE64(valueBase64, out var Value, out var errorResponse))
                {
                    ErrorResponse = "The given key value is not a valid BASE64 string: " + errorResponse;
                    return false;
                }

                #endregion

                #region NotBefore    [mandatory]

                if (!JSON.ParseMandatory("notBefore",
                                         "not before",
                                         out DateTimeOffset notBefore,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region NotAfter     [mandatory]

                if (!JSON.ParseMandatory("notAfter",
                                         "not after",
                                         out DateTimeOffset notAfter,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion


                MasterKey = new MasterKey(
                                keyId,
                                Value,
                                notBefore,
                                notAfter
                            );

                if (CustomMasterKeyParser is not null)
                    MasterKey = CustomMasterKeyParser(JSON,
                                                      MasterKey);

                return true;

            }
            catch (Exception e)
            {
                MasterKey      = default;
                ErrorResponse  = "The given JSON representation of a MasterKey is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON(IncludeJSONLDContext = false, CustomMasterKeySerializer = null)

        /// <summary>
        /// Return a JSON representation of this NTS server master key.
        /// </summary>
        /// <param name="IncludeJSONLDContext">Whether to include the JSON-LD context or not.</param>
        /// <param name="CustomMasterKeySerializer">A delegate to serialize custom MasterKey objects.</param>
        public JObject ToJSON(Boolean                                      IncludeJSONLDContext        = false,
                              CustomJObjectSerializerDelegate<MasterKey>?  CustomMasterKeySerializer   = null)
        {

            var json = JSONObject.Create(

                           IncludeJSONLDContext
                               ? new JProperty("@context",    DefaultJSONLDContext.ToString())
                               : null,

                                 new JProperty("keyId",       KeyId),
                                 new JProperty("masterKey",   Value.               ToBase64()),
                                 new JProperty("notBefore",   NotBefore.           ToIso8601()),
                                 new JProperty("notAfter",    NotAfter.            ToIso8601())

                       );

            return CustomMasterKeySerializer is not null
                       ? CustomMasterKeySerializer(this, json)
                       : json;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this NTS server master key.
        /// </summary>
        public MasterKey Clone()

            => new (
                   KeyId,
                   Value.ToHexString().FromHEX(),
                   NotBefore,
                   NotAfter
               );

        #endregion


        #region Operator overloading

        #region Operator == (MasterKey1, MasterKey2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="MasterKey1">A MasterKey.</param>
        /// <param name="MasterKey2">Another MasterKey.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (MasterKey MasterKey1,
                                           MasterKey MasterKey2)

            => MasterKey1.Equals(MasterKey2);

        #endregion

        #region Operator != (MasterKey1, MasterKey2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="MasterKey1">A MasterKey.</param>
        /// <param name="MasterKey2">Another MasterKey.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (MasterKey MasterKey1,
                                           MasterKey MasterKey2)

            => !MasterKey1.Equals(MasterKey2);

        #endregion

        #region Operator <  (MasterKey1, MasterKey2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="MasterKey1">A MasterKey.</param>
        /// <param name="MasterKey2">Another MasterKey.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (MasterKey MasterKey1,
                                          MasterKey MasterKey2)

            => MasterKey1.CompareTo(MasterKey2) < 0;

        #endregion

        #region Operator <= (MasterKey1, MasterKey2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="MasterKey1">A MasterKey.</param>
        /// <param name="MasterKey2">Another MasterKey.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (MasterKey MasterKey1,
                                           MasterKey MasterKey2)

            => MasterKey1.CompareTo(MasterKey2) <= 0;

        #endregion

        #region Operator >  (MasterKey1, MasterKey2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="MasterKey1">A MasterKey.</param>
        /// <param name="MasterKey2">Another MasterKey.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (MasterKey MasterKey1,
                                          MasterKey MasterKey2)

            => MasterKey1.CompareTo(MasterKey2) > 0;

        #endregion

        #region Operator >= (MasterKey1, MasterKey2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="MasterKey1">A MasterKey.</param>
        /// <param name="MasterKey2">Another MasterKey.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (MasterKey MasterKey1,
                                           MasterKey MasterKey2)

            => MasterKey1.CompareTo(MasterKey2) >= 0;

        #endregion

        #endregion

        #region IComparable<MasterKey> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two MasterKeys.
        /// </summary>
        /// <param name="Object">A MasterKey to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is MasterKey masterKeyInfo
                   ? CompareTo(masterKeyInfo)
                   : throw new ArgumentException("The given object is not a MasterKey!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(MasterKey)

        /// <summary>
        /// Compares two MasterKeys.
        /// </summary>
        /// <param name="MasterKey">A MasterKey to compare with.</param>
        public Int32 CompareTo(MasterKey MasterKey)
        {

            var c = KeyId.                  CompareTo(MasterKey.KeyId);

            if (c == 0)
                c = Value.    ToHexString().CompareTo(MasterKey.Value.    ToHexString());

            if (c == 0)
                c = NotBefore.ToIso8601().  CompareTo(MasterKey.NotBefore.ToIso8601());

            if (c == 0)
                c = NotAfter. ToIso8601().  CompareTo(MasterKey.NotAfter. ToIso8601());

            return c;

        }

        #endregion

        #endregion

        #region IEquatable<MasterKey> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two MasterKeys for equality.
        /// </summary>
        /// <param name="Object">A MasterKey to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is MasterKey masterKeyInfo &&
                   Equals(masterKeyInfo);

        #endregion

        #region Equals(MasterKey)

        /// <summary>
        /// Compares two MasterKeys for equality.
        /// </summary>
        /// <param name="MasterKey">A MasterKey to compare with.</param>
        public Boolean Equals(MasterKey MasterKey)

            => KeyId.                Equals       (MasterKey.KeyId)                 &&
               Value.                SequenceEqual(MasterKey.Value)                 &&
               NotBefore.ToIso8601().Equals       (MasterKey.NotBefore.ToIso8601()) &&
               NotAfter. ToIso8601().Equals       (MasterKey.NotAfter. ToIso8601());

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

            => $"{KeyId}: {Value.ToBase64()}, not before: {NotBefore}, not after: {NotAfter}";

        #endregion


    }

}
