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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// The Network Time Secure Key Exchange (NTS-KE) server information.
    /// </summary>
    public class NTSKE_ServerInfo : IEquatable<NTSKE_ServerInfo>
    {

        #region Data

        /// <summary>
        /// The JSON-LD context of this object.
        /// </summary>
        public readonly static JSONLDContext DefaultJSONLDContext = JSONLDContext.Parse("https://open.charging.cloud/context/ocpp/v2.1/ntsKEServerInfo");

        #endregion

        #region Properties

        /// <summary>
        /// The NTS C2S key.
        /// </summary>
        [Mandatory]
        public Byte[]                         C2SKey                     { get; }

        /// <summary>
        /// The NTS S2C key.
        /// </summary>
        [Mandatory]
        public Byte[]                         S2CKey                     { get; }

        /// <summary>
        /// The enumeration of NTS cookies.
        /// </summary>
        [Mandatory]
        public IEnumerable<Byte[]>            Cookies                    { get; }

        /// <summary>
        /// The optional enumeration of NTS URLs for NTS UDP requests.
        /// </summary>
        [Mandatory]
        public IEnumerable<URL>               URLs                       { get; }

        /// <summary>
        /// The optional enumeration of NTS Response Signature Public Keys.
        /// </summary>
        [Mandatory]
        public IEnumerable<Byte[]>            PublicKeys                 { get; }

        /// <summary>
        /// The optional NTS AEAD algorithm used.
        /// </summary>
        [Optional]
        public AEADAlgorithms?                AEADAlgorithm              { get; }

        /// <summary>
        /// The enumeration of NTS warnings.
        /// </summary>
        [Mandatory]
        public IEnumerable<Warning>           Warnings                   { get; }

        /// <summary>
        /// The enumeration of NTS errors.
        /// </summary>
        [Mandatory]
        public IEnumerable<String>            Errors                     { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create new NTS-KE server information.
        /// </summary>
        /// <param name="C2SKey"></param>
        /// <param name="S2CKey"></param>
        /// <param name="Cookies"></param>
        /// <param name="URLs"></param>
        /// <param name="PublicKeys"></param>
        /// <param name="AEADAlgorithm"></param>
        /// <param name="Warnings"></param>
        /// <param name="Errors"></param>
        public NTSKE_ServerInfo(Byte[]                 C2SKey,
                                Byte[]                 S2CKey,
                                IEnumerable<Byte[]>    Cookies,
                                IEnumerable<URL>       URLs,
                                IEnumerable<Byte[]>?   PublicKeys      = null,
                                AEADAlgorithms?        AEADAlgorithm   = null,
                                IEnumerable<Warning>?  Warnings        = null,
                                IEnumerable<String>?   Errors          = null)
        {

            #region Initial checks

            if (C2SKey. Length == 0)
                throw new ArgumentException("The given C2S key must not be empty!",
                                            nameof(C2SKey));

            if (S2CKey. Length == 0)
                throw new ArgumentException("The given S2C key must not be empty!",
                                            nameof(S2CKey));

            if (!Cookies.Any())
                throw new ArgumentException("The given enumeration of NTS cookies must not be empty!",
                                            nameof(S2CKey));

            #endregion

            this.C2SKey         = C2SKey;
            this.S2CKey         = S2CKey;
            this.Cookies        = Cookies.    Distinct();
            this.URLs           = URLs.       Distinct();
            this.PublicKeys     = PublicKeys?.Distinct() ?? [];
            this.AEADAlgorithm  = AEADAlgorithm;
            this.Warnings       = Warnings?.  Distinct() ?? [];
            this.Errors         = Errors?.    Distinct() ?? [];

            unchecked
            {

                hashCode = this.C2SKey.        GetHashCode()       * 27 ^
                           this.S2CKey.        CalcHashCode()      * 23 ^
                           this.Cookies.       CalcHashCode()      * 19 ^
                           this.URLs.          CalcHashCode()      * 17 ^
                           this.PublicKeys.    CalcHashCode()      * 13 ^
                          (this.AEADAlgorithm?.GetHashCode() ?? 0) * 11 ^
                           this.Warnings.      CalcHashCode()      *  7 ^
                           this.Errors.        CalcHashCode()      *  3 ^
                           base.               GetHashCode();

            }

        }

        #endregion


        #region Documentation

        // 

        #endregion

        #region (static) Parse   (JSON, CustomNTSKEServerInfoParser = null)

        /// <summary>
        /// Parse the given JSON representation of a NTSKEServerInfo.
        /// </summary>
        /// <param name="JSON">The JSON to be parsed.</param>
        /// <param name="CustomNTSKEServerInfoParser">A delegate to parse custom NTSKEServerInfos.</param>
        public static NTSKE_ServerInfo Parse(JObject                                        JSON,
                                            CustomJObjectParserDelegate<NTSKE_ServerInfo>?  CustomNTSKEServerInfoParser   = null)
        {

            if (TryParse(JSON,
                         out var ntsKEServerInfo,
                         out var errorResponse,
                         CustomNTSKEServerInfoParser))
            {
                return ntsKEServerInfo;
            }

            throw new ArgumentException("The given JSON representation of a NTSKEServerInfo is invalid: " + errorResponse,
                                        nameof(JSON));

        }

        #endregion

        #region (static) TryParse(JSON, out NTSKEServerInfo, CustomNTSKEServerInfoParser = null)

        // Note: The following is needed to satisfy pattern matching delegates! Do not refactor it!

        /// <summary>
        /// Try to parse the given JSON representation of a NTSKEServerInfo.
        /// </summary>
        /// <param name="JSON">The JSON to be parsed.</param>
        /// <param name="NTSKEServerInfo">The parsed connector type.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(JObject                                     JSON,
                                       [NotNullWhen(true)]  out NTSKE_ServerInfo?  NTSKEServerInfo,
                                       [NotNullWhen(false)] out String?            ErrorResponse)

            => TryParse(JSON,
                        out NTSKEServerInfo,
                        out ErrorResponse,
                        null);


        /// <summary>
        /// Try to parse the given JSON representation of a NTSKEServerInfo.
        /// </summary>
        /// <param name="JSON">The JSON to be parsed.</param>
        /// <param name="NTSKEServerInfo">The parsed connector type.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        /// <param name="CustomNTSKEServerInfoParser">A delegate to parse custom NTSKEServerInfos.</param>
        public static Boolean TryParse(JObject                                         JSON,
                                       [NotNullWhen(true)]  out NTSKE_ServerInfo?      NTSKEServerInfo,
                                       [NotNullWhen(false)] out String?                ErrorResponse,
                                       CustomJObjectParserDelegate<NTSKE_ServerInfo>?  CustomNTSKEServerInfoParser)
        {

            try
            {

                NTSKEServerInfo = null;

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

                #region Cookies          [mandatory]

                if (!JSON.ParseMandatoryHashSet("cookies",
                                                "NTS cookies",
                                                s => s,
                                                out HashSet<String> cookiesBASE64,
                                                out ErrorResponse))
                {
                    return false;
                }

                var cookies = cookiesBASE64.Select(cookieBASE64 => cookieBASE64.FromBASE64()).ToHashSet();

                #endregion

                #region URLs             [mandatory]

                if (!JSON.ParseMandatoryHashSet("urls",
                                                "NTS URLs",
                                                URL.TryParse,
                                                out HashSet<URL> urls,
                                                out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region PublicKeys       [optional]

                if (!JSON.ParseOptionalHashSet("publicKeys",
                                               "NTS public keys",
                                               s => s,
                                               out HashSet<String> publicKeysBASE64,
                                               out ErrorResponse))
                {
                    if (ErrorResponse is not null)
                        return false;
                }

                var publicKeys = publicKeysBASE64.Select(publicKeyBASE64 => publicKeyBASE64.FromBASE64()).ToHashSet();

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

                #region Warnings         [optional]

                if (!JSON.ParseOptionalHashSet("warnings",
                                               "NTS warnings",
                                               s => Warning.Create(s),
                                               out HashSet<Warning> warnings,
                                               out ErrorResponse))
                {
                    if (ErrorResponse is not null)
                        return false;
                }

                #endregion

                #region Errors           [optional]

                if (!JSON.ParseOptionalHashSet("errors",
                                               "NTS errors",
                                               s => s,
                                               out HashSet<String> errors,
                                               out ErrorResponse))
                {
                    if (ErrorResponse is not null)
                        return false;
                }

                #endregion


                NTSKEServerInfo = new NTSKE_ServerInfo(

                                      c2sKey,
                                      s2cKey,
                                      cookies,
                                      urls,
                                      publicKeys,
                                      aeadAlgorithm,
                                      warnings,
                                      errors

                                  );

                if (CustomNTSKEServerInfoParser is not null)
                    NTSKEServerInfo = CustomNTSKEServerInfoParser(JSON,
                                                                  NTSKEServerInfo);

                return true;

            }
            catch (Exception e)
            {
                NTSKEServerInfo  = default;
                ErrorResponse    = "The given JSON representation of a NTSKEServerInfo is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON(CustomNTSKEServerInfoSerializer = null, CustomLimitAtSoCSerializer = null, ...)

        /// <summary>
        /// Return a JSON representation of this object.
        /// </summary>
        /// <param name="CustomNTSKEServerInfoSerializer">A delegate to serialize custom NTSKEServerInfos.</param>
        public JObject ToJSON(Boolean                                            IncludeJSONLDContext              = false,
                              CustomJObjectSerializerDelegate<NTSKE_ServerInfo>? CustomNTSKEServerInfoSerializer   = null)
        {

            var json = JSONObject.Create(

                           IncludeJSONLDContext
                               ? new JProperty("@context",        DefaultJSONLDContext.ToString())
                               : null,

                                 new JProperty("c2sKey",          C2SKey.              ToBase64()),
                                 new JProperty("s2cKey",          S2CKey.              ToBase64()),
                                 new JProperty("cookies",         new JArray(Cookies.   Select(cookie      => cookie.   ToBase64()))),
                                 new JProperty("urls",            new JArray(URLs.      Select(url         => url.      ToString()))),

                           PublicKeys.Any()
                               ? new JProperty("publicKeys",      new JArray(PublicKeys.Select(publicKey   => publicKey.ToBase64())))
                               : null,

                           AEADAlgorithm.HasValue && AEADAlgorithm.Value != AEADAlgorithms.AES_SIV_CMAC_256
                               ? new JProperty("aeadAlgorithm",   AEADAlgorithm.Value.AsText())
                               : null,

                           Warnings.Any()
                               ? new JProperty("warnings",        new JArray(Warnings.  Select(warning     => warning.Text.FirstText())))
                               : null,

                           Errors.  Any()
                               ? new JProperty("errors",          new JArray(Errors.    Select(error       => error)))
                               : null

                       );

            return CustomNTSKEServerInfoSerializer is not null
                       ? CustomNTSKEServerInfoSerializer(this, json)
                       : json;

        }

        #endregion


        #region Operator overloading

        #region Operator == (NTSKEServerInfo1, NTSKEServerInfo2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="NTSKEServerInfo1">A NTSKEServerInfo.</param>
        /// <param name="NTSKEServerInfo2">Another NTSKEServerInfo.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (NTSKE_ServerInfo? NTSKEServerInfo1,
                                           NTSKE_ServerInfo? NTSKEServerInfo2)
        {

            // If both are null, or both are same instance, return true.
            if (ReferenceEquals(NTSKEServerInfo1, NTSKEServerInfo2))
                return true;

            // If one is null, but not both, return false.
            if (NTSKEServerInfo1 is null || NTSKEServerInfo2 is null)
                return false;

            return NTSKEServerInfo1.Equals(NTSKEServerInfo2);

        }

        #endregion

        #region Operator != (NTSKEServerInfo1, NTSKEServerInfo2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="NTSKEServerInfo1">A NTSKEServerInfo.</param>
        /// <param name="NTSKEServerInfo2">Another NTSKEServerInfo.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (NTSKE_ServerInfo? NTSKEServerInfo1,
                                           NTSKE_ServerInfo? NTSKEServerInfo2)

            => !(NTSKEServerInfo1 == NTSKEServerInfo2);

        #endregion

        #endregion

        #region IEquatable<NTSKEServerInfo> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two NTSKEServerInfos for equality.
        /// </summary>
        /// <param name="Object">A NTSKEServerInfo to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is NTSKE_ServerInfo ntsKEServerInfo &&
                   Equals(ntsKEServerInfo);

        #endregion

        #region Equals(NTSKEServerInfo)

        /// <summary>
        /// Compares two NTSKEServerInfos for equality.
        /// </summary>
        /// <param name="NTSKEServerInfo">A NTSKEServerInfo to compare with.</param>
        public Boolean Equals(NTSKE_ServerInfo? NTSKEServerInfo)

            => NTSKEServerInfo is not null &&

               C2SKey.SequenceEqual(NTSKEServerInfo.C2SKey) &&
               S2CKey.SequenceEqual(NTSKEServerInfo.S2CKey) &&

               Cookies.   Count().Equals(NTSKEServerInfo.Cookies.   Count()) &&
               Cookies.   Any(NTSKEServerInfo.Cookies.   Contains) &&

               URLs.      Count().Equals(NTSKEServerInfo.URLs.      Count()) &&
               URLs.      Any(NTSKEServerInfo.URLs.      Contains) &&

               PublicKeys.Count().Equals(NTSKEServerInfo.PublicKeys.Count()) &&
               PublicKeys.Any(NTSKEServerInfo.PublicKeys.Contains) &&

            ((!AEADAlgorithm.HasValue && !NTSKEServerInfo.AEADAlgorithm.HasValue) ||
              (AEADAlgorithm.HasValue &&  NTSKEServerInfo.AEADAlgorithm.HasValue && AEADAlgorithm.Value.Equals(NTSKEServerInfo.AEADAlgorithm.Value))) &&

               Warnings.  Count().Equals(NTSKEServerInfo.Warnings.  Count()) &&
               Warnings.  Any(NTSKEServerInfo.Warnings.  Contains) &&

               Errors.    Count().Equals(NTSKEServerInfo.Errors.    Count()) &&
               Errors.    Any(NTSKEServerInfo.Errors.    Contains) &&

               base.Equals(NTSKEServerInfo);

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

            => String.Concat(

                   $"'{URLs.First()}'",

                   URLs.Count() > 1
                       ? $" (of {URLs.Count()})"
                       : "",

                   AEADAlgorithm.HasValue
                       ? $" using '{AEADAlgorithm.Value.AsText()}'"
                       : "",

                   $" , {Cookies.Count()} cookies",

                   PublicKeys.Any()
                       ? $" ,  public key: 0x{PublicKeys.First().ToHexString().SubstringMax(12)} (of {PublicKeys.Count()})"
                       : "",

                   Warnings.Any()
                       ? $" ,  warnings: {Warnings.AggregateWith(", ")}"
                       : "",

                   Errors.Any()
                       ? $" ,  errors: {Errors.AggregateWith(", ")}"
                       : ""

               );

        #endregion


    }

}
