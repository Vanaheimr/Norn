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

using org.GraphDefined.Vanaheimr.Norn.NTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// Semantic validation for parsed NTP/NTS responses.
    /// </summary>
    public static class NTSResponseValidator
    {

        public static readonly TimeSpan  DefaultMaxRootDelay       = TimeSpan.FromSeconds(10);

        public static readonly TimeSpan  DefaultMaxRootDispersion  = TimeSpan.FromSeconds(10);

        #region Validate(Response, Request = null, ExpectedUniqueId = null, NTSKey = null, RequireNTS = true)

        public static NTSResponseValidationResult Validate(NTPResponse  Response,
                                                           NTPRequest?  Request           = null,
                                                           Byte[]?      ExpectedUniqueId  = null,
                                                           Byte[]?      NTSKey            = null,
                                                           Boolean      RequireNTS        = true,
                                                           Boolean      IsReplay          = false,
                                                           TimeSpan?    MaxRootDelay      = null,
                                                           TimeSpan?    MaxRootDispersion = null)
        {

            var errors        = new List<(NTSQueryErrorCategory Category, String Message)>();
            var expectedUid   = ExpectedUniqueId ?? Request?.UniqueIdentifier();
            var maxRootDelay  = MaxRootDelay      ?? DefaultMaxRootDelay;
            var maxRootDisp   = MaxRootDispersion ?? DefaultMaxRootDispersion;

            void Add(NTSQueryErrorCategory Category, String Message)
                => errors.Add((Category, Message));


            #region NTP sanity checks

            if (Response.Mode != 4)
                Add(NTSQueryErrorCategory.Protocol, $"NTP response mode must be server (4), but was {Response.Mode}.");

            if (Response.VN != 4)
                Add(NTSQueryErrorCategory.Protocol, $"NTP response version must be 4 for NTS/NTPv4, but was {Response.VN}.");

            if (Response.Stratum == 0)
                Add(NTSQueryErrorCategory.KissOfDeath,
                    $"NTP server returned Kiss-o'-Death '{Response.ReferenceIdentifier.ToString(Response.Stratum)}'.");

            else if (Response.Stratum >= 16)
                Add(NTSQueryErrorCategory.Protocol, $"NTP response stratum {Response.Stratum} is not usable for synchronization.");

            if (Response.LI == 3)
                Add(NTSQueryErrorCategory.Protocol, "NTP response leap indicator announces an unsynchronized clock.");

            if (IsReplay)
                Add(NTSQueryErrorCategory.Protocol, "NTP response transmit timestamp was already accepted before and looks like a duplicate/replay.");

            if (Request?.TransmitTimestamp is not null &&
                Response.OriginateTimestamp != Request.TransmitTimestamp.Value)
                Add(NTSQueryErrorCategory.Protocol, "NTP response originate timestamp does not match the request transmit timestamp.");

            if (Response.Stratum > 0 &&
                Response.ReferenceTimestamp == 0)
                Add(NTSQueryErrorCategory.Protocol, "NTP response reference timestamp is zero.");

            if (Response.ReceiveTimestamp == 0)
                Add(NTSQueryErrorCategory.Protocol, "NTP response receive timestamp is zero.");

            if (!Response.TransmitTimestamp.HasValue ||
                Response.TransmitTimestamp.Value == 0)
                Add(NTSQueryErrorCategory.Protocol, "NTP response transmit timestamp is zero.");

            if (Response.TransmitTimestamp.HasValue &&
                Response.ReceiveTimestamp > Response.TransmitTimestamp.Value)
                Add(NTSQueryErrorCategory.Protocol, "NTP response receive timestamp is later than its transmit timestamp.");

            var rootDelaySeconds      = Response.RootDelay      / 65536.0;
            var rootDispersionSeconds = Response.RootDispersion / 65536.0;

            if (rootDelaySeconds > maxRootDelay.TotalSeconds)
                Add(NTSQueryErrorCategory.Protocol, $"NTP response root delay {rootDelaySeconds:0.######}s exceeds the accepted maximum {maxRootDelay.TotalSeconds:0.######}s.");

            if (rootDispersionSeconds > maxRootDisp.TotalSeconds)
                Add(NTSQueryErrorCategory.Protocol, $"NTP response root dispersion {rootDispersionSeconds:0.######}s exceeds the accepted maximum {maxRootDisp.TotalSeconds:0.######}s.");

            #endregion


            #region NTS checks

            if (RequireNTS)
            {

                if (NTSKey is null || NTSKey.Length == 0)
                    Add(NTSQueryErrorCategory.NTSAuthentication, "Missing S2C key for NTS response validation.");

                var uniqueIdentifiers = Response.Extensions.
                                            OfType<UniqueIdentifierExtension>().
                                            ToArray();

                if (uniqueIdentifiers.Length != 1)
                    Add(NTSQueryErrorCategory.NTSAuthentication, $"NTS response must contain exactly one Unique Identifier extension, but contained {uniqueIdentifiers.Length}.");

                else
                {

                    var uniqueIdentifier = uniqueIdentifiers[0];

                    if (expectedUid is not null &&
                        !uniqueIdentifier.Value.SequenceEqual(expectedUid))
                        Add(NTSQueryErrorCategory.NTSAuthentication, "NTS response Unique Identifier does not match the request.");

                    if (!uniqueIdentifier.Authenticated)
                        Add(NTSQueryErrorCategory.NTSAuthentication, "NTS response Unique Identifier was not authenticated.");

                    if (uniqueIdentifier.Encrypted)
                        Add(NTSQueryErrorCategory.NTSAuthentication, "NTS response Unique Identifier must not be encrypted.");

                }

                var authenticators = Response.Extensions.
                                         OfType<AuthenticatorAndEncryptedExtension>().
                                         ToArray();

                if (authenticators.Length != 1)
                    Add(NTSQueryErrorCategory.NTSAuthentication, $"NTS response must contain exactly one Authenticator and Encrypted extension, but contained {authenticators.Length}.");

                var cookies = Response.Extensions.
                                  OfType<NTSCookieExtension>().
                                  ToArray();

                if (cookies.Length == 0)
                    Add(NTSQueryErrorCategory.Protocol, "NTS response did not provide a replacement cookie.");

                if (cookies.Any(cookie => !cookie.Authenticated || !cookie.Encrypted))
                    Add(NTSQueryErrorCategory.NTSAuthentication, "NTS response contains a cookie that was not authenticated and encrypted.");

            }

            #endregion


            if (errors.Count == 0)
                return NTSResponseValidationResult.Valid(Response);

            var category = errors.Any(error => error.Category == NTSQueryErrorCategory.KissOfDeath)
                               ? NTSQueryErrorCategory.KissOfDeath
                               : errors.Any(error => error.Category == NTSQueryErrorCategory.NTSAuthentication)
                                     ? NTSQueryErrorCategory.NTSAuthentication
                                     : NTSQueryErrorCategory.Protocol;

            return NTSResponseValidationResult.Invalid(
                       Response,
                       category,
                       errors.Select(error => error.Message)
                   );

        }

        #endregion

    }

}
