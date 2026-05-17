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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// DNS resolution measurement.
    /// </summary>
    public class DNSResolutionResult
    {

        #region Properties

        /// <summary>
        /// Whether DNS resolution succeeded.
        /// </summary>
        public Boolean                   Success          { get; }

        /// <summary>
        /// The duration of the DNS resolution.
        /// </summary>
        public TimeSpan                  Duration         { get; }

        /// <summary>
        /// The enumeration of resolved IPv4 addresses.
        /// </summary>
        public IEnumerable<IPv4Address>  IPv4Addresses    { get; } = [];

        /// <summary>
        /// The enumeration of resolved IPv6 addresses.
        /// </summary>
        public IEnumerable<IPv6Address>  IPv6Addresses    { get; } = [];

        /// <summary>
        /// An optional warning message if DNS resolution succeeded but with some issues
        /// (e.g. partial resolution, timeouts, etc.).
        /// </summary>
        public Warning?                  Warning          { get; }

        /// <summary>
        /// An optional error message if DNS resolution failed.
        /// </summary>
        public Error?                    ErrorMessage     { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new DNS resolution result.
        /// </summary>
        /// <param name="Success">Whether DNS resolution succeeded.</param>
        /// <param name="Duration">The duration of the DNS resolution.</param>
        /// <param name="IPv4Addresses">An optional enumeration of resolved IPv4 addresses.</param>
        /// <param name="IPv6Addresses">An optional enumeration of resolved IPv6 addresses.</param>
        /// <param name="Warning">An optional warning message if DNS resolution succeeded but with some issues (e.g. partial resolution, timeouts, etc.).</param>
        /// <param name="ErrorMessage">An optional error message if DNS resolution failed.</param>
        public DNSResolutionResult(Boolean                    Success,
                                   TimeSpan                   Duration,
                                   IEnumerable<IPv4Address>?  IPv4Addresses   = null,
                                   IEnumerable<IPv6Address>?  IPv6Addresses   = null,
                                   Warning?                   Warning         = null,
                                   Error?                     ErrorMessage    = null)
        {

            this.Success        = Success;
            this.Duration       = Duration;
            this.IPv4Addresses  = IPv4Addresses ?? [];
            this.IPv6Addresses  = IPv6Addresses ?? [];
            this.Warning        = Warning;
            this.ErrorMessage   = ErrorMessage;

        }

        #endregion


        #region ToJSON()

        public JObject ToJSON()
        {

            var json = JSONObject.Create(

                                 new JProperty("success",         Success),
                                 new JProperty("durationMs",      Math.Round(Duration.TotalMilliseconds, 3)),
                                 new JProperty("ipv4Addresses",   new JArray(IPv4Addresses.Select(ipv4address => ipv4address.ToString()))),
                                 new JProperty("ipv6Addresses",   new JArray(IPv6Addresses.Select(ipv6address => ipv6address.ToString()))),

                           ErrorMessage is not null
                               ? new JProperty("error",           ErrorMessage)
                               : null,

                           Warning is not null
                               ? new JProperty("warning",         Warning.ToJSON())
                               : null

                       );

            return json;

        }

        #endregion

    }

}
