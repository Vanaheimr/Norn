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
        public Boolean               Success          { get; init; }

        /// <summary>
        /// Resolved IPv4 addresses.
        /// </summary>
        public IEnumerable<String>   IPv4Addresses    { get; init; } = [];

        /// <summary>
        /// Resolved IPv6 addresses.
        /// </summary>
        public IEnumerable<String>   IPv6Addresses    { get; init; } = [];

        /// <summary>
        /// Duration of the DNS resolution.
        /// </summary>
        public TimeSpan              Duration         { get; init; }

        /// <summary>
        /// Error if DNS resolution failed.
        /// </summary>
        public String?               ErrorMessage     { get; init; }

        #endregion

        #region ToJSON()

        public JObject ToJSON()
        {

            var json = new JObject(
                           new JProperty("success",       Success),
                           new JProperty("durationMs",    Math.Round(Duration.TotalMilliseconds, 3)),
                           new JProperty("ipv4",          new JArray(IPv4Addresses)),
                           new JProperty("ipv6",          new JArray(IPv6Addresses))
                       );

            if (ErrorMessage is not null)
                json.Add("error", ErrorMessage);

            return json;

        }

        #endregion

    }

}
