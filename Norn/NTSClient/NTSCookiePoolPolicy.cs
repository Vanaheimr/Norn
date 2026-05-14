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

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// Policy settings for the NTS cookie pool.
    /// </summary>
    public class NTSCookiePoolPolicy
    {

        /// <summary>
        /// The maximum number of cookies retained for future NTP/NTS requests.
        /// </summary>
        public Int32  MaxCookiePoolSize  { get; init; } = 32;

        /// <summary>
        /// The threshold at or below which the cookie pool should be considered low.
        /// </summary>
        public Int32  LowWatermark       { get; init; } = 4;

        /// <summary>
        /// The preferred number of locally available cookies after a successful NTS exchange.
        /// </summary>
        public Int32  TargetCookieCount  { get; init; } = 8;

        /// <summary>
        /// The maximum number of cookie placeholders to send in a single request.
        /// </summary>
        public Int32  MaxPlaceholders    { get; init; } = 7;

        /// <summary>
        /// Normalize unsafe policy values into a usable policy.
        /// </summary>
        public NTSCookiePoolPolicy Normalize()
        {

            var maxCookiePoolSize = Math.Max(1, MaxCookiePoolSize);

            return new NTSCookiePoolPolicy {
                        MaxCookiePoolSize  = maxCookiePoolSize,
                       LowWatermark       = Math.Clamp(LowWatermark,      0, maxCookiePoolSize),
                       TargetCookieCount  = Math.Clamp(TargetCookieCount, 1, maxCookiePoolSize),
                       MaxPlaceholders    = Math.Clamp(MaxPlaceholders,   0, 7)
                    };

        }

    }

}
