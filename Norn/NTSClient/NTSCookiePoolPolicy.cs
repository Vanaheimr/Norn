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
        /// Whether an empty pool makes the client run the key exchange again by itself.
        /// </summary>
        /// <remarks>
        /// <para>
        /// RFC 8915 § 5.7: "If the client does not have any cookies that it has not already sent,
        /// it SHOULD initiate a rerun of the NTS-KE protocol." Without it a client that has spent
        /// its last cookie can never ask the time again, however long it waits — a cookie only
        /// arrives in answer to a request, and it has nothing left to make one with.
        /// </para>
        /// <para>
        /// A pool empties when requests go unanswered: each one spends a cookie and brings none
        /// back. So this is what a client does after a network outage, and turning it off is how
        /// a caller says it would rather handle that itself.
        /// </para>
        /// </remarks>
        public Boolean   RenegotiateWhenExhausted      { get; init; } = true;

        /// <summary>
        /// The shortest time between two key exchanges the client started on its own.
        /// </summary>
        /// <remarks>
        /// <para>
        /// § 5.7 again, on automatic reruns: an implementation "must implement rate limiting to
        /// avoid rapid retry loops". A key exchange is a TLS handshake, which is by far the most
        /// expensive thing a client can ask a time server for, and a server that is refusing
        /// everything is exactly the server a client would otherwise ask fastest.
        /// </para>
        /// <para>
        /// One minute is about one poll interval, so a client recovering normally is not delayed
        /// at all — its next attempt would have been then anyway — while a caller querying in a
        /// loop is held to one handshake a minute. The first rerun is never delayed: the limit is
        /// between reruns, not before the first.
        /// </para>
        /// </remarks>
        public TimeSpan  MinimumRenegotiationInterval  { get; init; } = TimeSpan.FromSeconds(60);

        /// <summary>
        /// Normalize unsafe policy values into a usable policy.
        /// </summary>
        public NTSCookiePoolPolicy Normalize()
        {

            var maxCookiePoolSize = Math.Max(1, MaxCookiePoolSize);

            return new NTSCookiePoolPolicy {
                       MaxCookiePoolSize             = maxCookiePoolSize,
                       LowWatermark                  = Math.Clamp(LowWatermark,      0, maxCookiePoolSize),
                       TargetCookieCount             = Math.Clamp(TargetCookieCount, 1, maxCookiePoolSize),
                       MaxPlaceholders               = Math.Clamp(MaxPlaceholders,   0, 7),
                       RenegotiateWhenExhausted      = RenegotiateWhenExhausted,
                       MinimumRenegotiationInterval  = MinimumRenegotiationInterval < TimeSpan.Zero
                                                           ? TimeSpan.Zero
                                                           : MinimumRenegotiationInterval
                    };

        }

    }

}
