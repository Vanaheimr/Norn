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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// Cached NTS-KE state for a server. Stores the keys, cookies, and client instance
    /// to avoid repeated TLS handshakes for every NTP query.
    /// </summary>
    public class CachedNTSKEState
    {

        public NTSKE_Response?  NTSKEResponse      { get; set; }
        public NTSClient?       NTSClient          { get; set; }
        public DateTimeOffset   LastRefreshed      { get; set; }
        public Byte             RemainingCookies   { get; set; }

        /// <summary>
        /// The SHA-256 fingerprint of the host key the server showed at the key
        /// exchange over SSH, as "SHA256:..." - or null after one over TLS.
        /// </summary>
        public String?          SSHHostKey         { get; set; }

        /// <summary>
        /// When the next key exchange is due, or none to age this entry by the
        /// MaxAge it is asked with.
        /// </summary>
        /// <remarks>
        /// Set by the engine at every key exchange, at a random time between the
        /// endpoint's MinRefresh and MaxRefresh after it.
        /// </remarks>
        public DateTimeOffset?  RefreshAt          { get; set; }


        /// <summary>
        /// Whether this cache entry needs a refresh
        /// (due, too old or cookies exhausted).
        /// </summary>
        /// <param name="MaxAge">How long an entry stays usable, where it has no <see cref="RefreshAt"/>.</param>
        /// <param name="TimeProvider">
        /// The clock to age the entry against — the same one that stamped
        /// <see cref="LastRefreshed"/>, or the comparison spans two clocks.
        /// </param>
        public Boolean NeedsRefresh(TimeSpan       MaxAge,
                                    TimeProvider?  TimeProvider   = null)
        {

            var now = TimeProvider?.GetUtcNow() ?? Timestamp.Now;

            return (RefreshAt is { } refreshAt
                        ? now >= refreshAt
                        : now - LastRefreshed > MaxAge) ||
                   RemainingCookies <= 1;  // Keep 1 cookie in reserve

        }

    }

}
