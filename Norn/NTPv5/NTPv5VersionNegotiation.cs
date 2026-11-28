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

namespace org.GraphDefined.Vanaheimr.Norn.NTPv5
{

    /// <summary>
    /// Which version the next unauthenticated request to a server goes out in, after
    /// draft-ietf-ntp-ntpv5-10 § 12.
    /// </summary>
    public enum NTPv5NegotiatedVersion
    {

        /// <summary>
        /// NTPv4, with the negotiation magic in the reference timestamp.
        /// </summary>
        NTPv4Advertising,

        /// <summary>
        /// NTPv5: the server echoed the magic.
        /// </summary>
        NTPv5,

        /// <summary>
        /// NTPv4 without the magic, for a while after NTPv5 failed.
        /// </summary>
        NTPv4Only

    }


    /// <summary>
    /// The version negotiation of draft-ietf-ntp-ntpv5-10 § 12 for one server, for a client
    /// that does not use NTS - under NTS the key exchange decides the version.
    /// </summary>
    /// <remarks>
    /// <para>
    /// § 12: a client "SHOULD start with the previous version and set the reference timestamp
    /// to" the magic. "If the server responds with the same reference timestamp, the client
    /// SHOULD switch to NTPv5. If no valid response is received for a number of requests
    /// (e.g. 2), the client SHOULD switch back to the orignal NTP version and stick with it for
    /// a larger number of requests (e.g. 256) before trying NTPv5 again."
    /// </para>
    /// <para>
    /// While it sticks with NTPv4 the requests carry no magic: an echo then would switch to a
    /// version that just failed. Free of I/O, and not thread-safe.
    /// </para>
    /// </remarks>
    public sealed class NTPv5VersionNegotiation
    {

        #region Data

        /// <summary>
        /// The example of § 12 for how many NTPv5 requests may go unanswered.
        /// </summary>
        public const Int32 DefaultMaxFailures      = 2;

        /// <summary>
        /// The example of § 12 for how many NTPv4 requests to stay with before trying again.
        /// </summary>
        public const Int32 DefaultBackoffRequests  = 256;

        private Int32 failures;
        private Int32 backoffRemaining;

        #endregion

        #region Properties

        /// <summary>
        /// The magic a draft implementation advertises in the reference timestamp.
        /// </summary>
        public UInt64                  Magic              { get; }

        /// <summary>
        /// How many NTPv5 requests in a row may go unanswered before falling back.
        /// </summary>
        public Int32                   MaxFailures        { get; }

        /// <summary>
        /// How many NTPv4 requests to send without the magic after falling back.
        /// </summary>
        public Int32                   BackoffRequests    { get; }

        /// <summary>
        /// The version of the next request.
        /// </summary>
        public NTPv5NegotiatedVersion  Version            { get; private set; } = NTPv5NegotiatedVersion.NTPv4Advertising;

        /// <summary>
        /// The reference timestamp of the next NTPv4 request: the magic while advertising,
        /// zero otherwise.
        /// </summary>
        public UInt64                  ReferenceTimestamp
            => Version == NTPv5NegotiatedVersion.NTPv4Advertising ? Magic : 0;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// A negotiation that starts with NTPv4 and advertises NTPv5.
        /// </summary>
        /// <param name="MaxFailures">How many NTPv5 requests in a row may go unanswered.</param>
        /// <param name="BackoffRequests">How many NTPv4 requests to send without the magic after falling back.</param>
        /// <param name="Magic">The magic, by default that of a draft implementation, NTP5DRFT.</param>
        public NTPv5VersionNegotiation(Int32?   MaxFailures      = null,
                                       Int32?   BackoffRequests  = null,
                                       UInt64?  Magic            = null)
        {

            this.MaxFailures      = Math.Max(1, MaxFailures     ?? DefaultMaxFailures);
            this.BackoffRequests  = Math.Max(0, BackoffRequests ?? DefaultBackoffRequests);
            this.Magic            = Magic ?? NTPv5Draft.NegotiationMagic;

        }

        #endregion


        #region RecordNTPv4Response(ReferenceTimestamp)

        /// <summary>
        /// A valid NTPv4 response and its reference timestamp: switch to NTPv5 where it echoes
        /// the magic this client sent.
        /// </summary>
        public NTPv5NegotiatedVersion RecordNTPv4Response(UInt64 ReferenceTimestamp)
        {

            if (Version == NTPv5NegotiatedVersion.NTPv4Advertising &&
                ReferenceTimestamp == Magic)
            {
                Version  = NTPv5NegotiatedVersion.NTPv5;
                failures = 0;
            }

            return Version;

        }

        #endregion

        #region RecordNTPv4Request()

        /// <summary>
        /// An NTPv4 request was sent: one fewer to go before advertising again.
        /// </summary>
        public NTPv5NegotiatedVersion RecordNTPv4Request()
        {

            if (Version == NTPv5NegotiatedVersion.NTPv4Only &&
                --backoffRemaining <= 0)
                Version = NTPv5NegotiatedVersion.NTPv4Advertising;

            return Version;

        }

        #endregion

        #region RecordNTPv5Result(ValidResponse)

        /// <summary>
        /// The outcome of an NTPv5 request: a valid response keeps NTPv5, too many requests in
        /// a row without one fall back to NTPv4 for <see cref="BackoffRequests"/> requests.
        /// </summary>
        public NTPv5NegotiatedVersion RecordNTPv5Result(Boolean ValidResponse)
        {

            if (Version != NTPv5NegotiatedVersion.NTPv5)
                return Version;

            if (ValidResponse)
            {
                failures = 0;
                return Version;
            }

            if (++failures >= MaxFailures)
            {
                failures          = 0;
                backoffRemaining  = BackoffRequests;
                Version           = BackoffRequests > 0
                                        ? NTPv5NegotiatedVersion.NTPv4Only
                                        : NTPv5NegotiatedVersion.NTPv4Advertising;
            }

            return Version;

        }

        #endregion

        #region Reset()

        /// <summary>
        /// Start over, advertising NTPv5 in NTPv4.
        /// </summary>
        public void Reset()
        {
            Version           = NTPv5NegotiatedVersion.NTPv4Advertising;
            failures          = 0;
            backoffRemaining  = 0;
        }

        #endregion

    }

}
