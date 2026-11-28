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
    /// A client's side of the NTPv5 interleaved mode (draft-ietf-ntp-ntpv5-10 § 8).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The same memory as RFC 9769 asks of an NTPv4 client, with less to it: the request no
    /// longer carries the client's timestamps, only the server cookie of the last valid
    /// response, and the response says by its Interleaved flag which mode it is in instead
    /// of leaving the client to work it out from which timestamp came back.
    /// </para>
    /// <para>
    /// Figure 15: an interleaved response's transmit timestamp is that of the previous
    /// response, so the measurement it completes is the previous exchange's - its T1, T2 and
    /// T4, which this type holds, and the T3 now delivered. A basic-mode response, which a
    /// server sends when it no longer has the timestamp, is a measurement of its own.
    /// </para>
    /// <para>
    /// Free of I/O and of any clock, as <c>InterleavedAssociation</c> is, and not thread-safe:
    /// one association is one server polled by one caller at a time.
    /// </para>
    /// </remarks>
    public sealed class NTPv5InterleavedAssociation
    {

        #region (private) Previous

        private sealed record Previous(UInt64            ServerCookie,
                                       DateTime          T1,
                                       DateTime          T2,
                                       DateTime          T4,
                                       NTPv5Correction?  Correction);

        #endregion

        #region Data

        /// <summary>
        /// How many requests in a row may go unanswered before the transmit timestamp the
        /// server holds is given up, by default 4: past that § 9 step 2 has the client send a
        /// zero server cookie, as the timestamp "would no longer be useful".
        /// </summary>
        public const Int32 DefaultMaxUnansweredRequests = 4;

        private Previous?  previous;
        private Int32      unanswered;

        #endregion

        #region Properties

        /// <summary>
        /// How many requests in a row may go unanswered.
        /// </summary>
        public Int32    MaxUnansweredRequests    { get; }

        /// <summary>
        /// The server cookie for the next request: that of the last valid response, or zero
        /// where there was none or too many requests since went unanswered.
        /// </summary>
        public UInt64   NextServerCookie
            => previous?.ServerCookie ?? 0;

        /// <summary>
        /// Whether a previous exchange is held, so that an interleaved response can complete it.
        /// </summary>
        public Boolean  HasPrevious
            => previous is not null;

        /// <summary>
        /// How many interleaved measurements were completed.
        /// </summary>
        public Int64    InterleavedResponses     { get; private set; }

        /// <summary>
        /// How many responses to interleaved requests came in the basic mode.
        /// </summary>
        public Int64    BasicResponses           { get; private set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// A new association, with no previous exchange.
        /// </summary>
        /// <param name="MaxUnansweredRequests">How many requests in a row may go unanswered.</param>
        public NTPv5InterleavedAssociation(Int32? MaxUnansweredRequests = null)
        {

            this.MaxUnansweredRequests = Math.Max(0, MaxUnansweredRequests ?? DefaultMaxUnansweredRequests);

        }

        #endregion


        #region RecordValidResponse(Request, Response, T1, T4, Parameters = null)

        /// <summary>
        /// The measurement a valid response completes, and the exchange it leaves behind for
        /// the next one. Null where the response lacks a timestamp, or claims the interleaved
        /// mode for a server cookie this association did not send.
        /// </summary>
        /// <param name="Request">The request it answers.</param>
        /// <param name="Response">The valid response.</param>
        /// <param name="T1">The client's transmit time of the request.</param>
        /// <param name="T4">The client's receive time of the response.</param>
        /// <param name="Parameters">What the corrections of § 8 need besides themselves.</param>
        public NTPv5Measurement? RecordValidResponse(NTPv5ClientRequest          Request,
                                                     NTPv5Packet                 Response,
                                                     DateTime                    T1,
                                                     DateTime                    T4,
                                                     NTPv5CorrectionParameters?  Parameters = null)
        {

            unanswered = 0;

            var held        = previous;
            var t2          = NTPv5Client.ReceiveTime(Response);
            var correction  = NTPv5Client.CorrectionOf(Response, Request);

            previous        = t2 is DateTime receive && Response.ServerCookie != 0
                                  ? new Previous(Response.ServerCookie, T1, receive, T4, correction)
                                  : null;

            if (!Response.Flags.HasFlag(NTPv5Flags.InterleavedMode))
            {

                if (Request.Flags.HasFlag(NTPv5Flags.InterleavedMode))
                    BasicResponses++;

                return NTPv5Client.Measure(T1, Response, T4, Request, Parameters);

            }

            // The transmit timestamp of the response that this server cookie came with - which
            // is only this association's previous one if that is the cookie the request sent.
            if (held is null                                  ||
                Request.Packet.ServerCookie != held.ServerCookie ||
                Response.TransmitTimestamp == 0)
                return null;

            if (NTPv5Client.ExpandNear(Response.TransmitTimestamp, held.T2) is not DateTime t3)
                return null;

            InterleavedResponses++;

            // § 8: Co belongs to the request of T1 and T2, Cd to the response of T3 and T4 -
            // the same, previous response.
            return NTPv5Client.Measure(held.T1, held.T2, t3, held.T4, Interleaved: true, held.Correction, Parameters);

        }

        #endregion

        #region RecordUnansweredRequest()

        /// <summary>
        /// A request that got no valid response. The held exchange survives a few, as the
        /// server's timestamp of it does; past <see cref="MaxUnansweredRequests"/> it is given
        /// up. Returns whether it is still held.
        /// </summary>
        public Boolean RecordUnansweredRequest()
        {

            if (++unanswered > MaxUnansweredRequests)
                previous = null;

            return previous is not null;

        }

        #endregion

        #region Reset()

        /// <summary>
        /// Forget the previous exchange, for example after the server changed.
        /// </summary>
        public void Reset()
        {
            previous   = null;
            unanswered = 0;
        }

        #endregion

    }

}
