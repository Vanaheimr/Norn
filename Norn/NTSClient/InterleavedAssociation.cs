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

using System.Security.Cryptography;

using org.GraphDefined.Vanaheimr.Norn.NTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// Which of the two RFC 9769 modes a server response turned out to be in.
    /// </summary>
    public enum InterleavedResponseMode
    {

        /// <summary>
        /// The origin timestamp echoed the request's transmit timestamp: an ordinary response,
        /// whose transmit timestamp describes its own transmission.
        /// </summary>
        Basic,

        /// <summary>
        /// The origin timestamp echoed the request's receive timestamp: the transmit timestamp
        /// beside it describes the transmission of the <em>previous</em> response.
        /// </summary>
        Interleaved,

        /// <summary>
        /// The origin timestamp matched neither, so this is not a response to the request that
        /// was sent — RFC 5905 calls such a packet bogus.
        /// </summary>
        Bogus

    }


    /// <summary>
    /// One completed RFC 9769 measurement, and the four timestamps it was computed from.
    /// </summary>
    /// <remarks>
    /// Kept separate from <see cref="NTPPacket.ClockOffset"/> rather than folded into it,
    /// because an interleaved measurement is not a property of one packet. Three of its four
    /// timestamps belong to the previous exchange, and only the fourth — the transmit timestamp
    /// that finally became available — comes from the packet in hand.
    /// </remarks>
    /// <param name="T1">The client's transmit timestamp of the previous request.</param>
    /// <param name="T2">The server's receive timestamp from the previous response.</param>
    /// <param name="T3">The server's transmit timestamp from the latest response — the accurate one.</param>
    /// <param name="T4">The client's receive timestamp of the previous response.</param>
    public readonly record struct InterleavedMeasurement(UInt64 T1,
                                                         UInt64 T2,
                                                         UInt64 T3,
                                                         UInt64 T4)
    {

        /// <summary>
        /// The clock offset, ((T2 - T1) + (T3 - T4)) / 2, from RFC 5905 § 8.
        /// </summary>
        public TimeSpan ClockOffset

            => TimeSpan.FromTicks(
                   (Difference(T2, T1).Ticks + Difference(T3, T4).Ticks) / 2
               );


        /// <summary>
        /// The round-trip delay, (T4 - T1) - (T3 - T2), from RFC 5905 § 8.
        /// </summary>
        public TimeSpan RoundtripDelay

            => Difference(T4, T1) - Difference(T3, T2);


        /// <summary>
        /// The difference between two NTP timestamps as a signed interval.
        /// </summary>
        /// <remarks>
        /// Computed on the unsigned 64-bit values rather than by converting each to a date
        /// first, so that a pair straddling the 2036 era boundary still yields the right
        /// interval: the subtraction wraps exactly as the format intends.
        /// </remarks>
        private static TimeSpan Difference(UInt64 A, UInt64 B)
        {

            var difference = unchecked((Int64) (A - B));

            // 2^32 units to the second, and 10^7 ticks to the second.
            return TimeSpan.FromTicks((Int64) (difference / 4294967296.0 * TimeSpan.TicksPerSecond));

        }

    }


    /// <summary>
    /// A client's side of an RFC 9769 interleaved client/server association.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What the client contributes to the interleaved mode is memory. The server's accurate
    /// transmit timestamp arrives one exchange after the transmission it describes, so a client
    /// that treats each query as self-contained can never use it — it has to still be holding
    /// the other three timestamps of the previous exchange when the fourth turns up.
    /// </para>
    /// <para>
    /// Those same three values are also what the next request must carry, which is the neat
    /// part of the design. Figure 1 of § 2 shows a client request in the interleaved mode
    /// carrying the server's receive timestamp as its origin, its own receive timestamp of that
    /// response, and its own accurate transmit timestamp of the previous request — exactly the
    /// three things it needs to remember anyway.
    /// </para>
    /// <para>
    /// This type is deliberately free of I/O and of any clock, so that the mode transitions can
    /// be exercised directly rather than only through a socket.
    /// </para>
    /// </remarks>
    public sealed class InterleavedAssociation
    {

        #region Data

        /// <summary>
        /// How many interleaved requests may go unanswered before the association is abandoned
        /// and the next request starts afresh in the basic mode.
        /// </summary>
        /// <remarks>
        /// RFC 9769 § 2: "The client SHOULD limit the number of requests in the interleaved mode
        /// between server responses to prevent the processing of very old timestamps in cases
        /// where a large number of consecutive requests are lost."
        ///
        /// The timestamps being held are only useful while the server still holds the matching
        /// pair; past that point an interleaved request can never be answered as one, and
        /// retrying with the same origin forever would mean never measuring anything again.
        /// </remarks>
        public const Int32 DefaultMaxUnansweredRequests = 4;


        private readonly Lock  padlock = new();

        private UInt64?        previousRequestTransmit;
        private UInt64?        previousServerReceive;
        private UInt64?        previousOwnReceive;
        private Int32          unansweredRequests;

        #endregion

        #region Properties

        /// <summary>How many interleaved requests may go unanswered before starting over.</summary>
        public Int32    MaxUnansweredRequests    { get; }

        /// <summary>
        /// Whether the next request can be sent in the interleaved mode, which needs a valid
        /// response to have come back first.
        /// </summary>
        /// <remarks>
        /// RFC 9769 § 2: "The first request from a client is always in the basic mode ... Only
        /// when the client receives a valid response from the server will it be able to send a
        /// request in the interleaved mode."
        /// </remarks>
        public Boolean  CanSendInterleaved
        {
            get
            {
                lock (padlock)
                    return previousServerReceive is not null;
            }
        }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new interleaved association.
        /// </summary>
        /// <param name="MaxUnansweredRequests">
        /// How many interleaved requests may go unanswered before the association restarts.
        /// </param>
        public InterleavedAssociation(Int32? MaxUnansweredRequests = null)
        {
            this.MaxUnansweredRequests = Math.Max(1, MaxUnansweredRequests ?? DefaultMaxUnansweredRequests);
        }

        #endregion


        #region NextRequestOrigin()

        /// <summary>
        /// The origin timestamp the next request should carry: the server's receive timestamp
        /// from the last valid response, or zero when there is not one yet.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Zero is the basic-mode opening of § 2 — "It has a zero origin timestamp and zero
        /// receive timestamp" — and it is what tells the server there is no earlier exchange to
        /// reach back to.
        /// </para>
        /// <para>
        /// The only real value the next request carries, which is why this returns one number
        /// rather than the three of Figure 1. The other two fields are nonces now: § 6 has a
        /// client "randomize all bits of receive and transmit timestamps in their requests", so
        /// what used to be this client's own timestamps of the previous exchange are minted per
        /// packet by the caller. They were never claims about time even before that — Figure 1
        /// has an interleaved request carry the transmit timestamp of the <em>previous</em>
        /// request — but they were guessable, and an off-path attacker who guesses one can forge
        /// the origin of a response.
        /// </para>
        /// <para>
        /// The real values stay here, where the measurement is made from them, and never reach
        /// the wire again.
        /// </para>
        /// </remarks>
        public UInt64 NextRequestOrigin()
        {

            lock (padlock)
            {

                if (previousServerReceive   is null ||
                    previousOwnReceive      is null ||
                    previousRequestTransmit is null)
                {
                    return 0;
                }

                return previousServerReceive.Value;

            }

        }

        #endregion

        #region (static) NewRequestNonces()

        /// <summary>
        /// A fresh pair of receive and transmit timestamps for a request, of RFC 9769 § 6:
        /// "Clients using the interleaved mode SHOULD randomize all bits of receive and transmit
        /// timestamps in their requests (i.e., provide a precision of 2^-32 seconds) to make it
        /// more difficult for off-path attackers to guess the origin timestamp in the server
        /// response."
        /// </summary>
        /// <remarks>
        /// <para>
        /// Both fields, because a server answering in the basic mode echoes the transmit
        /// timestamp as the origin and one answering in the interleaved mode echoes the receive
        /// timestamp — so both are values an attacker would need to guess to forge a response,
        /// and only one of them being unpredictable is no protection at all.
        /// </para>
        /// <para>
        /// Neither may be zero and the two may not be equal. Zero is how § 2 marks a request as
        /// basic-mode, and equal timestamps make a response ambiguous — <see cref="Classify"/>
        /// could not tell which mode it was in. Both are vanishingly unlikely and both are
        /// cheaper to exclude than to reason about.
        /// </para>
        /// </remarks>
        public static (UInt64 Receive, UInt64 Transmit) NewRequestNonces()
        {

            UInt64 receive, transmit;

            do
            {
                receive   = RandomTimestamp();
                transmit  = RandomTimestamp();
            }
            while (receive == 0 || transmit == 0 || receive == transmit);

            return (receive, transmit);

        }


        private static UInt64 RandomTimestamp()

            => BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8), 0);

        #endregion

        #region Classify(Response, RequestReceive, RequestTransmit)

        /// <summary>
        /// Decide which mode a response is in, by the RFC 9769 § 2 replacement for RFC 5905's
        /// bogus-packet test: "The check for bogus packets compares the origin timestamp with
        /// both transmit and receive timestamps from the request. If the origin timestamp is
        /// equal to the transmit timestamp, the response is in the basic mode. If the origin
        /// timestamp is equal to the receive timestamp, the response is in the interleaved
        /// mode."
        /// </summary>
        /// <remarks>
        /// The transmit timestamp is checked first. A request whose two timestamps were equal
        /// would be ambiguous, which is why both sides are forbidden from sending one — but if
        /// one arrives anyway, reading it as the basic mode is the safe way to be wrong: a basic
        /// response is interpreted with the timestamps of the exchange in hand, where an
        /// interleaved one reaches back to an earlier exchange.
        /// </remarks>
        public static InterleavedResponseMode Classify(NTPPacket  Response,
                                                       UInt64     RequestReceive,
                                                       UInt64     RequestTransmit)
        {

            if (Response.OriginateTimestamp == RequestTransmit)
                return InterleavedResponseMode.Basic;

            if (RequestReceive != 0 &&
                Response.OriginateTimestamp == RequestReceive)
                return InterleavedResponseMode.Interleaved;

            return InterleavedResponseMode.Bogus;

        }

        #endregion

        #region MeasurementFor(Response)

        /// <summary>
        /// The measurement an interleaved response completes, or null when the previous
        /// exchange's timestamps are no longer held.
        /// </summary>
        /// <remarks>
        /// The first of the two timestamp sets offered by § 2, "RECOMMENDED for clients that
        /// filter measurements based on the delay": every timestamp belongs to the previous
        /// exchange except T3, which is the accurate transmit timestamp that has only just
        /// arrived. The second set mixes the two exchanges to get a fresher offset at the cost
        /// of a delay estimate stretched across the whole poll interval, which is the wrong
        /// trade for a client that judges a measurement by its delay.
        /// </remarks>
        public InterleavedMeasurement? MeasurementFor(NTPPacket Response)
        {

            lock (padlock)
            {

                if (previousRequestTransmit is null ||
                    previousServerReceive   is null ||
                    previousOwnReceive      is null ||
                    Response.TransmitTimestamp is null)
                {
                    return null;
                }

                return new InterleavedMeasurement(
                           T1: previousRequestTransmit.Value,
                           T2: previousServerReceive.Value,
                           T3: Response.TransmitTimestamp.Value,
                           T4: previousOwnReceive.Value
                       );

            }

        }

        #endregion

        #region RecordValidResponse(Response, RequestTransmit, OwnReceiveTimestamp)

        /// <summary>
        /// Remember what this exchange will contribute to the next one.
        /// </summary>
        /// <param name="Response">The response, valid and not bogus.</param>
        /// <param name="RequestTransmit">
        /// When the request that drew it actually left this machine — captured after the send,
        /// not the estimate written into the packet.
        /// </param>
        /// <param name="OwnReceiveTimestamp">When this response arrived.</param>
        public void RecordValidResponse(NTPPacket  Response,
                                        UInt64     RequestTransmit,
                                        UInt64     OwnReceiveTimestamp)
        {

            lock (padlock)
            {

                previousRequestTransmit  = RequestTransmit;
                previousServerReceive    = Response.ReceiveTimestamp;
                previousOwnReceive       = OwnReceiveTimestamp;
                unansweredRequests       = 0;

            }

        }

        #endregion

        #region RecordUnansweredRequest()

        /// <summary>
        /// Note that a request went unanswered, and say whether the association still holds.
        /// </summary>
        /// <remarks>
        /// RFC 9769 § 2: "The protocol recovers from packet loss. When a client request or
        /// server response is lost, the client will use the same origin timestamp in the next
        /// request." So the state is deliberately kept rather than cleared — up to the point
        /// where the timestamps are too old to be worth offering, and the association restarts
        /// in the basic mode.
        /// </remarks>
        public Boolean RecordUnansweredRequest()
        {

            lock (padlock)
            {

                if (++unansweredRequests < MaxUnansweredRequests)
                    return true;

                Reset();
                return false;

            }

        }

        #endregion

        #region Reset()

        /// <summary>
        /// Forget the association, so the next request opens a new one in the basic mode.
        /// </summary>
        public void Reset()
        {

            lock (padlock)
            {

                previousRequestTransmit  = null;
                previousServerReceive    = null;
                previousOwnReceive       = null;
                unansweredRequests       = 0;

            }

        }

        #endregion

    }

}
