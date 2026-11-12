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
    /// What one server has told this client about how welcome it is, and how often it may come
    /// back.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 5905 § 7.4 puts two obligations on the recipient of a kiss code, and both of them are
    /// about restraint rather than time: "for kiss codes DENY and RSTR, the client MUST demobilize
    /// any associations to that server and stop sending packets to that server", and "for kiss
    /// code RATE, the client MUST immediately reduce its polling interval to that server and
    /// continue to reduce it each time it receives a RATE kiss code". RFC 8633 § 5.4 recommends
    /// the same and adds the caveat that makes it safe to obey.
    /// </para>
    /// <para>
    /// That caveat is the interesting part. § 5.4: "If the client uses the poll interval value
    /// sent by the server in the RATE packet, it MUST NOT simply accept any value. Using large
    /// interval values may create a vector for a denial-of-service attack that causes the client
    /// to stop querying its server." So a RATE kiss is read as two separate things — a fact, that
    /// this client is being limited and must slow down, and a suggestion, the poll value, which is
    /// not taken at all: each RATE kiss slows this client by one step, a factor of two, and
    /// never past <see cref="MaximumPollExponent"/>. One forged packet can therefore cost this
    /// client a factor of two in polling rate, and never more, however large the number in it.
    /// A server that means it says so again, and is obeyed again.
    /// </para>
    /// <para>
    /// The slower rate holds for as long as it is not earned back: every query is followed by
    /// a wait of one poll interval, and every answer that is not a kiss takes one step back
    /// towards the rate this client started from.
    /// </para>
    /// <para>
    /// "DENY" and "RSTR" end the association for good, as § 7.4 a says, unless the association
    /// is an NTS one and the kiss was not authenticated (<see cref="NTPKissTrust"/>). Then it
    /// costs this client one pause of <see cref="UnauthenticatedDenyPause"/>, by default the
    /// longest poll interval, and no more. Anyone on the
    /// path can write such a kiss; one datagram must not be the end of a time source.
    /// </para>
    /// <para>
    /// Deliberately free of any clock: the current time is passed in. A monitoring client's notion
    /// of "now" is the thing under measurement, and a policy object that reads a clock of its own
    /// cannot be tested against the interesting moments.
    /// </para>
    /// </remarks>
    public sealed class NTPServerAccessState
    {

        #region Data

        /// <summary>
        /// The fastest this client will poll: RFC 5905's minimum poll exponent, sixteen seconds.
        /// </summary>
        public const Byte DefaultMinimumPollExponent = 4;

        /// <summary>
        /// The slowest a RATE kiss can drive this client, and the ceiling RFC 8633 § 5.4 names:
        /// "should not exceed a poll interval value of 13 (two hours)".
        /// </summary>
        public const Byte DefaultMaximumPollExponent = 13;


        private readonly Lock  padlock = new();

        #endregion

        #region Properties

        /// <summary>
        /// The fastest this client will poll this server.
        /// </summary>
        public Byte             MinimumPollExponent  { get; }

        /// <summary>
        /// The slowest a kiss code can drive this client.
        /// </summary>
        public Byte             MaximumPollExponent  { get; }

        /// <summary>
        /// The poll exponent this client started from, and returns to as it is answered.
        /// </summary>
        public Byte             InitialPollExponent  { get; }

        /// <summary>
        /// How long this client stays away from an NTS server after a "DENY" or "RSTR" kiss
        /// that was not authenticated.
        /// </summary>
        /// <remarks>
        /// The price of one datagram that anyone on the path can write, so it is a weighing:
        /// long enough that a server which meant it is left alone, short enough that a
        /// forger gains little. The default is the longest poll interval, about two hours
        /// with RFC 8633's ceiling of 13. Zero ignores such a kiss altogether.
        /// </remarks>
        public TimeSpan         UnauthenticatedDenyPause  { get; }

        /// <summary>
        /// The current poll exponent: the interval between queries is 2^this seconds.
        /// </summary>
        public Byte             PollExponent         { get; private set; }

        /// <summary>
        /// Whether a RATE kiss has slowed this client down, and it has not yet earned
        /// its starting rate back.
        /// </summary>
        public Boolean          IsRateLimited
            => PollExponent > InitialPollExponent;

        /// <summary>
        /// The interval the current poll exponent stands for.
        /// </summary>
        public TimeSpan         PollInterval
            => TimeSpan.FromSeconds(Math.Pow(2, PollExponent));

        /// <summary>
        /// Whether this server has told this client to go away, with a "DENY" or "RSTR" kiss.
        /// </summary>
        /// <remarks>
        /// One-way on purpose. § 7.4 a says to stop sending packets, not to stop for a while, and
        /// nothing a server that is not being queried can send will change its mind — so undoing
        /// this is an operator's decision, made through <see cref="Reset"/>.
        /// </remarks>
        public Boolean          Demobilized          { get; private set; }

        /// <summary>
        /// The earliest this client should query again, or null when it may query now.
        /// </summary>
        public DateTimeOffset?  NextQueryNotBefore   { get; private set; }

        /// <summary>
        /// The last kiss code accepted from this server, if any.
        /// </summary>
        public NTPKissOfDeath?  LastKiss             { get; private set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create the access state for one server.
        /// </summary>
        /// <param name="InitialPollExponent">Where to start, before any kiss code (default: the minimum).</param>
        /// <param name="MinimumPollExponent">The fastest this client will poll this server.</param>
        /// <param name="MaximumPollExponent">The slowest a kiss code can drive this client.</param>
        /// <param name="UnauthenticatedDenyPause">How long to stay away after an unauthenticated "DENY" or "RSTR" on an NTS association (default: the longest poll interval).</param>
        public NTPServerAccessState(Byte?      InitialPollExponent        = null,
                                    Byte?      MinimumPollExponent        = null,
                                    Byte?      MaximumPollExponent        = null,
                                    TimeSpan?  UnauthenticatedDenyPause   = null)
        {

            if (UnauthenticatedDenyPause < TimeSpan.Zero)
                throw new ArgumentOutOfRangeException(nameof(UnauthenticatedDenyPause), "The pause must not be negative!");

            this.MinimumPollExponent  = MinimumPollExponent ?? DefaultMinimumPollExponent;
            this.MaximumPollExponent  = Math.Max(this.MinimumPollExponent,
                                                 MaximumPollExponent ?? DefaultMaximumPollExponent);

            this.InitialPollExponent  = (Byte) Math.Clamp(InitialPollExponent ?? this.MinimumPollExponent,
                                                          this.MinimumPollExponent,
                                                          this.MaximumPollExponent);

            this.PollExponent         = this.InitialPollExponent;

            this.UnauthenticatedDenyPause  = UnauthenticatedDenyPause ?? TimeSpan.FromSeconds(Math.Pow(2, this.MaximumPollExponent));

        }

        #endregion


        #region MayQuery(Now)

        /// <summary>
        /// Whether this client may send a request to this server right now.
        /// </summary>
        public Boolean MayQuery(DateTimeOffset Now)
        {

            lock (padlock)
            {

                if (Demobilized)
                    return false;

                return NextQueryNotBefore is null ||
                       Now >= NextQueryNotBefore.Value;

            }

        }

        #endregion

        #region RecordQuery(Now)

        /// <summary>
        /// A request is being sent to this server.
        /// </summary>
        /// <remarks>
        /// What makes a RATE kiss last: RFC 5905 § 7.4 b asks for a reduced polling interval,
        /// not for one pause after which everything is as before. While this client is rate
        /// limited, each query is followed by a wait of one poll interval.
        /// </remarks>
        /// <param name="Now">The current time.</param>
        public void RecordQuery(DateTimeOffset Now)
        {

            lock (padlock)
            {
                if (IsRateLimited)
                    NextQueryNotBefore = Now + PollInterval;
            }

        }

        #endregion

        #region RecordAnswer()

        /// <summary>
        /// This server answered a request with something other than a kiss.
        /// </summary>
        /// <remarks>
        /// One step back towards the starting rate per answer, the way it was lost one step
        /// per kiss. A server that is still limiting this client says so with the next RATE.
        /// </remarks>
        public void RecordAnswer()
        {

            lock (padlock)
            {
                if (IsRateLimited)
                    PollExponent--;
            }

        }

        #endregion

        #region Apply(Kiss, Now, Trust)

        /// <summary>
        /// Act on a kiss code, and report what was done about it.
        /// </summary>
        /// <remarks>
        /// The caller is expected to have obtained the kiss from
        /// <see cref="NTPKissOfDeath.TryRead"/>, which is where the origin timestamp is checked.
        /// Nothing here re-examines whether the kiss is genuine; this is the part that obeys.
        /// </remarks>
        /// <param name="Kiss">The kiss code, already established as answering a real request.</param>
        /// <param name="Now">The current time, from which the next permitted query is measured.</param>
        /// <param name="Trust">How far the kiss can be believed.</param>
        public NTPKissAction Apply(NTPKissOfDeath  Kiss,
                                   DateTimeOffset  Now,
                                   NTPKissTrust    Trust   = NTPKissTrust.Unprotected)
        {

            lock (padlock)
            {

                LastKiss = Kiss;

                switch (Kiss.Action)
                {

                    case NTPKissAction.Demobilize:

                        if (Trust == NTPKissTrust.Unauthenticated)
                        {

                            // An NTS server that wants this client gone can seal that under
                            // the S2C key. A kiss without it may come from anyone who saw
                            // the request, and "stop for good" is too much to take from
                            // them: it costs one pause, and leaves the polling rate as it
                            // was.
                            NextQueryNotBefore  = UnauthenticatedDenyPause > TimeSpan.Zero
                                                      ? Now + UnauthenticatedDenyPause
                                                      : NextQueryNotBefore;

                            break;

                        }

                        Demobilized         = true;
                        NextQueryNotBefore  = null;
                        break;

                    case NTPKissAction.ReducePollingRate:

                        // One step slower, whatever the server asked for. § 7.4 b wants the
                        // rate reduced on *each* RATE kiss, so a server repeating itself moves
                        // this client again — otherwise a client limited at its current rate
                        // would sit there being limited.
                        //
                        // And one step only, however large the number in the packet: that is
                        // RFC 8633 § 5.4's "MUST NOT simply accept any value". Taking the
                        // server's number, even capped, let a single forged kiss with a poll
                        // value of 255 send this client from sixteen seconds to two hours.
                        var target          = PollExponent + 1;

                        PollExponent        = (Byte) Math.Clamp(target,
                                                                MinimumPollExponent,
                                                                MaximumPollExponent);

                        NextQueryNotBefore  = Now + PollInterval;

                        break;

                    case NTPKissAction.RenegotiateNTS:
                        // Nothing to do here: the cookies are the NTS layer's business, and the
                        // server has said nothing about the rate or about access.
                        break;

                }

                return Kiss.Action;

            }

        }

        #endregion

        #region Reset()

        /// <summary>
        /// Forget everything this server has said: poll at the starting rate again, and query
        /// it again if it had demobilized the association.
        /// </summary>
        public void Reset()
        {

            lock (padlock)
            {

                PollExponent        = InitialPollExponent;
                Demobilized         = false;
                NextQueryNotBefore  = null;
                LastKiss            = null;

            }

        }

        #endregion


        public override String ToString()

            => Demobilized
                   ? $"demobilized ({LastKiss?.Code ?? "?"})"
                   : $"poll {PollExponent} ({PollInterval.TotalSeconds:0} s)";

    }

}
