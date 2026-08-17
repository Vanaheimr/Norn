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
    /// taken only as far as <see cref="MaximumPollExponent"/> allows. One forged packet can
    /// therefore cost this client a factor of two in polling rate, and never more, however large
    /// the number in it.
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
        /// The current poll exponent: the interval between queries is 2^this seconds.
        /// </summary>
        public Byte             PollExponent         { get; private set; }

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
        public NTPServerAccessState(Byte?  InitialPollExponent  = null,
                                    Byte?  MinimumPollExponent  = null,
                                    Byte?  MaximumPollExponent  = null)
        {

            this.MinimumPollExponent  = MinimumPollExponent ?? DefaultMinimumPollExponent;
            this.MaximumPollExponent  = Math.Max(this.MinimumPollExponent,
                                                 MaximumPollExponent ?? DefaultMaximumPollExponent);

            this.PollExponent         = (Byte) Math.Clamp(InitialPollExponent ?? this.MinimumPollExponent,
                                                          this.MinimumPollExponent,
                                                          this.MaximumPollExponent);

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

        #region Apply(Kiss, Now)

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
        public NTPKissAction Apply(NTPKissOfDeath  Kiss,
                                   DateTimeOffset  Now)
        {

            lock (padlock)
            {

                LastKiss = Kiss;

                switch (Kiss.Action)
                {

                    case NTPKissAction.Demobilize:
                        Demobilized         = true;
                        NextQueryNotBefore  = null;
                        break;

                    case NTPKissAction.ReducePollingRate:

                        // At least one step slower, whatever the server asked for. § 7.4 b wants
                        // the rate reduced on *each* RATE kiss, so a server repeating a value
                        // this client has already reached still has to move it — otherwise a
                        // client limited at its current rate would sit there being limited.
                        //
                        // And no further than the ceiling, however large the number in the
                        // packet: that is RFC 8633 § 5.4's "MUST NOT simply accept any value",
                        // and the reason an unauthenticated kiss cannot silence this client.
                        var target          = Math.Max(PollExponent + 1,
                                                       Math.Min(Kiss.PollExponent, MaximumPollExponent));

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
        /// Forget everything this server has said: poll from the minimum again, and query it
        /// again if it had demobilized the association.
        /// </summary>
        public void Reset()
        {

            lock (padlock)
            {

                PollExponent        = MinimumPollExponent;
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
