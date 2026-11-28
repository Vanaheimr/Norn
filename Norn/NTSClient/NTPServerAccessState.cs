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
    /// "DENY" and "RSTR" end the association, as § 7.4 a says: this client stops sending
    /// packets to the server. Where the association is a plain one, or the kiss was sealed under
    /// the S2C key, that is for good. Where it is an NTS one and the kiss was not authenticated
    /// (<see cref="NTPKissTrust"/>), anyone on the path could have written it, and one datagram
    /// must not be the end of a time source: RFC 8915 § 5.7 lets the client "automatically rerun
    /// the NTS-KE protocol upon forced disassociation", as long as it "MUST avoid quickly
    /// looping between the NTS-KE and NTP servers by rate limiting the retries". So the
    /// association ends all the same, and a new key exchange - a new association, with keys and
    /// cookies of its own - is allowed after a backoff of § 4.2: first after
    /// <see cref="UnauthenticatedDenyPause"/>, then 1.5 times as long each time, at least ten
    /// seconds and at most five days, and not reset before the new association has been
    /// answered (<see cref="TryBeginKeyExchangeRerun"/>, <see cref="RecordKeyExchange"/>).
    /// A forger costs this client one pause per forged datagram; a server that means it is
    /// asked less and less often.
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


        /// <summary>
        /// Upper bound on poll exponents so 2^exponent seconds can never overflow <see cref="TimeSpan"/>.
        /// </summary>
        public const Byte AbsoluteMaximumPollExponent = 30;

        /// <summary>
        /// The shortest wait before a new key exchange after a forced disassociation: the
        /// "initial and minimum retry interval of 10 seconds" of RFC 8915 § 4.2.
        /// </summary>
        public static readonly TimeSpan MinimumKeyExchangeRetryInterval = TimeSpan.FromSeconds(10);

        /// <summary>
        /// The longest wait before a new key exchange: the "maximum retry interval of 5 days"
        /// of RFC 8915 § 4.2.
        /// </summary>
        public static readonly TimeSpan MaximumKeyExchangeRetryInterval = TimeSpan.FromDays(5);

        /// <summary>
        /// How much longer each further wait is: the "base of 1.5" of RFC 8915 § 4.2.
        /// </summary>
        public const Double KeyExchangeRetryBase = 1.5;


        private readonly Lock             padlock = new();
        private          Byte             pollExponent;
        private          Boolean          demobilized;
        private          DateTimeOffset?  nextQueryNotBefore;
        private          NTPKissOfDeath?  lastKiss;

        // A forced disassociation after which a new key exchange may follow (RFC 8915 § 5.7),
        // the key exchanges begun since the last association that was answered (§ 4.2), and
        // whether one of them is under way.
        private          Boolean          mayRerunKeyExchange;
        private          Int32            keyExchangeReruns;
        private          Boolean          keyExchangeRerunBegun;
        private          DateTimeOffset?  keyExchangeNotBefore;

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
        /// How long this client waits before a new key exchange with an NTS server whose
        /// association a "DENY" or "RSTR" kiss without authentication ended: the first retry
        /// interval of RFC 8915 § 4.2, after which each one is 1.5 times as long.
        /// </summary>
        /// <remarks>
        /// The price of one datagram that anyone on the path can write, so it is a weighing:
        /// long enough that a server which meant it is left alone, short enough that a
        /// forger gains little. The default is the longest poll interval, about two hours
        /// with RFC 8633's ceiling of 13. It is held to § 4.2's range, ten seconds to five
        /// days: the kiss is never ignored, as § 5.7 has the client comply with it.
        /// </remarks>
        public TimeSpan         UnauthenticatedDenyPause  { get; }

        /// <summary>
        /// The current poll exponent: the interval between queries is 2^this seconds.
        /// </summary>
        public Byte             PollExponent
        {
            get { lock (padlock) return pollExponent; }
        }

        /// <summary>
        /// Whether a RATE kiss has slowed this client down, and it has not yet earned
        /// its starting rate back.
        /// </summary>
        public Boolean          IsRateLimited
        {
            get { lock (padlock) return pollExponent > InitialPollExponent; }
        }

        /// <summary>
        /// The interval the current poll exponent stands for.
        /// </summary>
        public TimeSpan         PollInterval
        {
            get { lock (padlock) return TimeSpan.FromSeconds(Math.Pow(2, pollExponent)); }
        }

        /// <summary>
        /// Whether this server has told this client to go away, with a "DENY" or "RSTR" kiss.
        /// </summary>
        /// <remarks>
        /// § 7.4 a says to stop sending packets, not to stop for a while, and nothing a server
        /// that is not being queried can send will change its mind. Undoing this is an
        /// operator's decision, made through <see cref="Reset"/> - or, where the kiss of an NTS
        /// association was not authenticated, a new key exchange after the backoff of RFC 8915
        /// § 4.2 (<see cref="MayRerunKeyExchange"/>).
        /// </remarks>
        public Boolean          Demobilized
        {
            get { lock (padlock) return demobilized; }
        }

        /// <summary>
        /// Where the association was ended by a kiss without authentication on an NTS
        /// association: the earliest a new key exchange may be begun. Null otherwise.
        /// </summary>
        public DateTimeOffset?  KeyExchangeNotBefore
        {
            get { lock (padlock) return mayRerunKeyExchange ? keyExchangeNotBefore : null; }
        }

        /// <summary>
        /// The key exchanges begun after forced disassociations since an association was last
        /// answered: the n of RFC 8915 § 4.2.
        /// </summary>
        public Int32            KeyExchangeReruns
        {
            get { lock (padlock) return keyExchangeReruns; }
        }

        /// <summary>
        /// The earliest this client should query again, or null when it may query now.
        /// </summary>
        public DateTimeOffset?  NextQueryNotBefore
        {
            get { lock (padlock) return nextQueryNotBefore; }
        }

        /// <summary>
        /// The last kiss code accepted from this server, if any.
        /// </summary>
        public NTPKissOfDeath?  LastKiss
        {
            get { lock (padlock) return lastKiss; }
        }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create the access state for one server.
        /// </summary>
        /// <param name="InitialPollExponent">Where to start, before any kiss code (default: the minimum).</param>
        /// <param name="MinimumPollExponent">The fastest this client will poll this server.</param>
        /// <param name="MaximumPollExponent">The slowest a kiss code can drive this client.</param>
        /// <param name="UnauthenticatedDenyPause">How long to wait before a new key exchange after an unauthenticated "DENY" or "RSTR" on an NTS association, the first time (default: the longest poll interval; held to ten seconds to five days).</param>
        public NTPServerAccessState(Byte?      InitialPollExponent        = null,
                                    Byte?      MinimumPollExponent        = null,
                                    Byte?      MaximumPollExponent        = null,
                                    TimeSpan?  UnauthenticatedDenyPause   = null)
        {

            if (UnauthenticatedDenyPause < TimeSpan.Zero)
                throw new ArgumentOutOfRangeException(nameof(UnauthenticatedDenyPause), "The pause must not be negative!");

            this.MinimumPollExponent  = Math.Min(AbsoluteMaximumPollExponent,
                                                 MinimumPollExponent ?? DefaultMinimumPollExponent);
            this.MaximumPollExponent  = Math.Clamp(MaximumPollExponent ?? DefaultMaximumPollExponent,
                                                   this.MinimumPollExponent,
                                                   AbsoluteMaximumPollExponent);

            this.InitialPollExponent  = (Byte) Math.Clamp(InitialPollExponent ?? this.MinimumPollExponent,
                                                          this.MinimumPollExponent,
                                                          this.MaximumPollExponent);

            this.pollExponent         = this.InitialPollExponent;

            var pause                      = UnauthenticatedDenyPause ?? TimeSpan.FromSeconds(Math.Pow(2, this.MaximumPollExponent));

            this.UnauthenticatedDenyPause  = pause < MinimumKeyExchangeRetryInterval ? MinimumKeyExchangeRetryInterval
                                           : pause > MaximumKeyExchangeRetryInterval ? MaximumKeyExchangeRetryInterval
                                           : pause;

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

                if (demobilized)
                    return false;

                return nextQueryNotBefore is null ||
                       Now >= nextQueryNotBefore.Value;

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
                if (pollExponent > InitialPollExponent)
                    nextQueryNotBefore = Now + TimeSpan.FromSeconds(Math.Pow(2, pollExponent));
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
        /// And the backoff of new key exchanges starts again from the beginning: RFC 8915 § 4.2
        /// resets it only after "a successful key establishment ... followed by a successful
        /// use of the negotiated Next Protocol", and an answer is that use.
        /// </remarks>
        public void RecordAnswer()
        {

            lock (padlock)
            {

                if (pollExponent > InitialPollExponent)
                    pollExponent--;

                if (!demobilized)
                    keyExchangeReruns = 0;

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

                lastKiss = Kiss;

                switch (Kiss.Action)
                {

                    case NTPKissAction.Demobilize:

                        if (Trust == NTPKissTrust.Unauthenticated)
                        {

                            // An NTS server that wants this client gone can seal that under
                            // the S2C key. A kiss without it may come from anyone who saw
                            // the request: the association ends as § 7.4 a says, and a new
                            // one may follow, rate limited (RFC 8915 § 5.7, § 4.2).
                            DemobilizeUntilAKeyExchange(Now);
                            break;

                        }

                        Demobilize();
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
                        var target          = pollExponent + 1;

                        pollExponent        = (Byte) Math.Clamp(target,
                                                                MinimumPollExponent,
                                                                MaximumPollExponent);

                        nextQueryNotBefore  = Now + TimeSpan.FromSeconds(Math.Pow(2, pollExponent));

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

        #region ApplyNTPv5Poll(Poll, Now, Trust)

        /// <summary>
        /// The largest minimum poll exponent an unauthenticated NTPv5 response is followed in,
        /// the example of draft-ietf-ntp-ntpv5-10 § 9: 2^15 seconds, about nine hours.
        /// </summary>
        public const SByte MaximumNTPv5PollUnauthenticated = 15;

        /// <summary>
        /// The largest minimum poll exponent an authenticated NTPv5 response is followed in,
        /// the example of § 9: 2^18 seconds, about three days.
        /// </summary>
        public const SByte MaximumNTPv5PollAuthenticated   = 18;

        /// <summary>
        /// The poll field of a valid NTPv5 response, which supersedes the RATE and DENY kisses
        /// of NTPv4 (§ 6): the minimum polling interval the server allows, or 127 where it
        /// "does not want to hear from the client again". Returns whether the server may
        /// still be queried at all.
        /// </summary>
        /// <remarks>
        /// <para>
        /// § 9: the client "SHOULD respect the minimum allowed polling interval provided by
        /// the server in the poll field of the last valid response, but only up to a reasonable
        /// maximum value", 2^15 without authentication and 2^18 with it. The interval counts
        /// from now, the time of the response, and only lengthens the wait: a server allowing
        /// a shorter one than a RATE kiss imposed does not lift it.
        /// </para>
        /// <para>
        /// 127 is taken as a DENY kiss would be, by <paramref name="Trust"/>: it ends the
        /// association, for good from a plain association or an authenticated response, and
        /// until a new key exchange after the backoff of RFC 8915 § 4.2 where an NTS
        /// association received it unauthenticated.
        /// </para>
        /// </remarks>
        public Boolean ApplyNTPv5Poll(SByte           Poll,
                                      DateTimeOffset  Now,
                                      NTPKissTrust    Trust   = NTPKissTrust.Unprotected)
        {

            lock (padlock)
            {

                if (Poll == NTPv5.NTPv5Packet.PollGoAway)
                {

                    if (Trust == NTPKissTrust.Unauthenticated)
                        DemobilizeUntilAKeyExchange(Now);
                    else
                        Demobilize();

                    return false;

                }

                ntpv5MinimumPoll = Math.Min(Poll, Trust == NTPKissTrust.Authenticated
                                                      ? MaximumNTPv5PollAuthenticated
                                                      : MaximumNTPv5PollUnauthenticated);

                if (ntpv5MinimumPoll > 0)
                {

                    var notBefore = Now + TimeSpan.FromSeconds(Math.Pow(2, ntpv5MinimumPoll.Value));

                    if (nextQueryNotBefore is null || notBefore > nextQueryNotBefore.Value)
                        nextQueryNotBefore = notBefore;

                }

                return !demobilized;

            }

        }

        private SByte? ntpv5MinimumPoll;

        /// <summary>
        /// The minimum poll exponent of the last valid NTPv5 response, capped as § 9 has it;
        /// null before the first.
        /// </summary>
        public SByte? NTPv5MinimumPoll
        {
            get { lock (padlock) return ntpv5MinimumPoll; }
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

                pollExponent           = InitialPollExponent;
                demobilized            = false;
                nextQueryNotBefore     = null;
                lastKiss               = null;
                ntpv5MinimumPoll       = null;
                mayRerunKeyExchange    = false;
                keyExchangeReruns      = 0;
                keyExchangeRerunBegun  = false;
                keyExchangeNotBefore   = null;

            }

        }

        #endregion


        #region MayRerunKeyExchange(Now)

        /// <summary>
        /// Whether a new key exchange may be begun now, for a new association in place of one
        /// a kiss without authentication ended (RFC 8915 § 5.7).
        /// </summary>
        public Boolean MayRerunKeyExchange(DateTimeOffset Now)
        {
            lock (padlock)
                return MayRerunKeyExchangeLocked(Now);
        }

        private Boolean MayRerunKeyExchangeLocked(DateTimeOffset Now)

            => demobilized         &&
               mayRerunKeyExchange &&
               keyExchangeNotBefore is DateTimeOffset notBefore &&
               Now >= notBefore;

        #endregion

        #region TryBeginKeyExchangeRerun(Now)

        /// <summary>
        /// A new key exchange is about to be begun: returns whether it may be, and if so, counts
        /// it and sets when the next may follow, should this one not succeed.
        /// </summary>
        /// <remarks>
        /// RFC 8915 § 4.2: "t = min(10 * 1.5^(n-1), 432000)" seconds, here from
        /// <see cref="UnauthenticatedDenyPause"/> instead of ten. A key exchange that fails
        /// is a retry like any other, and the next one waits longer.
        /// </remarks>
        public Boolean TryBeginKeyExchangeRerun(DateTimeOffset Now)
        {

            lock (padlock)
            {

                if (!MayRerunKeyExchangeLocked(Now))
                    return false;

                keyExchangeReruns++;
                keyExchangeRerunBegun  = true;
                keyExchangeNotBefore   = Now + KeyExchangeRetryInterval(keyExchangeReruns + 1);

                return true;

            }

        }

        #endregion

        #region RecordKeyExchange(Now)

        /// <summary>
        /// The key exchange begun with <see cref="TryBeginKeyExchangeRerun"/> has succeeded: the
        /// new association may be queried. Returns whether this client may query the server.
        /// </summary>
        /// <remarks>
        /// Nothing else lifts a demobilization: a key exchange that was not begun as a rerun, or
        /// one after a kiss that was authenticated, leaves it as it is.
        /// </remarks>
        public Boolean RecordKeyExchange(DateTimeOffset Now)
        {

            lock (padlock)
            {

                if (demobilized && mayRerunKeyExchange && keyExchangeRerunBegun)
                {
                    demobilized            = false;
                    mayRerunKeyExchange    = false;
                    keyExchangeRerunBegun  = false;
                    keyExchangeNotBefore   = null;
                    nextQueryNotBefore     = null;
                }

                return !demobilized;

            }

        }

        #endregion

        #region KeyExchangeRetryInterval(N)

        /// <summary>
        /// The wait before the n-th new key exchange since an association was last answered.
        /// </summary>
        public TimeSpan KeyExchangeRetryInterval(Int32 N)
        {

            var seconds = UnauthenticatedDenyPause.TotalSeconds * Math.Pow(KeyExchangeRetryBase, Math.Max(0, N - 1));

            return seconds >= MaximumKeyExchangeRetryInterval.TotalSeconds
                       ? MaximumKeyExchangeRetryInterval
                       : TimeSpan.FromSeconds(Math.Max(seconds, MinimumKeyExchangeRetryInterval.TotalSeconds));

        }

        #endregion

        #region (private) Demobilize() / DemobilizeUntilAKeyExchange(Now)

        private void Demobilize()
        {
            demobilized            = true;
            nextQueryNotBefore     = null;
            mayRerunKeyExchange    = false;
            keyExchangeRerunBegun  = false;
            keyExchangeNotBefore   = null;
        }

        private void DemobilizeUntilAKeyExchange(DateTimeOffset Now)
        {

            // An authenticated demobilization is not softened by a later forged one.
            if (demobilized && !mayRerunKeyExchange)
                return;

            demobilized            = true;
            nextQueryNotBefore     = null;
            mayRerunKeyExchange    = true;
            keyExchangeRerunBegun  = false;
            keyExchangeNotBefore   = Now + KeyExchangeRetryInterval(keyExchangeReruns + 1);

        }

        #endregion


        public override String ToString()
        {

            lock (padlock)
            {
                return demobilized
                           ? mayRerunKeyExchange
                                 ? $"demobilized ({lastKiss?.Code ?? "?"}), a new key exchange not before {keyExchangeNotBefore:o}"
                                 : $"demobilized ({lastKiss?.Code ?? "?"})"
                           : $"poll {pollExponent} ({Math.Pow(2, pollExponent):0} s)";
            }

        }

    }

}
