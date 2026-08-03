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

using System.Net;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// What a server should do with a request, once the rate limiter has looked at it.
    /// </summary>
    public enum RateLimitDecision
    {

        /// <summary>Answer it normally.</summary>
        Answer,

        /// <summary>Drop it without a word.</summary>
        Drop,

        /// <summary>
        /// Drop it, but tell the client why: a Kiss-o'-Death carrying the "RATE" kiss code, so a
        /// client that respects RFC 5905 § 7.4 can back off instead of being left to guess at
        /// silence.
        /// </summary>
        KissOfDeath

    }


    /// <summary>
    /// Per-address request rate limiting for the NTP/NTS server, and the budget governing how
    /// often it answers with a "RATE" Kiss-o'-Death.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 8633 § 5.4 recommends the mechanism from both ends: clients ought to respect a RATE
    /// kiss, and "server administrators are advised to be prepared" for the clients that do not.
    /// This is the server end. It is off unless an operator turns it on — a time server exists to
    /// answer, and a limit that silently drops packets is a policy decision about who the server
    /// is for, not a safe default. chrony makes the same choice with its <c>ratelimit</c>
    /// directive.
    /// </para>
    /// <para>
    /// The limit is a token bucket per client address: tokens accrue at one per
    /// <see cref="MinimumInterval"/> up to <see cref="Burst"/> of them, and every answered
    /// request spends one. A bucket rather than a fixed window because a client that polls
    /// steadily at the permitted rate should never be limited, while one that fires a burst
    /// after a long silence should be allowed to — which is exactly what a client following
    /// RFC 5905's <c>iburst</c> does on startup.
    /// </para>
    /// <para>
    /// Two things make the kisses themselves scarcer than the drops, and both matter more than
    /// they first appear. A KoD is a packet this server sends to whatever address was written in
    /// the request, and on UDP that address is whatever the sender chose — so an unthrottled
    /// kiss turns a limited server into a reflector aimed at somebody else. Per-address
    /// throttling alone does not help there, because every forged address arrives with its own
    /// unused allowance; hence the global budget as well, which is the only one of the two that
    /// bounds what this server can be made to emit in total.
    /// </para>
    /// <para>
    /// State is bounded and evicted in constant time for the same reason it is in
    /// <see cref="InterleavedTimestamps"/>: the table is keyed by an address an attacker picks,
    /// so both the memory it occupies and the work of making room in it have to be capped.
    /// </para>
    /// <para>
    /// Time is read from <see cref="TimeProvider.GetTimestamp"/> rather than the wall clock,
    /// which is deliberate on a time server of all things: the wall clock here is the thing being
    /// served and may be stepped, and a step backwards would hand every client a full bucket
    /// while a step forwards would freeze the limiter.
    /// </para>
    /// </remarks>
    public sealed class NTPRateLimiter
    {

        #region Data

        /// <summary>
        /// The default average interval between answered requests from one address.
        /// </summary>
        /// <remarks>
        /// Two seconds is far below any sane polling rate — RFC 5905's minimum poll exponent of 4
        /// is sixteen seconds — so this limits floods and nothing else.
        /// </remarks>
        public static readonly TimeSpan DefaultMinimumInterval    = TimeSpan.FromSeconds(2);

        /// <summary>
        /// The default depth of one client's bucket, and so the longest burst it may fire after
        /// being quiet. Eight covers an <c>iburst</c> start-up volley with room to spare.
        /// </summary>
        public const           Int32    DefaultBurst              = 8;

        /// <summary>
        /// The default shortest interval between two RATE kisses to the same address.
        /// </summary>
        /// <remarks>
        /// A client that heeds the first kiss does not need the second, and one that ignores it
        /// will not be persuaded by repetition — so this is generous. It is also the reason a
        /// limited client mostly meets silence: the kisses are the exception.
        /// </remarks>
        public static readonly TimeSpan DefaultKissInterval       = TimeSpan.FromSeconds(30);

        /// <summary>
        /// The default ceiling on RATE kisses per second across all addresses together.
        /// </summary>
        /// <remarks>
        /// This is the anti-reflection bound, and the one that survives forged source addresses.
        /// Low on purpose: kisses are a courtesy to well-behaved clients, of which there are
        /// never many being limited at once, and a courtesy is not worth being made to spray
        /// packets at a stranger.
        /// </remarks>
        public const           Double   DefaultMaxKissesPerSecond = 4.0;

        /// <summary>
        /// How many client addresses to track at once.
        /// </summary>
        public const           Int32    DefaultMaxClients         = 8192;

        /// <summary>
        /// The largest poll exponent this server will ask a client to move to.
        /// </summary>
        /// <remarks>
        /// RFC 8633 § 5.4: a client "MUST NOT simply accept any value ... should not exceed a
        /// poll interval value of 13 (two hours)", because a forged RATE kiss carrying a huge
        /// poll value is a denial of service in itself. A conformant client therefore clamps to
        /// 13, and a server asking for more is only asking to be second-guessed.
        /// </remarks>
        public const           Byte     MaxPollExponent           = 13;


        private sealed class ClientState
        {

            /// <summary>Tokens left in this client's bucket, fractional between refills.</summary>
            public Double                      Tokens        { get; set; }

            /// <summary>When the bucket was last refilled, on the monotonic clock.</summary>
            public Int64                       LastRefill    { get; set; }

            /// <summary>When this address was last sent a RATE kiss, or null if it never was.</summary>
            public Int64?                      LastKiss      { get; set; }

            /// <summary>This client's place in the recency order, so that eviction is O(1).</summary>
            public LinkedListNode<IPAddress>?  Recency       { get; set; }

        }


        private readonly Dictionary<IPAddress, ClientState>  clients      = [];
        private readonly LinkedList<IPAddress>               recency      = new ();
        private readonly Lock                                padlock      = new ();

        private          Double                              kissTokens;
        private          Int64                               kissRefill;

        #endregion

        #region Properties

        /// <summary>The clock the limiter measures elapsed time on.</summary>
        public TimeProvider  TimeProvider        { get; }

        /// <summary>The average interval between answered requests from one address.</summary>
        public TimeSpan      MinimumInterval     { get; }

        /// <summary>How many requests one address may fire back to back after being quiet.</summary>
        public Int32         Burst               { get; }

        /// <summary>The shortest interval between two RATE kisses to the same address.</summary>
        public TimeSpan      KissInterval        { get; }

        /// <summary>The ceiling on RATE kisses per second across all addresses together.</summary>
        public Double        MaxKissesPerSecond  { get; }

        /// <summary>How many client addresses are tracked at once.</summary>
        public Int32         MaxClients          { get; }

        /// <summary>How many client addresses are currently tracked.</summary>
        public Int32         TrackedClients
        {
            get
            {
                lock (padlock)
                    return clients.Count;
            }
        }

        /// <summary>
        /// The poll exponent to put in a RATE kiss: the smallest power of two that is at least
        /// <see cref="MinimumInterval"/>, so a client that adopts it stops being limited.
        /// </summary>
        /// <remarks>
        /// Clamped to <see cref="MaxPollExponent"/> at the top, because that is where a client
        /// following RFC 8633 § 5.4 would clamp it anyway, and to RFC 5905's minimum poll
        /// exponent of 4 at the bottom: asking a client to poll faster than the protocol's floor
        /// is not something this mechanism is for.
        /// </remarks>
        public Byte          KissPollExponent    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a rate limiter.
        /// </summary>
        /// <param name="MinimumInterval">The average interval between answered requests from one address.</param>
        /// <param name="Burst">How many requests one address may fire back to back after being quiet.</param>
        /// <param name="KissInterval">The shortest interval between two RATE kisses to the same address.</param>
        /// <param name="MaxKissesPerSecond">The ceiling on RATE kisses per second across all addresses together.</param>
        /// <param name="MaxClients">How many client addresses to track at once.</param>
        /// <param name="TimeProvider">The clock to measure elapsed time on.</param>
        public NTPRateLimiter(TimeSpan?      MinimumInterval      = null,
                              Int32?         Burst                = null,
                              TimeSpan?      KissInterval         = null,
                              Double?        MaxKissesPerSecond   = null,
                              Int32?         MaxClients           = null,
                              TimeProvider?  TimeProvider         = null)
        {

            this.TimeProvider        = TimeProvider ?? System.TimeProvider.System;
            this.MinimumInterval     = MinimumInterval is not null && MinimumInterval.Value > TimeSpan.Zero
                                           ? MinimumInterval.Value
                                           : DefaultMinimumInterval;
            this.Burst               = Math.Max(1, Burst ?? DefaultBurst);
            this.KissInterval        = KissInterval       ?? DefaultKissInterval;
            this.MaxKissesPerSecond  = Math.Max(0, MaxKissesPerSecond ?? DefaultMaxKissesPerSecond);
            this.MaxClients          = Math.Max(1, MaxClients         ?? DefaultMaxClients);

            var exponent             = Math.Ceiling(Math.Log2(Math.Max(1.0, this.MinimumInterval.TotalSeconds)));

            this.KissPollExponent    = (Byte) Math.Clamp(exponent, 4, MaxPollExponent);

            this.kissRefill          = this.TimeProvider.GetTimestamp();
            this.kissTokens          = 1;

        }

        #endregion


        #region Check(RemoteAddress)

        /// <summary>
        /// Decide what to do with one request from one address, and charge it against that
        /// address's budget.
        /// </summary>
        /// <remarks>
        /// Called once per datagram and before anything is parsed, which is the whole point:
        /// unsealing a cookie and verifying an authenticator is the most expensive thing this
        /// server does per packet, and a flood that gets that far has already won something.
        /// The cost of a limited packet is one dictionary lookup and two subtractions.
        /// </remarks>
        /// <param name="RemoteAddress">The address the datagram claims to come from.</param>
        public RateLimitDecision Check(IPAddress RemoteAddress)
        {

            var now = TimeProvider.GetTimestamp();

            lock (padlock)
            {

                var client   = GetOrAddClient(RemoteAddress, now);

                var elapsed  = TimeProvider.GetElapsedTime(client.LastRefill, now);

                client.Tokens      = Math.Min(
                                         Burst,
                                         client.Tokens + elapsed.TotalSeconds / MinimumInterval.TotalSeconds
                                     );
                client.LastRefill  = now;

                if (client.Tokens >= 1.0)
                {
                    client.Tokens -= 1.0;
                    return RateLimitDecision.Answer;
                }

                // Limited from here on. Whether the client is told so is a second, stricter
                // question — one it does not get to ask more than once per KissInterval, and one
                // the global budget can refuse outright however many addresses are asking.
                if (client.LastKiss is not null &&
                    TimeProvider.GetElapsedTime(client.LastKiss.Value, now) < KissInterval)
                {
                    return RateLimitDecision.Drop;
                }

                if (!TrySpendKissToken(now))
                    return RateLimitDecision.Drop;

                client.LastKiss = now;

                return RateLimitDecision.KissOfDeath;

            }

        }

        #endregion

        #region Forget(RemoteAddress)

        /// <summary>
        /// Drop everything remembered about one client address.
        /// </summary>
        public void Forget(IPAddress RemoteAddress)
        {
            lock (padlock)
            {

                if (clients.Remove(RemoteAddress, out var removed) &&
                    removed.Recency is not null)
                {
                    recency.Remove(removed.Recency);
                }

            }
        }

        #endregion

        #region Clear()

        /// <summary>
        /// Drop everything.
        /// </summary>
        public void Clear()
        {
            lock (padlock)
            {
                clients.Clear();
                recency.Clear();
            }
        }

        #endregion


        #region (private) TrySpendKissToken(Now)

        /// <summary>
        /// The global kiss budget: a second token bucket, shared by every address, refilling at
        /// <see cref="MaxKissesPerSecond"/> and never deeper than one second's worth.
        /// </summary>
        /// <remarks>
        /// Shallow on purpose. Depth here would be a stored allowance for a burst of kisses, and
        /// a burst of kisses to forged addresses is the exact thing this bucket exists to
        /// prevent.
        /// </remarks>
        private Boolean TrySpendKissToken(Int64 Now)
        {

            if (MaxKissesPerSecond <= 0)
                return false;

            kissTokens  = Math.Min(
                              MaxKissesPerSecond,
                              kissTokens + TimeProvider.GetElapsedTime(kissRefill, Now).TotalSeconds * MaxKissesPerSecond
                          );
            kissRefill  = Now;

            if (kissTokens < 1.0)
                return false;

            kissTokens -= 1.0;

            return true;

        }

        #endregion

        #region (private) GetOrAddClient(RemoteAddress, Now)

        private ClientState GetOrAddClient(IPAddress  RemoteAddress,
                                           Int64      Now)
        {

            if (clients.TryGetValue(RemoteAddress, out var existing))
            {

                if (existing.Recency is not null)
                {
                    recency.Remove(existing.Recency);
                    recency.AddLast(existing.Recency);
                }

                return existing;

            }

            // Evicting the address used longest ago, rather than refusing to track the new one.
            // Refusing would mean an untracked address is an unlimited one, so a flood large
            // enough to fill the table would switch the limiter off for its own later packets —
            // which is the opposite of what it is for.
            if (clients.Count >= MaxClients &&
                recency.First is not null)
            {

                var leastRecentlyUsed = recency.First;

                recency.Remove(leastRecentlyUsed);
                clients.Remove(leastRecentlyUsed.Value);

            }

            // A new address starts with a full bucket. It has not been seen misbehaving, and the
            // alternative — starting empty — would limit every first-time client, including the
            // one packet a passing monitoring system sends.
            var created = new ClientState {
                              Tokens      = Burst,
                              LastRefill  = Now,
                              Recency     = recency.AddLast(RemoteAddress)
                          };

            clients.Add(RemoteAddress, created);

            return created;

        }

        #endregion

    }

}
