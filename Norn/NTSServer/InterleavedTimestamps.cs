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

using org.GraphDefined.Vanaheimr.Norn.NTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// Who a server will answer in the RFC 9769 interleaved mode.
    /// </summary>
    /// <remarks>
    /// RFC 9769 § 2: "The server MAY restrict the interleaved mode to specific IP addresses
    /// and/or authenticated clients."
    ///
    /// The reason to want that is resources. Interleaved mode obliges a server to remember
    /// something per client address, and on a UDP service the source address is whatever the
    /// sender wrote there — so an unauthenticated flood is also a stream of new "clients". The
    /// table is bounded and evicts in constant time, so the cost is capped either way; this is
    /// the stronger option for a public server, where nothing but an NTS client's cookie proves
    /// the address it came from is real.
    /// </remarks>
    public enum InterleavedModePolicy
    {

        /// <summary>Never answer in the interleaved mode.</summary>
        Disabled,

        /// <summary>Answer any client that asks for it, as chrony does.</summary>
        Everyone,

        /// <summary>
        /// Answer only requests carrying a verified NTS authenticator, so that an address has
        /// to have completed a key exchange before it can occupy a slot.
        /// </summary>
        AuthenticatedOnly

    }


    /// <summary>
    /// The server-side state of RFC 9769 interleaved client/server mode.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The idea behind the interleaved mode is that a server cannot know when a response left
    /// until after it has left. Everything between reading the clock and the packet reaching
    /// the wire — building the header, encrypting the extension fields, the write into the
    /// socket — sits between the timestamp a client is told and the transmission it actually
    /// measured. So the server sends the transmit timestamp of the <em>previous</em> response
    /// instead, captured after that one went out, and the client completes the earlier
    /// measurement with it.
    /// </para>
    /// <para>
    /// Nothing about this changes the packet: no new extension field, no header change, and
    /// the negotiation is implicit. Which is what makes the bookkeeping delicate, because the
    /// only thing distinguishing an interleaved request from a basic one is <em>which</em> of
    /// the server's previous timestamps the client echoed in the origin field. Get the
    /// bookkeeping wrong and a perfectly ordinary basic-mode request draws a response carrying
    /// a transmit timestamp from some other exchange, which the client will believe.
    /// </para>
    /// <para>
    /// Two rules of § 2 protect against that, and both are enforced here. The receive and
    /// transmit timestamps this server hands out must be unique, or two clients could arrive
    /// at the same origin timestamp and one would be answered with the other's transmission.
    /// And a receive timestamp may satisfy an interleaved request exactly once, so a replayed
    /// request cannot draw the same answer twice.
    /// </para>
    /// <para>
    /// Timestamps are kept per IP address and never per port: RFC 9769 § 2 asks for this
    /// explicitly, so that a client following RFC 9109 and drawing a fresh source port for
    /// each request does not lose its association on every exchange.
    /// </para>
    /// </remarks>
    public sealed class InterleavedTimestamps
    {

        #region Data

        /// <summary>
        /// How many exchanges to remember per client address. RFC 9769 § 2 asks for "a
        /// fixed-length queue"; four covers a client whose requests overtake its responses
        /// without giving one address room to crowd out the others.
        /// </summary>
        public const Int32 DefaultMaxExchangesPerClient = 4;

        /// <summary>
        /// How many client addresses to remember at once. The cap is what stops the interleaved
        /// mode from becoming a way to make a public server allocate without limit.
        /// </summary>
        public const Int32 DefaultMaxClients            = 4096;


        private sealed class Exchange
        {

            /// <summary>The receive timestamp this server put in the response, and the client will echo.</summary>
            public UInt64   ReceiveTimestamp    { get; init; }

            /// <summary>
            /// When the response actually left, filled in once it has. Null until then, and an
            /// exchange without it cannot answer an interleaved request — there is nothing yet
            /// to answer it with.
            /// </summary>
            public UInt64?  TransmitTimestamp   { get; set; }

        }


        private sealed class ClientState
        {

            public LinkedList<Exchange>        Exchanges  { get; } = new ();

            /// <summary>
            /// This client's place in the recency order, so that using it and evicting the
            /// least recent are both O(1).
            /// </summary>
            public LinkedListNode<IPAddress>?  Recency    { get; set; }

        }


        private readonly Dictionary<IPAddress, ClientState>  clients   = [];

        /// <summary>
        /// The client addresses in order of use, least recent first.
        /// </summary>
        /// <remarks>
        /// A list rather than a timestamp to sort by, because sorting would be work an attacker
        /// controls the amount of. This table is keyed by source address on a UDP service, so
        /// addresses can be forged freely and every forged one is a new client: with a scan to
        /// find the least recently used, each spoofed packet would cost a pass over the whole
        /// table once it filled. The memory stayed bounded and the CPU did not.
        /// </remarks>
        private readonly LinkedList<IPAddress>               recency   = new();

        private readonly Lock                                padlock   = new();

        #endregion

        #region Properties

        /// <summary>Who may be answered in the interleaved mode.</summary>
        public InterleavedModePolicy Policy    { get; }

        /// <summary>How many exchanges are remembered per client address.</summary>
        public Int32  MaxExchangesPerClient    { get; }

        /// <summary>How many client addresses are remembered at once.</summary>
        public Int32  MaxClients               { get; }

        /// <summary>How many client addresses are currently remembered.</summary>
        public Int32  TrackedClients
        {
            get
            {
                lock (padlock)
                    return clients.Count;
            }
        }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create the interleaved-mode timestamp store.
        /// </summary>
        /// <param name="Policy">Who may be answered in the interleaved mode.</param>
        /// <param name="MaxExchangesPerClient">How many exchanges to remember per client address.</param>
        /// <param name="MaxClients">How many client addresses to remember at once.</param>
        public InterleavedTimestamps(InterleavedModePolicy?  Policy                  = null,
                                     Int32?                  MaxExchangesPerClient   = null,
                                     Int32?                  MaxClients              = null)
        {

            this.Policy                 = Policy ?? InterleavedModePolicy.Everyone;
            this.MaxExchangesPerClient  = Math.Max(1, MaxExchangesPerClient ?? DefaultMaxExchangesPerClient);
            this.MaxClients             = Math.Max(1, MaxClients            ?? DefaultMaxClients);

        }

        #endregion


        #region BeginExchange(RemoteAddress, ReceiveTimestamp, RequestPacket, TimeProvider)

        /// <summary>
        /// Decide how to answer this request, and reserve the timestamps the answer will carry.
        /// </summary>
        /// <remarks>
        /// RFC 9769 § 2: "the server MUST NOT respond in the interleaved mode unless the
        /// following two conditions are met: 1. The request does not have a receive timestamp
        /// equal to the transmit timestamp. 2. The origin timestamp from the request matches
        /// the local receive timestamp of a previous request that the server has saved."
        ///
        /// Condition 1 is the client's half of the same rule that binds the server: if the two
        /// timestamps in a packet were equal, whoever received it could not tell which of them
        /// a reply was echoing, and so could not tell the two modes apart.
        ///
        /// Whichever mode results, the new timestamps are saved — § 2: "In any case, the server
        /// SHOULD save the new receive and transmit timestamps to be able to respond in the
        /// interleaved mode to the next request from the client."
        /// </remarks>
        /// <param name="RemoteAddress">The client's address; the mode is tracked per address, never per port.</param>
        /// <param name="ReceiveTimestamp">When the datagram arrived.</param>
        /// <param name="RequestPacket">The parsed request.</param>
        /// <param name="TimeProvider">The clock to read for a basic-mode transmit timestamp.</param>
        /// <param name="Authenticated">
        /// Whether the request carried a verified NTS authenticator, which decides whether it
        /// qualifies under <see cref="InterleavedModePolicy.AuthenticatedOnly"/>.
        /// </param>
        public InterleavedExchange BeginExchange(IPAddress     RemoteAddress,
                                                 UInt64        ReceiveTimestamp,
                                                 NTPPacket     RequestPacket,
                                                 TimeProvider  TimeProvider,
                                                 Boolean       Authenticated   = false)
        {

            // Nothing is remembered about a client that may not use the mode, so an
            // unauthenticated flood cannot occupy the table under this policy.
            if (Policy == InterleavedModePolicy.AuthenticatedOnly && !Authenticated)
                return InterleavedExchange.Basic(RequestPacket, ReceiveTimestamp, TimeProvider);


            var requestOrigin    = RequestPacket.OriginateTimestamp;
            var requestReceive   = RequestPacket.ReceiveTimestamp;
            var requestTransmit  = RequestPacket.TransmitTimestamp ?? 0UL;

            lock (padlock)
            {

                var client = GetOrAddClient(RemoteAddress);

                // Condition 1, and the shortcut of § 2's closing paragraph: a zero origin
                // timestamp is the first request of an association and can match nothing.
                var interleavedRequest = requestOrigin != 0 &&
                                         requestReceive != requestTransmit;

                UInt64? previousTransmit = null;

                if (interleavedRequest)
                {

                    // Condition 2. Consumed rather than merely read: § 2 — "The receive
                    // timestamp MUST NOT be used again to detect a request conforming to the
                    // interleaved mode." Without that, a replayed request would draw the same
                    // interleaved answer a second time.
                    var match = FindByReceiveTimestamp(client, requestOrigin);

                    if (match?.Value.TransmitTimestamp is not null)
                    {
                        previousTransmit = match.Value.TransmitTimestamp;
                        client.Exchanges.Remove(match);
                    }

                }

                var receiveTimestamp   = MakeUnique(client, ReceiveTimestamp);

                // The transmit timestamp of an interleaved response is a past one, already
                // measured; a basic response can only report the clock as it is now, before the
                // packet has been built, let alone sent.
                var transmitTimestamp  = previousTransmit
                                             ?? MakeUnique(client, NTPPacket.GetCurrentNTPTimestamp(TimeProvider));

                // § 2: "Both servers and clients that support the interleaved mode MUST NOT
                // send a packet that has a transmit timestamp equal to the receive timestamp in
                // order to reliably detect whether received packets conform to the interleaved
                // mode." The RFC's own remedy: "increment the transmit timestamp by 1 unit".
                if (transmitTimestamp == receiveTimestamp)
                    transmitTimestamp++;

                var exchange = new Exchange { ReceiveTimestamp = receiveTimestamp };

                client.Exchanges.AddLast(exchange);

                while (client.Exchanges.Count > MaxExchangesPerClient)
                    client.Exchanges.RemoveFirst();

                return new InterleavedExchange(
                           OriginTimestamp:    previousTransmit is not null ? requestReceive : requestTransmit,
                           ReceiveTimestamp:   receiveTimestamp,
                           TransmitTimestamp:  transmitTimestamp,
                           IsInterleaved:      previousTransmit is not null,
                           OnTransmitted:      actualTransmitTimestamp => {
                                                   lock (padlock)
                                                       exchange.TransmitTimestamp = MakeUnique(client, actualTransmitTimestamp);
                                               }
                       );

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


        #region (private) GetOrAddClient(RemoteAddress)

        private ClientState GetOrAddClient(IPAddress RemoteAddress)
        {

            if (clients.TryGetValue(RemoteAddress, out var existing))
            {

                // Move to the most-recent end. Removing a known node and appending it are both
                // O(1) on a linked list, which is the point of holding the node here.
                if (existing.Recency is not null)
                {
                    recency.Remove(existing.Recency);
                    recency.AddLast(existing.Recency);
                }

                return existing;

            }

            // Evicting the address used longest ago, rather than refusing the new one, so that
            // a flood of one-off addresses degrades the interleaved mode for everybody instead
            // of letting whoever arrived first keep it to themselves.
            if (clients.Count >= MaxClients &&
                recency.First is not null)
            {

                var leastRecentlyUsed = recency.First;

                recency.Remove(leastRecentlyUsed);
                clients.Remove(leastRecentlyUsed.Value);

            }

            var created = new ClientState {
                              Recency = recency.AddLast(RemoteAddress)
                          };

            clients.Add(RemoteAddress, created);

            return created;

        }

        #endregion

        #region (private) FindByReceiveTimestamp(Client, Timestamp)

        private static LinkedListNode<Exchange>? FindByReceiveTimestamp(ClientState  Client,
                                                                        UInt64       Timestamp)
        {

            for (var node = Client.Exchanges.First; node is not null; node = node.Next)
            {
                if (node.Value.ReceiveTimestamp == Timestamp)
                    return node;
            }

            return null;

        }

        #endregion

        #region (private) MakeUnique(Client, Timestamp)

        /// <summary>
        /// Make sure a timestamp is not already outstanding as a receive timestamp for this
        /// client, nudging it forward by the smallest amount the format can express until it is
        /// not.
        /// </summary>
        /// <remarks>
        /// <para>
        /// RFC 9769 § 2: "If the timestamps are not guaranteed to be monotonically increasing,
        /// the server SHOULD check that the transmit and receive timestamps are not already
        /// saved as a receive timestamp of a previous request (from the same IP address if the
        /// server separates timestamps by addresses), and generate a new timestamp if
        /// necessary, to prevent an incorrect interleaved response later."
        /// </para>
        /// <para>
        /// They are certainly not guaranteed to be increasing here. The clock can be stepped,
        /// and — the case that actually bites — the Windows system clock advances about once a
        /// millisecond, so two requests arriving inside one tick read exactly the same value.
        /// A duplicate receive timestamp would let a later interleaved request be answered with
        /// the transmit timestamp of the wrong exchange.
        /// </para>
        /// <para>
        /// One unit of the NTP fraction is about 233 picoseconds, which is why incrementing is
        /// the right remedy rather than a compromise: it is the same fix § 2 prescribes for a
        /// transmit timestamp colliding with a receive timestamp, and it perturbs the reported
        /// time by an amount some twenty million times smaller than the resolution of the clock
        /// being reported. Filling the sub-precision bits with random data would also work and
        /// is what some implementations do, but it moves the reported time by up to a full tick
        /// of that clock to solve a problem three additions solve exactly.
        /// </para>
        /// <para>
        /// Uniqueness is only ever needed within one address, because that is the granularity
        /// at which the timestamps are stored and looked up. Two clients colliding on the same
        /// value cannot be confused with one another.
        /// </para>
        /// </remarks>
        private static UInt64 MakeUnique(ClientState  Client,
                                         UInt64       Timestamp)
        {

            var candidate = Timestamp;

            // Bounded by the queue length: each step either finds a free value or steps past one
            // of a handful of occupied ones, so it cannot run long. Zero is skipped because a
            // zero origin timestamp means "no association" and must never match a saved one.
            for (var attempt = 0; attempt <= Client.Exchanges.Count; attempt++)
            {

                if (candidate != 0 &&
                    FindByReceiveTimestamp(Client, candidate) is null)
                {
                    return candidate;
                }

                candidate++;

            }

            return candidate;

        }

        #endregion

    }


    /// <summary>
    /// What one request/response exchange decided about RFC 9769 interleaved mode, and the
    /// three header timestamps that follow from it.
    /// </summary>
    public sealed class InterleavedExchange
    {

        private readonly Action<UInt64>? onTransmitted;
        private          Boolean         transmissionRecorded;


        internal InterleavedExchange(UInt64           OriginTimestamp,
                                     UInt64           ReceiveTimestamp,
                                     UInt64           TransmitTimestamp,
                                     Boolean          IsInterleaved,
                                     Action<UInt64>?  OnTransmitted   = null)
        {

            this.OriginTimestamp    = OriginTimestamp;
            this.ReceiveTimestamp   = ReceiveTimestamp;
            this.TransmitTimestamp  = TransmitTimestamp;
            this.IsInterleaved      = IsInterleaved;
            this.onTransmitted      = OnTransmitted;

        }


        /// <summary>
        /// The origin timestamp to echo: the request's transmit timestamp in the basic mode,
        /// its receive timestamp in the interleaved mode. This is the only thing telling the
        /// client which mode the response is in.
        /// </summary>
        public UInt64   OriginTimestamp    { get; }

        /// <summary>The receive timestamp to report, which the client may echo back as an origin timestamp.</summary>
        public UInt64   ReceiveTimestamp   { get; }

        /// <summary>
        /// The transmit timestamp to report: when the previous response actually left, in the
        /// interleaved mode, or the clock as it reads now in the basic mode.
        /// </summary>
        public UInt64   TransmitTimestamp  { get; }

        /// <summary>Whether this response is in the interleaved mode.</summary>
        public Boolean  IsInterleaved      { get; }


        /// <summary>
        /// A response with no interleaved bookkeeping behind it, for a server with the mode
        /// switched off.
        /// </summary>
        public static InterleavedExchange Basic(NTPPacket     RequestPacket,
                                                UInt64        ReceiveTimestamp,
                                                TimeProvider  TimeProvider)

            => new (OriginTimestamp:    RequestPacket.TransmitTimestamp ?? 0,
                    ReceiveTimestamp:   ReceiveTimestamp,
                    TransmitTimestamp:  NTPPacket.GetCurrentNTPTimestamp(TimeProvider),
                    IsInterleaved:      false);


        /// <summary>
        /// Record when the response actually left the machine — the whole point of the
        /// interleaved mode, and the value the <em>next</em> response to this client will carry.
        /// </summary>
        /// <remarks>
        /// Only the first call counts. A request answered with more than one packet, as a
        /// request for a signed response is, must attribute the measurement to the packet the
        /// client timed, which is the first one.
        /// </remarks>
        public void RecordTransmission(UInt64 ActualTransmitTimestamp)
        {

            if (transmissionRecorded)
                return;

            transmissionRecorded = true;

            onTransmitted?.Invoke(ActualTransmitTimestamp);

        }

    }

}
