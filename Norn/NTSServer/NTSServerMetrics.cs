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
    /// A point-in-time snapshot of NTS server counters.
    /// </summary>
    public class NTSServerMetrics(Int64 NTPRequestsReceived,
                                  Int64 NTPRequestsRejected,
                                  Int64 NTPRequestsRateLimited,
                                  Int64 NTPKissesOfDeathSent,
                                  Int64 NTPRequestsInvalid,
                                  Int64 NTPResponsesSent,
                                  Int64 NTPSignedResponsesSent,
                                  Int64 NTPRequestFailures,
                                  Int64 NTSKEConnectionsAccepted,
                                  Int64 NTSKEConnectionsRejected,
                                  Int64 NTSKEHandshakeFailures,
                                  Int64 NTSKERequestsInvalid,
                                  Int64 NTSKEResponsesSent,
                                  Int64 NTPRequestsDenied       = 0,
                                  Int64 NTSKEConnectionsDenied  = 0,
                                  Int64 NTPPlainRequestsIgnored = 0,
                                  Int64 NTPv5RequestsReceived            = 0,
                                  Int64 NTPv5ResponsesSent               = 0,
                                  Int64 NTPv5AuthenticatedResponsesSent  = 0,
                                  Int64 NTPv5InterleavedResponsesSent    = 0,
                                  Int64 NTPv5AuthenticationNAKsSent      = 0)
    {

        public Int64 NTPRequestsReceived       { get; } = NTPRequestsReceived;
        /// <summary>
        /// How many requests were dropped because the access list of RFC 8633 § 5.1 does not
        /// allow where they came from. Never answered, so never counted as rate-limited too.
        /// </summary>
        public Int64 NTPRequestsDenied         { get; } = NTPRequestsDenied;

        /// <summary>
        /// How many plain NTP requests, without NTS, a server of NTS alone left unanswered -
        /// see <see cref="NTSServer.PlainNTP"/>.
        /// </summary>
        public Int64 NTPPlainRequestsIgnored   { get; } = NTPPlainRequestsIgnored;

        public Int64 NTPRequestsRejected       { get; } = NTPRequestsRejected;

        /// <summary>
        /// How many requests the RFC 8633 § 5.4 rate limiter refused, whether or not the client
        /// was told about it.
        /// </summary>
        public Int64 NTPRequestsRateLimited    { get; } = NTPRequestsRateLimited;

        /// <summary>
        /// How many of those refusals were answered with a "RATE" Kiss-o'-Death. Always the
        /// smaller number, and by design: the kisses are throttled far harder than the drops.
        /// </summary>
        public Int64 NTPKissesOfDeathSent      { get; } = NTPKissesOfDeathSent;

        public Int64 NTPRequestsInvalid        { get; } = NTPRequestsInvalid;
        public Int64 NTPResponsesSent          { get; } = NTPResponsesSent;
        public Int64 NTPSignedResponsesSent    { get; } = NTPSignedResponsesSent;
        public Int64 NTPRequestFailures        { get; } = NTPRequestFailures;
        public Int64 NTSKEConnectionsAccepted  { get; } = NTSKEConnectionsAccepted;
        /// <summary>
        /// How many NTS-KE connections, over TLS or over this server's own SSH listener, were
        /// turned away by the access list of RFC 8633 § 5.1.
        /// </summary>
        public Int64 NTSKEConnectionsDenied    { get; } = NTSKEConnectionsDenied;

        public Int64 NTSKEConnectionsRejected  { get; } = NTSKEConnectionsRejected;
        public Int64 NTSKEHandshakeFailures    { get; } = NTSKEHandshakeFailures;
        public Int64 NTSKERequestsInvalid      { get; } = NTSKERequestsInvalid;
        public Int64 NTSKEResponsesSent        { get; } = NTSKEResponsesSent;

        /// <summary>
        /// How many of the requests received were NTPv5 (draft-ietf-ntp-ntpv5-10), on a server that
        /// answers it - each also counted in <see cref="NTPRequestsReceived"/>. So that whoever
        /// asks can tell an NTPv5 client from one that negotiated its way down to NTPv4.
        /// </summary>
        public Int64 NTPv5RequestsReceived            { get; } = NTPv5RequestsReceived;

        /// <summary>
        /// How many NTPv5 responses were sent, Authentication NAKs included; each also counted in
        /// <see cref="NTPResponsesSent"/>.
        /// </summary>
        public Int64 NTPv5ResponsesSent               { get; } = NTPv5ResponsesSent;

        /// <summary>
        /// How many of the NTPv5 responses were under NTS (§ 11).
        /// </summary>
        public Int64 NTPv5AuthenticatedResponsesSent  { get; } = NTPv5AuthenticatedResponsesSent;

        /// <summary>
        /// How many of the NTPv5 responses were in the interleaved mode (§ 8).
        /// </summary>
        public Int64 NTPv5InterleavedResponsesSent    { get; } = NTPv5InterleavedResponsesSent;

        /// <summary>
        /// How many of the NTPv5 responses were Authentication NAKs (flag 0x4).
        /// </summary>
        public Int64 NTPv5AuthenticationNAKsSent      { get; } = NTPv5AuthenticationNAKsSent;


        /// <summary>
        /// The counters that are not zero, in one line.
        /// </summary>
        /// <remarks>
        /// These end up in test failure messages and log lines, where the default
        /// "NTSServerMetrics" says nothing at all, and where a full listing of eleven counters
        /// buries the one that moved.
        /// </remarks>
        public override String ToString()
        {

            var counters = new (String Name, Int64 Value)[] {
                               ("received",         NTPRequestsReceived),
                               ("denied",           NTPRequestsDenied),
                               ("plain-ignored",    NTPPlainRequestsIgnored),
                               ("rejected",         NTPRequestsRejected),
                               ("rate-limited",     NTPRequestsRateLimited),
                               ("kisses",           NTPKissesOfDeathSent),
                               ("invalid",          NTPRequestsInvalid),
                               ("sent",             NTPResponsesSent),
                               ("signed",           NTPSignedResponsesSent),
                               ("failures",         NTPRequestFailures),
                               ("ke-accepted",      NTSKEConnectionsAccepted),
                               ("ke-denied",        NTSKEConnectionsDenied),
                               ("ke-rejected",      NTSKEConnectionsRejected),
                               ("ke-handshakes",    NTSKEHandshakeFailures),
                               ("ke-invalid",       NTSKERequestsInvalid),
                               ("ke-sent",          NTSKEResponsesSent),
                               ("v5-received",      NTPv5RequestsReceived),
                               ("v5-sent",          NTPv5ResponsesSent),
                               ("v5-nts",           NTPv5AuthenticatedResponsesSent),
                               ("v5-interleaved",   NTPv5InterleavedResponsesSent),
                               ("v5-naks",          NTPv5AuthenticationNAKsSent)
                           }.
                           Where (counter => counter.Value != 0).
                           Select(counter => $"{counter.Name}: {counter.Value}").
                           ToArray();

            return counters.Length != 0
                       ? String.Join(", ", counters)
                       : "all counters zero";

        }

    }

}
