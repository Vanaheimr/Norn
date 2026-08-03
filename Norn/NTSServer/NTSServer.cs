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
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Concurrent;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.X509;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using org.GraphDefined.Vanaheimr.Norn.NTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// A Network Time Secure (NTS) Server.
    /// It will serve a NTS-KeyEstablishment (NTS-KE) TLS Server and a NTP UDP Server.
    /// </summary>
    public class NTSServer
    {

        #region Data

        /// <summary>
        /// The most NTS Cookie extension fields this server will put in one response.
        ///
        /// RFC 8915 §5.7 ties the count to the number of valid Cookie Placeholder fields in
        /// the request; capping it keeps a client from using placeholders to make responses
        /// arbitrarily larger than requests. Eight matches the pool size §5.7 suggests
        /// clients aim for.
        /// </summary>
        public  const            UInt16                                   MaxCookiesPerResponse  = 8;

        /// <summary>
        /// The granularity of the system clock, measured once on first use.
        ///
        /// Measured rather than assumed: <c>Stopwatch.Frequency</c> describes the high-resolution
        /// timer, not the wall clock the timestamps actually come from, and on Windows those can
        /// differ by five orders of magnitude. Reporting the timer's resolution as the clock's
        /// would be a more precise claim than the clock can support.
        /// </summary>
        public static TimeSpan SystemClockResolution
            => systemClockResolution.Value;

        private static readonly Lazy<TimeSpan> systemClockResolution =
            new(() => MeasureClockResolution(System.TimeProvider.System) ?? UnknownClockResolution);

        /// <summary>
        /// What to report when a clock's granularity cannot be observed at all — most likely a
        /// substituted <see cref="System.TimeProvider"/> that does not advance on its own.
        /// Deliberately coarse: a clock we cannot measure must not be described as a precise one.
        /// </summary>
        public static readonly TimeSpan UnknownClockResolution = TimeSpan.FromMilliseconds(1);

        /// <summary>
        /// Observe how finely the given clock advances, by reading it until it changes.
        ///
        /// Bounded by real elapsed time rather than by a read count, because both ends of the
        /// range have to terminate: a 15.6 ms clock needs a great many reads before it moves,
        /// and a frozen test clock never moves at all. Returns null in the latter case, so the
        /// caller can say "unknown" instead of inventing a resolution.
        /// </summary>
        private static TimeSpan? MeasureClockResolution(TimeProvider  TimeProvider,
                                                        TimeSpan?     MaxWait   = null)
        {

            var first     = TimeProvider.GetUtcNow();
            var watchdog  = System.Diagnostics.Stopwatch.StartNew();
            var deadline  = MaxWait ?? TimeSpan.FromMilliseconds(100);

            DateTimeOffset next;

            do
            {
                next = TimeProvider.GetUtcNow();
            }
            while (next == first && watchdog.Elapsed < deadline);

            var resolution = next - first;

            return resolution > TimeSpan.Zero
                       ? resolution
                       : null;

        }

        /// <summary>
        /// <see cref="ListenIPAddress"/> in the form the socket layer takes, converted once here
        /// so the conversion happens at the boundary and nowhere else.
        /// </summary>
        private readonly         System.Net.IPAddress                     listenIPAddress;

        private                  Socket?                                  tcpSocket;
        private                  Socket?                                  udpSocket;
        private                  CancellationTokenSource?                 cts;
        private                  Task?                                    tcpLoopTask;
        private                  Task?                                    udpLoopTask;

        private readonly         ConcurrentDictionary<UInt64, MasterKey>  masterKeys             = [];
        private static readonly  Lock                                     currentMasterKeyLock   = new();
        private                  MasterKey?                               currentMasterKey;
        private readonly         String?                                  masterKeysFilePath;

        private readonly         ConcurrentDictionary<UInt64, KeyPair>    keyPairs               = [];
        private                  KeyPair?                                 currentKeyPair;
        private                  PublicKey?                               currentPublicKey;

        private readonly         SemaphoreSlim                            ntpRequestSemaphore;
        private readonly         SemaphoreSlim                            ntskeConnectionSemaphore;
        private readonly         Boolean                                  advertiseExternalURLs;
        private readonly         X509Certificate?                         tlsCertificate;
        private readonly         ECPrivateKeyParameters?                  tlsPrivateKey;
        private readonly         String?                                  tlsServerSubjectName;

        private                  Int64                                    ntpRequestsReceived;
        private                  Int64                                    ntpRequestsRejected;
        private                  Int64                                    ntpRequestsInvalid;
        private                  Int64                                    ntpResponsesSent;
        private                  Int64                                    ntpSignedResponsesSent;
        private                  Int64                                    ntpRequestFailures;
        private                  Int64                                    ntskeConnectionsAccepted;
        private                  Int64                                    ntskeConnectionsRejected;
        private                  Int64                                    ntskeHandshakeFailures;
        private                  Int64                                    ntskeRequestsInvalid;
        private                  Int64                                    ntskeResponsesSent;

        #endregion

        #region Properties

        /// <summary>
        /// A description of the NTS server.
        /// </summary>
        public I18NString        Description     { get; set; } = I18NString.Empty;

        /// <summary>
        /// The NTP-KE TCP port.
        /// </summary>
        public IPPort            TCPPort         { get; }      = IPPort.NTSKE;

        /// <summary>
        /// The NTP UDP port.
        /// </summary>
        public IPPort            UDPPort         { get; }      = IPPort.NTP;

        /// <summary>
        /// The size of the buffer used for receiving NTP packets.
        /// </summary>
        public UInt32            BufferSize      { get; }      = 4096;


        public IEnumerable<URL>  ExternalURLs    { get; }


        public DNSClient         DNSClient       { get; }

        /// <summary>
        /// The local IP address used for the TCP and UDP listener sockets.
        ///
        /// <see cref="IPvXAddress.Any"/> asks for both address families at once; an
        /// <see cref="IPv4Address"/> or <see cref="IPv6Address"/> pins the listener to one.
        /// </summary>
        public IIPAddress            ListenIPAddress               { get; }

        /// <summary>
        /// Whether an IPv6 listener socket should also accept IPv4 traffic.
        /// </summary>
        public Boolean               EnableDualStack               { get; }

        /// <summary>
        /// The clock this server reads and reports.
        ///
        /// Everything time-dependent goes through here — the response timestamps, master key
        /// rotation, cookie timestamps and certificate validity — so a test can substitute a
        /// clock for one server without the process-wide side effects of
        /// <see cref="Illias.Timestamp.TravelBackInTime"/>.
        /// </summary>
        public TimeProvider          TimeProvider                  { get; }

        #region Clock characteristics (RFC 5905 § 7.3)

        /// <summary>
        /// The stratum this server reports. Default 1: it serves the local clock directly.
        /// </summary>
        public Byte                  Stratum                       { get; }

        /// <summary>
        /// What this server's time comes from. At stratum 1 this is a four-character source
        /// identifier from RFC 5905 § 7.3 ("LOCL" for an uncalibrated local clock); at stratum 2
        /// or above it identifies the upstream server, so clients can detect a timing loop.
        /// </summary>
        public ReferenceIdentifier   ReferenceIdentifier           { get; }

        /// <summary>
        /// Total round-trip delay to the reference clock. Zero when the reference *is* the local
        /// clock, since there is no network path to traverse.
        /// </summary>
        public TimeSpan              RootDelay                     { get; }

        /// <summary>
        /// Maximum error relative to the reference clock. Never zero — that would claim a
        /// perfect clock, and a client's root-distance calculation (§ 11.3) would then
        /// understate its true uncertainty.
        /// </summary>
        public TimeSpan              RootDispersion                { get; }

        /// <summary>
        /// The leap indicator to report. 3 announces that this server is not synchronized.
        /// </summary>
        public Byte                  LeapIndicator                 { get; }

        /// <summary>
        /// How finely <see cref="TimeProvider"/> advances, reported in the Precision field of
        /// § 7.3. Measured on construction unless given, and <see cref="UnknownClockResolution"/>
        /// when the clock cannot be observed to advance at all.
        /// </summary>
        public TimeSpan              ClockResolution               { get; }

        /// <summary>
        /// The RFC 9769 interleaved client/server mode, or null when it is switched off.
        /// </summary>
        /// <remarks>
        /// On by default, as it is in chrony, and safe to be: the mode is invisible to a client
        /// that does not ask for it, since an interleaved response is only ever sent to a
        /// request whose origin timestamp echoes one this server previously issued. What it
        /// costs is a bounded amount of memory per client address.
        /// </remarks>
        public InterleavedTimestamps? InterleavedTimestamps        { get; }

        /// <summary>
        /// When this server's clock was last set or corrected — the Reference Timestamp of
        /// § 7.3, which tells a client how stale the synchronization is.
        ///
        /// Defaults to when the server started, which is when it began trusting this clock.
        /// Settable so a process that does observe a real synchronization can report it;
        /// reporting "now" on every reply, as this used to, makes the field meaningless.
        /// </summary>
        public DateTimeOffset        ClockLastSynchronized         { get; set; }

        #endregion

        public TimeSpan              MasterKeyLifetime             { get; }

        public TimeSpan              MasterKeyRotationGracePeriod  { get; }

        public TimeSpan              NTSKEHandshakeTimeout         { get; }

        public TimeSpan              NTSKERequestTimeout           { get; }

        public Int32                 MaxNTSKERequestSize           { get; }

        public Int32                 MaxConcurrentNTPRequests      { get; }

        public Int32                 MaxConcurrentNTSKEConnections { get; }

        /// <summary>
        /// The key id currently used for newly generated NTS cookies.
        /// </summary>
        public UInt64                CurrentMasterKeyId
            => GetCurrentMasterKey().Id;

        /// <summary>
        /// A point-in-time snapshot of the NTS server counters.
        /// </summary>
        public NTSServerMetrics      Metrics
            => new (
                   NTPRequestsReceived:       System.Threading.Interlocked.Read(ref ntpRequestsReceived),
                   NTPRequestsRejected:       System.Threading.Interlocked.Read(ref ntpRequestsRejected),
                   NTPRequestsInvalid:        System.Threading.Interlocked.Read(ref ntpRequestsInvalid),
                   NTPResponsesSent:          System.Threading.Interlocked.Read(ref ntpResponsesSent),
                   NTPSignedResponsesSent:    System.Threading.Interlocked.Read(ref ntpSignedResponsesSent),
                   NTPRequestFailures:        System.Threading.Interlocked.Read(ref ntpRequestFailures),
                   NTSKEConnectionsAccepted:  System.Threading.Interlocked.Read(ref ntskeConnectionsAccepted),
                   NTSKEConnectionsRejected:  System.Threading.Interlocked.Read(ref ntskeConnectionsRejected),
                   NTSKEHandshakeFailures:    System.Threading.Interlocked.Read(ref ntskeHandshakeFailures),
                   NTSKERequestsInvalid:      System.Threading.Interlocked.Read(ref ntskeRequestsInvalid),
                   NTSKEResponsesSent:        System.Threading.Interlocked.Read(ref ntskeResponsesSent)
               );

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new Network Time Secure (NTS) Server.
        /// </summary>
        /// <param name="Description">An optional description of the NTS server.</param>
        /// <param name="NTSKEPort">The optional TCP port for NTS-KE to listen on (default: 4460).</param>
        /// <param name="NTSPort">The optional UDP port for NTP to listen on (default: 123).</param>
        /// <param name="KeyPair">An optional key pair to be used for NTS response signing.</param>
        /// <param name="ExternalURLs">An enumeration of external URLs to be used for NTP/NTS requests.</param>
        /// <param name="DNSClient">An optional DNS client to use.</param>
        /// <param name="ListenIPAddress">The optional local IP address to listen on (default: 0.0.0.0). Pass <see cref="IPvXAddress.Any"/> to serve IPv4 and IPv6 together.</param>
        /// <param name="ClockResolution">The optional granularity of the clock, when it is known better than it can be measured.</param>
        /// <param name="TimeProvider">The optional clock this server reads and reports (default: <see cref="System.TimeProvider.System"/>).</param>
        public NTSServer(I18NString?        Description    = null,
                         IPPort?            NTSKEPort      = null,
                         IPPort?            NTSPort        = null,
                         KeyPair?           KeyPair        = null,
                         IEnumerable<URL>?  ExternalURLs   = null,
                         DNSClient?         DNSClient      = null,
                         IIPAddress?        ListenIPAddress               = null,
                         Boolean            EnableDualStack               = true,
                         String?            MasterKeysFilePath            = "masterKeys.json",
                         TimeSpan?          MasterKeyLifetime             = null,
                         TimeSpan?          MasterKeyRotationGracePeriod  = null,
                         TimeSpan?          NTSKEHandshakeTimeout         = null,
                         TimeSpan?          NTSKERequestTimeout           = null,
                         Int32?             MaxNTSKERequestSize           = null,
                         Int32?             MaxConcurrentNTPRequests      = null,
                         Int32?             MaxConcurrentNTSKEConnections = null,
                         X509Certificate?   TLSCertificate                = null,
                         ECPrivateKeyParameters? TLSPrivateKey            = null,
                         String?            TLSServerSubjectName          = null,
                         Byte?              Stratum                       = null,
                         ReferenceIdentifier? ReferenceIdentifier         = null,
                         TimeSpan?          RootDelay                     = null,
                         TimeSpan?          RootDispersion                = null,
                         Byte?              LeapIndicator                 = null,
                         TimeSpan?          ClockResolution               = null,
                         Boolean            InterleavedMode               = true,
                         TimeProvider?      TimeProvider                  = null)
        {

            this.TimeProvider                 = TimeProvider                 ?? System.TimeProvider.System;
            this.Description                  = Description                  ?? I18NString.Empty;
            this.TCPPort                      = NTSKEPort                    ?? IPPort.NTSKE;
            this.UDPPort                      = NTSPort                      ?? IPPort.NTP;
            this.ExternalURLs                 = ExternalURLs                 ?? [ URL.Parse($"udp://localhost:{this.UDPPort}") ];
            this.DNSClient                    = DNSClient                    ?? new DNSClient();
            // IPv4 0.0.0.0 unless asked otherwise. IPvXAddress.Any would listen on both families
            // at once, which is often what an operator wants, but it needs a working IPv6 stack
            // to bind at all — so it stays an explicit choice rather than a default.
            this.ListenIPAddress              = ListenIPAddress              ?? IPv4Address.Any;
            this.listenIPAddress              = this.ListenIPAddress.ToDotNet();
            this.EnableDualStack              = EnableDualStack;
            this.masterKeysFilePath           = MasterKeysFilePath;
            this.MasterKeyLifetime            = MasterKeyLifetime            ?? TimeSpan.FromDays(1);
            this.MasterKeyRotationGracePeriod = MasterKeyRotationGracePeriod ?? TimeSpan.FromDays(7);
            this.NTSKEHandshakeTimeout        = NTSKEHandshakeTimeout        ?? TimeSpan.FromSeconds(10);
            this.NTSKERequestTimeout          = NTSKERequestTimeout          ?? TimeSpan.FromSeconds(10);
            this.MaxNTSKERequestSize          = MaxNTSKERequestSize          ?? 64 * 1024;
            this.MaxConcurrentNTPRequests     = MaxConcurrentNTPRequests     ?? 1024;
            this.MaxConcurrentNTSKEConnections= MaxConcurrentNTSKEConnections?? 64;
            this.advertiseExternalURLs        = ExternalURLs is not null;
            this.ntpRequestSemaphore          = new SemaphoreSlim(this.MaxConcurrentNTPRequests);
            this.ntskeConnectionSemaphore     = new SemaphoreSlim(this.MaxConcurrentNTSKEConnections);
            this.tlsCertificate               = TLSCertificate;
            this.tlsPrivateKey                = TLSPrivateKey;
            this.tlsServerSubjectName         = TLSServerSubjectName;

            // What this server can honestly say about its own clock (RFC 5905 § 7.3).
            //
            // The defaults describe what Norn actually is when nothing is configured: a server
            // handing out the operating system's clock, with no upstream of its own. That makes
            // it a stratum-1 server whose reference is the local clock ("LOCL" in the § 7.3
            // reference identifier table), reachable over no network path, so a root delay of
            // zero is the truth rather than a placeholder.
            //
            // Root dispersion is the one value that cannot be zero: it is the maximum error
            // relative to the reference, and Norn cannot observe how well the OS clock is
            // actually synchronized. The default is therefore the measured clock resolution
            // plus a deliberately conservative allowance, and operators who know better should
            // say so.
            this.ClockResolution              = ClockResolution              ?? MeasureClockResolution(this.TimeProvider)
                                                                              ?? UnknownClockResolution;
            this.Stratum                      = Stratum                      ?? 1;
            this.ReferenceIdentifier          = ReferenceIdentifier          ?? NTP.ReferenceIdentifier.From("LOCL");
            this.RootDelay                    = RootDelay                    ?? TimeSpan.Zero;
            this.RootDispersion               = RootDispersion               ?? this.ClockResolution + TimeSpan.FromMilliseconds(1);
            this.LeapIndicator                = LeapIndicator                ?? 0;
            this.ClockLastSynchronized        = this.TimeProvider.GetUtcNow();

            this.InterleavedTimestamps        = InterleavedMode
                                                    ? new InterleavedTimestamps()
                                                    : null;

            if (KeyPair is not null)
            {

                this.currentKeyPair   = KeyPair;
                this.currentPublicKey = KeyPair.ToPublicKey();

                this.keyPairs.TryAdd(KeyPair.Id, KeyPair);

            }

            try
            {

                var invalidAfter = this.TimeProvider.GetUtcNow() + this.MasterKeyRotationGracePeriod;

                foreach (var masterKeyText in MasterKeysFilePath.IsNotNullOrEmpty()
                                                  ? File.ReadAllLines(MasterKeysFilePath)
                                                  : [])
                {
                    if (MasterKey.TryParse(masterKeyText, out var masterKey, out var errorResponse))
                    {

                        if (masterKey.NotAfter < invalidAfter)
                            continue;

                        masterKeys.TryAdd(
                            masterKey.Id,
                            masterKey
                        );

                    }
                    else
                    {
                        DebugX.Log($"Invalid master key: {masterKeyText}");
                    }
                }

            }
            catch (FileNotFoundException)
            { }

        }


        #endregion


        #region (private) CreateSocket(SocketType, ProtocolType)

        private Socket CreateSocket(SocketType     SocketType,
                                    ProtocolType   ProtocolType)
        {

            var socket = new Socket(
                             listenIPAddress.AddressFamily,
                             SocketType,
                             ProtocolType
                         );

            if (listenIPAddress.AddressFamily == AddressFamily.InterNetworkV6 &&
                EnableDualStack)
            {
                socket.DualMode = true;
            }

            return socket;

        }

        #endregion

        #region (private) AnyRemoteEndPoint()

        /// <summary>
        /// The wildcard endpoint used as the template for receiving a datagram.
        ///
        /// It has to match the listening socket's address family: the socket layer rejects a
        /// mismatch outright, so an IPv4 wildcard against an IPv6 listener breaks every receive.
        /// </summary>
        private IPEndPoint AnyRemoteEndPoint()

            => new (listenIPAddress.AddressFamily == AddressFamily.InterNetworkV6
                        ? System.Net.IPAddress.IPv6Any
                        : System.Net.IPAddress.Any,
                    0);

        #endregion

        #region (private) NTS-KE request validation and negotiation

        /// <summary>The next-protocol IDs this server implements (RFC 8915 § 4.1.2).</summary>
        private static readonly UInt16[] supportedNextProtocols = [ 0 ];   // 0 = NTPv4

        /// <summary>The AEAD algorithms this server implements (RFC 8915 § 4.1.5).</summary>
        private static readonly AEADAlgorithms[] supportedAEADAlgorithms = [ AEADAlgorithms.AES_SIV_CMAC_256 ];

        /// <summary>Protocol ID 0, NTPv4 — the only next protocol that makes cookies meaningful.</summary>
        private const UInt16 NextProtocolNTPv4 = 0;


        /// <summary>
        /// What examining an NTS-KE request concluded: either an error code the request must be
        /// refused with, or the protocol and algorithm that were actually agreed.
        /// </summary>
        /// <param name="ErrorCode">Set when the request must be refused; null when it is acceptable.</param>
        /// <param name="NextProtocol">The agreed next protocol, or null when none could be agreed.</param>
        /// <param name="AEADAlgorithm">The agreed AEAD algorithm, or null when none could be agreed.</param>
        private sealed record NTSKENegotiation(NTSKEErrorCodes?  ErrorCode,
                                               UInt16?           NextProtocol,
                                               AEADAlgorithms?   AEADAlgorithm,
                                               String?           Reason)
        {

            public static NTSKENegotiation Refuse(NTSKEErrorCodes ErrorCode, String Reason)
                => new (ErrorCode, null, null, Reason);

            public static NTSKENegotiation Accept(UInt16? NextProtocol, AEADAlgorithms? AEADAlgorithm)
                => new (null, NextProtocol, AEADAlgorithm, null);

            /// <summary>True when NTPv4 was agreed, which is what makes NTPv4 cookies meaningful.</summary>
            public Boolean NTPv4Negotiated
                => NextProtocol == NextProtocolNTPv4 && AEADAlgorithm.HasValue;

        }


        /// <summary>
        /// Examine a parsed NTS-KE request: reject what RFC 8915 requires be rejected, and
        /// otherwise work out what was actually negotiated.
        ///
        /// Previously nothing inbound was examined at all — the response was a fixed set of
        /// records, so a malformed request was answered with a successful handshake and a
        /// client's offers were ignored in favour of this server's defaults.
        /// </summary>
        private static NTSKENegotiation NegotiateNTSKE(IEnumerable<NTSKE_Record> NTSKERequest)
        {

            var records = NTSKERequest.ToArray();

            // RFC 8915 § 4: "Implementations which receive a record with an unrecognized Record
            // Type MUST ignore the record if the Critical Bit is 0 and MUST treat it as an
            // error if the Critical Bit is 1", and § 4.1.3 code 0 covers exactly that case.
            var unknownCritical = records.FirstOrDefault(record => record.IsCritical &&
                                                                   !IsKnownRecordType(record.Type));

            if (unknownCritical is not null)
                return NTSKENegotiation.Refuse(
                           NTSKEErrorCodes.UnrecognizedCriticalRecord,
                           $"unrecognized critical record type {(UInt16) unknownCritical.Type}"
                       );

            #region Next Protocol Negotiation (§ 4.1.2)

            var nextProtocolRecords = records.Where(record => record.Type == NTSKE_RecordTypes.NTSNextProtocolNegotiation).ToArray();

            if (nextProtocolRecords.Length == 0)
                return NTSKENegotiation.Refuse(
                           NTSKEErrorCodes.BadRequest,
                           "the request carries no NTS Next Protocol Negotiation record"
                       );

            if (nextProtocolRecords.Length > 1)
                return NTSKENegotiation.Refuse(
                           NTSKEErrorCodes.BadRequest,
                           $"the request carries {nextProtocolRecords.Length} NTS Next Protocol Negotiation records"
                       );

            var nextProtocolRecord = nextProtocolRecords[0];

            if (nextProtocolRecord.Body.Length % 2 != 0)
                return NTSKENegotiation.Refuse(
                           NTSKEErrorCodes.BadRequest,
                           $"the NTS Next Protocol Negotiation body is {nextProtocolRecord.Body.Length} octets, " +
                            "which is not a whole number of 16-bit protocol IDs"
                       );

            var offeredProtocols = ParseUInt16Body(nextProtocolRecord.Body);

            // § 4.1.2: "The request MUST list at least one protocol".
            if (offeredProtocols.Length == 0)
                return NTSKENegotiation.Refuse(
                           NTSKEErrorCodes.BadRequest,
                           "the NTS Next Protocol Negotiation record offers no protocol"
                       );

            #endregion

            #region AEAD Algorithm Negotiation (§ 4.1.5)

            var aeadRecords = records.Where(record => record.Type == NTSKE_RecordTypes.AEADAlgorithmNegotiation).ToArray();

            if (aeadRecords.Length > 1)
                return NTSKENegotiation.Refuse(
                           NTSKEErrorCodes.BadRequest,
                           $"the request carries {aeadRecords.Length} AEAD Algorithm Negotiation records"
                       );

            if (aeadRecords.Length == 1 && aeadRecords[0].Body.Length % 2 != 0)
                return NTSKENegotiation.Refuse(
                           NTSKEErrorCodes.BadRequest,
                           $"the AEAD Algorithm Negotiation body is {aeadRecords[0].Body.Length} octets, " +
                            "which is not a whole number of 16-bit algorithm IDs"
                       );

            var offeredAEADAlgorithms = aeadRecords.Length == 1
                                            ? ParseUInt16Body(aeadRecords[0].Body)
                                            : [];

            #endregion

            // The response must be a subset of the request (§ 4.1.2), and the algorithm one the
            // client offered (§ 4.1.5). Both may end up empty, which is how the server says it
            // supports none of what was offered.
            UInt16? negotiatedProtocol = offeredProtocols.
                                             Where(supportedNextProtocols.Contains).
                                             Select(protocol => (UInt16?) protocol).
                                             FirstOrDefault();

            AEADAlgorithms? negotiatedAEAD = offeredAEADAlgorithms.
                                                 Select(id => (AEADAlgorithms) id).
                                                 Where(supportedAEADAlgorithms.Contains).
                                                 Select(algorithm => (AEADAlgorithms?) algorithm).
                                                 FirstOrDefault();

            return NTSKENegotiation.Accept(negotiatedProtocol, negotiatedAEAD);

        }


        /// <summary>Whether this server understands the given record type.</summary>
        private static Boolean IsKnownRecordType(NTSKE_RecordTypes RecordType)

            => RecordType is NTSKE_RecordTypes.EndOfMessage
                          or NTSKE_RecordTypes.NTSNextProtocolNegotiation
                          or NTSKE_RecordTypes.Error
                          or NTSKE_RecordTypes.Warning
                          or NTSKE_RecordTypes.AEADAlgorithmNegotiation
                          or NTSKE_RecordTypes.NewCookieForNTPv4
                          or NTSKE_RecordTypes.NTPv4ServerNegotiation
                          or NTSKE_RecordTypes.NTPv4PortNegotiation
                          or NTSKE_RecordTypes.NTSRequestPublicKey
                          or NTSKE_RecordTypes.NTSPublicKey;


        private static UInt16[] ParseUInt16Body(Byte[] Body)
        {

            var values = new UInt16[Body.Length / 2];

            for (var i = 0; i < values.Length; i++)
                values[i] = (UInt16) ((Body[i * 2] << 8) | Body[i * 2 + 1]);

            return values;

        }

        #endregion

        #region (private) BuildNTSKEErrorRecords(ErrorCode)

        /// <summary>
        /// An NTS-KE error response: the Error record and the End of Message that RFC 8915
        /// § 4.1.1 requires as the final record of every message.
        /// </summary>
        private static IEnumerable<NTSKE_Record> BuildNTSKEErrorRecords(NTSKEErrorCodes ErrorCode)

            => [
                   NTSKE_Record.Error(ErrorCode),
                   NTSKE_Record.EndOfMessage
               ];

        #endregion

        #region (private) BuildNTSKEResponseRecords(Negotiation, NTSKERequest, C2SKey, S2CKey)

        private IEnumerable<NTSKE_Record> BuildNTSKEResponseRecords(NTSKENegotiation           Negotiation,
                                                                    IEnumerable<NTSKE_Record>  NTSKERequest,
                                                                    Byte[]                    C2SKey,
                                                                    Byte[]                    S2CKey)
        {

            // Both lists carry what was actually agreed, and are empty when nothing was —
            // never this server's defaults.
            var ntsKERecords = new List<NTSKE_Record> {
                                   Negotiation.NextProtocol.HasValue
                                       ? NTSKE_Record.NextProtocolNegotiation(Negotiation.NextProtocol.Value)
                                       : NTSKE_Record.NextProtocolNegotiation(),
                                   Negotiation.AEADAlgorithm.HasValue
                                       ? NTSKE_Record.AEADAlgorithmNegotiation([ Negotiation.AEADAlgorithm.Value ])
                                       : NTSKE_Record.AEADAlgorithmNegotiation([])
                               };

            // Everything below concerns an NTPv4 association. Without one there is nothing to
            // point the client at and nothing a cookie could authenticate.
            if (!Negotiation.NTPv4Negotiated)
            {
                ntsKERecords.Add(NTSKE_Record.EndOfMessage);
                return ntsKERecords;
            }

            if (advertiseExternalURLs)
            {
                foreach (var externalURL in ExternalURLs.Where(url => url.Scheme == URIScheme.udp))
                {

                    // The record carries a bare ASCII host, so any brackets around an IPv6
                    // literal have to come off — URLHost keeps them for round-tripping.
                    var hostname = externalURL.Host.ToString().Trim('[', ']');

                    if (hostname.IsNotNullOrEmpty())
                        ntsKERecords.Add(
                            NTSKE_Record.NTPv4ServerNegotiation(
                                Encoding.ASCII.GetBytes(hostname)
                            )
                        );

                    if (externalURL.Port.HasValue)
                        ntsKERecords.Add(
                            NTSKE_Record.NTPv4PortNegotiation(
                                ToNetworkByteOrder(externalURL.Port.Value)
                            )
                        );

                }
            }

            ntsKERecords.AddRange(
                GetCurrentMasterKey().
                    GenerateNTSKECookies(
                        NumberOfCookies:   MaxCookiesPerResponse,
                        C2SKey:            C2SKey,
                        S2CKey:            S2CKey,
                        AEADAlgorithm:     Negotiation.AEADAlgorithm!.Value,
                        IsCritical:        false,
                        TimeProvider:      TimeProvider
                    )
            );

            if (NTSKERequest.Any(ntsKERecord => ntsKERecord.Type == NTSKE_RecordTypes.NTSRequestPublicKey) &&
                currentPublicKey is not null)
            {
                ntsKERecords.Add(
                    NTSKE_Record.NTSPublicKey(currentPublicKey)
                );
            }

            ntsKERecords.Add(NTSKE_Record.EndOfMessage);

            return ntsKERecords;

        }

        #endregion

        #region (private static) ToNetworkByteOrder(Port)

        private static Byte[] ToNetworkByteOrder(IPPort Port)
        {

            var port = Port.ToUInt16();

            return [
                (Byte) (port >> 8),
                (Byte) (port & 0xFF)
            ];

        }

        #endregion


        #region (private) GetCurrentMasterKey()

        private MasterKey GetCurrentMasterKey()
        {

            // https://datatracker.ietf.org/doc/html/rfc8915#name-suggested-format-for-nts-co
            // Servers should periodically(e.g., once daily) generate a new pair '(I,K)' and immediately
            // switch to using these values for all newly-generated cookies. Following each such key
            // rotation, servers should securely erase any previously generated keys that should now be
            // expired.
            // Servers should continue to accept any cookie generated using keys that they have not yet
            // erased, even if those keys are no longer current. Erasing old keys provides for forward
            // secrecy, limiting the scope of what old information can be stolen if a master key is
            // somehow compromised. Holding on to a limited number of old keys allows clients to
            // seamlessly transition from one generation to the next without having to perform a new
            // NTS-KE handshake.

            var now = TimeProvider.GetUtcNow();

            if (currentMasterKey is null ||
                currentMasterKey.Value.NotBefore > now ||
                currentMasterKey.Value.NotAfter  <= now)
            {
                lock (currentMasterKeyLock)
                {

                    now = TimeProvider.GetUtcNow();

                    foreach (var masterKey in masterKeys.Values)
                    {
                        if (masterKey.NotAfter <= now - MasterKeyRotationGracePeriod)
                            masterKeys.TryRemove(masterKey.Id, out _);
                    }

                    if (currentMasterKey is null ||
                        currentMasterKey.Value.NotBefore > now ||
                        currentMasterKey.Value.NotAfter  <= now)
                    {
                        currentMasterKey = null;

                        foreach (var masterKey in masterKeys.Values.OrderByDescending(masterKey => masterKey.NotAfter))
                        {
                            if (masterKey.NotBefore <= now &&
                                masterKey.NotAfter  >  now)
                            {
                                currentMasterKey = masterKey;
                                break;
                            }
                        }
                    }

                    if (currentMasterKey is null)
                    {

                        var newKeyId      = masterKeys.IsEmpty
                                                ? 1UL
                                                : masterKeys.Keys.Max() + 1;

                        currentMasterKey  = new MasterKey(
                                                 Id:         newKeyId,
                                                 Value:      RandomNumberGenerator.GetBytes(32),
                                                 NotBefore:  now,
                                                 NotAfter:   now + MasterKeyLifetime
                                             );

                        masterKeys.TryAdd(
                            currentMasterKey.Value.Id,
                            currentMasterKey.Value
                        );

                        try
                        {
                            if (masterKeysFilePath.IsNotNullOrEmpty())
                            {

                                var masterKeysDirectory = Path.GetDirectoryName(masterKeysFilePath);

                                if (masterKeysDirectory.IsNotNullOrEmpty())
                                    Directory.CreateDirectory(masterKeysDirectory);

                                File.AppendAllText(
                                    masterKeysFilePath,
                                    currentMasterKey.Value.ToJSON().ToString(Newtonsoft.Json.Formatting.None) + Environment.NewLine
                                );

                            }
                        }
                        catch (Exception e) {
                            DebugX.LogException(e, "Failed to write master key to file!");
                        }

                    }

                }
            }

            return currentMasterKey.Value;

        }

        #endregion


        #region (private) GenerateNTSKEServerInfos    (MasterKey, NumberOfCookies, C2SKey, S2CKey, AEADAlgorithm = AEADAlgorithms.AES_SIV_CMAC_256, IsCritical = false)

        public NTSKE_ServerInfo

            GenerateNTSKEServerInfo(MasterKey       MasterKey,
                                    UInt16          NumberOfCookies,
                                    Byte[]          C2SKey,
                                    Byte[]          S2CKey,
                                    AEADAlgorithms  AEADAlgorithm   = AEADAlgorithms.AES_SIV_CMAC_256)

        {

            #region Initial checks

            if (NumberOfCookies == 0)
                throw new ArgumentException("The number of cookies must be greater than 0!", nameof(NumberOfCookies));

            if (C2SKey.Length == 0)
                throw new ArgumentException("The C2SKey must not be empty!", nameof(C2SKey));

            if (S2CKey.Length == 0)
                throw new ArgumentException("The S2CKey must not be empty!", nameof(S2CKey));

            if (C2SKey.Length != S2CKey.Length)
                throw new ArgumentException("The C2SKey and S2CKey must be of the same length!");

            #endregion

            return new NTSKE_ServerInfo(
                       C2SKey,
                       S2CKey,
                       Enumerable.Range(0, NumberOfCookies).
                                  Select(_ => NTSCookie.Create (MasterKey, C2SKey, S2CKey, AEADAlgorithm, TimeProvider).
                                                        Encrypt(MasterKey)),
                       ExternalURLs,
                       this.currentPublicKey is not null
                           ? [ currentPublicKey.ToByteArray() ]
                           : null,
                       AEADAlgorithm,
                       null,
                       null
                   );

        }

        #endregion

        #region GetServerInfos(NumberOfCookies = 7)

        public IEnumerable<NTSKE_ServerInfo> GetServerInfos(UInt16 NumberOfCookies = 7)
        {

            var serverInfos = new List<NTSKE_ServerInfo>();

            // Might include other NTS-KE servers in the future...
            serverInfos.Add(
                GenerateNTSKEServerInfo(
                    MasterKey:         GetCurrentMasterKey(),
                    NumberOfCookies:   NumberOfCookies,
                    C2SKey:            RandomNumberGenerator.GetBytes(32),
                    S2CKey:            RandomNumberGenerator.GetBytes(32),
                    AEADAlgorithm:     AEADAlgorithms.AES_SIV_CMAC_256
                )
            );

            return serverInfos;

        }

        #endregion


        #region Start(CancellationToken = default)

        /// <summary>
        /// Start the NTP server.
        /// </summary>
        public async Task Start(CancellationToken CancellationToken = default)
        {

            if (udpSocket is not null || tcpSocket is not null)
                return;

            cts       = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);

            #region Start NTP/NTS UDP server

            udpSocket = CreateSocket(SocketType.Dgram, ProtocolType.Udp);

            udpSocket.Bind(
                new IPEndPoint(
                    listenIPAddress,
                    UDPPort.ToUInt16()
                )
            );

            DebugX.Log($"NTP Server started on port {UDPPort}/UDP");

            // Fire-and-forget task that handles incoming NTP in a loop
            udpLoopTask = Task.Run(async () => {

                try
                {
                    while (!cts.Token.IsCancellationRequested)
                    {

                        var buffer          = new Byte[BufferSize];
                        var remoteEP        = AnyRemoteEndPoint();

                        var udpPacket       = await udpSocket.ReceiveFromAsync(
                                                        new ArraySegment<Byte>(buffer),
                                                        SocketFlags.None,
                                                        remoteEP,
                                                        cts.Token
                                                    );

                        // Read here and nowhere later. Everything after this point — parsing,
                        // unsealing the cookie, verifying the authenticator, queueing onto a
                        // worker — happens after the packet arrived, and a receive timestamp
                        // taken at the end of all that reports this server as slower than it is.
                        // RFC 5905 § 8 wants the timestamp at the end of reception; this is as
                        // close as a user-space socket gets.
                        var receivedAt      = NTPPacket.GetCurrentNTPTimestamp(TimeProvider);

                        System.Threading.Interlocked.Increment(ref ntpRequestsReceived);

                        // Local copy to pass into the Task
                        var udpPacketLocal  = udpPacket;


                        if (!await ntpRequestSemaphore.WaitAsync(0, cts.Token).ConfigureAwait(false))
                        {
                            System.Threading.Interlocked.Increment(ref ntpRequestsRejected);
                            DebugX.Log($"Dropping NTP request from {udpPacketLocal.RemoteEndPoint}: too many concurrent requests.");
                            continue;
                        }

                        _ = Task.Run(async () => {

                            try
                            {

                                Array.Resize(ref buffer, udpPacketLocal.ReceivedBytes);

                                if (NTPRequest.TryParse(buffer,
                                                        out var requestPacket,
                                                        out var errorResponse,
                                                        MasterKeys: masterKeys))
                                {

                                    var toBeSigned       = requestPacket.NTSRequestSignedResponse() is not null;

                                    // RFC 9769 § 2 decides here which of this server's earlier
                                    // timestamps the answer carries, before anything is built:
                                    // the header has to be final before the NTS authenticator
                                    // is computed over it.
                                    var exchange         = InterleavedTimestamps is not null &&
                                                           udpPacketLocal.RemoteEndPoint is IPEndPoint remoteIPEndPoint

                                                               ? InterleavedTimestamps.BeginExchange(
                                                                     remoteIPEndPoint.Address,
                                                                     receivedAt,
                                                                     requestPacket,
                                                                     TimeProvider
                                                                 )

                                                               : InterleavedExchange.Basic(
                                                                     requestPacket,
                                                                     receivedAt,
                                                                     TimeProvider
                                                                 );

                                    var responsePacket1  = BuildResponse(
                                                               requestPacket,
                                                               exchange,
                                                               toBeSigned
                                                           );

                                    await udpSocket.SendToAsync(
                                               new ArraySegment<Byte>(responsePacket1.ToByteArray()),
                                               SocketFlags.None,
                                               udpPacketLocal.RemoteEndPoint,
                                               cts.Token
                                           );

                                    // The whole point of RFC 9769: the transmit timestamp worth
                                    // reporting is the one taken once the packet has actually
                                    // gone, after building, encrypting and writing it. It cannot
                                    // travel in this response, so it travels in the next one.
                                    exchange.RecordTransmission(NTPPacket.GetCurrentNTPTimestamp(TimeProvider));

                                    System.Threading.Interlocked.Increment(ref ntpResponsesSent);

                                    if (toBeSigned && currentKeyPair is not null)
                                    {

                                        // The unsigned response is intentionally sent first so clients can
                                        // measure RTT with minimal signing latency. The signed response follows
                                        // as a scheduled security confirmation once the digital signature is ready.
                                        var responsePacket2 = SignResponse(responsePacket1, currentKeyPair);

                                        await udpSocket.SendToAsync(
                                                  new ArraySegment<Byte>(responsePacket2.ToByteArray()),
                                                  SocketFlags.None,
                                                  udpPacketLocal.RemoteEndPoint,
                                                  cts.Token
                                              );
                                        System.Threading.Interlocked.Increment(ref ntpSignedResponsesSent);

                                    }

                                }
                                else
                                {
                                    System.Threading.Interlocked.Increment(ref ntpRequestsInvalid);
                                    DebugX.Log($"Invalid NTP request from {udpPacketLocal.RemoteEndPoint}: {errorResponse}");
                                }
                            }
                            catch (Exception e)
                            {
                                System.Threading.Interlocked.Increment(ref ntpRequestFailures);
                                DebugX.Log($"Exception while processing a NTP request: {e}");
                            }
                            finally
                            {
                                ntpRequestSemaphore.Release();
                            }

                        }, cts.Token);

                    }
                }
                catch (ObjectDisposedException)
                {
                    // Will be thrown when the UDP client is closed during shutdown.
                }
                catch (Exception ex)
                {
                    DebugX.Log($"Exception: {ex}");
                }

                try { udpSocket?.Close(); } catch { }
                udpSocket = null;

            }, cts.Token);

            #endregion

            #region Start NTS-KE TCP server

            tcpSocket = CreateSocket(SocketType.Stream, ProtocolType.Tcp);

            tcpSocket.Bind(
                new IPEndPoint(
                    listenIPAddress,
                    TCPPort.ToUInt16()
                )
            );

            tcpSocket.Listen(backlog: 20);

            DebugX.Log($"NTP/NTS-KE Server started on port {TCPPort}/TCP");

            // telnet 127.0.0.1:4460
            // openssl s_client -connect 127.0.0.1:4460
            // openssl s_client -connect 127.0.0.1:4460 -showcerts
            // openssl s_client -connect 127.0.0.1:4460 -verify 0

            // Fire-and-forget loop that Accepts new sockets
            tcpLoopTask = Task.Run(async () => {

                try
                {
                    while (!cts.Token.IsCancellationRequested)
                    {

                        var clientSocket = await tcpSocket.AcceptAsync(cts.Token);

                        if (clientSocket == null)
                            continue;

                        System.Threading.Interlocked.Increment(ref ntskeConnectionsAccepted);

                        if (!await ntskeConnectionSemaphore.WaitAsync(0, cts.Token).ConfigureAwait(false))
                        {
                            System.Threading.Interlocked.Increment(ref ntskeConnectionsRejected);
                            DebugX.Log($"Closing NTS-KE connection from {clientSocket.RemoteEndPoint}: too many concurrent connections.");
                            clientSocket.Close();
                            continue;
                        }

                        _ = Task.Run(async () => {

                            try
                            {

                                using var networkStream  = new NetworkStream    (clientSocket, ownsSocket: false);
                                using var requestCTS     = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
                                requestCTS.CancelAfter(NTSKEHandshakeTimeout + NTSKERequestTimeout);
                                var tlsServerProtocol    = new TlsServerProtocol(networkStream);
                                var tlsServer            = new NTSKE_TLSService (
                                                               tlsCertificate,
                                                               tlsPrivateKey,
                                                               tlsServerSubjectName,
                                                               TimeProvider
                                                           );

                                await Task.Run(
                                          () => tlsServerProtocol.Accept(tlsServer),
                                          requestCTS.Token
                                      ).WaitAsync(NTSKEHandshakeTimeout, requestCTS.Token).
                                        ConfigureAwait(false);

                                var c2sKey               = tlsServer.NTS_C2S_Key ?? [];
                                var s2cKey               = tlsServer.NTS_S2C_Key ?? [];


                                // A generous socket-level backstop, so a client that stalls
                                // mid-TLS-record cannot hold this connection and its semaphore
                                // slot indefinitely. Passing the socket to the reader means the
                                // normal case never reaches it: the reader waits for the socket
                                // to become readable and only then descends into the TLS stream,
                                // so a truncated request expires with the TLS connection still
                                // healthy and the Error record below can actually be written.
                                clientSocket.ReceiveTimeout = (Int32) (NTSKERequestTimeout + TimeSpan.FromSeconds(5)).TotalMilliseconds;

                                var (requestBytes, errorMessage) = await NTSKEMessageReader.ReadAsync(
                                                                        tlsServerProtocol.Stream,
                                                                        NTSKERequestTimeout,
                                                                        MaxNTSKERequestSize,
                                                                        requestCTS.Token,
                                                                        clientSocket
                                                                    ).ConfigureAwait(false);

                                // Whatever happens from here, the client is told why. RFC 8915
                                // § 4.1.3 requires an Error record; closing the connection in
                                // silence leaves a client unable to tell a rejected request
                                // from a network fault, and unable to learn what to change.
                                IEnumerable<NTSKE_Record> ntsKERecords;

                                if (requestBytes is null)
                                {
                                    // § 4.1.3 code 1 covers both a malformed request and one
                                    // that never arrived complete before the timeout.
                                    System.Threading.Interlocked.Increment(ref ntskeRequestsInvalid);
                                    DebugX.Log($"Invalid NTS-KE request: {errorMessage}");
                                    ntsKERecords = BuildNTSKEErrorRecords(NTSKEErrorCodes.BadRequest);
                                }

                                else if (!NTSKE_Record.TryParse(requestBytes, out var ntsKERequest, out var errorResponse))
                                {
                                    System.Threading.Interlocked.Increment(ref ntskeRequestsInvalid);
                                    DebugX.Log($"Invalid NTS-KE request: {errorResponse}");
                                    ntsKERecords = BuildNTSKEErrorRecords(NTSKEErrorCodes.BadRequest);
                                }

                                else
                                {

                                    var negotiation = NegotiateNTSKE(ntsKERequest);

                                    if (negotiation.ErrorCode.HasValue)
                                    {
                                        System.Threading.Interlocked.Increment(ref ntskeRequestsInvalid);
                                        DebugX.Log($"Refusing NTS-KE request with error {(UInt16) negotiation.ErrorCode.Value}: {negotiation.Reason}");
                                        ntsKERecords = BuildNTSKEErrorRecords(negotiation.ErrorCode.Value);
                                    }

                                    else
                                        ntsKERecords = BuildNTSKEResponseRecords(
                                                           negotiation,
                                                           ntsKERequest,
                                                           c2sKey,
                                                           s2cKey
                                                       );

                                }

                                await tlsServerProtocol.Stream.WriteAsync(ntsKERecords.ToByteArray(), requestCTS.Token).
                                                                  ConfigureAwait(false);
                                await tlsServerProtocol.Stream.FlushAsync(requestCTS.Token).
                                                                  ConfigureAwait(false);
                                System.Threading.Interlocked.Increment(ref ntskeResponsesSent);

                                tlsServerProtocol.Close();

                            }
                            catch (Exception ex)
                            {
                                System.Threading.Interlocked.Increment(ref ntskeHandshakeFailures);
                                DebugX.Log($"TLS handshake/IO failed: {ex.Message}");
                            }
                            finally
                            {
                                try { clientSocket.Shutdown(SocketShutdown.Both); } catch { }
                                clientSocket.Close();
                                ntskeConnectionSemaphore.Release();
                            }

                        });

                    }
                }
                catch (ObjectDisposedException)
                {
                    // normal on shutdown
                }
                catch (Exception ex)
                {
                    DebugX.Log($"Exception in TLS Accept loop: {ex}");
                }

                try { tcpSocket?.Close(); } catch { }
                tcpSocket = null;

            }, cts.Token);

            #endregion

        }

        #endregion

        #region Shutdown()

        /// <summary>
        /// Stop the server.
        /// </summary>
        public void Shutdown()
            => ShutdownAsync().GetAwaiter().GetResult();

        /// <summary>
        /// Stop the server and wait for the listener loops to exit.
        /// </summary>
        public async Task ShutdownAsync()
        {

            cts?.Cancel();

            try { udpSocket?.Close(); } catch { }
            try { tcpSocket?.Close(); } catch { }

            var listenerTasks = new[] {
                                    udpLoopTask,
                                    tcpLoopTask
                                }.
                                Where(task => task is not null).
                                Select(task => task!).
                                ToArray();

            if (listenerTasks.Length > 0)
            {
                try
                {
                    await Task.WhenAll(listenerTasks).
                               WaitAsync(TimeSpan.FromSeconds(5)).
                               ConfigureAwait(false);
                }
                catch (TimeoutException)
                {
                    DebugX.Log("Timed out while waiting for NTS server listener loops to stop.");
                }
            }

            cts?.Dispose();
            cts          = null;
            udpLoopTask  = null;
            tcpLoopTask  = null;

        }

        #endregion


        #region (private) BuildResponseHeader(RequestPacket, Extensions, ...)

        /// <summary>
        /// The RFC 5905 § 7.3 header common to every response, plain or NTS-protected, so both
        /// describe this server's clock the same way.
        /// </summary>
        private NTPPacket BuildResponseHeader(NTPPacket                  RequestPacket,
                                              IEnumerable<NTPExtension>  Extensions,
                                              InterleavedExchange        Exchange)

            => new (

                   LI:                   LeapIndicator,
                   Mode:                 4, // Server
                   Stratum:              Stratum,
                   Poll:                 RequestPacket.Poll,

                   // This server's own clock resolution, not the client's. Echoing the
                   // request's precision reported the client's clock back to it as though it
                   // described the server's.
                   Precision:            ClockPrecisionExponent,

                   RootDelay:            ToShortFormat(RootDelay),
                   RootDispersion:       ToShortFormat(RootDispersion),
                   ReferenceIdentifier:  ReferenceIdentifier,

                   // When the clock was last set, per § 7.3 — not the moment of this reply,
                   // which said nothing about synchronization at all.
                   ReferenceTimestamp:   NTPPacket.GetCurrentNTPTimestamp(ClockLastSynchronized.UtcDateTime),

                   // All three come from the exchange, because RFC 9769 makes them a set: which
                   // timestamp is echoed as the origin is the only signal telling the client
                   // whether the transmit timestamp beside it belongs to this response or to
                   // the one before it.
                   OriginateTimestamp:   Exchange.OriginTimestamp,
                   ReceiveTimestamp:     Exchange.ReceiveTimestamp,
                   TransmitTimestamp:    Exchange.TransmitTimestamp,
                   Extensions:           Extensions,

                   Request:              RequestPacket

               );

        #endregion

        #region (private) Clock reporting helpers

        /// <summary>
        /// The Precision field of RFC 5905 § 7.3: a signed exponent, so that 2^Precision is the
        /// clock's resolution in seconds.
        /// </summary>
        private SByte ClockPrecisionExponent
            => ToPrecisionExponent(ClockResolution);

        internal static SByte ToPrecisionExponent(TimeSpan ClockResolution)
        {

            var seconds  = ClockResolution.TotalSeconds;
            var exponent = Math.Floor(Math.Log2(seconds));

            // Clamped to the range the field can express; a resolution outside it says the
            // measurement went wrong, not that the clock is extraordinary.
            return (SByte) Math.Clamp(exponent, -32, 0);

        }


        /// <summary>
        /// Convert to the 32-bit 16.16 fixed-point "short format" of RFC 5905 § 6, used by the
        /// Root Delay and Root Dispersion fields. Saturates rather than wrapping: a value too
        /// large to express should read as "very uncertain", not as a small one.
        /// </summary>
        private static UInt32 ToShortFormat(TimeSpan Value)
        {

            if (Value <= TimeSpan.Zero)
                return 0;

            var scaled = Value.TotalSeconds * 65536.0;

            return scaled >= UInt32.MaxValue
                       ? UInt32.MaxValue
                       : (UInt32) Math.Round(scaled);

        }

        #endregion

        /// <summary>
        /// Build an NTS NAK, as RFC 8915 §5.7 prescribes for a request whose cookie cannot be
        /// validated or whose authenticator does not verify: a Kiss-o'-Death packet (RFC 5905
        /// §7.4, stratum 0) carrying the kiss code "NTSN".
        ///
        /// The client's Unique Identifier is echoed so the client can match the NAK to the
        /// request that caused it. No NTS Cookie and no NTS Authenticator extension field may
        /// appear — the server has no validated key with which to produce one.
        /// </summary>
        private NTPPacket BuildNTSNAK(NTPPacket            RequestPacket,
                                      InterleavedExchange  Exchange,
                                      String               ErrorMessage)
        {

            var extensions  = new List<NTPExtension>();
            var uniqueId    = RequestPacket.UniqueIdentifier();

            if (uniqueId?.Length > 0)
                extensions.Add(new UniqueIdentifierExtension(uniqueId));

            return new NTPPacket(

                       LI:                     0,
                       VN:                     4,
                       Mode:                   4, // Server
                       Stratum:                0, // Kiss-o'-Death
                       Poll:                   RequestPacket.Poll,
                       Precision:              RequestPacket.Precision,
                       RootDelay:              0,
                       RootDispersion:         0,
                       ReferenceIdentifier:    ReferenceIdentifier.From("NTSN"),
                       ReferenceTimestamp:     0,
                       // A refusal still has to keep the RFC 9769 bookkeeping honest: the
                       // receive timestamp saved for this exchange is the one the client was
                       // actually shown, or a later interleaved request echoing it would be
                       // answered from a timestamp that never went out.
                       OriginateTimestamp:     Exchange.OriginTimestamp,
                       ReceiveTimestamp:       Exchange.ReceiveTimestamp,
                       TransmitTimestamp:      Exchange.TransmitTimestamp,
                       Extensions:             extensions,

                       Request:                RequestPacket,
                       ResponseBytes:          null,
                       ErrorMessage:           ErrorMessage

                   );

        }


        private NTPPacket BuildResponse(NTPPacket            RequestPacket,
                                        InterleavedExchange  Exchange,
                                        Boolean              SignedResponseRequested = false)
        {

            var extensions           = new List<NTPExtension>();
            var encryptedExtensions  = new List<NTPExtension>();

            // A request carrying no NTS extension field at all is a plain NTPv4 request and
            // must be answered as one. RFC 8915 § 5.7's NTS NAK is for a request that *tried*
            // to use NTS and failed; returning a Kiss-o'-Death to a client that never asked for
            // NTS tells it this server is unusable, and a plain NTP client — chronyd without
            // the "nts" option, for one — will drop the server entirely.
            if (!RequestPacket.Extensions.Any(extension => extension.Type is ExtensionTypes.UniqueIdentifier
                                                                          or ExtensionTypes.NTSCookie
                                                                          or ExtensionTypes.NTSCookiePlaceholder
                                                                          or ExtensionTypes.AuthenticatorAndEncrypted))
            {
                return BuildResponseHeader(RequestPacket, [], Exchange);
            }

            var u1 = RequestPacket.UniqueIdentifier();

            if (u1?.Length > 0)
                extensions.Add(new UniqueIdentifierExtension(u1));

            var n1 = RequestPacket.NTSCookieExtension();

            if (n1 is null)
                return BuildNTSNAK(RequestPacket, Exchange, "Invalid NTS cookie!");

            // Unsealing authenticates the cookie under this server's master key and checks
            // it against that key's validity window, so a forged or expired cookie fails here.
            if (!NTSCookie.TryParse(n1.Value, masterKeys, out var ntsCookie, out var errorResponse))
                return BuildNTSNAK(RequestPacket, Exchange, "Invalid NTS cookie: " + errorResponse);


            // RFC 8915 §5.7: "The number of NTS Cookie extension fields included SHOULD be
            // equal to, and MUST NOT exceed, one plus the number of valid NTS Cookie
            // Placeholder extension fields included in the request." Replacing the cookie the
            // client just spent, plus one per placeholder, is what keeps its pool from draining.
            //
            // §5.5 makes a placeholder valid only when its body is the same length as a cookie,
            // so a client cannot inflate the response by sending oversized placeholders.
            // Matched on the wire type rather than the CLR type: placeholders arrive as the
            // NTSCookiePlaceholderExtension subclass when parsed here, but the client builds
            // them from the NTPExtension.NTSCookiePlaceholder factory, which returns the base
            // type. The type field is the same either way.
            var validPlaceholders = RequestPacket.Extensions.
                                        Count(extension => extension.Type == ExtensionTypes.NTSCookiePlaceholder &&
                                                           extension.Value.Length == n1.Value.Length);

            var numberOfCookies   = (UInt16) Math.Min(1 + validPlaceholders, MaxCookiesPerResponse);

            encryptedExtensions.AddRange(
                GetCurrentMasterKey().
                    GenerateNTSCookieExtensions(
                        NumberOfCookies:  numberOfCookies,
                        C2SKey:           ntsCookie.C2SKey,
                        S2CKey:           ntsCookie.S2CKey,
                        AEADAlgorithm:    ntsCookie.AEADAlgorithm,
                        TimeProvider:     TimeProvider
                    )
            );


            if (SignedResponseRequested)
                extensions.Add(
                    new NTSSignedResponseAnnouncementExtension(IsScheduled: true)
                );


            var response1 = BuildResponseHeader(RequestPacket, extensions, Exchange);


            var associatedData = new List<Byte[]>() { response1.ToByteArray(SkipExtensions: true) }.
                                     Concat(extensions.Select(ext => ext.ToByteArray())).ToArray();

            extensions.Add(
                AuthenticatorAndEncryptedExtension.Create(
                    NTSKey:          ntsCookie.S2CKey,
                    AssociatedData:  associatedData,
                    Plaintext:       encryptedExtensions.Select(ext => ext.ToByteArray()).Aggregate(),
                    Nonce:           null
                )
            );

            return new NTPPacket(
                       response1,
                       Extensions: extensions
                   );

        }


        private NTPPacket SignResponse(NTPPacket  NTPResponse,
                                       KeyPair    KeyPair)
        {

            var extensions = new List<NTPExtension>();
            extensions.AddRange(NTPResponse.Extensions);


            var response2 = new NTPPacket(
                                NTPResponse,
                                Extensions: extensions
                            ).ToByteArray();

            extensions.Add(
                NTSSignedResponseExtension.Sign(
                    KeyPair,
                    response2
                )
            );

            return new NTPPacket(
                       NTPResponse,
                       Extensions: extensions
                   );

        }

    }

}
