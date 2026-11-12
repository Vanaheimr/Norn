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
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Collections.Concurrent;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.X509;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

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
        private        readonly  Lock                                     currentMasterKeyLock   = new();

        /// <summary>
        /// The master key new cookies are sealed under. MasterKey is a struct of several
        /// words, and a Nullable of it cannot be read while another thread writes it without
        /// the risk of seeing half of each. So the key is published as a reference to an
        /// immutable box: every packet reads one reference, without taking the lock.
        /// </summary>
        private volatile         CurrentMasterKey?                        currentMasterKey;

        private sealed class CurrentMasterKey(MasterKey Key)
        {

            public MasterKey Key { get; } = Key;

            public Boolean IsValidAt(DateTimeOffset Timestamp)
                => Key.NotBefore <= Timestamp &&
                   Key.NotAfter  >  Timestamp;

        }
        private readonly         String?                                  masterKeysFilePath;

        /// <summary>
        /// The highest master key id this server ever saw, in its key file or made itself: the
        /// next key is numbered above it.
        /// </summary>
        private                  UInt64                                   highestMasterKeyId;

        private readonly         ConcurrentDictionary<UInt64, KeyPair>    keyPairs               = [];
        private                  KeyPair?                                 currentKeyPair;
        private                  PublicKey?                               currentPublicKey;

        private readonly         SemaphoreSlim                            ntpRequestSemaphore;
        private readonly         SemaphoreSlim                            ntskeConnectionSemaphore;
        private readonly         ConcurrentDictionary<System.Net.IPAddress, Int32>  ntskeConnectionsPerClient = [];
        private readonly         Boolean                                  advertiseExternalURLs;
        private readonly         X509Certificate?                         tlsCertificate;
        private readonly         ECPrivateKeyParameters?                  tlsPrivateKey;
        private readonly         String?                                  tlsServerSubjectName;
        private readonly         ISshUserAuthenticator?                   sshAuthenticator;
        private                  SshServer?                               sshServer;

        private                  Int64                                    ntpRequestsReceived;
        private                  Int64                                    ntpRequestsDenied;
        private                  Int64                                    ntpRequestsRejected;
        private                  Int64                                    ntpRequestsRateLimited;
        private                  Int64                                    ntpKissesOfDeathSent;
        private                  Int64                                    ntpRequestsInvalid;
        private                  Int64                                    ntpResponsesSent;
        private                  Int64                                    ntpSignedResponsesSent;
        private                  Int64                                    ntpRequestFailures;
        private                  Int64                                    ntskeConnectionsAccepted;
        private                  Int64                                    ntskeConnectionsDenied;
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
        /// The TCP port of the SSH listener for NTS-KE over SSH, or null when this server has none.
        /// </summary>
        /// <remarks>
        /// Without a listener of its own the server can still answer NTS-KE over SSH on somebody
        /// else's, see <see cref="ServeSSHSubsystemAsync"/>.
        /// </remarks>
        public IPPort?                     SSHPort       { get; }

        /// <summary>
        /// The host keys of the SSH listener, which clients pin. Empty when there is no listener.
        /// </summary>
        public IReadOnlyList<ISshHostKey>  SSHHostKeys   { get; }

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
        /// Who this server will answer in the RFC 9769 interleaved mode.
        /// </summary>
        public InterleavedModePolicy  InterleavedMode
            => InterleavedTimestamps?.Policy ?? InterleavedModePolicy.Disabled;

        /// <summary>
        /// The RFC 8633 § 5.4 request rate limiter, or null when this server answers everything
        /// it can.
        /// </summary>
        /// <remarks>
        /// Off unless an operator asks for it, unlike the interleaved mode. The interleaved mode
        /// costs memory this server can cap on its own; a rate limit costs answers, and how many
        /// answers a client is entitled to is not something the protocol can decide.
        /// </remarks>
        public NTPRateLimiter?        RateLimiter                  { get; }

        /// <summary>
        /// Who may query this server at all, the access list of RFC 8633 § 5.1: over NTP, over
        /// NTS-KE and over this server's own SSH listener.
        /// </summary>
        /// <remarks>
        /// Everyone unless an operator says otherwise. A key exchange in the NTS-KE subsystem of an
        /// SSH listener that is not this server's - <see cref="ServeSSHSubsystemAsync"/> serving a
        /// shared one - is let in by whoever serves that listener, and this list is not asked.
        /// </remarks>
        public NTPAccessList          AccessList                   { get; }

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
        /// How many NTS-KE connections one client may have open at the same time. A client
        /// is an IPv4 address or an IPv6 /64, as for the rate limiter.
        /// </summary>
        /// <remarks>
        /// Without it, whoever opens <see cref="MaxConcurrentNTSKEConnections"/> connections
        /// and then says nothing holds every slot for as long as the timeouts allow, and
        /// can do so again the moment they expire. A TCP connection cannot be opened under a
        /// forged address, so this limit is one an attacker has to pay for in real addresses.
        /// </remarks>
        public Int32                 MaxNTSKEConnectionsPerClient  { get; }

        /// <summary>
        /// The default of <see cref="MaxNTSKEConnectionsPerClient"/>. A key exchange is rare
        /// and short, so this leaves ample room for several clients behind one address.
        /// </summary>
        public const Int32           DefaultMaxNTSKEConnectionsPerClient = 8;

        /// <summary>
        /// The key id currently used for newly generated NTS cookies.
        /// </summary>
        public UInt64                CurrentMasterKeyId
            => GetCurrentMasterKey().Id;

        /// <summary>
        /// The master keys this server keeps, oldest first: their ids and when they are valid,
        /// never their values. The current one seals new cookies, the others still open the
        /// cookies they sealed until their grace period is over.
        /// </summary>
        public IReadOnlyList<MasterKeyInfo>  MasterKeys
        {
            get
            {

                var current = GetCurrentMasterKey().Id;

                return [.. masterKeys.Values.
                               OrderBy(masterKey => masterKey.Id).
                               Select (masterKey => new MasterKeyInfo(masterKey.Id,
                                                                      masterKey.NotBefore,
                                                                      masterKey.NotAfter,
                                                                      masterKey.Id == current))];

            }
        }

        /// <summary>
        /// A point-in-time snapshot of the NTS server counters.
        /// </summary>
        public NTSServerMetrics      Metrics
            => new (
                   NTPRequestsReceived:       System.Threading.Interlocked.Read(ref ntpRequestsReceived),
                   NTPRequestsRejected:       System.Threading.Interlocked.Read(ref ntpRequestsRejected),
                   NTPRequestsRateLimited:    System.Threading.Interlocked.Read(ref ntpRequestsRateLimited),
                   NTPKissesOfDeathSent:      System.Threading.Interlocked.Read(ref ntpKissesOfDeathSent),
                   NTPRequestsInvalid:        System.Threading.Interlocked.Read(ref ntpRequestsInvalid),
                   NTPResponsesSent:          System.Threading.Interlocked.Read(ref ntpResponsesSent),
                   NTPSignedResponsesSent:    System.Threading.Interlocked.Read(ref ntpSignedResponsesSent),
                   NTPRequestFailures:        System.Threading.Interlocked.Read(ref ntpRequestFailures),
                   NTSKEConnectionsAccepted:  System.Threading.Interlocked.Read(ref ntskeConnectionsAccepted),
                   NTSKEConnectionsRejected:  System.Threading.Interlocked.Read(ref ntskeConnectionsRejected),
                   NTSKEHandshakeFailures:    System.Threading.Interlocked.Read(ref ntskeHandshakeFailures),
                   NTSKERequestsInvalid:      System.Threading.Interlocked.Read(ref ntskeRequestsInvalid),
                   NTSKEResponsesSent:        System.Threading.Interlocked.Read(ref ntskeResponsesSent),
                   NTPRequestsDenied:         System.Threading.Interlocked.Read(ref ntpRequestsDenied),
                   NTSKEConnectionsDenied:    System.Threading.Interlocked.Read(ref ntskeConnectionsDenied)
               );

        #endregion

        #region Events

        /// <summary>
        /// A key exchange over SSH was answered - with cookies, or with an Error record - or failed.
        /// Raised after the answer went out; a handler that throws does not touch the exchange.
        /// </summary>
        public event Action<NTSKEOverSSHExchange>?  OnSSHKeyExchange;

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
        /// <param name="InterleavedMode">Who may be answered in the RFC 9769 interleaved mode (default: everyone).</param>
        /// <param name="RateLimiter">An optional RFC 8633 § 5.4 request rate limiter (default: none, so every request is answered).</param>
        /// <param name="SupportedAEADAlgorithms">The AEAD algorithms to agree to (default: <see cref="NTSAEAD.Supported"/>).</param>
        /// <param name="TimeProvider">The optional clock this server reads and reports (default: <see cref="System.TimeProvider.System"/>).</param>
        /// <param name="SSHPort">The optional TCP port of an SSH listener for NTS-KE over SSH (default: none).</param>
        /// <param name="SSHHostKeys">The host keys of that listener (default: a fresh Ed25519 key, which no client can have pinned yet).</param>
        /// <param name="SSHAuthenticator">Who may log in to that listener; required with <paramref name="SSHPort"/>.</param>
        /// <param name="AccessList">Who may query this server at all, RFC 8633 § 5.1 (default: everyone).</param>
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
                         InterleavedModePolicy? InterleavedMode           = null,
                         NTPRateLimiter?    RateLimiter                   = null,
                         IEnumerable<AEADAlgorithms>? SupportedAEADAlgorithms = null,
                         TimeProvider?      TimeProvider                  = null,
                         IPPort?            SSHPort                       = null,
                         IEnumerable<ISshHostKey>? SSHHostKeys            = null,
                         ISshUserAuthenticator?    SSHAuthenticator       = null,
                         NTPAccessList?            AccessList             = null,
                         Int32?                    MaxNTSKEConnectionsPerClient = null)
        {

            // An SSH listener hands out cookies to whoever logs in, so who that may be is never a
            // default: there is no SSH server here that lets everybody in by accident.
            if (SSHPort.HasValue && SSHAuthenticator is null)
                throw new ArgumentException("An SSH listener for NTS-KE needs an authenticator that says who may log in.",
                                            nameof(SSHAuthenticator));

            this.SSHPort                      = SSHPort;
            this.SSHHostKeys                  = SSHPort.HasValue
                                                    ? SSHHostKeys?.ToArray() is { Length: > 0 } hostKeys
                                                          ? hostKeys
                                                          : [ SshHostKey.GenerateEd25519() ]
                                                    : [];
            this.sshAuthenticator             = SSHAuthenticator;

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
            this.MaxNTSKEConnectionsPerClient = Math.Max(1, MaxNTSKEConnectionsPerClient ?? DefaultMaxNTSKEConnectionsPerClient);
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

            // Everyone by default, as in chrony: a client that does not ask for the mode cannot
            // be given it, since an interleaved response only ever answers a request echoing a
            // timestamp this server issued. Operators of public servers who would rather spend
            // the per-address state only on clients that completed a key exchange can say
            // AuthenticatedOnly, which RFC 9769 § 2 explicitly allows.
            var interleavedMode               = InterleavedMode              ?? InterleavedModePolicy.Everyone;

            this.InterleavedTimestamps        = interleavedMode != InterleavedModePolicy.Disabled
                                                    ? new InterleavedTimestamps(interleavedMode)
                                                    : null;

            this.RateLimiter                  = RateLimiter;
            this.AccessList                   = AccessList                   ?? NTPAccessList.Everyone;

            // What this server will agree to. Defaults to NTSAEAD.Supported, which is narrower
            // than what is implemented — see there. Anything named that cannot be performed is
            // dropped rather than honoured: agreeing to an algorithm and then failing every
            // packet is the one outcome worse than refusing it.
            this.supportedAEADAlgorithms      = (SupportedAEADAlgorithms ?? NTSAEAD.Supported).
                                                    Where(NTSAEAD.IsSupported).
                                                    ToArray();

            if (this.supportedAEADAlgorithms.Length == 0)
                throw new ArgumentException("At least one of the given AEAD algorithms has to be one this server can perform.",
                                            nameof(SupportedAEADAlgorithms));

            if (KeyPair is not null)
            {

                this.currentKeyPair   = KeyPair;
                this.currentPublicKey = KeyPair.ToPublicKey();

                this.keyPairs.TryAdd(KeyPair.Id, KeyPair);

            }

            // The master keys an earlier run of this server wrote are taken up again, so that the
            // cookies its clients still hold stay good across a restart. A key is forgotten by the
            // same rule GetCurrentMasterKey() forgets keys by: once it ended longer ago than the
            // grace period. (This used to compare the end of a key against now *plus* the grace
            // period, which - with a lifetime of one day and a grace period of seven - passed over
            // every key that was ever written.)
            //
            // Every key of the file counts for the id of the next one, the forgotten ones as well:
            // the id is all a cookie says of the key it was sealed under, so it is never given to a
            // second key. Should an id stand in the file twice all the same - as in every file
            // written while no key was taken up again, each run having begun anew with 1 - the
            // later line, being the newer key, is the one kept.
            try
            {

                var forgetUpTo  = this.TimeProvider.GetUtcNow() - this.MasterKeyRotationGracePeriod;
                var lineNumber  = 0;

                foreach (var masterKeyText in MasterKeysFilePath.IsNotNullOrEmpty()
                                                  ? File.ReadAllLines(MasterKeysFilePath)
                                                  : [])
                {

                    lineNumber++;

                    if (String.IsNullOrWhiteSpace(masterKeyText))
                        continue;

                    if (MasterKey.TryParse(masterKeyText, out var masterKey, out var errorResponse))
                    {

                        if (masterKey.Id > highestMasterKeyId)
                            highestMasterKeyId = masterKey.Id;

                        if (masterKey.NotAfter <= forgetUpTo)
                            continue;

                        masterKeys[masterKey.Id] = masterKey;

                    }

                    // The line itself is not logged: it may well hold a key.
                    else
                        DebugX.Log($"Invalid master key in line {lineNumber} of '{MasterKeysFilePath}': {errorResponse}");

                }

            }
            catch (FileNotFoundException)
            { }
            catch (DirectoryNotFoundException)
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

        /// <summary>
        /// The next-protocol IDs this server implements (RFC 8915 § 4.1.2).
        /// </summary>
        private static readonly UInt16[] supportedNextProtocols = [ 0 ];   // 0 = NTPv4

        /// <summary>
        /// The AEAD algorithms this server implements (RFC 8915 § 4.1.5).
        /// </summary>
        private readonly AEADAlgorithms[] supportedAEADAlgorithms;

        /// <summary>
        /// Protocol ID 0, NTPv4 — the only next protocol that makes cookies meaningful.
        /// </summary>
        private const UInt16 NextProtocolNTPv4 = 0;


        /// <summary>
        /// What examining an NTS-KE request concluded: either an error code the request must be
        /// refused with, or the protocol and algorithm that were actually agreed.
        /// </summary>
        /// <param name="ErrorCode">Set when the request must be refused; null when it is acceptable.</param>
        /// <param name="NextProtocol">The agreed next protocol, or null when none could be agreed.</param>
        /// <param name="AEADAlgorithm">The agreed AEAD algorithm, or null when none could be agreed.</param>
        /// <param name="CompliantAES128GCMSIVExporterContext">
        /// Whether AES-128-GCM-SIV was agreed <em>and</em> the client asked for RFC 8915 § 5.1's
        /// exporter context by sending IANA record type 1024. Both halves matter: the record is
        /// meaningless under any other algorithm, and a client that did not send it is waiting
        /// for chrony's derivation.
        /// </param>
        private sealed record NTSKENegotiation(NTSKEErrorCodes?  ErrorCode,
                                               UInt16?           NextProtocol,
                                               AEADAlgorithms?   AEADAlgorithm,
                                               String?           Reason,
                                               Boolean           CompliantAES128GCMSIVExporterContext   = false)
        {

            public static NTSKENegotiation Refuse(NTSKEErrorCodes ErrorCode, String Reason)
                => new (ErrorCode, null, null, Reason);

            public static NTSKENegotiation Accept(UInt16?          NextProtocol,
                                                  AEADAlgorithms?  AEADAlgorithm,
                                                  Boolean          CompliantAES128GCMSIVExporterContext   = false)
                => new (null, NextProtocol, AEADAlgorithm, null, CompliantAES128GCMSIVExporterContext);

            /// <summary>
            /// True when NTPv4 was agreed, which is what makes NTPv4 cookies meaningful.
            /// </summary>
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
        /// <param name="NTSKERequest">The records of the request.</param>
        /// <param name="OverSSH">
        /// Whether the request came over the SSH subsystem. Only there is the SSH Key Binding
        /// record known; over TLS its critical bit makes it an unrecognized critical record, as it
        /// would be for any server that follows RFC 8915.
        /// </param>
        private NTSKENegotiation NegotiateNTSKE(IEnumerable<NTSKE_Record>  NTSKERequest,
                                                Boolean                    OverSSH   = false)
        {

            var records = NTSKERequest.ToArray();

            // RFC 8915 § 4: "Implementations which receive a record with an unrecognized Record
            // Type MUST ignore the record if the Critical Bit is 0 and MUST treat it as an
            // error if the Critical Bit is 1", and § 4.1.3 code 0 covers exactly that case.
            var unknownCritical = records.FirstOrDefault(record => record.IsCritical &&
                                                                   !IsKnownRecordType(record.Type) &&
                                                                   !(OverSSH && record.Type == NTSKE_RecordTypes.SSHKeyBinding));

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

            // "If the NTS Next Protocol Negotiation record offers Protocol ID 0 (for NTPv4),
            // then this record MUST be included exactly once."
            if (aeadRecords.Length == 0 && offeredProtocols.Contains(NextProtocolNTPv4))
                return NTSKENegotiation.Refuse(
                           NTSKEErrorCodes.BadRequest,
                           "the request offers NTPv4 but carries no AEAD Algorithm Negotiation record"
                       );

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

            // § 5.1's exporter context for AES-128-GCM-SIV, but only if the client said it can
            // do it — chrony's clients cannot, and answering one of those with the compliant
            // derivation produces a session neither side can use. Under any other algorithm the
            // record has nothing to say, so it is not echoed and does not change the keys.
            //
            // Over SSH it has nothing to say either: the deviation it works around lives in the
            // TLS-based implementations, and NTS-KE over SSH always uses § 5.1's context.
            var compliantAES128GCMSIVExporterContext = !OverSSH &&
                                                       negotiatedAEAD == AEADAlgorithms.AES_128_GCM_SIV &&
                                                       records.Any(record => record.Type == NTSKE_RecordTypes.CompliantAES128GCMSIVExporterContext);

            return NTSKENegotiation.Accept(
                       negotiatedProtocol,
                       negotiatedAEAD,
                       compliantAES128GCMSIVExporterContext
                   );

        }


        /// <summary>
        /// Whether this server understands the given record type.
        /// </summary>
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
                          or NTSKE_RecordTypes.NTSPublicKey
                          or NTSKE_RecordTypes.CompliantAES128GCMSIVExporterContext;


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

        /// <param name="Negotiation">What the request agreed.</param>
        /// <param name="NTSKERequest">The records of the request.</param>
        /// <param name="C2SKey">The client-to-server key the cookies carry.</param>
        /// <param name="S2CKey">The server-to-client key the cookies carry.</param>
        /// <param name="KeyBinding">The SSH Key Binding record of a response over SSH, which says where the two keys came from.</param>
        private IEnumerable<NTSKE_Record> BuildNTSKEResponseRecords(NTSKENegotiation           Negotiation,
                                                                    IEnumerable<NTSKE_Record>  NTSKERequest,
                                                                    Byte[]                    C2SKey,
                                                                    Byte[]                    S2CKey,
                                                                    NTSKE_Record?             KeyBinding   = null)
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

            // Echoed only when the client asked and AES-128-GCM-SIV was agreed, because it is
            // what tells the client which of the two derivations the cookies below were built
            // with. Silence means chrony's, which is what silence has always meant.
            if (Negotiation.CompliantAES128GCMSIVExporterContext)
                ntsKERecords.Add(NTSKE_Record.CompliantAES128GCMSIVExporterContext());

            if (KeyBinding is not null)
                ntsKERecords.Add(KeyBinding);

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

        #region ServeSSHSubsystemAsync(Context, CancellationToken)

        /// <summary>
        /// Serve one NTS-KE exchange over SSH: read the request from the channel of the subsystem
        /// <see cref="NTSKE_SSH.SubsystemName"/>, answer it, and end the channel.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Public, and shaped as the subsystem handler of Hermod's SSH server, so that it serves
        /// the SSH listener of this server as well as the shared SSH listener of a charging
        /// infrastructure node, which offers NTS-KE next to OCPP (section 8.3 of the white paper).
        /// Whoever serves it decides who may open the subsystem; this only answers.
        /// </para>
        /// <para>
        /// One exchange per channel, as RFC 8915 has one per TLS connection. A client may open the
        /// subsystem again on the same connection, and every exchange gets keys of its own: with
        /// option B from a secret of its own, with option A from the exporter of the connection
        /// and a nonce of its own, both of which the server sends in the SSH Key Binding record.
        /// </para>
        /// </remarks>
        /// <param name="Context">The session and the channel of the subsystem.</param>
        /// <param name="CancellationToken">Fires when the channel is closed or the SSH server stops.</param>
        public async ValueTask ServeSSHSubsystemAsync(SshSubsystemContext  Context,
                                                      CancellationToken    CancellationToken)
        {

            System.Threading.Interlocked.Increment(ref ntskeConnectionsAccepted);

            if (!await ntskeConnectionSemaphore.WaitAsync(0, CancellationToken).ConfigureAwait(false))
            {
                System.Threading.Interlocked.Increment(ref ntskeConnectionsRejected);
                DebugX.Log($"Closing NTS-KE over SSH from {Context.Session.Peer}: too many concurrent key exchanges.");
                await SendExitStatusAsync(Context.Channel, 1, CancellationToken).ConfigureAwait(false);
                ReportSSHKeyExchange(Context.Session, new SSHExchangeOutcome { Problem = "too many concurrent key exchanges" }, []);
                return;     // and the SSH server closes the channel
            }

            var outcome = new SSHExchangeOutcome();

            try
            {

                // The request is given NTSKERequestTimeout, and the answer a little more, so that a
                // request that never arrived complete can still be told why it was refused.
                using var requestCTS = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
                requestCTS.CancelAfter(NTSKERequestTimeout + TimeSpan.FromSeconds(5));

                var (requestBytes, errorMessage) = await NTSKEMessageReader.ReadAsync(
                                                             Context.Channel.Input,
                                                             NTSKERequestTimeout,
                                                             MaxNTSKERequestSize,
                                                             requestCTS.Token
                                                         ).ConfigureAwait(false);

                var ntsKERecords = AnswerNTSKERequestOverSSH(
                                       requestBytes,
                                       errorMessage,
                                       Context.Session,
                                       outcome
                                   ).ToArray();

                await Context.Channel.SendDataAsync(ntsKERecords.ToByteArray(), requestCTS.Token).ConfigureAwait(false);

                // Data, exit-status, EOF, and then the SSH server closes the channel: the order of
                // OpenSSH's sshd. Without an exit-status `ssh -s` reports the exchange as failed
                // (exit code 255), although every record arrived. 0 means cookies, 1 an Error record.
                //
                // With the data the exchange is done. A client has what it asked for once it has
                // read the End of Message record, and Norn's own client closes its channel then,
                // which may be before the exit-status and the EOF are out: its CLOSE cancels the
                // token they are sent with. So neither may fail the exchange. The EOF did, and a
                // key exchange that had been served was counted and reported as a failed one,
                // "A task was canceled."
                await SendExitStatusAsync(Context.Channel,
                                          ntsKERecords.Any(record => record.Type == NTSKE_RecordTypes.Error) ? 1U : 0U,
                                          requestCTS.Token).ConfigureAwait(false);

                await SendEofAsync(Context.Channel, requestCTS.Token).ConfigureAwait(false);

                System.Threading.Interlocked.Increment(ref ntskeResponsesSent);

                ReportSSHKeyExchange(Context.Session, outcome, ntsKERecords);

            }
            catch (Exception e)
            {
                System.Threading.Interlocked.Increment(ref ntskeHandshakeFailures);
                DebugX.Log($"NTS-KE over SSH from {Context.Session.Peer} failed: {e.Message}");
                await SendExitStatusAsync(Context.Channel, 1, CancellationToken.None).ConfigureAwait(false);
                ReportSSHKeyExchange(Context.Session, new SSHExchangeOutcome { Problem = e.Message }, []);
            }
            finally
            {
                ntskeConnectionSemaphore.Release();
            }

        }

        #endregion

        #region (private static) SendExitStatusAsync(Channel, ExitStatus, CancellationToken)

        /// <summary>
        /// Tell the client how the subsystem ended (RFC 4254, section 6.10), as an SSH server does
        /// when the program behind a subsystem exits. A channel that is already gone has nobody
        /// left to tell, so a failure here is not one of the exchange.
        /// </summary>
        private static async ValueTask SendExitStatusAsync(SshMuxChannel      Channel,
                                                           UInt32             ExitStatus,
                                                           CancellationToken  CancellationToken)
        {

            var payload = new Byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(payload, ExitStatus);

            try
            {
                await Channel.SendRequestAsync("exit-status", false, payload, CancellationToken).ConfigureAwait(false);
            }
            catch
            { }

        }

        #endregion

        #region (private static) SendEofAsync(Channel, CancellationToken)

        /// <summary>
        /// Tell the client that nothing more will come (RFC 4254, section 5.3), once the answer is
        /// out. Like the exit-status: a channel the client has closed already, having read the
        /// answer, has nobody left to tell, so a failure here is not one of the exchange.
        /// </summary>
        private static async ValueTask SendEofAsync(SshMuxChannel      Channel,
                                                    CancellationToken  CancellationToken)
        {
            try
            {
                await Channel.SendEofAsync(CancellationToken).ConfigureAwait(false);
            }
            catch
            { }
        }

        #endregion

        #region (private) SSHExchangeOutcome / ReportSSHKeyExchange(Session, Outcome, Response)

        /// <summary>
        /// What the answer to one key exchange over SSH made of it, for those who are told.
        /// </summary>
        private sealed class SSHExchangeOutcome
        {
            public SSHKeyBindingMethods?  Method;
            public AEADAlgorithms?        AEADAlgorithm;
            public NTSKEErrorCodes?       ErrorCode;
            public String?                Problem;
        }

        private void ReportSSHKeyExchange(SshSessionInfo             Session,
                                          SSHExchangeOutcome         Outcome,
                                          IEnumerable<NTSKE_Record>  Response)
        {

            if (OnSSHKeyExchange is not Action<NTSKEOverSSHExchange> handlers)
                return;

            var exchange = new NTSKEOverSSHExchange(
                               TimeProvider.GetUtcNow(),
                               Session,
                               Outcome.Method,
                               Outcome.AEADAlgorithm,
                               Response.Count(record => record.Type == NTSKE_RecordTypes.NewCookieForNTPv4),
                               Outcome.ErrorCode,
                               Outcome.Problem
                           );

            foreach (var handler in handlers.GetInvocationList().Cast<Action<NTSKEOverSSHExchange>>())
            {
                try
                {
                    handler(exchange);
                }
                catch (Exception e)
                {
                    DebugX.Log($"A handler of OnSSHKeyExchange failed: {e.Message}");
                }
            }

        }

        #endregion

        #region (private) AnswerNTSKERequestOverSSH(RequestBytes, ReadError, Session, Outcome)

        /// <summary>
        /// The response to an NTS-KE request over SSH: the records of RFC 8915 as over TLS, plus
        /// the SSH Key Binding record that says where the keys come from: the exporter of the
        /// connection, or the secret it carries.
        /// </summary>
        /// <param name="RequestBytes">The request, or null when none arrived complete.</param>
        /// <param name="ReadError">Why no request arrived complete.</param>
        /// <param name="Session">Who sent it.</param>
        /// <param name="Outcome">Filled with what the answer made of the request.</param>
        private IEnumerable<NTSKE_Record> AnswerNTSKERequestOverSSH(Byte[]?             RequestBytes,
                                                                    String?             ReadError,
                                                                    SshSessionInfo      Session,
                                                                    SSHExchangeOutcome  Outcome)
        {

            IEnumerable<NTSKE_Record> Refuse(NTSKEErrorCodes ErrorCode, String? Reason)
            {
                System.Threading.Interlocked.Increment(ref ntskeRequestsInvalid);
                DebugX.Log($"Refusing NTS-KE request over SSH from {Session.Username} ({Session.Peer}) with error {(UInt16) ErrorCode}: {Reason}");
                Outcome.ErrorCode  = ErrorCode;
                Outcome.Problem    = Reason ?? $"error {(UInt16) ErrorCode}";
                return BuildNTSKEErrorRecords(ErrorCode);
            }

            if (RequestBytes is null)
                return Refuse(NTSKEErrorCodes.BadRequest, ReadError);

            if (!NTSKE_Record.TryParse(RequestBytes, out var ntsKERequest, out var errorResponse))
                return Refuse(NTSKEErrorCodes.BadRequest, errorResponse);

            var negotiation = NegotiateNTSKE(ntsKERequest, OverSSH: true);

            if (negotiation.ErrorCode.HasValue)
                return Refuse(negotiation.ErrorCode.Value, negotiation.Reason);

            #region SSH Key Binding (section 5 of the white paper)

            // Exactly one: the record is how the client says which sources of keys it can use,
            // and the server cannot pick from two lists.
            var keyBindings = ntsKERequest.OfType<NTSKERecords.SSHKeyBinding>().ToArray();

            if (keyBindings.Length != 1)
                return Refuse(NTSKEErrorCodes.BadRequest,
                              $"the request carries {keyBindings.Length} SSH Key Binding records instead of one");

            if (!keyBindings[0].TryGetOfferedMethods(out var offeredMethods, out var methodError))
                return Refuse(NTSKEErrorCodes.BadRequest, methodError);

            // The first method of the client's list that this server can use: the exporter of
            // option A where the SSH stack hands it out, the transport of option B always, which is
            // why every client offers it. Either way with data of its own for every exchange, so
            // that every exchange on one connection gets keys of its own.
            NTSKE_Exporter?  exporter      = null;
            NTSKE_Record?    keyBinding    = null;

            foreach (var method in offeredMethods)
            {

                if (method == (UInt16) SSHKeyBindingMethods.Exporter &&
                    Session.Exporter is SshExporter sshExporter)
                {

                    // The keys come from the connection; the nonce, which need not be secret, only
                    // keeps them apart from those of every other exchange on it.
                    var exporterNonce = RandomNumberGenerator.GetBytes(NTSKE_ExportedKeys.ExporterNonceLength);

                    exporter        = NTSKE_ExportedKeys.SSHExporter(sshExporter, exporterNonce);
                    keyBinding      = NTSKE_Record.SSHKeyBindingResponse(SSHKeyBindingMethods.Exporter, exporterNonce);
                    Outcome.Method  = SSHKeyBindingMethods.Exporter;
                    break;

                }

                if (method == (UInt16) SSHKeyBindingMethods.Transport)
                {

                    // A secret of its own for every exchange. It travels inside the SSH channel,
                    // whose far end the client authenticated by its host key, and leaves this
                    // method only there.
                    var ntsKESecret = RandomNumberGenerator.GetBytes(NTSKE_ExportedKeys.TransportedSecretLength);

                    exporter        = NTSKE_ExportedKeys.TransportedSecretExporter(ntsKESecret);
                    keyBinding      = NTSKE_Record.SSHKeyBindingResponse(SSHKeyBindingMethods.Transport, ntsKESecret);
                    Outcome.Method  = SSHKeyBindingMethods.Transport;
                    break;

                }

            }

            if (exporter is null || keyBinding is null)
                return Refuse(NTSKEErrorCodes.BadRequest,
                              $"the SSH Key Binding record offers {String.Join(", ", offeredMethods.Select(method => $"0x{method:x4}"))}, " +
                              $"none of which this server can use");

            #endregion

            Outcome.AEADAlgorithm = negotiation.AEADAlgorithm ?? NTSAEAD.Default;

            // Always § 5.1's context: see NegotiateNTSKE on why record 1024 means nothing here.
            var (c2sKey, s2cKey)  = NTSKE_ExportedKeys.ExportAll(exporter).
                                                       For(Outcome.AEADAlgorithm.Value,
                                                           CompliantExporterContext: true);

            return BuildNTSKEResponseRecords(
                       negotiation,
                       ntsKERequest,
                       c2sKey,
                       s2cKey,
                       keyBinding
                   );

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


        #region (private) ReleaseNTSKEClient(Client)

        /// <summary>
        /// One NTS-KE connection of this client has ended.
        /// </summary>
        private void ReleaseNTSKEClient(System.Net.IPAddress? Client)
        {

            if (Client is null)
                return;

            // The entry is removed when its last connection ends, and only if it still says
            // so: comparing the pair makes the removal lose against a connection that was
            // counted in between, instead of deleting that connection's count.
            while (ntskeConnectionsPerClient.TryGetValue(Client, out var open))
            {

                if (open <= 1
                        ? ntskeConnectionsPerClient.TryRemove(new KeyValuePair<System.Net.IPAddress, Int32>(Client, open))
                        : ntskeConnectionsPerClient.TryUpdate(Client, open - 1, open))
                {
                    return;
                }

            }

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

            var now     = TimeProvider.GetUtcNow();

            // Read once, and only this copy is looked at: the field may be replaced by
            // another thread at any moment, the box it pointed to never changes.
            var current = currentMasterKey;

            if (current?.IsValidAt(now) == true)
                return current.Key;

            lock (currentMasterKeyLock)
            {

                now = TimeProvider.GetUtcNow();

                foreach (var masterKey in masterKeys.Values)
                {
                    if (masterKey.NotAfter <= now - MasterKeyRotationGracePeriod)
                        masterKeys.TryRemove(masterKey.Id, out _);
                }

                // Another thread may have replaced the key while this one waited for the lock.
                current = currentMasterKey;

                if (current?.IsValidAt(now) == true)
                    return current.Key;

                current = null;

                foreach (var masterKey in masterKeys.Values.OrderByDescending(masterKey => masterKey.NotAfter))
                {
                    if (masterKey.NotBefore <= now &&
                        masterKey.NotAfter  >  now)
                    {
                        current = new CurrentMasterKey(masterKey);
                        break;
                    }
                }

                if (current is null)
                {

                    // Above every id ever seen, not only above those still kept: see the
                    // constructor.
                    highestMasterKeyId = Math.Max(highestMasterKeyId,
                                                  masterKeys.IsEmpty
                                                      ? 0UL
                                                      : masterKeys.Keys.Max()) + 1;

                    current            = new CurrentMasterKey(
                                             new MasterKey(
                                                 Id:         highestMasterKeyId,
                                                 Value:      RandomNumberGenerator.GetBytes(32),
                                                 NotBefore:  now,
                                                 NotAfter:   now + MasterKeyLifetime
                                             )
                                         );

                    masterKeys.TryAdd(
                        current.Key.Id,
                        current.Key
                    );

                    // Published before it is written, and never as null in between: the
                    // field goes from one valid key straight to the next.
                    currentMasterKey   = current;

                    WriteMasterKeys();

                }

                else
                    currentMasterKey   = current;

                return current.Key;

            }

        }

        #endregion

        #region RotateMasterKey(ForgetTheOthers = false)

        /// <summary>
        /// Make a new master key the current one now, rather than when the current one ends: the
        /// "rotate the cookie master key" of section 8.2 of the white paper "NTS Key Establishment
        /// over SSH".
        /// </summary>
        /// <remarks>
        /// <para>
        /// New cookies are sealed with the new key from now on. The earlier keys still open the
        /// cookies they sealed, each until its grace period after its end is over, so that clients
        /// move to the new key with the cookies NTP hands them, without a key exchange of their own.
        /// </para>
        /// <para>
        /// <paramref name="ForgetTheOthers"/> is for a key that may have been read by somebody: the
        /// earlier keys are forgotten at once, here and in the key file, and every cookie they sealed
        /// is refused from now on. Every client has to make a key exchange again.
        /// </para>
        /// </remarks>
        /// <param name="ForgetTheOthers">Whether to forget every earlier key at once.</param>
        /// <returns>The new key, without its value.</returns>
        public MasterKeyInfo RotateMasterKey(Boolean ForgetTheOthers = false)
        {

            lock (currentMasterKeyLock)
            {

                var now = TimeProvider.GetUtcNow();

                if (ForgetTheOthers)
                    masterKeys.Clear();

                // Above every id ever seen, not only above those still kept: see the constructor.
                highestMasterKeyId = Math.Max(highestMasterKeyId,
                                              masterKeys.IsEmpty
                                                  ? 0UL
                                                  : masterKeys.Keys.Max()) + 1;

                var rotated        = new MasterKey(
                                         Id:         highestMasterKeyId,
                                         Value:      RandomNumberGenerator.GetBytes(32),
                                         NotBefore:  now,
                                         NotAfter:   now + MasterKeyLifetime
                                     );

                masterKeys.TryAdd(rotated.Id, rotated);
                currentMasterKey   = new CurrentMasterKey(rotated);

                WriteMasterKeys();

                return new MasterKeyInfo(rotated.Id, rotated.NotBefore, rotated.NotAfter, IsCurrent: true);

            }

        }

        #endregion

        #region (private) WriteMasterKeys()

        /// <summary>
        /// Write the master keys this server keeps - and only those - into its key file.
        ///
        /// The file is written anew rather than appended to: a key this server forgot is gone from
        /// the file as well, as RFC 8915 § 6 asks of keys that should now be expired. (That is no
        /// secure erasure of the disk below it, which no file API can promise.) It is written next
        /// to the file and moved over it, so that a crash leaves the old file or the new one, never
        /// half of one; and it is the owner's alone before the first key is written into it, for
        /// whoever reads the master keys can open every cookie and with it the keys its client
        /// authenticates time with.
        ///
        /// Called within the master key lock. A file that cannot be written leaves the keys in
        /// memory, which is what a server without a key file has as well.
        /// </summary>
        private void WriteMasterKeys()
        {

            if (masterKeysFilePath.IsNullOrEmpty())
                return;

            try
            {

                var masterKeysDirectory = Path.GetDirectoryName(masterKeysFilePath);

                if (masterKeysDirectory.IsNotNullOrEmpty())
                    Directory.CreateDirectory(masterKeysDirectory);

                var next    = masterKeysFilePath + ".next";

                // Made anew, so that it is made with the mode below: a file of that name left by
                // a run that died before its move would keep whatever mode it had.
                File.Delete(next);

                var options = new FileStreamOptions {
                                  Mode    = FileMode.CreateNew,
                                  Access  = FileAccess.Write,
                                  Share   = FileShare.None
                              };

                // Not even null on Windows, which refuses the property itself; there the access
                // list is narrowed right after, while the file is still empty.
                if (!OperatingSystem.IsWindows())
                    options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

                using (new FileStream(next, options)) { }

                if (OperatingSystem.IsWindows())
                    SshPrivateKeyFile.RestrictToOwner(next);

                File.WriteAllLines(
                    next,
                    masterKeys.Values.
                               OrderBy(masterKey => masterKey.Id).
                               Select (masterKey => masterKey.ToJSON().ToString(Newtonsoft.Json.Formatting.None))
                );

                File.Move(next, masterKeysFilePath, overwrite: true);

            }
            catch (Exception e)
            {
                DebugX.LogException(e, $"Failed to write the master keys to '{masterKeysFilePath}'!");
            }

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

                        SocketReceiveFromResult udpPacket;

                        try
                        {
                            udpPacket       = await udpSocket.ReceiveFromAsync(
                                                        new ArraySegment<Byte>(buffer),
                                                        SocketFlags.None,
                                                        remoteEP,
                                                        cts.Token
                                                    );
                        }
                        catch (SocketException e) when (!cts.Token.IsCancellationRequested)
                        {
                            // A datagram socket reports the fate of an earlier answer here: an
                            // ICMP "port unreachable" for a client that has already closed its
                            // socket arrives as ConnectionReset on Windows. That is news about
                            // one client and must not end the service for all the others.
                            System.Threading.Interlocked.Increment(ref ntpRequestFailures);
                            DebugX.Log($"Receiving an NTP request failed: {e.SocketErrorCode}");
                            continue;
                        }

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


                        // RFC 8633 § 5.1: an address that may not query this server learns
                        // nothing from it, not even that it is there - so no kiss, only silence.
                        // Before the rate limiter, which would otherwise keep state for it.
                        if (!AccessList.IsEveryone &&
                            !AccessList.Allows((udpPacketLocal.RemoteEndPoint as IPEndPoint)?.Address))
                        {
                            System.Threading.Interlocked.Increment(ref ntpRequestsDenied);
                            continue;
                        }


                        // Only a client request (mode 3) is answered (RFC 5905 § 9.2). Answering
                        // anything else lets a single forged datagram bounce between two servers
                        // forever: a server's answer (mode 4) arriving here would be answered,
                        // and that answer answered in turn.
                        if (udpPacketLocal.ReceivedBytes < 48 ||
                            (buffer[0] & 0x07) != 3)
                        {
                            System.Threading.Interlocked.Increment(ref ntpRequestsInvalid);
                            continue;
                        }

                        // RFC 8633 § 5.4, and deliberately the first thing done with an allowed
                        // datagram: the point of a rate limit is to not spend work on the traffic
                        // it refuses, and the expensive work here — unsealing a cookie, verifying
                        // an authenticator — is all downstream of the parse below.
                        if (RateLimiter is not null &&
                            udpPacketLocal.RemoteEndPoint is IPEndPoint limitedEndPoint)
                        {

                            var decision = RateLimiter.Check(limitedEndPoint.Address);

                            if (decision != RateLimitDecision.Answer)
                            {

                                System.Threading.Interlocked.Increment(ref ntpRequestsRateLimited);

                                if (decision == RateLimitDecision.KissOfDeath &&
                                    TryBuildRateKiss(buffer,
                                                     udpPacketLocal.ReceivedBytes,
                                                     out var kissOfDeath))
                                {

                                    try
                                    {

                                        await udpSocket.SendToAsync(
                                                  new ArraySegment<Byte>(kissOfDeath),
                                                  SocketFlags.None,
                                                  udpPacketLocal.RemoteEndPoint,
                                                  cts.Token
                                              );

                                        System.Threading.Interlocked.Increment(ref ntpKissesOfDeathSent);

                                    }
                                    catch (SocketException e) when (!cts.Token.IsCancellationRequested)
                                    {
                                        // An address that cannot be reached is that client's
                                        // problem, and must not end the receive loop.
                                        DebugX.Log($"Sending a kiss-o'-death to {udpPacketLocal.RemoteEndPoint} failed: {e.SocketErrorCode}");
                                    }

                                }

                                continue;

                            }

                        }


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

                                    // Only a request the authenticator covers may ask for a
                                    // second, signed datagram: honouring the extension outside
                                    // of it would let anyone double the traffic sent to an
                                    // address of their choosing.
                                    //
                                    // And only a server that has a key to sign with says yes.
                                    // The announcement goes into the first response; made
                                    // without a key, it had the client wait out its timeout
                                    // for a second response that was never sent.
                                    var signingKeyPair   = currentKeyPair;

                                    var toBeSigned       = signingKeyPair is not null &&
                                                           requestPacket.NTSRequestSignedResponse()?.Authenticated == true;

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
                                                                     TimeProvider,
                                                                     // TryParse yields the typed extension only for an
                                                                     // authenticator that verified; one that did not is
                                                                     // kept as an opaque field, and does not count.
                                                                     Authenticated: requestPacket.Extensions.Any(
                                                                                        extension => extension is AuthenticatorAndEncryptedExtension)
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

                                    if (toBeSigned && signingKeyPair is not null)
                                    {

                                        // The unsigned response is intentionally sent first so clients can
                                        // measure RTT with minimal signing latency. The signed response follows
                                        // as a scheduled security confirmation once the digital signature is ready.
                                        var responsePacket2 = SignResponse(responsePacket1, signingKeyPair);

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

                        Socket clientSocket;

                        try
                        {
                            clientSocket = await tcpSocket.AcceptAsync(cts.Token);
                        }
                        catch (SocketException e) when (!cts.Token.IsCancellationRequested)
                        {
                            // A connection that was reset while it waited in the backlog is
                            // reported here, and is no reason to stop accepting the next one.
                            DebugX.Log($"Accepting an NTS-KE connection failed: {e.SocketErrorCode}");
                            continue;
                        }

                        if (clientSocket == null)
                            continue;

                        System.Threading.Interlocked.Increment(ref ntskeConnectionsAccepted);

                        // RFC 8633 § 5.1, before the TLS handshake: an address that may not query
                        // this server is not shown its certificate either.
                        if (!AccessList.IsEveryone &&
                            !AccessList.Allows((clientSocket.RemoteEndPoint as IPEndPoint)?.Address))
                        {
                            System.Threading.Interlocked.Increment(ref ntskeConnectionsDenied);
                            clientSocket.Close();
                            continue;
                        }

                        // Before the shared limit, so that one client at its own limit
                        // does not take a slot from everybody else on top of it.
                        var ntskeClient = (clientSocket.RemoteEndPoint as IPEndPoint)?.Address is System.Net.IPAddress remoteAddress
                                              ? NTPRateLimiter.ClientOf(remoteAddress, NTPRateLimiter.DefaultIPv6PrefixLength)
                                              : null;

                        if (ntskeClient is not null &&
                            ntskeConnectionsPerClient.AddOrUpdate(ntskeClient, 1, (_, open) => open + 1) > MaxNTSKEConnectionsPerClient)
                        {
                            ReleaseNTSKEClient(ntskeClient);
                            System.Threading.Interlocked.Increment(ref ntskeConnectionsRejected);
                            DebugX.Log($"Closing NTS-KE connection from {clientSocket.RemoteEndPoint}: too many concurrent connections from this client.");
                            clientSocket.Close();
                            continue;
                        }

                        if (!await ntskeConnectionSemaphore.WaitAsync(0, cts.Token).ConfigureAwait(false))
                        {
                            ReleaseNTSKEClient(ntskeClient);
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

                                // The handshake of this TLS library blocks its thread until the
                                // client has said everything it has to say. On a thread of its
                                // own, then, and not on one borrowed from the pool: the pool is
                                // what answers NTP requests, and it grows by a thread or two a
                                // second, so a few dozen clients stalling here would otherwise
                                // delay every NTP answer, and with it the timestamps in them.
                                await Task.Factory.StartNew(
                                          () => tlsServerProtocol.Accept(tlsServer),
                                          requestCTS.Token,
                                          TaskCreationOptions.LongRunning,
                                          TaskScheduler.Default
                                      ).WaitAsync(NTSKEHandshakeTimeout, requestCTS.Token).
                                        ConfigureAwait(false);



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
                                                                        clientSocket,
                                                                        BlockingReadsOnOwnThread: true
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
                                    {

                                        // Derived here rather than at handshake time, because
                                        // RFC 8915 § 5.1 puts the negotiated algorithm into the
                                        // exporter context and its key length decides how much
                                        // to ask for — neither is known until the line above.
                                        var (c2sKey, s2cKey) = tlsServer.KeysFor(
                                                                   negotiation.AEADAlgorithm ?? NTSAEAD.Default,
                                                                   negotiation.CompliantAES128GCMSIVExporterContext
                                                               );

                                        ntsKERecords = BuildNTSKEResponseRecords(
                                                           negotiation,
                                                           ntsKERequest,
                                                           c2sKey,
                                                           s2cKey
                                                       );

                                    }

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
                                ReleaseNTSKEClient(ntskeClient);
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

            #region Start NTS-KE SSH server

            // A special-purpose SSH server, section 8.1 of the white paper: the NTS-KE subsystem
            // and nothing else. No shell, no exec, no SFTP and no forwarding are configured, and
            // Hermod's SSH server offers nothing it was not told to.
            if (SSHPort.HasValue)
            {

                sshServer = new SshServer(
                                new SshServerOptions {
                                    HostKeys             = SSHHostKeys,
                                    Authenticator        = sshAuthenticator!,

                                    // RFC 8633 § 5.1, as soon as the connection is accepted: a denied
                                    // address is closed before the version exchange, so it learns as
                                    // little of this server as it does over UDP and TLS - neither its
                                    // version nor its host key.
                                    AuthorizeConnection  = (peer, local) => {

                                                               if (AccessList.Allows(peer?.IPAddress.ToDotNet()))
                                                                   return null;

                                                               System.Threading.Interlocked.Increment(ref ntskeConnectionsDenied);

                                                               return $"{peer?.IPAddress.ToString() ?? "an unknown address"} is not on the access list";

                                                           },

                                    Subsystems           = (session, name, ct) => ValueTask.FromResult<SshSubsystemHandler?>(
                                                                                      name == NTSKE_SSH.SubsystemName
                                                                                          ? ServeSSHSubsystemAsync
                                                                                          : null
                                                                                  )
                                }
                            );

                await sshServer.StartAsync(
                          new IPSocket(
                              ListenIPAddress,
                              SSHPort.Value
                          ),
                          CancellationToken
                      ).ConfigureAwait(false);

                DebugX.Log($"NTS-KE over SSH started on port {SSHPort}/TCP");

            }

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

            if (sshServer is not null)
            {
                try { await sshServer.DisposeAsync().ConfigureAwait(false); } catch { }
                sshServer = null;
            }

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
                   // RFC 5905 § 9.2: the answer carries the version of the request, so an
                   // NTPv3 client is not handed a version it did not ask for.
                   VN:                   RequestPacket.VN is >= 1 and <= 4
                                             ? RequestPacket.VN
                                             : (Byte) 4,
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

        #region (private) TryBuildRateKiss(Datagram, Length, out Response)

        /// <summary>
        /// Build the "RATE" Kiss-o'-Death of RFC 5905 § 7.4 for a request the rate limiter
        /// refused, straight from the unparsed datagram.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Straight from the datagram because the parse is what the limiter is saving. Only four
        /// things are read out of it, and all four are needed for the kiss to be usable rather
        /// than merely well-formed.
        /// </para>
        /// <para>
        /// The origin timestamp is the load-bearing one. RFC 8633 § 5.4: "a client MUST only
        /// accept a KoD packet if it has a valid origin timestamp" — the same test that protects
        /// an ordinary response from being spoofed protects the client from a forged demand to
        /// back off, so a kiss that does not echo the request is a kiss a conformant client is
        /// right to ignore.
        /// </para>
        /// <para>
        /// The Unique Identifier is the same argument one layer up. An NTS client discards
        /// anything that does not echo its identifier, so without it the kiss reaches exactly the
        /// clients that authenticate nothing. Finding it costs a walk over the extension fields
        /// and no cryptography, and only happens on the rare packet that is actually answered
        /// with a kiss.
        /// </para>
        /// <para>
        /// What this cannot do is authenticate the kiss: the S2C key lives inside the cookie, and
        /// unsealing that is precisely the work being declined. So the kiss is unauthenticated,
        /// like RFC 8915 § 5.7's NTS NAK, and a client should treat it the way § 5.4 says to
        /// treat any KoD — as a hint to back off within limits it sets itself, never as an
        /// instruction it follows to the letter.
        /// </para>
        /// </remarks>
        private Boolean TryBuildRateKiss(Byte[]                          Datagram,
                                         Int32                           Length,
                                         [NotNullWhen(true)] out Byte[]? Response)
        {

            Response = null;

            if (RateLimiter is null || Length < 48)
                return false;

            var version  = (Byte) ((Datagram[0] >> 3) & 0x07);
            var mode     = (Byte)  (Datagram[0]       & 0x07);

            // Only a client request draws a kiss. Answering a mode this server does not serve —
            // or a broadcast — would be a packet sent for no reason at all.
            if (mode != 3 || version is < 1 or > 4)
                return false;

            var clientTransmit = 0UL;

            for (var i = 0; i < 8; i++)
                clientTransmit = (clientTransmit << 8) | Datagram[40 + i];

            var extensions = new List<NTPExtension>();
            var uniqueId   = FindUniqueIdentifier(Datagram, Length);

            if (uniqueId is not null)
                extensions.Add(new UniqueIdentifierExtension(uniqueId));

            var now = NTPPacket.GetCurrentNTPTimestamp(TimeProvider);

            Response = new NTPPacket(

                           LI:                   0,
                           VN:                   version,
                           Mode:                 4, // Server
                           Stratum:              0, // Kiss-o'-Death

                           // The rate this server is willing to serve, as the poll exponent a
                           // client should move to. § 7.4 leaves the value to the server and
                           // RFC 8633 § 5.4 leaves the response to the client; this is the
                           // honest number, which is the most either can ask for.
                           Poll:                 RateLimiter.KissPollExponent,

                           Precision:            ClockPrecisionExponent,
                           RootDelay:            0,
                           RootDispersion:       0,
                           ReferenceIdentifier:  NTP.ReferenceIdentifier.From("RATE"),
                           ReferenceTimestamp:   0,
                           OriginateTimestamp:   clientTransmit,
                           ReceiveTimestamp:     now,
                           TransmitTimestamp:    now,
                           Extensions:           extensions

                       ).ToByteArray();

            return true;

        }

        #endregion

        #region (private static) FindUniqueIdentifier(Datagram, Length)

        /// <summary>
        /// Find the RFC 8915 § 5.3 Unique Identifier in an unparsed datagram, or null if there
        /// is nothing there that convincingly is one.
        /// </summary>
        /// <remarks>
        /// A deliberately incurious walk over the RFC 7822 extension field chain. Anything that
        /// does not add up — a length that is not a positive multiple of four, a field running
        /// past the end of the datagram, an identifier shorter than the 32 octets § 5.3 requires
        /// — ends the walk rather than raising anything, because the caller has already decided
        /// this packet is not worth work and an absent identifier is a perfectly good answer.
        /// </remarks>
        private static Byte[]? FindUniqueIdentifier(Byte[]  Datagram,
                                                    Int32   Length)
        {

            var offset = 48;

            while (offset + 4 <= Length)
            {

                var type          = (UInt16) ((Datagram[offset]     << 8) | Datagram[offset + 1]);
                var fieldLength   = (UInt16) ((Datagram[offset + 2] << 8) | Datagram[offset + 3]);

                if (fieldLength < 4 ||
                    fieldLength % 4 != 0 ||
                    offset + fieldLength > Length)
                {
                    return null;
                }

                if (type == (UInt16) ExtensionTypes.UniqueIdentifier)
                {

                    var bodyLength = fieldLength - 4;

                    if (bodyLength < 32 || bodyLength > 64)
                        return null;

                    return Datagram[(offset + 4)..(offset + fieldLength)];

                }

                offset += fieldLength;

            }

            return null;

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
            // NTPRequest.TryParse has done that already, to find the key the authenticator
            // was made with, and left the result on the extension. Unsealing it a second
            // time was the most expensive thing done per request, done twice. Only a cookie
            // that did not unseal there is looked at again, for the reason to put in the log.
            var ntsCookie = n1.Cookie;

            if (ntsCookie is null &&
                !NTSCookie.TryParse(n1.Value, masterKeys, out ntsCookie, out var errorResponse))
            {
                return BuildNTSNAK(RequestPacket, Exchange, "Invalid NTS cookie: " + errorResponse);
            }

            // RFC 8915 §5.7: a request carries exactly one cookie in the clear. With two, the
            // one the authenticator was checked under and the one answered here could differ.
            if (RequestPacket.Extensions.Count(extension => extension.Type == ExtensionTypes.NTSCookie &&
                                                            !extension.Encrypted) != 1)
            {
                return BuildNTSNAK(RequestPacket, Exchange, "The request must carry exactly one NTS cookie!");
            }

            // RFC 8915 §5.7: the cookie alone proves nothing, as it crosses the network in the
            // clear and anyone who saw it can send it again. Only the authenticator shows that
            // the sender holds the C2S key. NTPRequest.TryParse yields the typed extension
            // only when it verified under this cookie's key; a missing one, or one that did
            // not verify, is answered with an NTS NAK and nothing else.
            if (!RequestPacket.Extensions.Any(extension => extension is AuthenticatorAndEncryptedExtension))
                return BuildNTSNAK(RequestPacket, Exchange, "The request is not authenticated!");


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
                                                           extension.Authenticated                               &&
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
                    Nonce:           null,
                    // The cookie says which algorithm this session agreed on, and it is the only
                    // thing that does: the key exchange that decided it may have been days ago
                    // and on another machine.
                    AEADAlgorithm:   ntsCookie.AEADAlgorithm
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
