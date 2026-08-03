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

using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;

using Org.BouncyCastle.Tls;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using org.GraphDefined.Vanaheimr.Norn.NTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// The Network Time Security (NTS) client.
    /// </summary>
    /// 
    public class NTSClient
    {

        #region Data

        public static readonly IPPort                   DefaultNTSKE_Port      = IPPort.          Parse      (4460);
        public static readonly IPPort                   DefaultNTP_Port        = IPPort.          Parse      ( 123);
        public        readonly TimeSpan                 DefaultTimeout         = TimeSpan.        FromSeconds(   3);
        public        readonly Int32                    MaxNTSKEResponseSize   = 64 * 1024;
        public        readonly Int32                    MaxRecentResponses     = 1024;

        public static readonly PercentageDouble         DefaultJitter          = PercentageDouble.Parse      (0.25);

        private       readonly Lock                     cookieLock             = new();
        private       readonly Queue<Byte[]>            cookieQueue            = new();
        private       readonly HashSet<String>          knownCookies           = [];
        private       readonly HashSet<NTSKE_Response>  seededNTSKEResponses   = [];
        private       readonly Lock                     responseHistoryLock    = new();
        private       readonly Queue<String>            recentResponseQueue    = new();
        private       readonly HashSet<String>          recentResponses        = [];
        private                Int64                    seededCookieCount      = 0;
        private                Int64                    cookiesReceived        = 0;
        private                Int64                    cookiesConsumed        = 0;
        private                Int64                    droppedCookieCount     = 0;

        #endregion

        #region Properties
        public UInt16                                                         Id                            { get; }
        public DomainName                                                     Hostname                      { get; }
        public IPPort                                                         NTSKE_Port                    { get; }
        public IPPort                                                         NTP_Port                      { get; }
        public RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient>?  RemoteCertificateValidator    { get; }
        public IPVersionPreference                                            IPVersionPreference           { get; }
        public TimeSpan?                                                      Timeout                       { get; set; }
        public Byte[]                                                         C2S_Key                       { get; set; } = [];
        public Byte[]                                                         S2C_Key                       { get; set; } = [];
        public DNSClient                                                      DNSClient                     { get; }
        public NTSCookiePoolPolicy                                            CookiePoolPolicy              { get; }

        /// <summary>
        /// The clock this client stamps its requests from and reads its own arrival times with —
        /// T1 and T4 of the RFC 5905 § 8 offset calculation.
        ///
        /// This is the wall clock only. The high-resolution timestamps captured around the UDP
        /// exchange stay on <see cref="System.Diagnostics.Stopwatch"/> deliberately: they measure
        /// how long the network took, which is a physical quantity, not a reading of the clock
        /// under correction. Substituting them would fabricate round-trip times rather than
        /// control the clock.
        /// </summary>
        public TimeProvider                                                   TimeProvider                  { get; }

        /// <summary>
        /// The number of currently queued NTS cookies available for future NTP/NTS requests.
        /// </summary>
        public Int32 AvailableCookieCount
        {
            get
            {
                lock (cookieLock)
                    return cookieQueue.Count;
            }
        }

        /// <summary>
        /// A snapshot of the current NTS cookie pool diagnostics.
        /// </summary>
        public NTSCookiePoolDiagnostics CookiePoolDiagnostics
        {
            get
            {
                lock (cookieLock)
                    return CreateCookiePoolDiagnosticsLocked();
            }
        }

        /// <summary>
        /// The RFC 9769 interleaved association, or null when the interleaved mode is off.
        /// </summary>
        /// <remarks>
        /// State that outlives a single query, which is what makes the mode possible at all: the
        /// server's accurate transmit timestamp arrives one exchange after the transmission it
        /// describes, so a client that forgets the previous exchange can never use it.
        ///
        /// It follows that the interleaved mode belongs to a client <em>instance</em>, and that
        /// a program creating a fresh client for every query gets nothing from switching it on.
        /// </remarks>
        public InterleavedAssociation? InterleavedAssociation { get; }

        /// <summary>
        /// The AEAD algorithms this client offers, in the order it prefers them.
        /// </summary>
        /// <remarks>
        /// Everything it can perform, unless an operator narrows it. RFC 8915 § 4.1.5 has the
        /// server choose from this list, so narrowing it is how a client pins an algorithm —
        /// worth having for a deployment with a policy about which primitives it will use, and
        /// the only way to exercise a given one against a server that prefers another.
        /// </remarks>
        public IReadOnlyList<AEADAlgorithms> OfferedAEADAlgorithms { get; }

        /// <summary>
        /// Whether this client claims RFC 8915 § 5.1's exporter context for AES-128-GCM-SIV, by
        /// sending IANA record type 1024 whenever it offers that algorithm.
        /// </summary>
        /// <remarks>
        /// <para>
        /// On by default, and there is no good reason to turn it off except to be an older
        /// client on purpose. chrony derives algorithm 30's keys with algorithm id 15 in the
        /// exporter context and has done since it shipped the algorithm; the record is how the
        /// two implementations agree to stop. Claiming it costs four octets and is ignored by a
        /// server that has never heard of it.
        /// </para>
        /// <para>
        /// Turning it off makes this client speak the older dialect outright, which is the only
        /// way to reach that code path deliberately — and it is a path that will be taken in the
        /// field for as long as there are servers that predate the record.
        /// </para>
        /// </remarks>
        public Boolean CompliantAES128GCMSIVExporterContext { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new NTS client.
        /// </summary>
        /// <param name="Hostname">The hostname or IP address of the NTS server.</param>
        /// <param name="NTSKE_Port">An optional NTS-KE port (default: 4460).</param>
        /// <param name="NTP_Port">An optional NTP port (default: 123).</param>
        /// <param name="Id">An optional unique identifier for the client.</param>
        /// <param name="RemoteCertificateValidator">An optional remote certificate validator.</param>
        /// <param name="IPVersionPreference">The IP version preference for NTS-KE and NTP/NTS network connections.</param>
        /// <param name="Timeout">An optional timeout for the NTS-KE/NTS requests.</param>
        /// <param name="DNSClient">An optional DNS client to use.</param>
        /// <param name="InterleavedMode">
        /// Whether to use the RFC 9769 interleaved client/server mode, which trades one exchange
        /// of latency for a server transmit timestamp taken after the packet was actually sent.
        /// Off by default and opt-in per association, as chrony's <c>xleave</c> is: it only pays
        /// for a client that queries the same server repeatedly, and a single query can never
        /// use it at all.
        /// </param>
        public NTSClient(DomainName                                                     Hostname,
                         IPPort?                                                        NTSKE_Port                   = null,
                         IPPort?                                                        NTP_Port                     = null,
                         UInt16?                                                        Id                           = null,
                         RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient>?  RemoteCertificateValidator   = null,
                         IPVersionPreference?                                           IPVersionPreference          = null,
                         TimeSpan?                                                      Timeout                      = null,
                         DNSClient?                                                     DNSClient                    = null,
                         NTSCookiePoolPolicy?                                           CookiePoolPolicy             = null,
                         Boolean                                                        InterleavedMode              = false,
                         IEnumerable<AEADAlgorithms>?                                   OfferedAEADAlgorithms        = null,
                         Boolean                                                        CompliantAES128GCMSIVExporterContext = true,
                         TimeProvider?                                                  TimeProvider                 = null)
        {

            this.Id                          = Id                  ?? RandomExtensions.RandomUInt16();
            this.Hostname                    = Hostname;
            this.NTSKE_Port                  = NTSKE_Port          ?? DefaultNTSKE_Port;
            this.NTP_Port                    = NTP_Port            ?? DefaultNTP_Port;
            this.RemoteCertificateValidator  = RemoteCertificateValidator;
            this.IPVersionPreference         = IPVersionPreference ?? Hermod.IPVersionPreference.PreferIPv6;
            this.Timeout                     = Timeout             ?? DefaultTimeout;
            this.DNSClient                   = DNSClient           ?? new DNSClient();
            this.CookiePoolPolicy            = (CookiePoolPolicy   ?? new NTSCookiePoolPolicy()).Normalize();
            this.TimeProvider                = TimeProvider        ?? System.TimeProvider.System;
            this.InterleavedAssociation      = InterleavedMode ? new InterleavedAssociation() : null;
            this.OfferedAEADAlgorithms       = (OfferedAEADAlgorithms ?? NTSAEAD.Supported).
                                                   Where(NTSAEAD.IsSupported).
                                                   ToArray();
            this.CompliantAES128GCMSIVExporterContext = CompliantAES128GCMSIVExporterContext;

            if (this.OfferedAEADAlgorithms.Count == 0)
                throw new ArgumentException("At least one of the offered AEAD algorithms has to be one this client can perform.",
                                            nameof(OfferedAEADAlgorithms));

        }

        #endregion


        #region (private) BuildNTSKERequest (RequestNTSPublicKeys = false)

        /// <summary>
        /// Create a new NTS-KE request.
        /// </summary>
        /// <param name="RequestNTSPublicKeys">Whether to request the public keys used for NTS response signing.</param>
        private Byte[] BuildNTSKERequest(Boolean RequestNTSPublicKeys = false)
        {

            var records = new List<NTSKE_Record>() {
                              NTSKE_Record.NTSNextProtocolNegotiation,
                              // Everything this client can perform, in preference order.
                              // RFC 8915 § 4.1.5 leaves the choice to the server but has it
                              // choose from this list, so offering only the mandatory algorithm
                              // — as this used to — silently declines every faster one a server
                              // has.
                              NTSKE_Record.AEADAlgorithmNegotiation(OfferedAEADAlgorithms)
                          };

            // Offering AES-128-GCM-SIV means saying which of the two key derivations in the wild
            // this client can do. Without this record chrony's server assumes the other one — and
            // so must this client, or the two agree on an algorithm and then never manage to
            // exchange a packet on it.
            if (CompliantAES128GCMSIVExporterContext &&
                OfferedAEADAlgorithms.Contains(AEADAlgorithms.AES_128_GCM_SIV))
            {
                records.Add(NTSKE_Record.CompliantAES128GCMSIVExporterContext());
            }

            if (RequestNTSPublicKeys)
                records.Add(NTSKE_Record.NTSRequestPublicKey());

            records.Add(NTSKE_Record.EndOfMessage);

            return records.ToByteArray();

        }

        #endregion

        #region (private) BuildNTSRequest   (NTSKEResponse = null, UniqueId = null)

        /// <summary>
        /// Builds an NTP mode=3 request with minimal NTS EFs:
        ///   1) Unique ID (0104)
        ///   2) NTS Cookie (0204)
        ///   3) NTS Auth & Encrypted (0404) - with placeholder AEAD data
        /// </summary>
        private static NTPRequest BuildNTSRequest(NTSKE_Response?     NTSKEResponse           = null,
                                                  Byte[]?             Cookie                  = null,
                                                  Byte[]?             UniqueId                = null,
                                                  Byte[]?             Plaintext               = null,
                                                  SignedResponseMode  RequestSignedResponse   = SignedResponseMode.None,
                                                  UInt16              SignedResponseKeyId     = 1,
                                                  UInt64?             TransmitTimestamp       = null,
                                                  UInt64?             OriginateTimestamp      = null,
                                                  UInt64?             ReceiveTimestamp        = null,
                                                  UInt16              CookiePlaceholderCount  = 0,
                                                  UInt16              CookiePlaceholderLength = 100,
                                                  TimeProvider?       TimeProvider            = null)
        {

            // The caller normally supplies the transmit timestamp, having read the clock right
            // before the send; the clock is only read here when it does not, and then from the
            // given clock rather than the ambient one.
            var ntpPacket1  = new NTPRequest(
                                  OriginateTimestamp: OriginateTimestamp,
                                  ReceiveTimestamp:   ReceiveTimestamp,
                                  TransmitTimestamp:  TransmitTimestamp
                                                          ?? NTPPacket.GetCurrentNTPTimestamp(TimeProvider ?? System.TimeProvider.System)
                              );

            var extensions  = new List<NTPExtension>();

            if (NTSKEResponse is not null &&
                Cookie        is not null &&
                NTSKEResponse.C2SKey.Length > 0)
            {

                var uniqueIdExtension  = NTPExtension.UniqueIdentifier(UniqueId);
                var cookieExtension    = NTPExtension.NTSCookie(Cookie);

                extensions.Add(
                    uniqueIdExtension
                );

                extensions.Add(
                    cookieExtension
                );

                var extensionBytes = new List<Byte[]>() {
                                         ntpPacket1.       ToByteArray(),
                                         uniqueIdExtension.ToByteArray(),
                                          cookieExtension.  ToByteArray()
                                      };

                for (var i = 0; i < CookiePlaceholderCount; i++)
                {

                    var cookiePlaceholderExtension = NTPExtension.NTSCookiePlaceholder(CookiePlaceholderLength);

                    extensions.    Add(cookiePlaceholderExtension);
                    extensionBytes.Add(cookiePlaceholderExtension.ToByteArray());

                }

                if (RequestSignedResponse != SignedResponseMode.None)
                {
                    var requestSignedResponseExtension = new NTSRequestSignedResponseExtension(SignedResponseKeyId);
                    extensions.    Add(requestSignedResponseExtension);
                    extensionBytes.Add(requestSignedResponseExtension.ToByteArray());
                }

                // Basically this extension validates all data (NTP header + extensions) which came before it!
                extensions.Add(
                    AuthenticatorAndEncryptedExtension.Create(
                        NTSKEResponse,
                        extensionBytes,
                        Plaintext
                    )
                );

            }

            var ntpPacket = new NTPRequest(
                                ntpPacket1,
                                Extensions: extensions
                            );

            return ntpPacket;

        }

        #endregion

        #region GetNTSKERecords (RequestNTSPublicKeys = false, Timeout = null, CancellationToken = default)

        /// <summary>
        /// Get NTS-KE records from the server and return a structured result.
        /// </summary>
        /// <param name="RequestNTSPublicKeys">Whether to request the public keys used for NTS response signing.</param>
        /// <param name="Timeout">An optional timeout.</param>
        /// <param name="CancellationToken">An optional cancellation token.</param>
        public async Task<NTSKEResult> GetNTSKERecords(Boolean            RequestNTSPublicKeys   = false,
                                                       TimeSpan?          Timeout                = null,
                                                       CancellationToken  CancellationToken      = default)
        {

            var timeout                  = Timeout ?? this.Timeout ?? DefaultTimeout;
            var totalStopwatch           = Stopwatch.StartNew();
            var resolvedIPAddresses      = Array.Empty<IIPAddress>();
            var connectedIPAddress       = default(IIPAddress);
            var dnsLookupDuration        = default(TimeSpan?);
            var tcpConnectDuration       = default(TimeSpan?);
            var tlsHandshakeDuration     = default(TimeSpan?);
            var ntsKEProtocolDuration    = default(TimeSpan?);

            NTSKE_TimingInfo TakeTimingInfoSnapshot()
                => new (
                       DNSLookupDuration:      dnsLookupDuration,
                       TCPConnectDuration:     tcpConnectDuration,
                       TLSHandshakeDuration:   tlsHandshakeDuration,
                       NTSKEProtocolDuration:  ntsKEProtocolDuration,
                       TotalDuration:          totalStopwatch.Elapsed,
                       ResolvedIPAddresses:    resolvedIPAddresses,
                       ConnectedIPAddress:     connectedIPAddress
                   );

            try
            {

                using var timeoutCTS = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
                timeoutCTS.CancelAfter(timeout);

                var dnsStopwatch     = Stopwatch.StartNew();

                // An NTS-KE host given as a bare IP address needs no lookup, and asking a
                // resolver for it would fail. NTPRemoteEndPointResolver already handles
                // literals for the UDP leg; this keeps the two legs consistent, so a server
                // can be addressed by IP throughout.
                IEnumerable<IIPAddress> ipAddresses;

                // DomainName renders as an FQDN, so the trailing root dot has to come off
                // before this can look like an address literal.
                var hostnameText = Hostname.ToString().TrimEnd('.').Trim('[', ']');

                if (System.Net.IPAddress.TryParse(hostnameText, out var literalIPAddress))
                    ipAddresses = [ literalIPAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                                        ? IPv6Address.Parse(literalIPAddress.ToString())
                                        : IPv4Address.Parse(literalIPAddress.ToString()) ];

                else
                    ipAddresses = await DNSClient.Query_IPAddresses(
                                            Hostname,
                                            Timeout:            timeout,
                                            CancellationToken:  timeoutCTS.Token
                                        ).ConfigureAwait(false);

                resolvedIPAddresses  = this.IPVersionPreference switch {
                                           IPVersionPreference.IPv6Only    => [.. ipAddresses.Where  (ipAddress => ipAddress is IPv6Address        )],
                                           IPVersionPreference.IPv4Only    => [.. ipAddresses.Where  (ipAddress => ipAddress is IPv4Address        )],
                                           IPVersionPreference.PreferIPv4  => [.. ipAddresses.OrderBy(ipAddress => ipAddress is IPv4Address ? 0 : 1)],
                                           _                               => [.. ipAddresses.OrderBy(ipAddress => ipAddress is IPv6Address ? 0 : 1)]
                                       };
                dnsLookupDuration    = dnsStopwatch.Elapsed;

                if (resolvedIPAddresses.Length == 0)
                    return NTSKEResult.Failed(
                               $"No IP address found for {Hostname}!",
                               NTSKEErrorCategory.DNS,
                               TakeTimingInfoSnapshot()
                           );

                var tcpStopwatch     = Stopwatch.StartNew();
                var lastException    = default(Exception);
                var tcpClient        = default(TcpClient);

                foreach (var ipAddress in resolvedIPAddresses)
                {

                    var candidate = new TcpClient() {
                                        ReceiveTimeout = (Int32) timeout.TotalMilliseconds,
                                        SendTimeout    = (Int32) timeout.TotalMilliseconds
                                    };

                    try
                    {

                        await candidate.ConnectAsync(
                                  ipAddress. ToDotNet(),
                                  NTSKE_Port.ToUInt16(),
                                  timeoutCTS.Token
                              ).ConfigureAwait(false);

                        tcpClient          = candidate;
                        connectedIPAddress = ipAddress;
                        break;

                    }
                    catch (Exception ex)
                    {
                        lastException = ex;
                        candidate.Dispose();
                    }

                }

                tcpConnectDuration = tcpStopwatch.Elapsed;

                if (tcpClient is null)
                    return NTSKEResult.Failed(
                               lastException?.Message ?? $"Could not connect to {Hostname}:{NTSKE_Port}!",
                               NTSKEErrorCategory.TCPConnect,
                               TakeTimingInfoSnapshot()
                           );

                using (tcpClient)
                using (var networkStream = tcpClient.GetStream())
                {

                    var tlsClientProtocol  = new TlsClientProtocol(networkStream);
                    var ntsTlsClient       = new NTSKE_TLSClient  (RemoteCertificateValidator,
                                                                   Hostname);

                    var tlsStopwatch       = Stopwatch.StartNew();
                    var tlsHandshakeTask   = Task.Run(
                                                 () => tlsClientProtocol.Connect(ntsTlsClient),
                                                 CancellationToken.None
                                             );

                    if (await Task.WhenAny(tlsHandshakeTask, Task.Delay(timeout, timeoutCTS.Token)).ConfigureAwait(false) != tlsHandshakeTask)
                        return NTSKEResult.Failed(
                                   "TLS handshake timed out.",
                                   NTSKEErrorCategory.TLSHandshake,
                                   TakeTimingInfoSnapshot(),
                                   ntsTlsClient.TLSInfo
                               );

                    await tlsHandshakeTask.ConfigureAwait(false);
                    tlsHandshakeDuration   = tlsStopwatch.Elapsed;

                    var ntsKEStopwatch     = Stopwatch.StartNew();
                    var ntsKERequest       = BuildNTSKERequest(RequestNTSPublicKeys);
                    await tlsClientProtocol.Stream.WriteAsync(ntsKERequest, timeoutCTS.Token).ConfigureAwait(false);
                    await tlsClientProtocol.Stream.FlushAsync(              timeoutCTS.Token).ConfigureAwait(false);

                    var readResult         = await NTSKEMessageReader.ReadAsync(
                                                       tlsClientProtocol.Stream,
                                                       timeout,
                                                       MaxNTSKEResponseSize,
                                                       timeoutCTS.Token
                                                   ).ConfigureAwait(false);

                    ntsKEProtocolDuration  = ntsKEStopwatch.Elapsed;

                    if (readResult.ErrorMessage is not null)
                        return NTSKEResult.Failed(
                                   readResult.ErrorMessage,
                                   TakeTimingInfoSnapshot(),
                                   ntsTlsClient.TLSInfo
                               );

                    if (readResult.ResponseBytes is not null &&
                        readResult.ResponseBytes.Length > 0)
                    {

                        if (NTSKE_Record.TryParse(readResult.ResponseBytes, out var records, out var errorResponse))
                        {

                            if (!NTSKERecordValidator.ValidateServerResponse(records, out var validationError, out var validationErrorCategory))
                                return NTSKEResult.Failed(
                                           validationError ?? "Invalid NTS-KE response!",
                                           validationErrorCategory,
                                           TakeTimingInfoSnapshot(),
                                           ntsTlsClient.TLSInfo
                                       );

                            // Only now, because RFC 8915 § 5.1 puts the negotiated algorithm
                            // into the exporter context and its key length decides how much to
                            // ask for. Deriving at handshake time — as this used to — means
                            // deciding the algorithm before the server has said which one, and
                            // works exactly as long as there is only one.
                            var negotiation = new NTSKE_Response(records, [], []);
                            var negotiated  = negotiation.AEADAlgorithm;

                            try
                            {
                                // And whether the server echoed record 1024, which for
                                // AES-128-GCM-SIV decides which of the two exporter contexts in
                                // the wild both sides are about to use.
                                (C2S_Key, S2C_Key) = ntsTlsClient.KeysFor(
                                                         negotiated,
                                                         CompliantAES128GCMSIVExporterContext &&
                                                             negotiation.CompliantAES128GCMSIVExporterContext
                                                     );
                            }
                            catch (Exception e)
                            {
                                return NTSKEResult.Failed(
                                           $"The server chose AEAD algorithm {negotiated.AsText()}, which this " +
                                           $"client cannot use: {e.Message}",
                                           NTSKEErrorCategory.Protocol,
                                           TakeTimingInfoSnapshot(),
                                           ntsTlsClient.TLSInfo
                                       );
                            }
                            finally
                            {
                                try
                                {
                                    tlsClientProtocol.Close();
                                }
                                catch
                                { }
                            }

                            return NTSKEResult.SuccessResult(
                                       new NTSKE_Response(
                                           records,
                                           C2S_Key,
                                           S2C_Key,
                                           TakeTimingInfoSnapshot(),
                                           ntsTlsClient.TLSInfo
                                       )
                                   );

                        }

                        return NTSKEResult.Failed(
                                   errorResponse ?? "Could not parse NTS-KE response!",
                                   NTSKEErrorCategory.Protocol,
                                   TakeTimingInfoSnapshot(),
                                   ntsTlsClient.TLSInfo
                               );

                    }

                    return NTSKEResult.Failed(
                               $"No response received from {Hostname}!",
                               NTSKEErrorCategory.Timeout,
                               TakeTimingInfoSnapshot(),
                               ntsTlsClient.TLSInfo
                           );

                }

            }
            catch (OperationCanceledException) when (!CancellationToken.IsCancellationRequested)
            {
                return NTSKEResult.Failed(
                           "NTS-KE operation timed out.",
                           NTSKEErrorCategory.Timeout,
                           TakeTimingInfoSnapshot()
                       );
            }
            catch (OperationCanceledException) when (CancellationToken.IsCancellationRequested)
            {
                return NTSKEResult.Failed(
                           "NTS-KE operation canceled.",
                           NTSKEErrorCategory.Canceled,
                           TakeTimingInfoSnapshot()
                       );
            }
            catch (Exception ex)
            {
                return NTSKEResult.Failed(
                           ex.Message,
                           TakeTimingInfoSnapshot()
                       );
            }

        }

        #endregion


        #region (private) CreateCookiePoolDiagnosticsLocked()

        private NTSCookiePoolDiagnostics CreateCookiePoolDiagnosticsLocked()

            => new (
                   cookieQueue.Count,
                   CookiePoolPolicy.MaxCookiePoolSize,
                   CookiePoolPolicy.LowWatermark,
                   seededCookieCount,
                   cookiesReceived,
                   cookiesConsumed,
                   droppedCookieCount
               );

        #endregion

        #region (private) AddReceivedCookies(Cookies)

        private void AddReceivedCookies(IEnumerable<Byte[]> Cookies)
        {

            lock (cookieLock)
                AddCookiesLocked(Cookies, IsSeeded: false);

        }

        #endregion

        #region (private) AddCookiesLocked(Cookies, IsSeeded)

        private void AddCookiesLocked(IEnumerable<Byte[]>  Cookies,
                                      Boolean              IsSeeded)
        {

            foreach (var cookie in Cookies)
            {

                var cookieId = Convert.ToBase64String(cookie);

                if (!IsSeeded)
                    cookiesReceived++;

                if (cookie.Length == 0 ||
                    cookieQueue.Count >= CookiePoolPolicy.MaxCookiePoolSize ||
                    !knownCookies.Add(cookieId))
                {
                    droppedCookieCount++;
                    continue;
                }

                cookieQueue.Enqueue(cookie);

                if (IsSeeded)
                    seededCookieCount++;

            }

        }

        #endregion

        #region (private) AddCookies(Cookies)

        private void AddCookies(IEnumerable<Byte[]> Cookies)
        {

            AddReceivedCookies(Cookies);

        }

        #endregion

        #region SeedCookies(NTSKEResponse)

        /// <summary>
        /// Seed the local cookie pool from an NTS-KE response.
        /// Already seeded responses are ignored.
        /// </summary>
        public void SeedCookies(NTSKE_Response NTSKEResponse)
        {

            lock (cookieLock)
            {

                if (seededNTSKEResponses.Add(NTSKEResponse))
                    AddCookiesLocked(NTSKEResponse.Cookies, IsSeeded: true);

            }

        }

        #endregion

        #region (private) TryTakeCookie(NTSKEResponse, out Cookie)

        private Boolean TryTakeCookie(NTSKE_Response? NTSKEResponse,
                                      out Byte[]?     Cookie)
        {

            lock (cookieLock)
            {

                if (NTSKEResponse is not null &&
                    seededNTSKEResponses.Add(NTSKEResponse))
                    AddCookiesLocked(NTSKEResponse.Cookies, IsSeeded: true);

                if (cookieQueue.TryDequeue(out Cookie))
                {
                    knownCookies.Remove(Convert.ToBase64String(Cookie));
                    cookiesConsumed++;
                    return true;
                }

            }

            Cookie = null;
            return false;

        }

        #endregion

        #region (private) CalculateCookiePlaceholderCount()

        private UInt16 CalculateCookiePlaceholderCount()
        {

            lock (cookieLock)
            {

                var missingCookies = CookiePoolPolicy.TargetCookieCount - cookieQueue.Count - 1;
                return (UInt16) Math.Clamp(
                                    missingCookies,
                                    0,
                                    CookiePoolPolicy.MaxPlaceholders
                                );

            }

        }

        #endregion

        #region (private) AddCookies(NTPResponse)

        private void AddCookies(NTPResponse NTPResponse)
        {

            AddCookies(
                NTPResponse.Extensions.
                    OfType<NTSCookieExtension>().
                    Where(cookieExtension => cookieExtension.Encrypted).
                    Select(cookieExtension => cookieExtension.Value)
            );

        }

        #endregion

        #region (private) TryRememberAcceptedResponse(Response, RemoteDescription)

        private Boolean TryRememberAcceptedResponse(NTPResponse Response,
                                                    String      RemoteDescription)
        {

            if (!Response.TransmitTimestamp.HasValue)
                return true;

            var fingerprint = $"{RemoteDescription}|{Response.TransmitTimestamp.Value:X16}";

            lock (responseHistoryLock)
            {

                if (!recentResponses.Add(fingerprint))
                    return false;

                recentResponseQueue.Enqueue(fingerprint);

                while (recentResponseQueue.Count > MaxRecentResponses &&
                       recentResponseQueue.TryDequeue(out var oldFingerprint))
                {
                    recentResponses.Remove(oldFingerprint);
                }

                return true;

            }

        }

        #endregion


        #region (private static) ReceiveUdpResponseAsync(UDPClient, Timeout, CancellationToken)

        private static async Task<(UdpReceiveResult? Result, Boolean TimedOut)>

            ReceiveUdpResponseAsync(UdpClient           UDPClient,
                                    TimeSpan            Timeout,
                                    CancellationToken   CancellationToken)

        {

            using var timeoutCTS = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
            timeoutCTS.CancelAfter(Timeout);

            try
            {
                return (
                    await UDPClient.ReceiveAsync(timeoutCTS.Token).AsTask().ConfigureAwait(false),
                    false
                );
            }
            catch (OperationCanceledException) when (!CancellationToken.IsCancellationRequested)
            {
                return (null, true);
            }

        }

        #endregion

        #region QueryTime (Timeout = null, NTSKEResponse = null, SignedResponseMode = None, SignedResponseKeyId = 1, ...)

        /// <summary>
        /// Sends a single NTS-authenticated NTP request and returns a structured result.
        /// </summary>
        public async Task<NTSQueryResult> QueryTime(TimeSpan?           Timeout               = null,
                                                    NTSKE_Response?     NTSKEResponse         = null,
                                                    SignedResponseMode  SignedResponseMode    = SignedResponseMode.None,
                                                    UInt16              SignedResponseKeyId   = 1,
                                                    CancellationToken   CancellationToken     = default)
        {

            if (NTSKEResponse?.ErrorMessage is not null)
                return NTSQueryResult.FailedWithPacket(
                           NTSKEResponse.ErrorMessage ?? "Unknown NTS-KE error!",
                           NTSQueryErrorCategory.NTSKE,
                           RemainingCookiesAfterQuery: AvailableCookieCount,
                           CookiePoolDiagnostics:      CookiePoolDiagnostics
                       );

            var timeout = Timeout ?? this.Timeout ?? DefaultTimeout;

            #region Documentation

            // NTP + UniqueId + NTS Cookie + NTS Auth request
            // 230008200000000000000000000000000000000000000000000000000000000000000000000000005001ac7cd6000835
            // 0104 0024 2027e75e68914d89bdd2461d6c18a87914ae432326ae452516f1af36876c37e2
            // 0204 0068 9dad3e6fcd545c8fc9a6eb945be9e2a600760641ea6e3d89c47fc692135e9ba4ca075866699e30a46b4b31f195f6d7cf8c72a4556189029c19d3c2eedda04969441c47a62004307a62c9b57cae3dc4a4af2be69757c30bd5c917e3e25564dfa3a3e283a0
            // 0404 0028 0010 0010 768f82009746999ea26472c70d9e4906 3b474cf41d387f62e78ae20224c53209

            // NTP + UniqueId + NTS Auth with Encrypted Data response
            // 240308e7000001a00000003974cb60e3eb51b89a96d03cb65001ac7cd6000835eb51b99eb19a6fd1eb51b99eb19e575e
            // 0104 0024 2027e75e68914d89bdd2461d6c18a87914ae432326ae452516f1af36876c37e2
            // 0404 0090 0010 0078 c562375b4cf5e6338cecf184f1c9b739ecc6daa3e27bbda9935a184f9089bc5ad6060a80afd71b5dcd421b332f4f26fdb53d9a1d092662595944696573fea2c1ae33761b04f5b399f504779bf4745caab96ac43c10595f0abe61aedbb6471b806e737cba62035e8bfd44279ed869996102168d9c68edf37cba02d3db49ca6aaf28923d67bb43e0ba

            #endregion

            var cookie = default(Byte[]?);
            var cookiePlaceholderCount = (UInt16) 0;

            if (NTSKEResponse is not null &&
                !TryTakeCookie(NTSKEResponse, out cookie))
            {

                return NTSQueryResult.FailedWithPacket(
                           "No NTS cookie available!",
                           NTSQueryErrorCategory.Cookie,
                           RemainingCookiesAfterQuery: AvailableCookieCount,
                           CookiePoolDiagnostics:      CookiePoolDiagnostics
                       );

            }

            if (NTSKEResponse is not null)
                cookiePlaceholderCount = CalculateCookiePlaceholderCount();

            var remoteEndPoint     = await NTPRemoteEndPointResolver.ResolveAsync(
                                               NTSKEResponse,
                                               Hostname,
                                               NTP_Port,
                                               DNSClient,
                                               IPVersionPreference,
                                               timeout,
                                               CancellationToken
                                           ).ConfigureAwait(false);

            var remoteDescription  = remoteEndPoint is not null
                                         ? remoteEndPoint.ToString()
                                         : NTPRemoteEndPointResolver.GetRemoteDescription(
                                               NTSKEResponse,
                                               Hostname,
                                               NTP_Port
                                           );

            // RFC 8915 § 4.1.7: the NTPv4 Server Negotiation record names the server "with
            // which the client should associate and that will accept the supplied cookies".
            // Nobody else was said to accept them.
            //
            // So when the key exchange directed this client elsewhere and that server cannot
            // be resolved, there is no measurement to be had. Sending the request to the
            // fallback host instead — the host the key exchange happened on — spends a cookie
            // on a server that in any real deployment holds different master keys, and turns
            // a plain misconfiguration into an authentication failure reported against the
            // wrong machine. On a single host serving both roles it would even appear to
            // work, which is worse: the redirect would be silently ineffective.
            //
            // The fallback below remains right for every other case, including a plain NTP
            // query with no key exchange behind it.
            if (remoteEndPoint is null &&
                NTSKEResponse?.NTPv4ServerNames.Any() == true)
            {

                return NTSQueryResult.FailedWithPacket(
                           $"The NTS-KE server directed this client to {remoteDescription}, which could not be resolved.",
                           NTSQueryErrorCategory.DNS,
                           RemainingCookiesAfterQuery: AvailableCookieCount,
                           CookiePoolDiagnostics:      CookiePoolDiagnostics
                       );

            }

            // RFC 9769 § 2. In the interleaved mode all three timestamp fields carry values
            // from the previous exchange rather than the clock as it reads now: the origin is
            // the server's receive timestamp, the receive field this client's arrival time for
            // that response, and the transmit field this client's accurate transmit timestamp
            // of the previous request. Figure 1 of § 2 shows the pattern.
            //
            // Which means the transmit field is a cookie for the server to echo, not a claim
            // about when this packet was sent. The value that matters for the measurement is
            // taken after the send, below.
            var interleaved        = InterleavedAssociation;
            var interleavedRequest = interleaved?.CanSendInterleaved == true;

            var (requestOrigin,
                 requestReceive,
                 requestTransmitField) = interleavedRequest
                                             ? interleaved!.NextRequestTimestamps()
                                             : (0UL, 0UL, 0UL);

            var transmitTimestamp  = interleavedRequest
                                         ? requestTransmitField
                                         : NTPPacket.GetCurrentNTPTimestamp(TimeProvider);

            var requestPacket      = BuildNTSRequest(
                                         NTSKEResponse,
                                         cookie,
                                         RandomNumberGenerator.GetBytes(32),
                                          Plaintext:              null,
                                          RequestSignedResponse:  SignedResponseMode,
                                          SignedResponseKeyId:    SignedResponseKeyId,
                                          TransmitTimestamp:      transmitTimestamp,
                                          OriginateTimestamp:     requestOrigin,
                                          ReceiveTimestamp:       requestReceive,
                                          CookiePlaceholderCount: cookiePlaceholderCount,
                                          CookiePlaceholderLength: (UInt16) Math.Min(UInt16.MaxValue, Math.Max(0, cookie?.Length ?? 100)),
                                          TimeProvider:           TimeProvider
                                      );

            var requestData        = requestPacket.ToByteArray();

            using (var udpClient = remoteEndPoint is not null
                                       ? new UdpClient(remoteEndPoint.AddressFamily)
                                       : new UdpClient())
            {

                try
                {

                    var sendStopwatchTimestamp = Stopwatch.GetTimestamp();

                    if (remoteEndPoint is not null)
                    {

                        await udpClient.SendAsync(
                                  requestData,
                                  remoteEndPoint,
                                  CancellationToken
                              );

                    }
                    else
                    {

                        await udpClient.SendAsync(
                                  requestData,
                                  Hostname.ToString(),
                                  NTP_Port.ToUInt16(),
                                  CancellationToken
                              );

                    }

                    // T1, and the client's half of what RFC 9769 is for: read after the send
                    // rather than before, so the cost of building, sealing and writing the
                    // packet is not charged to the network. In the interleaved mode this is
                    // the value the *next* request will carry in its transmit field, and the
                    // one the measurement completed by the next response will use.
                    var actualRequestTransmit       = NTPPacket.GetCurrentNTPTimestamp(TimeProvider);

                    var receiveResult1WithTimeout   = await ReceiveUdpResponseAsync(
                                                                udpClient,
                                                                timeout,
                                                                CancellationToken
                                                            ).ConfigureAwait(false);

                    if (interleaved is not null &&
                        (receiveResult1WithTimeout.TimedOut || receiveResult1WithTimeout.Result is null))
                    {
                        // § 2: "The protocol recovers from packet loss. When a client request or
                        // server response is lost, the client will use the same origin timestamp
                        // in the next request." So the association is kept — but not forever;
                        // past the limit the held timestamps are too old for the server to still
                        // have the matching pair, and the next request starts over.
                        interleaved.RecordUnansweredRequest();
                    }

                    if (receiveResult1WithTimeout.TimedOut ||
                        receiveResult1WithTimeout.Result is null)
                    {

                        return NTSQueryResult.FailedWithPacket(
                                   $"No 1st NTP response from {remoteDescription} within {Math.Round(timeout.TotalSeconds, 2)} seconds timeout!",
                                   NTSQueryErrorCategory.NTPTimeout,
                                   remoteEndPoint,
                                   remoteDescription,
                                   cookie,
                                   AvailableCookieCount,
                                   SendStopwatchTimestamp: sendStopwatchTimestamp,
                                   CookiePoolDiagnostics:  CookiePoolDiagnostics
                               );

                    }

                    var receiveResult1              = receiveResult1WithTimeout.Result.Value;
                    // T4: this client's clock, the same one T1 came from — an offset computed
                    // from two different clocks would be meaningless. The Stopwatch reading
                    // beside it measures the network, not the clock; see the TimeProvider
                    // property for why that one stays where it is.
                    var destinationTimestamp1       = NTPPacket.GetCurrentNTPTimestamp(TimeProvider);
                    var receiveStopwatchTimestamp1  = Stopwatch.GetTimestamp();

                    if (NTPResponse.TryParse(receiveResult1.Buffer,
                                             out var ntpResponse1,
                                             out var errorResponse1,
                                             Request:                    requestPacket,
                                             NTSKey:                     NTSKEResponse?.S2CKey,
                                             ExpectedUniqueId:           requestPacket.UniqueIdentifier(),
                                             DestinationTimestamp:       destinationTimestamp1,
                                             SendStopwatchTimestamp:     sendStopwatchTimestamp,
                                             ReceiveStopwatchTimestamp:  receiveStopwatchTimestamp1,
                                             // Sealed under whatever the key exchange agreed on,
                                             // so it can only be opened under the same.
                                             AEADAlgorithm:              NTSKEResponse?.AEADAlgorithm ?? NTSAEAD.Default))
                    {

                        // RFC 9769 § 2: which of the request's two timestamps came back as the
                        // origin says which mode the response is in, and that decides how the
                        // rest of it must be read. Decided before validation, because two of
                        // the validator's checks depend on the answer.
                        var responseMode = interleaved is null
                                               ? InterleavedResponseMode.Basic
                                               : InterleavedAssociation.Classify(
                                                     ntpResponse1,
                                                     requestPacket.ReceiveTimestamp,
                                                     requestPacket.TransmitTimestamp ?? 0
                                                 );

                        var validation1 = NTSResponseValidator.Validate(
                                              ntpResponse1,
                                              requestPacket,
                                              requestPacket.UniqueIdentifier(),
                                              NTSKEResponse?.S2CKey,
                                              RequireNTS:   NTSKEResponse is not null,
                                              Interleaved:  responseMode == InterleavedResponseMode.Interleaved
                                          );

                        if (!validation1.IsValid)
                            return NTSQueryResult.Failed(
                                       validation1.ErrorMessage ?? "NTP/NTS response validation failed.",
                                       validation1.ErrorCategory,
                                       remoteEndPoint,
                                       remoteDescription,
                                       cookie,
                                       AvailableCookieCount,
                                       SendStopwatchTimestamp:     sendStopwatchTimestamp,
                                       ReceiveStopwatchTimestamp:  receiveStopwatchTimestamp1,
                                       DestinationTimestamp:       destinationTimestamp1,
                                       Response:                   ntpResponse1,
                                       CookiePoolDiagnostics:      CookiePoolDiagnostics,
                                       ResponseValidation:         validation1
                                   );

                        NTSResponseValidationResult? replayValidation1 = null;

                        #region A 2nd signed response was announced

                        if (ntpResponse1.NTSSignedResponseAnnouncement()?.IsScheduled == true)
                        {

                            var receiveResult2WithTimeout = await ReceiveUdpResponseAsync(
                                                                      udpClient,
                                                                      timeout,
                                                                      CancellationToken
                                                                  ).ConfigureAwait(false);

                            if (receiveResult2WithTimeout.TimedOut ||
                                receiveResult2WithTimeout.Result is null)
                            {

                                return NTSQueryResult.FailedWithPacket(
                                           $"No 2nd NTP response from {remoteDescription} within {Math.Round(timeout.TotalSeconds, 2)} seconds timeout!",
                                           NTSQueryErrorCategory.NTPTimeout,
                                           remoteEndPoint,
                                           remoteDescription,
                                           cookie,
                                           AvailableCookieCount,
                                           SendStopwatchTimestamp:     sendStopwatchTimestamp,
                                           ReceiveStopwatchTimestamp:  receiveStopwatchTimestamp1,
                                           DestinationTimestamp:       destinationTimestamp1,
                                           CookiePoolDiagnostics:      CookiePoolDiagnostics
                                       );

                            }

                            var receiveResult2              = receiveResult2WithTimeout.Result.Value;
                            var destinationTimestamp2       = NTPPacket.GetCurrentNTPTimestamp(TimeProvider);
                            var receiveStopwatchTimestamp2  = Stopwatch.GetTimestamp();

                            if (!receiveResult1.Buffer.IsPrefixOf(receiveResult2.Buffer))
                            {

                                return NTSQueryResult.FailedWithPacket(
                                           "1st NTP response is not a prefix of the 2nd NTP response!",
                                           NTSQueryErrorCategory.Protocol,
                                           remoteEndPoint,
                                           remoteDescription,
                                           cookie,
                                           AvailableCookieCount,
                                           SendStopwatchTimestamp:     sendStopwatchTimestamp,
                                           ReceiveStopwatchTimestamp:  receiveStopwatchTimestamp2,
                                           DestinationTimestamp:       destinationTimestamp2,
                                           CookiePoolDiagnostics:      CookiePoolDiagnostics
                                       );
                            }

                            if (NTPResponse.TryParse(receiveResult2.Buffer,
                                                     out var ntpResponse2,
                                                     out var errorResponse2,
                                                     Request:                    requestPacket,
                                                     NTSKey:                     NTSKEResponse?.S2CKey,
                                                     ExpectedUniqueId:           requestPacket.UniqueIdentifier(),
                                                     DestinationTimestamp:       destinationTimestamp2,
                                                     SendStopwatchTimestamp:     sendStopwatchTimestamp,
                                                     ReceiveStopwatchTimestamp:  receiveStopwatchTimestamp2,
                                                     AEADAlgorithm:              NTSKEResponse?.AEADAlgorithm ?? NTSAEAD.Default))
                            {

                                var validation2 = NTSResponseValidator.Validate(
                                                      ntpResponse2,
                                                      requestPacket,
                                                      requestPacket.UniqueIdentifier(),
                                                      NTSKEResponse?.S2CKey,
                                                      RequireNTS: NTSKEResponse is not null
                                                  );

                                if (!validation2.IsValid)
                                    return NTSQueryResult.Failed(
                                               validation2.ErrorMessage ?? "NTP/NTS 2nd response validation failed.",
                                               validation2.ErrorCategory,
                                               remoteEndPoint,
                                               remoteDescription,
                                               cookie,
                                               AvailableCookieCount,
                                               SendStopwatchTimestamp:     sendStopwatchTimestamp,
                                               ReceiveStopwatchTimestamp:  receiveStopwatchTimestamp2,
                                               DestinationTimestamp:       destinationTimestamp2,
                                               Response:                   ntpResponse2,
                                               CookiePoolDiagnostics:      CookiePoolDiagnostics,
                                               ResponseValidation:         validation2
                                           );

                                if (!TryRememberAcceptedResponse(ntpResponse2, remoteDescription))
                                {

                                    var replayValidation2 = NTSResponseValidator.Validate(
                                                                ntpResponse2,
                                                                requestPacket,
                                                                requestPacket.UniqueIdentifier(),
                                                                NTSKEResponse?.S2CKey,
                                                                RequireNTS:  NTSKEResponse is not null,
                                                                IsReplay:    true
                                                            );

                                    return NTSQueryResult.Failed(
                                               replayValidation2.ErrorMessage ?? "NTP/NTS 2nd response duplicate/replay detected.",
                                               replayValidation2.ErrorCategory,
                                               remoteEndPoint,
                                               remoteDescription,
                                               cookie,
                                               AvailableCookieCount,
                                               SendStopwatchTimestamp:     sendStopwatchTimestamp,
                                               ReceiveStopwatchTimestamp:  receiveStopwatchTimestamp2,
                                               DestinationTimestamp:       destinationTimestamp2,
                                               Response:                   ntpResponse2,
                                               CookiePoolDiagnostics:      CookiePoolDiagnostics,
                                               ResponseValidation:         replayValidation2
                                           );

                                }

                                AddCookies(ntpResponse2);

                                return NTSQueryResult.SuccessResult(
                                           ntpResponse2,
                                           remoteEndPoint,
                                           remoteDescription,
                                           cookie,
                                           AvailableCookieCount,
                                           1,
                                           ntpResponse2.Extensions.Any(extension => extension is NTSCookieExtension { Encrypted: true }),
                                           CookiePoolDiagnostics,
                                           validation2
                                       );
                            }

                            return NTSQueryResult.FailedWithClassifiedPacket(
                                       "NTP 2nd response error: " + errorResponse2,
                                       remoteEndPoint,
                                       remoteDescription,
                                       cookie,
                                       AvailableCookieCount,
                                       SendStopwatchTimestamp:     sendStopwatchTimestamp,
                                       ReceiveStopwatchTimestamp:  receiveStopwatchTimestamp2,
                                       DestinationTimestamp:       destinationTimestamp2,
                                       CookiePoolDiagnostics:      CookiePoolDiagnostics
                                   );

                        }

                        #endregion

                        if (!TryRememberAcceptedResponse(ntpResponse1, remoteDescription))
                        {

                            replayValidation1 = NTSResponseValidator.Validate(
                                                    ntpResponse1,
                                                    requestPacket,
                                                    requestPacket.UniqueIdentifier(),
                                                    NTSKEResponse?.S2CKey,
                                                    RequireNTS:  NTSKEResponse is not null,
                                                    IsReplay:    true
                                                );

                            return NTSQueryResult.Failed(
                                       replayValidation1.ErrorMessage ?? "NTP/NTS response duplicate/replay detected.",
                                       replayValidation1.ErrorCategory,
                                       remoteEndPoint,
                                       remoteDescription,
                                       cookie,
                                       AvailableCookieCount,
                                       SendStopwatchTimestamp:     sendStopwatchTimestamp,
                                       ReceiveStopwatchTimestamp:  receiveStopwatchTimestamp1,
                                       DestinationTimestamp:       destinationTimestamp1,
                                       Response:                   ntpResponse1,
                                       CookiePoolDiagnostics:      CookiePoolDiagnostics,
                                       ResponseValidation:         replayValidation1
                                   );

                        }

                        AddCookies(ntpResponse1);

                        // RFC 9769 § 2. The measurement has to be taken before the association
                        // is advanced, because it is made from the timestamps the previous
                        // exchange left behind and this response's transmit timestamp — and
                        // recording this response overwrites exactly those.
                        var measurement = responseMode == InterleavedResponseMode.Interleaved
                                              ? interleaved?.MeasurementFor(ntpResponse1)
                                              : null;

                        interleaved?.RecordValidResponse(
                            ntpResponse1,
                            actualRequestTransmit,
                            destinationTimestamp1
                        );

                        return NTSQueryResult.SuccessResult(
                                   ntpResponse1,
                                   remoteEndPoint,
                                   remoteDescription,
                                   cookie,
                                   AvailableCookieCount,
                                   1,
                                   ntpResponse1.Extensions.Any(extension => extension is NTSCookieExtension { Encrypted: true }),
                                   CookiePoolDiagnostics,
                                   validation1,
                                   measurement
                               );

                    }
                    else
                    {

                        return NTSQueryResult.FailedWithClassifiedPacket(
                                   "NTP 1st response error: " + errorResponse1,
                                   remoteEndPoint,
                                   remoteDescription,
                                   cookie,
                                   AvailableCookieCount,
                                   SendStopwatchTimestamp:     sendStopwatchTimestamp,
                                   ReceiveStopwatchTimestamp:  receiveStopwatchTimestamp1,
                                   DestinationTimestamp:       destinationTimestamp1,
                                   CookiePoolDiagnostics:      CookiePoolDiagnostics,
                                   Response:                   ntpResponse1
                                );
                    }

                }
                catch (OperationCanceledException)
                {
                    return NTSQueryResult.FailedWithPacket(
                               "NTP query operation canceled.",
                               NTSQueryErrorCategory.Canceled,
                               remoteEndPoint,
                               remoteDescription,
                               cookie,
                               AvailableCookieCount,
                               CookiePoolDiagnostics: CookiePoolDiagnostics
                           );
                }
                catch (Exception e)
                {
                    return NTSQueryResult.FailedWithPacket(
                               $"NTP receive exception from {remoteDescription}: {e.Message}",
                               NTSQueryErrorCategory.Exception,
                               remoteEndPoint,
                               remoteDescription,
                               cookie,
                               AvailableCookieCount,
                               CookiePoolDiagnostics: CookiePoolDiagnostics
                           );
                }

            }

        }

        #endregion


        


        #region TryValidateNTSAuthenticatorExtension(ReceivedValue, AssociatedData, C2SKey, ExpectedPlaintext, out ErrorResponse)

        /// <summary>
        /// Validates the NTS Authenticator and Encrypted Extension Field received from an NTS request.
        /// The extension value should have the format:
        /// [NonceLength (2 bytes) || CiphertextLength (2 bytes) || padded(Nonce) || padded(Ciphertext)]
        /// where each of nonce and ciphertext is padded to a 4-byte boundary.
        /// The validation is performed by re-computing the AEAD encryption using the provided C2S key,
        /// the expected associated data (e.g. NTP header || UniqueId EF || Cookie EF)
        /// and the expected plaintext.
        /// </summary>
        /// <param name="ReceivedValue">
        /// The raw value bytes of the authenticator extension (excluding the 4-byte NTPExtension header).
        /// </param>
        /// <param name="AssociatedData">
        /// The associated data as a list of byte arrays (for example: [NTP header, UniqueId extension, Cookie extension]).
        /// </param>
        /// <param name="S2CKey">The server-to-client key derived from the TLS session (e.g. 32 bytes for AES-SIV).</param>
        /// <param name="ExpectedPlaintext">
        /// The plaintext that was encrypted (for example, in testing it might be "Hello world!" as UTF8 bytes).
        /// In a real implementation, this would be the concatenation of confidential internal extension fields.
        /// </param>
        internal static Boolean TryValidateNTSAuthenticatorExtension(Byte[]         ReceivedValue,
                                                                   IList<Byte[]>  AssociatedData,
                                                                   Byte[]         S2CKey,
                                                                   Byte[]         ExpectedPlaintext,
                                                                   out String?    ErrorResponse)
        {

            ErrorResponse = null;

            if (ReceivedValue is null || ReceivedValue.Length < 4)
            {
                ErrorResponse = "NTS Authenticator and Encrypted extension value is null or too short!";
                return false;
            }

            var nonceLen                  = (UInt16) ((ReceivedValue[0] << 8) | ReceivedValue[1]);
            var ciphertextLen             = (UInt16) ((ReceivedValue[2] << 8) | ReceivedValue[3]);

            var paddedNonceLen            = (nonceLen      + 3) & ~3;
            var paddedCiphertextLen       = (ciphertextLen + 3) & ~3;

            // Verify that the total length of the received value matches expectations:
            var expectedTotalValueLength  = 4 + paddedNonceLen + paddedCiphertextLen;
            if (ReceivedValue.Length != expectedTotalValueLength)
            {
                ErrorResponse = "NTS Authenticator and Encrypted extension value has unexpected length!";
                return false;
            }

            var receivedNonce             = new Byte[nonceLen];
            Buffer.BlockCopy(ReceivedValue, 4, receivedNonce, 0, nonceLen);

            var receivedCiphertext        = new Byte[ciphertextLen];
            if (ciphertextLen > 0)
                Buffer.BlockCopy(ReceivedValue, 4 + paddedNonceLen, receivedCiphertext, 0, ciphertextLen);

            // Recompute the AEAD output using AES-SIV.
            // Our AesSiv class expects an IList<byte[]> as associated data.
            var aesSiv                    = new AES_SIV(S2CKey);
            var computedOutput            = aesSiv.Encrypt(AssociatedData, receivedNonce, ExpectedPlaintext);

            // computedOutput should be SIV || Ciphertext.
            // Let’s assume that our implementation produces a computedOutput of length = (nonceLen + ciphertextLen)
            // (e.g. if plaintext is non-empty, computedOutput includes both parts).
            if (computedOutput.Length < nonceLen)
            {
                ErrorResponse = "Computed AEAD output is too short!";
                return false;
            }

            var computedNonce             = new Byte[nonceLen];
            Buffer.BlockCopy(computedOutput, 0, computedNonce, 0, nonceLen);

            var computedCiphertextLen     = Math.Max(computedOutput.Length - nonceLen, 16);
            var computedCiphertext        = new Byte[computedCiphertextLen];
            if (computedOutput.Length > nonceLen)
                Buffer.BlockCopy(computedOutput, nonceLen, computedCiphertext, 0, computedCiphertextLen);

            var nonceMatch                = receivedNonce.     IsEqualTo(computedNonce);
            var ciphertextMatch           = receivedCiphertext.IsEqualTo(computedCiphertext);

            return nonceMatch && ciphertextMatch;

        }

        #endregion


        #region GetNextPollInterval(MinPollInterval, MaxPollInterval, RandomizationMode, JitterFactor)

        /// <summary>
        /// Gets the next poll interval for NTP requests.
        /// </summary>
        /// <param name="MinPollInterval">The minimum poll interval (e.g. 64 seconds).</param>
        /// <param name="MaxPollInterval">The maximum poll interval (e.g. 1024 seconds).</param>
        /// <param name="RandomizationMode">The randomization mode to apply to the poll interval (e.g. None, Uniform, Jitter, Poisson).</param>
        /// <param name="JitterFactor">The jitter factor to apply when using Jitter randomization mode (e.g. 0.25 for ±25% jitter).</param>
        public static TimeSpan GetNextPollInterval(TimeSpan?             MinPollInterval,
                                                   TimeSpan?             MaxPollInterval,
                                                   NTPRandomizationMode  RandomizationMode,
                                                   PercentageDouble?     JitterFactor)
        {

            if (!MinPollInterval.HasValue || !MaxPollInterval.HasValue)
                return TimeSpan.FromSeconds(128);

            var minSec         = MinPollInterval.Value.TotalSeconds;
            var maxSec         = MaxPollInterval.Value.TotalSeconds;

            if (minSec > maxSec)
                throw new ArgumentException("The minimum poll interval cannot be greater than the maximum poll interval!", nameof(MinPollInterval));

            // BaseIntervall: geometrical mean (works well for powers of 2)
            var baseSec        = Math.Sqrt(minSec * maxSec);
            var randomizedSec  = baseSec;

            switch (RandomizationMode)
            {

                // just the base interval!
                case NTPRandomizationMode.None:
                    break;

                case NTPRandomizationMode.Uniform:
                    randomizedSec  = Random.Shared.NextDouble()
                                        * (maxSec - minSec) + minSec;
                    break;

                case NTPRandomizationMode.Jitter:
                    randomizedSec  = baseSec
                                        * (1.0 + (Random.Shared.NextDouble() * 2.0 - 1.0)
                                        * (JitterFactor?.Value ?? DefaultJitter.Value));
                    break;

                case NTPRandomizationMode.Poisson:
                    randomizedSec  = - Math.Log(1.0 - Random.Shared.NextDouble())
                                        / (1.0 / baseSec);
                    break;

            }

            return TimeSpan.FromSeconds(
                       Math.Clamp(
                           randomizedSec,
                           minSec,
                           maxSec
                       )
                   );

        }

        #endregion


    }

}
