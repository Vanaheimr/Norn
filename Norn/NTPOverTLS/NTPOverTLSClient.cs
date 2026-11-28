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

using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;

using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Crypto;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

using BCX509Certificate = Org.BouncyCastle.X509.X509Certificate;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTPOverTLS
{

    /// <summary>
    /// A client of NTP over TLS after chapter 7 of BSI TR-03109-5: one 48-octet NTPv4 request in a
    /// TLS connection of its own, one response, and the checks of TA.NTP.ProcessResponse before
    /// the response is believed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The request (TA.NTP.BuildRequest) is an NTPv4 client request (.10) of 48 octets (.30),
    /// without a UDP header (.20). With <see cref="DataMinimization"/>, as .40 recommends, it says
    /// no more about this client than Table 7.1's column "Datenminimierung": every field zero
    /// but the version, the mode, a precision of 32 and a transmit timestamp of random bits,
    /// which the server echoes and this client alone can tell from a timestamp.
    /// </para>
    /// <para>
    /// A response is ignored (TA.NTP.ProcessResponse) when it was delayed more than 9 seconds on
    /// the way (.10), does not echo the transmit timestamp of the request (.30), has a transmit
    /// timestamp this client cannot convert to UTC (.40), comes from a server that is not
    /// synchronized (.50), is not of version 4 (.51), or is not a server's (.52); and, where the
    /// caller says its clock is synchronized, when it is more than 1000 seconds off that clock
    /// (.110, a SHOULD). Further, after RFC 5905 Appendix A.5.1.1, when its stratum is 0 - a kiss,
    /// which § 7.1.1 does not oblige a client to process - or above 15, or when the server
    /// claims to have answered before it received.
    /// </para>
    /// <para>
    /// NTPv5 is section 6.1 of the white paper "Secure Time Synchronization", not the guideline's:
    /// <see cref="QueryNTPv5"/> sends an NTPv5 request of draft-ietf-ntp-ntpv5 behind its length
    /// and holds the response to the same rules in the terms of NTPv5, and to § 9.4 and § 9.5 of
    /// the draft. <see cref="QueryNegotiated"/> asks in whichever version the negotiation of
    /// § 12 has come to: NTPv4 offering NTPv5, NTPv5 once the server echoed the offer, and NTPv4
    /// alone for a while after NTPv5 failed. The offer travels inside TLS, so nobody on the way
    /// can remove it.
    /// </para>
    /// </remarks>
    public class NTPOverTLSClient
    {

        #region Data

        /// <summary>
        /// The longest a response may take, by REQ.TA.NTP.ProcessResponse.10.
        /// </summary>
        public static readonly TimeSpan MaxTransportDelay        = TimeSpan.FromSeconds(9);

        /// <summary>
        /// The most a response may differ from a synchronized clock, by REQ.TA.NTP.ProcessResponse.110.
        /// </summary>
        public static readonly TimeSpan MaxDeviationWhenSynchronized = TimeSpan.FromSeconds(1000);

        /// <summary>
        /// The precision a minimized request claims, after Table 7.1 - the value chrony sends.
        /// </summary>
        public const SByte MinimizedPrecision = 32;

        #endregion

        #region Properties

        /// <summary>
        /// The server, by name or by literal address.
        /// </summary>
        public String                Host                        { get; }

        /// <summary>
        /// Its NTP-over-TLS port.
        /// </summary>
        public IPPort                Port                        { get; }

        /// <summary>
        /// How long the whole exchange may take: connecting, the handshake and the response.
        /// </summary>
        public TimeSpan              Timeout                     { get; }

        /// <summary>
        /// The clock T1 and T4 are read from.
        /// </summary>
        public TimeProvider          TimeProvider                { get; }

        /// <summary>
        /// Whether the request says no more than Table 7.1's column "Datenminimierung"
        /// (REQ.TA.NTP.BuildRequest.40, a SHOULD), which is the default.
        /// </summary>
        /// <remarks>
        /// ICS.TA.NTP.BuildRequest.10 has a manufacturer declare whether this is done.
        /// </remarks>
        public Boolean               DataMinimization            { get; }

        /// <summary>
        /// The certificate shown where the server asks for one.
        /// </summary>
        public BCX509Certificate?    ClientCertificate           { get; }

        private readonly AsymmetricKeyParameter?                                              clientPrivateKey;
        private readonly IReadOnlyList<BCX509Certificate>                                     clientCertificateChain;
        private readonly RemoteTLSServerCertificateValidationHandler<NTPOverTLS_TLSClient>?   remoteCertificateValidator;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// A client of one NTP-over-TLS server.
        /// </summary>
        /// <param name="Host">The server, by name or by literal address.</param>
        /// <param name="Port">Its port (default: <see cref="NTPOverTLSProtocol.DefaultPort"/>).</param>
        /// <param name="RemoteCertificateValidator">Judges the server's certificate; by default the platform's chain and the name or address connected to.</param>
        /// <param name="ClientCertificate">A certificate to show where the server asks for one.</param>
        /// <param name="ClientPrivateKey">Its private key.</param>
        /// <param name="ClientCertificateChain">Intermediates to show after it.</param>
        /// <param name="Timeout">How long the whole exchange may take (default: 5 seconds).</param>
        /// <param name="TimeProvider">The clock T1 and T4 are read from (default: the system's).</param>
        /// <param name="DataMinimization">Whether the request is minimized after Table 7.1 (default: yes).</param>
        public NTPOverTLSClient(String                                                             Host,
                                IPPort?                                                            Port                        = null,
                                RemoteTLSServerCertificateValidationHandler<NTPOverTLS_TLSClient>? RemoteCertificateValidator  = null,
                                BCX509Certificate?                                                 ClientCertificate           = null,
                                AsymmetricKeyParameter?                                            ClientPrivateKey            = null,
                                IEnumerable<BCX509Certificate>?                                    ClientCertificateChain      = null,
                                TimeSpan?                                                          Timeout                     = null,
                                TimeProvider?                                                      TimeProvider                = null,
                                Boolean                                                            DataMinimization            = true)
        {

            if (String.IsNullOrWhiteSpace(Host))
                throw new ArgumentException("The server has to be named.", nameof(Host));

            if ((ClientCertificate is null) != (ClientPrivateKey is null))
                throw new ArgumentException("A client certificate and its private key are given together, or neither of them.");

            this.Host                        = Host.Trim();
            this.Port                        = Port         ?? NTPOverTLSProtocol.DefaultPort;
            this.remoteCertificateValidator  = RemoteCertificateValidator;
            this.ClientCertificate           = ClientCertificate;
            this.clientPrivateKey            = ClientPrivateKey;
            this.clientCertificateChain      = ClientCertificateChain?.ToArray() ?? [];
            this.Timeout                     = Timeout      ?? TimeSpan.FromSeconds(5);
            this.TimeProvider                = TimeProvider ?? System.TimeProvider.System;
            this.DataMinimization            = DataMinimization;

        }

        #endregion


        #region QueryTime(ClockSynchronized = false, AdvertiseNTPv5 = false, CancellationToken = default)

        /// <summary>
        /// Ask the server for the time, once, in NTPv4.
        /// </summary>
        /// <param name="ClockSynchronized">Whether this client's clock is synchronized, so that a response more than <see cref="MaxDeviationWhenSynchronized"/> from it is ignored (REQ.TA.NTP.ProcessResponse.110).</param>
        /// <param name="AdvertiseNTPv5">Whether the request offers NTPv5 with the magic of draft-ietf-ntp-ntpv5 § 12 in its reference timestamp, minimized or not.</param>
        /// <param name="CancellationToken">Ends the query.</param>
        public Task<NTPOverTLSResult> QueryTime(Boolean            ClockSynchronized   = false,
                                                Boolean            AdvertiseNTPv5      = false,
                                                CancellationToken  CancellationToken   = default)

            => Query(ClockSynchronized, AdvertiseNTPv5, AsNTPv5: false, CancellationToken);

        #endregion

        #region QueryNTPv5(ClockSynchronized = false, CancellationToken = default)

        /// <summary>
        /// Ask the server for the time, once, in NTPv5 behind its length (section 6.1 of the white
        /// paper "Secure Time Synchronization").
        /// </summary>
        /// <param name="ClockSynchronized">Whether this client's clock is synchronized, so that a response more than <see cref="MaxDeviationWhenSynchronized"/> from it is ignored.</param>
        /// <param name="CancellationToken">Ends the query.</param>
        public Task<NTPOverTLSResult> QueryNTPv5(Boolean            ClockSynchronized   = false,
                                                 CancellationToken  CancellationToken   = default)

            => Query(ClockSynchronized, AdvertiseNTPv5: false, AsNTPv5: true, CancellationToken);

        #endregion

        #region QueryNegotiated(Negotiation, ClockSynchronized = false, CancellationToken = default)

        /// <summary>
        /// Ask the server for the time, once, in whichever version the negotiation of
        /// draft-ietf-ntp-ntpv5 § 12 with it has come to, and advance the negotiation by what
        /// came back: the mode `NTPTLS` with `Versions` `v5, v4` of section 3.2.4 of the white
        /// paper "Secure Time Synchronization".
        /// </summary>
        /// <param name="Negotiation">The negotiation with this server, which this query advances.</param>
        /// <param name="ClockSynchronized">Whether this client's clock is synchronized.</param>
        /// <param name="CancellationToken">Ends the query.</param>
        public async Task<NTPOverTLSResult> QueryNegotiated(NTPv5VersionNegotiation  Negotiation,
                                                            Boolean                  ClockSynchronized   = false,
                                                            CancellationToken        CancellationToken   = default)
        {

            ArgumentNullException.ThrowIfNull(Negotiation);

            if (Negotiation.Version == NTPv5NegotiatedVersion.NTPv5)
            {

                var v5 = await QueryNTPv5(ClockSynchronized, CancellationToken).ConfigureAwait(false);

                // § 12: what counts is whether a valid response came. A cancelled query says
                // nothing about the server either way.
                if (!CancellationToken.IsCancellationRequested)
                    Negotiation.RecordNTPv5Result(v5.Success);

                return v5;

            }

            var advertise = Negotiation.Version == NTPv5NegotiatedVersion.NTPv4Advertising;

            var v4 = await QueryTime(ClockSynchronized, advertise, CancellationToken).ConfigureAwait(false);

            // The echo first, while the version is still the one the request went out in.
            if (advertise && v4.Success && v4.Response is not null)
                Negotiation.RecordNTPv4Response(v4.Response.ReferenceTimestamp);

            Negotiation.RecordNTPv4Request();

            return v4;

        }

        #endregion

        #region (private) Query(ClockSynchronized, AdvertiseNTPv5, AsNTPv5, CancellationToken)

        private async Task<NTPOverTLSResult> Query(Boolean            ClockSynchronized,
                                                   Boolean            AdvertiseNTPv5,
                                                   Boolean            AsNTPv5,
                                                   CancellationToken  CancellationToken)
        {

            using var timeoutCTS = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
            timeoutCTS.CancelAfter(Timeout);

            var literalAddress = System.Net.IPAddress.TryParse(Host.Trim('[', ']'), out var address)
                                     ? address
                                     : null;

            var tlsClient      = new NTPOverTLS_TLSClient(remoteCertificateValidator,
                                                          literalAddress is null && DomainName.TryParse(Host, out var hostName, out _)
                                                              ? hostName
                                                              : null,
                                                          literalAddress,
                                                          ClientCertificate,
                                                          clientPrivateKey,
                                                          clientCertificateChain);

            using var tcpClient = new TcpClient(literalAddress?.AddressFamily ?? AddressFamily.InterNetworkV6);

            if (literalAddress is null)
                tcpClient.Client.DualMode = true;

            try
            {

                if (literalAddress is not null)
                    await tcpClient.ConnectAsync(literalAddress, Port.ToUInt16(), timeoutCTS.Token).ConfigureAwait(false);
                else
                    await tcpClient.ConnectAsync(Host, Port.ToUInt16(), timeoutCTS.Token).ConfigureAwait(false);

            }
            catch (Exception e) when (e is SocketException or OperationCanceledException)
            {
                return new NTPOverTLSResult {
                           ErrorMessage = CancellationToken.IsCancellationRequested
                                              ? "The query was cancelled."
                                              : $"Could not connect to {Host}:{Port}: {(e is SocketException s ? s.SocketErrorCode.ToString() : "timeout")}"
                       };
            }

            // Every blocking read and write of the TLS library is bounded by the socket, and the
            // cancellation closes the socket, which ends whatever is blocked on it.
            var remaining = (Int32) Math.Max(1, Math.Min(Int32.MaxValue, Timeout.TotalMilliseconds));
            tcpClient.Client.ReceiveTimeout = remaining;
            tcpClient.Client.SendTimeout    = remaining;

            using var closeOnCancel = timeoutCTS.Token.Register(() => { try { tcpClient.Client.Close(); } catch { } });

            try
            {

                return await Task.Factory.StartNew(() => Exchange(tcpClient, tlsClient, ClockSynchronized, AdvertiseNTPv5, AsNTPv5),
                                                   CancellationToken.None,
                                                   TaskCreationOptions.LongRunning,
                                                   TaskScheduler.Default).
                                          ConfigureAwait(false);

            }
            catch (Exception e)
            {
                return Failed(tlsClient,
                              timeoutCTS.IsCancellationRequested
                                  ? CancellationToken.IsCancellationRequested
                                        ? "The query was cancelled."
                                        : $"No response within {Timeout.TotalSeconds:0.###} s."
                                  : e.Message) with { Version = AsNTPv5 ? (Byte) 5 : (Byte) 4, NTPv5Offered = AdvertiseNTPv5 };
            }

        }

        #endregion

        #region (private) Exchange(TCPClient, TLSClient, ClockSynchronized, AdvertiseNTPv5, AsNTPv5)

        private NTPOverTLSResult Exchange(TcpClient             TCPClient,
                                          NTPOverTLS_TLSClient  TLSClient,
                                          Boolean               ClockSynchronized,
                                          Boolean               AdvertiseNTPv5,
                                          Boolean               AsNTPv5)
        {

            var tlsProtocol = new TlsClientProtocol(TCPClient.GetStream());

            try
            {

                try
                {
                    tlsProtocol.Connect(TLSClient);
                }
                catch (TlsFatalAlert alert)
                {
                    return Failed(TLSClient, $"The TLS handshake failed: {AlertDescription.GetText(alert.AlertDescription)}");
                }
                catch (TlsFatalAlertReceived alert)
                {
                    return Failed(TLSClient, $"The server ended the TLS handshake: {AlertDescription.GetText(alert.AlertDescription)}");
                }

                if (AsNTPv5)
                    return ExchangeNTPv5(tlsProtocol, TLSClient, ClockSynchronized);

                #region Build the request (TA.NTP.BuildRequest)

                var request      = new Byte[NTPOverTLSProtocol.PacketLength];
                var nonce        = DataMinimization
                                       ? RandomTransmitTimestamp()
                                       : 0UL;

                // T1, read as late as possible: the request is written the moment after.
                var t1Time       = TimeProvider.GetUtcNow().UtcDateTime;
                var t1           = NTPPacket.GetCurrentNTPTimestamp(t1Time);
                var sentAt       = TimeProvider.GetTimestamp();

                var transmit     = DataMinimization ? nonce : t1;

                request[0]       = (4 << 3) | 3;   // LI 0, VN 4, mode 3 (client)

                if (DataMinimization)
                    request[3]   = unchecked((Byte) MinimizedPrecision);
                else
                {
                    request[2]   = 6;              // poll: 64 s, the shortest of the guideline's one per minute
                    request[3]   = unchecked((Byte) (-20));
                }

                // draft-ietf-ntp-ntpv5 § 12: the offer, in a minimized request as well - the magic is
                // the same for every client and says nothing about this one.
                if (AdvertiseNTPv5)
                    BinaryPrimitives.WriteUInt64BigEndian(request.AsSpan(16, 8), NTPv5Draft.NegotiationMagic);

                BinaryPrimitives.WriteUInt64BigEndian(request.AsSpan(40, 8), transmit);

                #endregion

                tlsProtocol.Stream.Write(request);
                tlsProtocol.Stream.Flush();

                var response     = new Byte[NTPOverTLSProtocol.PacketLength];
                var read         = 0;

                while (read < response.Length)
                {

                    // A server that closes the TCP connection without close_notify is a server
                    // that closed it all the same; BouncyCastle reports that as an exception.
                    Int32 n;

                    try
                    {
                        n = tlsProtocol.Stream.Read(response, read, response.Length - read);
                    }
                    catch (TlsNoCloseNotifyException)
                    {
                        n = 0;
                    }

                    if (n <= 0)
                        return Failed(TLSClient,
                                      read == 0
                                          ? "The server closed the connection without a response."
                                          : $"The server closed the connection after {read} of the 48 octets of a response.",
                                      request);

                    read += n;

                }

                // T4, at once.
                var elapsed      = TimeProvider.GetElapsedTime(sentAt);
                var t4Time       = TimeProvider.GetUtcNow().UtcDateTime;
                var t4           = NTPPacket.GetCurrentNTPTimestamp(t4Time);

                try { tlsProtocol.Close(); } catch { }

                return Judge(TLSClient,
                             request,
                             response,
                             transmit,
                             t1,
                             t4,
                             t4Time,
                             elapsed,
                             ClockSynchronized) with { NTPv5Offered = AdvertiseNTPv5 };

            }
            finally
            {
                try { tlsProtocol.Close(); } catch { }
            }

        }

        #endregion

        #region (private) ExchangeNTPv5(TLSProtocol, TLSClient, ClockSynchronized)

        /// <summary>
        /// One NTPv5 request behind its length, and its response.
        /// </summary>
        private NTPOverTLSResult ExchangeNTPv5(TlsClientProtocol     TLSProtocol,
                                               NTPOverTLS_TLSClient  TLSClient,
                                               Boolean               ClockSynchronized)
        {

            // § 9 step 2: a new random client cookie, UTC, the Draft Identification - and nothing
            // else, so the request says no more than the minimized one of NTPv4.
            var request    = NTPv5Client.BuildRequest();
            var framed     = NTPOverTLSProtocol.Frame(request.Datagram);

            // T1, read as late as possible: the request is written the moment after.
            var t1Time     = TimeProvider.GetUtcNow().UtcDateTime;
            var sentAt     = TimeProvider.GetTimestamp();

            TLSProtocol.Stream.Write(framed);
            TLSProtocol.Stream.Flush();

            var (status, response, responseFramed) = NTPOverTLSProtocol.ReadMessage(TLSProtocol.Stream);

            // T4, at once.
            var elapsed    = TimeProvider.GetElapsedTime(sentAt);
            var t4Time     = TimeProvider.GetUtcNow().UtcDateTime;

            try { TLSProtocol.Close(); } catch { }

            NTPOverTLSResult Ignored(String Requirement, String Why)

                => Failed(TLSClient, Why, request.Datagram, response) with { IgnoredBy = Requirement, Version = 5 };

            if (status == NTPOverTLSReadStatus.EndOfStream)
                return Failed(TLSClient, "The server closed the connection without a response.", request.Datagram) with { Version = 5 };

            if (status != NTPOverTLSReadStatus.Message || response is null)
                return Failed(TLSClient, $"The server's response is no whole message: {status}.", request.Datagram) with { Version = 5 };

            var version    = (response[0] >> 3) & 0x07;
            var mode       =  response[0] & 0x07;

            if (!responseFramed)
                return Ignored("REQ.TA.NTP.ProcessResponse.51", $"The server answered without a length, with a message of version {version}, not NTPv5.");

            if (mode != 4)
                return Ignored("REQ.TA.NTP.ProcessResponse.52", $"The response is of mode {mode}, not a server's (4).");

            if (version != NTPv5Packet.VersionNumber)
                return Ignored("REQ.TA.NTP.ProcessResponse.51", $"The response is of version {version}, not of the version 5 the request was.");

            if (!NTPv5Packet.TryParse(response, out var packet, out var parseError))
                return Ignored("draft-ietf-ntp-ntpv5 § 9.4", $"The response does not parse: {parseError}");

            if (packet.ClientCookie != request.ClientCookie)
                return Ignored("REQ.TA.NTP.ProcessResponse.30", "The client cookie of the response is not that of the request.");

            // The request does not set the flag, so an unsynchronized server does not answer it
            // (§ 10 of the draft), and one that does all the same is ignored as .50 has it.
            if (packet.Flags.HasFlag(NTPv5Flags.Unsynchronized))
                return Ignored("REQ.TA.NTP.ProcessResponse.50", "The server is not synchronized (flag Unsynchronized).");

            var validation = NTPv5Client.Validate(response, request);

            if (!validation.IsValid)
                return Ignored("draft-ietf-ntp-ntpv5 § 9.4", validation.ErrorMessage ?? $"The response is not valid: {validation.Status}.");

            if (elapsed > MaxTransportDelay)
                return Ignored("REQ.TA.NTP.ProcessResponse.10", $"The response took {elapsed.TotalSeconds:0.###} s, more than {MaxTransportDelay.TotalSeconds:0} s.");

            switch (NTPv5Client.CheckUsable(packet, request))
            {

                case NTPv5Unusable.None:
                    break;

                case NTPv5Unusable.Unsynchronized:
                    return Ignored("REQ.TA.NTP.ProcessResponse.50", "The server is not synchronized (flag Unsynchronized).");

                case NTPv5Unusable.MissingTimestamps:
                case NTPv5Unusable.Era:
                    return Ignored("REQ.TA.NTP.ProcessResponse.40", "The response carries no time this client can convert: a receive or transmit timestamp is zero, or its era is out of range.");

                case var unusable:
                    return Ignored("draft-ietf-ntp-ntpv5 § 9.5", $"The response is not usable for synchronization: {unusable}.");

            }

            if (NTPv5Client.Measure(t1Time, packet, t4Time, request) is not NTPv5Measurement measurement)
                return Ignored("REQ.TA.NTP.ProcessResponse.40", "The response carries no time this client can convert.");

            if (measurement.T3 < measurement.T2)
                return Ignored("draft-ietf-ntp-ntpv5 § 9", "The server says it sent its response before it received the request.");

            if (ClockSynchronized &&
                (measurement.T3 - t4Time).Duration() > MaxDeviationWhenSynchronized)
            {
                return Ignored("REQ.TA.NTP.ProcessResponse.110",
                               $"The response is {(measurement.T3 - t4Time).Duration().TotalSeconds:0} s off the synchronized clock, more than {MaxDeviationWhenSynchronized.TotalSeconds:0} s.");
            }

            return new NTPOverTLSResult {
                       Success                     = true,
                       Version                     = 5,
                       RequestBytes                = request.Datagram,
                       ResponseBytes               = response,
                       NTPv5Response               = packet,
                       ClockOffset                 = measurement.Offset,
                       RoundTripDelay              = measurement.Delay,
                       MaximumError                = packet.RootDelayTime!.Value / 2 + packet.RootDispersionTime!.Value,
                       ServerTransmitTime          = measurement.T3,
                       TLSVersion                  = TLSClient.NegotiatedTLSVersion,
                       CipherSuite                 = TLSClient.NegotiatedCipherSuite,
                       ServerCertificate           = TLSClient.ServerCertificate,
                       CertificatePolicyErrors     = TLSClient.CertificatePolicyErrors,
                       ClientCertificateRequested  = TLSClient.ClientCertificateRequested,
                       ClientCertificateSent       = TLSClient.ClientCertificateSent
                   };

        }

        #endregion

        #region (private) Judge(...)

        /// <summary>
        /// TA.NTP.ProcessResponse: whether the response may be used.
        /// </summary>
        private NTPOverTLSResult Judge(NTPOverTLS_TLSClient  TLSClient,
                                       Byte[]                Request,
                                       Byte[]                Response,
                                       UInt64                SentTransmitTimestamp,
                                       UInt64                T1,
                                       UInt64                T4,
                                       DateTime              T4Time,
                                       TimeSpan              Elapsed,
                                       Boolean               ClockSynchronized)
        {

            var leap            = (Byte)  (Response[0] >> 6);
            var version         = (Byte) ((Response[0] >> 3) & 0x07);
            var mode            = (Byte)  (Response[0] & 0x07);
            var stratum         = Response[1];
            var rootDelay       = BinaryPrimitives.ReadUInt32BigEndian(Response.AsSpan( 4, 4));
            var rootDispersion  = BinaryPrimitives.ReadUInt32BigEndian(Response.AsSpan( 8, 4));
            var origin          = BinaryPrimitives.ReadUInt64BigEndian(Response.AsSpan(24, 8));
            var receive         = BinaryPrimitives.ReadUInt64BigEndian(Response.AsSpan(32, 8));
            var transmit        = BinaryPrimitives.ReadUInt64BigEndian(Response.AsSpan(40, 8));

            NTPOverTLSResult Ignored(String Requirement, String Why)

                => Failed(TLSClient, Why, Request, Response) with { IgnoredBy = Requirement };

            if (mode != 4)
                return Ignored("REQ.TA.NTP.ProcessResponse.52", $"The response is of mode {mode}, not a server's (4).");

            if (version < 4)
                return Ignored("REQ.TA.NTP.ProcessResponse.51", $"The response is of version {version}, below 4.");

            // .51 speaks of versions below 4 alone. Above it is no NTPv4 response either: the
            // request was of version 4, and RFC 5905 § 9.2 has the server answer with that.
            if (version != 4)
                return Ignored("REQ.TA.NTP.ProcessResponse.51", $"The response is of version {version}, not of the version 4 the request was.");

            if (leap == 3)
                return Ignored("REQ.TA.NTP.ProcessResponse.50", "The server is not synchronized (leap indicator 3).");

            if (stratum == 0)
                return Ignored("RFC 5905 A.5.1.1", $"The response is a kiss (stratum 0, \"{System.Text.Encoding.ASCII.GetString(Response, 12, 4).TrimEnd('\0')}\").");

            if (stratum > 15)
                return Ignored("RFC 5905 A.5.1.1", $"The server is of stratum {stratum}, which is unsynchronized.");

            if (origin != SentTransmitTimestamp)
                return Ignored("REQ.TA.NTP.ProcessResponse.30", "The origin timestamp of the response is not the transmit timestamp of the request.");

            if (Elapsed > MaxTransportDelay)
                return Ignored("REQ.TA.NTP.ProcessResponse.10", $"The response took {Elapsed.TotalSeconds:0.###} s, more than {MaxTransportDelay.TotalSeconds:0} s.");

            if (transmit == 0 || receive == 0)
                return Ignored("REQ.TA.NTP.ProcessResponse.40", "The response carries no time: its receive or transmit timestamp is zero.");

            var t2Time          = NTPPacket.NTPTimestampToDateTime(receive,  T4Time);
            var t3Time          = NTPPacket.NTPTimestampToDateTime(transmit, T4Time);

            if (t3Time < t2Time)
                return Ignored("RFC 5905 A.5.1.1", "The server says it sent its response before it received the request.");

            if (ClockSynchronized &&
                (t3Time - T4Time).Duration() > MaxDeviationWhenSynchronized)
            {
                return Ignored("REQ.TA.NTP.ProcessResponse.110",
                               $"The response is {(t3Time - T4Time).Duration().TotalSeconds:0} s off the synchronized clock, more than {MaxDeviationWhenSynchronized.TotalSeconds:0} s.");
            }

            var referenceTime   = BinaryPrimitives.ReadUInt64BigEndian(Response.AsSpan(16, 8));

            var packet          = new NTPPacket(LI:                        leap,
                                                VN:                        version,
                                                Mode:                      mode,
                                                Stratum:                   stratum,
                                                Poll:                      Response[2],
                                                Precision:                 unchecked((SByte) Response[3]),
                                                RootDelay:                 rootDelay,
                                                RootDispersion:            rootDispersion,
                                                ReferenceIdentifier:       null,
                                                ReferenceTimestamp:        referenceTime,
                                                OriginateTimestamp:        origin,
                                                ReceiveTimestamp:          receive,
                                                TransmitTimestamp:         transmit,
                                                DestinationTimestamp:      T4,
                                                ResponseBytes:             Response,
                                                RequestTransmitTimestamp:  T1,
                                                DestinationTime:           T4Time);

            return new NTPOverTLSResult {
                       Success                     = true,
                       RequestBytes                = Request,
                       ResponseBytes               = Response,
                       Response                    = packet,
                       NTPv5Echoed                 = BinaryPrimitives.ReadUInt64BigEndian(Request.AsSpan(16, 8)) == NTPv5Draft.NegotiationMagic &&
                                                     referenceTime == NTPv5Draft.NegotiationMagic,
                       ClockOffset                 = packet.ClockOffset,
                       RoundTripDelay              = packet.RoundTripDelay,
                       MaximumError                = FromShortFormat(rootDelay) / 2 + FromShortFormat(rootDispersion),
                       ServerTransmitTime          = t3Time,
                       TLSVersion                  = TLSClient.NegotiatedTLSVersion,
                       CipherSuite                 = TLSClient.NegotiatedCipherSuite,
                       ServerCertificate           = TLSClient.ServerCertificate,
                       CertificatePolicyErrors     = TLSClient.CertificatePolicyErrors,
                       ClientCertificateRequested  = TLSClient.ClientCertificateRequested,
                       ClientCertificateSent       = TLSClient.ClientCertificateSent
                   };

        }

        #endregion

        #region (private) helpers

        private static NTPOverTLSResult Failed(NTPOverTLS_TLSClient  TLSClient,
                                               String                ErrorMessage,
                                               Byte[]?               Request    = null,
                                               Byte[]?               Response   = null)

            => new () {
                   ErrorMessage                = ErrorMessage,
                   RequestBytes                = Request,
                   ResponseBytes               = Response,
                   TLSVersion                  = TLSClient.NegotiatedTLSVersion,
                   CipherSuite                 = TLSClient.NegotiatedCipherSuite,
                   ServerCertificate           = TLSClient.ServerCertificate,
                   CertificatePolicyErrors     = TLSClient.CertificatePolicyErrors,
                   ClientCertificateRequested  = TLSClient.ClientCertificateRequested,
                   ClientCertificateSent       = TLSClient.ClientCertificateSent
               };

        /// <summary>
        /// 64 random bits for the transmit timestamp of a minimized request, never zero: a
        /// server echoes zero for a request that had none, and that echo must not pass.
        /// </summary>
        private static UInt64 RandomTransmitTimestamp()
        {

            Span<Byte> bytes = stackalloc Byte[8];
            UInt64 value;

            do
            {
                RandomNumberGenerator.Fill(bytes);
                value = BinaryPrimitives.ReadUInt64BigEndian(bytes);
            }
            while (value == 0);

            return value;

        }

        private static TimeSpan FromShortFormat(UInt32 Value)
            => TimeSpan.FromTicks((Int64) ((UInt64) Value * (UInt64) TimeSpan.TicksPerSecond >> 16));

        #endregion

    }

}
