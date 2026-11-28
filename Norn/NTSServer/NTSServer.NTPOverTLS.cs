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
using System.Collections.Concurrent;

using IPAddress = System.Net.IPAddress;

using Org.BouncyCastle.Tls;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTPOverTLS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    public partial class NTSServer
    {

        #region (private) StartNTPOverTLS(Port)

        /// <summary>
        /// Listen for NTP over TLS (BSI TR-03109-5 § 7) on the given port.
        /// </summary>
        /// <remarks>
        /// Every connection is admitted as one of NTS-KE is: by the access list of RFC 8633 § 5.1
        /// before the handshake, so that a denied address is not even shown the certificate; by
        /// <see cref="MaxNTSKEConnectionsPerClient"/> per client and by
        /// <see cref="MaxConcurrentNTSKEConnections"/> in all, counted apart from NTS-KE.
        /// </remarks>
        private void StartNTPOverTLS(IPPort Port)
        {

            var listener = CreateSocket(SocketType.Stream, ProtocolType.Tcp);

            listener.Bind(new IPEndPoint(listenIPAddress, Port.ToUInt16()));
            listener.Listen(backlog: Math.Max(64, MaxConcurrentNTSKEConnections));

            ntpOverTLSSocket = listener;

            DebugX.Log($"NTP-over-TLS Server started on port {Port}/TCP");

            var token = cts!.Token;

            ntpOverTLSLoopTask = Task.Run(async () => {

                try
                {
                    while (!token.IsCancellationRequested)
                    {

                        Socket connection;

                        try
                        {
                            connection = await listener.AcceptAsync(token).ConfigureAwait(false);
                        }
                        catch (SocketException e) when (!token.IsCancellationRequested)
                        {
                            DebugX.Log($"Accepting an NTP-over-TLS connection failed: {e.SocketErrorCode}");
                            continue;
                        }

                        System.Threading.Interlocked.Increment(ref ntpOverTLSConnectionsAccepted);

                        var remoteAddress = (connection.RemoteEndPoint as IPEndPoint)?.Address;

                        if (!AccessList.IsEveryone &&
                            !AccessList.Allows(remoteAddress))
                        {
                            System.Threading.Interlocked.Increment(ref ntpOverTLSConnectionsDenied);
                            connection.Close();
                            continue;
                        }

                        var client = remoteAddress is not null
                                         ? NTPRateLimiter.ClientOf(remoteAddress, NTPRateLimiter.DefaultIPv6PrefixLength)
                                         : null;

                        if (client is not null &&
                            ntpOverTLSConnectionsPerClient.AddOrUpdate(client, 1, (_, open) => open + 1) > MaxNTSKEConnectionsPerClient)
                        {
                            ReleaseConnectionOf(ntpOverTLSConnectionsPerClient, client);
                            System.Threading.Interlocked.Increment(ref ntpOverTLSConnectionsRejected);
                            connection.Close();
                            continue;
                        }

                        if (!ntpOverTLSConnectionSemaphore.Wait(0))
                        {
                            ReleaseConnectionOf(ntpOverTLSConnectionsPerClient, client);
                            System.Threading.Interlocked.Increment(ref ntpOverTLSConnectionsRejected);
                            connection.Close();
                            continue;
                        }

                        ntpOverTLSConnections[connection] = 0;

                        // A thread of its own for every connection, as for the handshake of
                        // NTS-KE: this TLS library blocks the thread it reads on, and a connection
                        // here waits for its client's next request for as long as the idle timeout
                        // allows. The pool answers NTP over UDP and must not be what waits.
                        _ = Task.Factory.StartNew(() => ServeNTPOverTLSConnection(connection, remoteAddress, client, token),
                                                  CancellationToken.None,
                                                  TaskCreationOptions.LongRunning,
                                                  TaskScheduler.Default);

                    }
                }
                catch (ObjectDisposedException)
                {
                    // normal on shutdown
                }
                catch (OperationCanceledException)
                {
                    // normal on shutdown
                }
                catch (Exception e)
                {
                    DebugX.Log($"Exception in the NTP-over-TLS accept loop: {e}");
                }

                try { listener.Close(); } catch { }

            }, token);

        }

        #endregion

        #region (private) ServeNTPOverTLSConnection(Connection, RemoteAddress, Client, Token)

        /// <summary>
        /// One NTP-over-TLS connection: the handshake, then a request in and its answer out for as
        /// long as the client keeps asking.
        /// </summary>
        /// <remarks>
        /// <para>
        /// A bare client request (mode 3) of a version from 1 to 4 is answered, as over UDP, and
        /// with the header of RFC 5905 § 7.3 that every response of this server carries - echoing
        /// the offer of NTPv5 of draft-ietf-ntp-ntpv5 § 12 where <see cref="NTPv5"/> is enabled.
        /// An NTPv5 request behind its length (section 6.1 of the white paper "Secure Time
        /// Synchronization") is answered as over UDP as well, by <see cref="NTPv5Responder"/>,
        /// and its response goes back behind its length. A server of NTS alone answers both in
        /// plain, since TLS authenticates and protects them.
        /// </para>
        /// <para>
        /// Anything else closes the connection: on a stream, a message that is no request leaves
        /// nothing that could be read as the next one. So does an NTPv5 request this server does
        /// not answer, or one in the framing of the other version. The same is done to a request
        /// the rate limiter refuses - a kiss is not sent, since § 7.1.1 of the guideline obliges
        /// no client to process one, and a client that closes its connection learns as much.
        /// </para>
        /// <para>
        /// The receive timestamp is taken the moment the last octet of the request is read, which
        /// over TLS is after the record it came in was decrypted.
        /// </para>
        /// </remarks>
        private void ServeNTPOverTLSConnection(Socket             Connection,
                                               IPAddress?         RemoteAddress,
                                               IPAddress?         Client,
                                               CancellationToken  Token)
        {

            try
            {

                Connection.NoDelay        = true;
                Connection.ReceiveTimeout = Milliseconds(NTSKEHandshakeTimeout);
                Connection.SendTimeout    = Milliseconds(TimeSpan.FromTicks(Math.Max(TimeSpan.TicksPerSecond, NTSKERequestTimeout.Ticks)));

                using var networkStream   = new NetworkStream(Connection, ownsSocket: false);

                var tlsProtocol           = new TlsServerProtocol(networkStream);

                // Read once: a RenewTLSIdentity in between must not hand this connection the
                // certificate of one identity and the key of another.
                var identity              = tlsIdentity;
                var validator             = ntpOverTLSClientCertificateValidator;

                var tlsService            = new NTPOverTLS_TLSService(identity.ShownCertificate!,
                                                                      identity.ShownPrivateKey!,
                                                                      identity.CertificateChain,
                                                                      validator is not null
                                                                          ? (certificate, chain, policyErrors) => validator(this, certificate, chain, this, policyErrors)
                                                                          : null);

                try
                {
                    tlsProtocol.Accept(tlsService);
                }
                catch (Exception e)
                {
                    System.Threading.Interlocked.Increment(ref ntpOverTLSHandshakeFailures);
                    DebugX.Log($"NTP-over-TLS handshake with {RemoteAddress} failed: {e.Message}");
                    return;
                }

                Connection.ReceiveTimeout = Milliseconds(NTPOverTLSIdleTimeout);

                var remoteEndPoint        = Connection.RemoteEndPoint ?? new IPEndPoint(RemoteAddress ?? IPAddress.None, 0);

                while (!Token.IsCancellationRequested)
                {

                    var (status, request, framed) = NTPOverTLSProtocol.ReadMessage(tlsProtocol.Stream);

                    if (status == NTPOverTLSReadStatus.EndOfStream)
                        break;

                    var receivedAtTime  = TimeProvider.GetUtcNow().UtcDateTime;
                    var receivedAt      = NTPPacket.GetCurrentNTPTimestamp(receivedAtTime);
                    var receivedAtTicks = TimeProvider.GetTimestamp();

                    System.Threading.Interlocked.Increment(ref ntpOverTLSRequestsReceived);

                    if (status != NTPOverTLSReadStatus.Message || request is null)
                    {
                        System.Threading.Interlocked.Increment(ref ntpOverTLSRequestsInvalid);
                        DebugX.Log($"NTP-over-TLS client {RemoteAddress} sent no whole message: {status}.");
                        break;
                    }

                    var mode    = request[0] & 0x07;
                    var version = (request[0] >> 3) & 0x07;

                    // Section 6.1: NTPv5 behind a length, NTPv1 to NTPv4 bare, and either a request.
                    var expected = framed
                                       ? version == NTPv5Packet.VersionNumber && NTPv5 != NTPv5Support.Disabled
                                       : version is >= 1 and <= 4;

                    if (mode != 3 || !expected)
                    {
                        System.Threading.Interlocked.Increment(ref ntpOverTLSRequestsInvalid);
                        DebugX.Log($"NTP-over-TLS client {RemoteAddress} sent mode {mode}, version {version}{(framed ? " behind a length" : "")}: no request this server answers.");
                        break;
                    }

                    if (RateLimiter is not null &&
                        RemoteAddress is not null &&
                        RateLimiter.Check(RemoteAddress) != RateLimitDecision.Answer)
                    {
                        System.Threading.Interlocked.Increment(ref ntpOverTLSRequestsInvalid);
                        System.Threading.Interlocked.Increment(ref ntpRequestsRateLimited);
                        break;
                    }

                    Byte[] response;

                    if (framed)
                    {

                        Byte[]? answer = null;

                        AnswerNTPv5Async((bytes, _) => { answer = bytes; return Task.CompletedTask; },
                                         request,
                                         receivedAt,
                                         receivedAtTime,
                                         receivedAtTicks,
                                         remoteEndPoint,
                                         OverChannel: true,
                                         Token).GetAwaiter().GetResult();

                        // The response is as long as the request, so it fits behind a length as well.
                        if (answer is not { Length: >= NTPOverTLSProtocol.MinFramedLength and <= NTPOverTLSProtocol.MaxFramedLength })
                        {
                            System.Threading.Interlocked.Increment(ref ntpOverTLSRequestsInvalid);
                            DebugX.Log($"NTPv5 request over TLS from {RemoteAddress} not answered.");
                            break;
                        }

                        response = NTPOverTLSProtocol.Frame(answer);

                    }
                    else
                    {

                        if (!NTPRequest.TryParse(request, out var requestPacket, out var errorResponse))
                        {
                            System.Threading.Interlocked.Increment(ref ntpOverTLSRequestsInvalid);
                            DebugX.Log($"Invalid NTP-over-TLS request from {RemoteAddress}: {errorResponse}");
                            break;
                        }

                        response = BuildResponseHeader(requestPacket,
                                                       [],
                                                       InterleavedExchange.Basic(requestPacket, receivedAt, TimeProvider),
                                                       OverChannel: true).
                                       ToByteArray(SkipExtensions: true);

                    }

                    tlsProtocol.Stream.Write(response, 0, response.Length);
                    tlsProtocol.Stream.Flush();

                    System.Threading.Interlocked.Increment(ref ntpOverTLSResponsesSent);

                }

                try { tlsProtocol.Close(); } catch { }

            }
            catch (IOException)
            {
                // The client said nothing for the idle timeout, or went away.
            }
            catch (ObjectDisposedException)
            {
                // Closed by the shutdown.
            }
            catch (Exception e)
            {
                DebugX.Log($"Exception on the NTP-over-TLS connection of {RemoteAddress}: {e.Message}");
            }
            finally
            {

                ntpOverTLSConnections.TryRemove(Connection, out _);

                try { Connection.Shutdown(SocketShutdown.Both); } catch { }
                try { Connection.Close(); } catch { }
                try { ntpOverTLSConnectionSemaphore.Release(); } catch (ObjectDisposedException) { }

                ReleaseConnectionOf(ntpOverTLSConnectionsPerClient, Client);

            }

        }

        #endregion

        #region (private static) helpers

        private static Int32 Milliseconds(TimeSpan Value)
            => (Int32) Math.Clamp(Value.TotalMilliseconds, 1, Int32.MaxValue);

        /// <summary>
        /// One connection of the client fewer; its entry goes with its last one.
        /// </summary>
        private static void ReleaseConnectionOf(ConcurrentDictionary<IPAddress, Int32>  Connections,
                                                IPAddress?                              Client)
        {

            if (Client is null)
                return;

            while (Connections.TryGetValue(Client, out var open))
            {

                if (open <= 1
                        ? Connections.TryRemove(new KeyValuePair<IPAddress, Int32>(Client, open))
                        : Connections.TryUpdate(Client, open - 1, open))
                {
                    return;
                }

            }

        }

        #endregion

    }

}
