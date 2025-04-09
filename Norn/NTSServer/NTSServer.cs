/*
 * Copyright (c) 2010-2025 GraphDefined GmbH <achim.friedland@graphdefined.com>
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
using System.Security.Cryptography;
using System.Collections.Concurrent;

using Org.BouncyCastle.Tls;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
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

        private                  Socket?                                      tcpSocket;
        private                  Socket?                                      udpSocket;
        private                  CancellationTokenSource?                     cts;

        private readonly         ConcurrentDictionary<UInt64, MasterKey>  masterKeys            = [];
        private static readonly  Lock                                         currentMasterKeyLock  = new();
        private                  MasterKey?                               currentMasterKey;

        #endregion

        #region Properties

        /// <summary>
        /// The NTP-KE TCP port.
        /// </summary>
        public IPPort  TCPPort       { get; } = IPPort.NTSKE;

        /// <summary>
        /// The NTP UDP port.
        /// </summary>
        public IPPort  UDPPort       { get; } = IPPort.NTP;

        /// <summary>
        /// The size of the buffer used for receiving NTP packets.
        /// </summary>
        public UInt32  BufferSize    { get; } = 4096;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new Network Time Secure (NTS) Server.
        /// </summary>
        /// <param name="TCPPort">The optional TCP port for NTS-KE to listen on (default: 4460).</param>
        /// <param name="UDPPort">The optional UDP port for NTP to listen on (default: 123).</param>
        public NTSServer(IPPort?  TCPPort   = null,
                         IPPort?  UDPPort   = null)
        {

            this.TCPPort = TCPPort ?? IPPort.NTSKE;
            this.UDPPort = UDPPort ?? IPPort.NTP;

            foreach (var masterKeyText in File.ReadAllLines("masterKeys.json"))
            {
                if (MasterKey.TryParse(masterKeyText, out var masterKey, out var errorResponse))
                {
                    masterKeys.TryAdd(
                        masterKey.KeyId,
                        masterKey
                    );
                }
                else
                {
                    DebugX.Log($"Invalid master key: {masterKeyText}");
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

            if (currentMasterKey is null)
            {
                lock (currentMasterKeyLock)
                {

                    if (currentMasterKey is null)
                    {
                        foreach (var masterKey in masterKeys.Values.OrderByDescending(masterKey => masterKey.NotAfter))
                        {
                            if (masterKey.NotBefore <= Timestamp.Now &&
                                masterKey.NotAfter  >  Timestamp.Now)
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
                                                newKeyId,
                                                RandomNumberGenerator.GetBytes(32),
                                                Timestamp.Now,
                                                Timestamp.Now + TimeSpan.FromDays(1)
                                            );

                        masterKeys.TryAdd(
                            currentMasterKey.Value.KeyId,
                            currentMasterKey.Value
                        );

                    }

                }
            }

            return currentMasterKey.Value;

        }

        #endregion

        #region (private) GenerateNTSCookies(MasterKey, NumberOfCookies, C2SKey, S2CKey, AEADAlgorithm = AEADAlgorithms.AES_SIV_CMAC_256)

        private IEnumerable<NTSKE_Record> GenerateNTSCookies(MasterKey       MasterKey,
                                                             Byte            NumberOfCookies,
                                                             Byte[]          C2SKey,
                                                             Byte[]          S2CKey,
                                                             AEADAlgorithms  AEADAlgorithm   = AEADAlgorithms.AES_SIV_CMAC_256)
        {

            #region Initial checks

            if (NumberOfCookies == 0)
                return [];
            if (C2SKey.Length == 0)
                throw new ArgumentException("The C2SKey must not be empty!", nameof(C2SKey));
            if (S2CKey.Length == 0)
                throw new ArgumentException("The S2CKey must not be empty!", nameof(S2CKey));
            if (C2SKey.Length != S2CKey.Length)
                throw new ArgumentException("The C2SKey and S2CKey must be of the same length!");

            #endregion

            #region Data

            const Byte OffsetAlgorithmId  = 0;
            const Byte OffsetTimestamp    = 4;
            const Byte OffsetNonce        = 12;
            const Byte OffsetKeyLength    = 44;
            const Byte OffsetC2SKey       = 46;
            var        OffsetS2CKey       = (Byte) (OffsetC2SKey + C2SKey.Length);
            var        totalLength        = OffsetS2CKey + S2CKey.Length;

            #endregion


            var unixTimestamp  = (UInt64) Timestamp.Now.ToUnixTimestamp();
            var cookies        = new List<NTSKE_Record>();

            for (var i = 0; i < NumberOfCookies; i++)
            {

                // rfc8915 Section 6 https://datatracker.ietf.org/doc/html/rfc8915#name-suggested-format-for-nts-co
                // gives just some general hints about the cookie format!
                //
                // Therefore this is OUR format!

                var cookie          = new Byte[totalLength];
                var algorithmBytes  = AEADAlgorithm.GetBytes();
                cookie[OffsetAlgorithmId  ] = algorithmBytes[0];
                cookie[OffsetAlgorithmId+1] = algorithmBytes[1];

                // Timestamp (Big-Endian)
                for (var j = 0; j < 8; j++)
                    cookie[OffsetTimestamp + j] = (Byte) (unixTimestamp >> (56 - 8 * j));

                // Nonce (32 bytes)
                var nonce = RandomNumberGenerator.GetBytes(32);
                Buffer.BlockCopy(nonce, 0, cookie, OffsetNonce, nonce.Length);

                // Key length (Big-Endian)
                cookie[OffsetKeyLength + 0] = (Byte) (C2SKey.Length >> 8);
                cookie[OffsetKeyLength + 1] = (Byte) (C2SKey.Length & 0xFF);

                // Keys
                Buffer.BlockCopy(C2SKey, 0, cookie, OffsetC2SKey,                 C2SKey.Length);
                Buffer.BlockCopy(S2CKey, 0, cookie, OffsetC2SKey + C2SKey.Length, S2CKey.Length);

                // TODO: AEAD-Encrypt `cookie` with master key

                cookies.Add(
                    new NTSKE_Record(
                        false,
                        NTSKE_RecordTypes.NewCookieForNTPv4,
                        cookie
                    )
                );

            }

            return cookies;

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

            #region Start UDP server

            udpSocket = new Socket(
                            AddressFamily.InterNetwork,
                            SocketType.Dgram,
                            ProtocolType.Udp
                        );

            udpSocket.Bind(
                new IPEndPoint(
                    System.Net.IPAddress.Any,
                    UDPPort.ToUInt16()
                )
            );

            DebugX.Log($"NTP Server started on port {UDPPort}/UDP");

            // Fire-and-forget task that handles incoming NTP in a loop
            _ = Task.Run(async () => {

                try
                {
                    while (!cts.Token.IsCancellationRequested)
                    {

                        var buffer       = new Byte[BufferSize];
                        var remoteEP     = new IPEndPoint(System.Net.IPAddress.Any, 0);

                        var result       = await udpSocket.ReceiveFromAsync(
                                                     new ArraySegment<Byte>(buffer),
                                                     SocketFlags.None,
                                                     remoteEP,
                                                     cts.Token
                                                 );

                        // Local copy to pass into the Task
                        var resultLocal  = result;


                        _ = Task.Run(async () => {

                            try
                            {

                                Array.Resize(ref buffer, resultLocal.ReceivedBytes);

                                if (NTPPacket.TryParseRequest(buffer, out var requestPacket, out var errorResponse))
                                {

                                    var responsePacket = BuildResponse(requestPacket);

                                    await udpSocket.SendToAsync(
                                              new ArraySegment<Byte>(responsePacket.ToByteArray()),
                                              SocketFlags.None,
                                              resultLocal.RemoteEndPoint
                                          );

                                }
                                else
                                {
                                    DebugX.Log($"Invalid NTP request from {resultLocal.RemoteEndPoint}: {errorResponse}");
                                }
                            }
                            catch (Exception e)
                            {
                                DebugX.Log($"Exception while processing a NTP request: {e}");
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

            #region Start TCP server

            tcpSocket = new Socket(
                            AddressFamily.InterNetwork,
                            SocketType.Stream,
                            ProtocolType.Tcp
                        );

            tcpSocket.Bind(
                new IPEndPoint(
                    System.Net.IPAddress.Any,
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
            _ = Task.Run(async () => {

                try
                {
                    while (!cts.Token.IsCancellationRequested)
                    {

                        var clientSocket = await tcpSocket.AcceptAsync(cts.Token);

                        if (clientSocket == null)
                            continue;

                        _ = Task.Run(async () => {

                            try
                            {

                                using var networkStream  = new NetworkStream    (clientSocket, ownsSocket: false);
                                var tlsServerProtocol    = new TlsServerProtocol(networkStream);
                                var tlsServer            = new NTSKE_TLSService ();
                                tlsServerProtocol.Accept(tlsServer);

                                var c2sKey               = tlsServer.NTS_C2S_Key ?? [];
                                var s2cKey               = tlsServer.NTS_S2C_Key ?? [];


                                // Read client request bytes from the stream
                                var buffer               = new Byte[BufferSize];
                                var bytesRead            = await tlsServerProtocol.Stream.ReadAsync(buffer, cts.Token);
                                if (bytesRead > 0)
                                {

                                    Array.Resize(ref buffer, bytesRead);

                                    if (NTSKE_Record.TryParse(buffer, out var ntsKERequest, out var errorResponse))
                                    {

                                        DebugX.Log($"Received NTS-KE request: {ntsKERequest}");

                                        var ntsKERecords = new List<NTSKE_Record> {
                                                               NTSKE_Record.NTSNextProtocolNegotiation,
                                                               NTSKE_Record.AEADAlgorithmNegotiation()
                                                           };

                                        ntsKERecords.AddRange(
                                            GenerateNTSCookies(
                                                GetCurrentMasterKey(),
                                                7,
                                                c2sKey,
                                                s2cKey
                                            )
                                        );

                                        ntsKERecords.Add(NTSKE_Record.EndOfMessage);

                                        await tlsServerProtocol.Stream.WriteAsync(ntsKERecords.ToByteArray());
                                        await tlsServerProtocol.Stream.FlushAsync();

                                    }
                                    else
                                    {
                                        DebugX.Log($"Invalid NTS-KE response: {errorResponse}");
                                    }

                                }

                                tlsServerProtocol.Close();

                            }
                            catch (Exception ex)
                            {
                                DebugX.Log($"TLS handshake/IO failed: {ex.Message}");
                            }
                            finally
                            {
                                try { clientSocket.Shutdown(SocketShutdown.Both); } catch { }
                                clientSocket.Close();
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

        #region Stop()

        /// <summary>
        /// Stop the server.
        /// </summary>
        public void Stop()
        {
            cts?.Cancel();
        }

        #endregion


        private Byte[] GetS2CKey(NTSCookieExtension CookieExtension)
        {

            return CookieExtension.Value;

        }


        private NTPPacket BuildResponse(NTPPacket RequestPacket)
        {

            var extensions  = new List<NTPExtension>();

            if (RequestPacket.UniqueIdentifier?.Length > 0)
                extensions.Add(new UniqueIdentifierExtension(RequestPacket.UniqueIdentifier ?? []));

            var s2cKey      = RequestPacket.NTSCookie is not null
                                  ? GetS2CKey(RequestPacket.NTSCookie)
                                  : [];




            // AuthenticatorAndEncryptedExtension with embedded NTSCookieExtension

            extensions.Add(NTSSignedResponseExtension.Create(extensions.Select(extension => extension.ToByteArray())));


            var response = new NTPPacket(

                               Mode:                4, // 4 (Server)
                               Stratum:             2,
                               Poll:                RequestPacket.Poll,
                               Precision:           RequestPacket.Precision,
                               TransmitTimestamp:   NTPPacket.GetCurrentNTPTimestamp(),

                               Extensions:          extensions

                           );

            return response;

        }

    }

}
