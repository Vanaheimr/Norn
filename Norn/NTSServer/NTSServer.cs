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

        private                  Socket?                                  tcpSocket;
        private                  Socket?                                  udpSocket;
        private                  CancellationTokenSource?                 cts;

        private readonly         ConcurrentDictionary<UInt64, MasterKey>  masterKeys             = [];
        private static readonly  Lock                                     currentMasterKeyLock   = new();
        private                  MasterKey?                               currentMasterKey;
        private const            String                                   masterKeysFile         = "masterKeys.json";

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

            try
            {

                var invalidAfter = Timestamp.Now + TimeSpan.FromDays(7);

                foreach (var masterKeyText in File.ReadAllLines(masterKeysFile))
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
                                                Id:         newKeyId,
                                                Value:      RandomNumberGenerator.GetBytes(32),
                                                NotBefore:  Timestamp.Now,
                                                NotAfter:   Timestamp.Now + TimeSpan.FromDays(1)
                                            );

                        masterKeys.TryAdd(
                            currentMasterKey.Value.Id,
                            currentMasterKey.Value
                        );

                        try
                        {
                            File.AppendAllText(
                                masterKeysFile,
                                currentMasterKey.Value.ToJSON().ToString(Newtonsoft.Json.Formatting.None) + Environment.NewLine
                            );
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

                                if (NTPPacket.TryParseRequest(buffer, out var requestPacket, out var errorResponse,
                                                              MasterKeys: masterKeys))
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

                                        var ntsKERecords = new List<NTSKE_Record> {
                                                               NTSKE_Record.NTSNextProtocolNegotiation,
                                                               NTSKE_Record.AEADAlgorithmNegotiation()
                                                           };

                                        ntsKERecords.AddRange(
                                            GetCurrentMasterKey().
                                                GenerateNTSKECookies(
                                                    NumberOfCookies:   7,
                                                    C2SKey:            c2sKey,
                                                    S2CKey:            s2cKey,
                                                    AEADAlgorithm:     AEADAlgorithms.AES_SIV_CMAC_256,
                                                    IsCritical:        false
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


        private NTPPacket BuildResponse(NTPPacket RequestPacket)
        {

            var extensions           = new List<NTPExtension>();
            var encryptedExtensions  = new List<NTPExtension>();

            var u1 = RequestPacket.UniqueIdentifier();

            if (u1?.Length > 0)
                extensions.Add(new UniqueIdentifierExtension(u1));

            var n1 = RequestPacket.NTSCookieExtension();

            if (n1 is null)
                return new NTPPacket(
                           LI:                     0,
                           VN:                     0,
                           Mode:                   0,
                           Stratum:                0,
                           Poll:                   0,
                           Precision:              0,
                           RootDelay:              0,
                           RootDispersion:         0,
                           ReferenceIdentifier:    ReferenceIdentifier.Zero,
                           ReferenceTimestamp:     0,
                           OriginateTimestamp:     0,
                           ReceiveTimestamp:       0,
                           TransmitTimestamp:      0,
                           Extensions:             [],
                           KeyId:                  0,
                           MessageDigest:          null,
                           DestinationTimestamp:   0,

                           Request:                RequestPacket,
                           ResponseBytes:          null,
                           ErrorMessage:           "Invalid NTS cookie!"
                       );

            if (!NTSCookie.TryParse(n1.Value, out var ntsCookie, out var errorResponse))
                return new NTPPacket(
                           LI:                     0,
                           VN:                     0,
                           Mode:                   0,
                           Stratum:                0,
                           Poll:                   0,
                           Precision:              0,
                           RootDelay:              0,
                           RootDispersion:         0,
                           ReferenceIdentifier:    ReferenceIdentifier.Zero,
                           ReferenceTimestamp:     0,
                           OriginateTimestamp:     0,
                           ReceiveTimestamp:       0,
                           TransmitTimestamp:      0,
                           Extensions:             [],
                           KeyId:                  0,
                           MessageDigest:          null,
                           DestinationTimestamp:   0,

                           Request:                RequestPacket,
                           ResponseBytes:          null,
                           ErrorMessage:           "Invalid NTS cookie: " + errorResponse
                       );


            encryptedExtensions.Add(
                GetCurrentMasterKey().
                    GenerateNTSCookieExtensions(
                        NumberOfCookies:  1,
                        C2SKey:           ntsCookie.C2SKey,
                        S2CKey:           ntsCookie.S2CKey,
                        AEADAlgorithm:    ntsCookie.AEADAlgorithm
                        //IsCritical:       true
                    ).First()
            );


            var response1 = new NTPPacket(

                                Mode:                4, // 4 (Server)
                                Stratum:             2,
                                Poll:                RequestPacket.Poll,
                                Precision:           RequestPacket.Precision,
                                TransmitTimestamp:   NTPPacket.GetCurrentNTPTimestamp()

                            );


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


            var response2 = new NTPPacket(
                                response1,
                                Extensions: extensions
                            ).ToByteArray();

            extensions.Add(
                NTSSignedResponseExtension.Sign(
                    1,
                    response2
                )
            );


            return new NTPPacket(
                       response1,
                       Extensions: extensions
                   );

        }

    }

}
