﻿/*
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

        private                  Socket?                                  tcpSocket;
        private                  Socket?                                  udpSocket;
        private                  CancellationTokenSource?                 cts;

        private readonly         ConcurrentDictionary<UInt64, MasterKey>  masterKeys             = [];
        private static readonly  Lock                                     currentMasterKeyLock   = new();
        private                  MasterKey?                               currentMasterKey;
        private const            String                                   masterKeysFile         = "masterKeys.json";

        private readonly         ConcurrentDictionary<UInt64, KeyPair>    keyPairs               = [];
        private                  KeyPair?                                 currentKeyPair;
        private                  PublicKey?                               currentPublicKey;

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
        public NTSServer(I18NString?        Description    = null,
                         IPPort?            NTSKEPort      = null,
                         IPPort?            NTSPort        = null,
                         KeyPair?           KeyPair        = null,
                         IEnumerable<URL>?  ExternalURLs   = null,
                         DNSClient?         DNSClient      = null)
        {

            this.Description   = Description  ?? I18NString.Empty;
            this.TCPPort       = NTSKEPort    ?? IPPort.NTSKE;
            this.UDPPort       = NTSPort      ?? IPPort.NTP;
            this.ExternalURLs  = ExternalURLs ?? [ URL.Parse($"udp://localhost:{this.UDPPort}") ];
            this.DNSClient     = DNSClient    ?? new DNSClient();

            if (KeyPair is not null)
            {

                this.currentKeyPair   = KeyPair;
                this.currentPublicKey = KeyPair.ToPublicKey();

                this.keyPairs.TryAdd(KeyPair.Id, KeyPair);

            }

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
                                  Select(_ => NTSCookie.Create (MasterKey, C2SKey, S2CKey, AEADAlgorithm).
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

                        var buffer          = new Byte[BufferSize];
                        var remoteEP        = new IPEndPoint(System.Net.IPAddress.Any, 0);

                        var udpPacket       = await udpSocket.ReceiveFromAsync(
                                                        new ArraySegment<Byte>(buffer),
                                                        SocketFlags.None,
                                                        remoteEP,
                                                        cts.Token
                                                    );

                        // Local copy to pass into the Task
                        var udpPacketLocal  = udpPacket;


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

                                    var responsePacket1  = BuildResponse(
                                                               requestPacket,
                                                               toBeSigned
                                                           );

                                    await udpSocket.SendToAsync(
                                              new ArraySegment<Byte>(responsePacket1.ToByteArray()),
                                              SocketFlags.None,
                                              udpPacketLocal.RemoteEndPoint
                                          );

                                    if (toBeSigned && currentKeyPair is not null)
                                    {

                                        var responsePacket2 = SignResponse(responsePacket1, currentKeyPair);

                                        await udpSocket.SendToAsync(
                                                  new ArraySegment<Byte>(responsePacket2.ToByteArray()),
                                                  SocketFlags.None,
                                                  udpPacketLocal.RemoteEndPoint
                                              );

                                    }

                                }
                                else
                                {
                                    DebugX.Log($"Invalid NTP request from {udpPacketLocal.RemoteEndPoint}: {errorResponse}");
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

            #region Start NTS-KE TCP server

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

                                        if (ntsKERequest.Any(ntsKERecord => ntsKERecord.Type == NTSKE_RecordTypes.NTSRequestPublicKey) &&
                                            currentPublicKey is not null)
                                        {
                                            ntsKERecords.Add(
                                                NTSKE_Record.NTSPublicKey(currentPublicKey)
                                            );
                                        }

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

        #region Shutdown()

        /// <summary>
        /// Stop the server.
        /// </summary>
        public void Shutdown()
        {
            cts?.Cancel();
        }

        #endregion


        private NTPPacket BuildResponse(NTPPacket  RequestPacket,
                                        Boolean    SignedResponseRequested = false)
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


            // Generate a new NTS Cookie to be added to the response
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


            if (SignedResponseRequested)
                extensions.Add(
                    new NTSSignedResponseAnnouncementExtension(IsScheduled: true)
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
