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
        /// </summary>
        public System.Net.IPAddress  ListenIPAddress               { get; }

        /// <summary>
        /// Whether an IPv6 listener socket should also accept IPv4 traffic.
        /// </summary>
        public Boolean               EnableDualStack               { get; }

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
                         DNSClient?         DNSClient      = null,
                         System.Net.IPAddress? ListenIPAddress               = null,
                         Boolean            EnableDualStack               = true,
                         String?            MasterKeysFilePath            = "masterKeys.json",
                         TimeSpan?          MasterKeyLifetime             = null,
                         TimeSpan?          MasterKeyRotationGracePeriod  = null,
                         TimeSpan?          NTSKEHandshakeTimeout         = null,
                         TimeSpan?          NTSKERequestTimeout           = null,
                         Int32?             MaxNTSKERequestSize           = null,
                         Int32?             MaxConcurrentNTPRequests      = null,
                         Int32?             MaxConcurrentNTSKEConnections = null)
        {

            this.Description                  = Description                  ?? I18NString.Empty;
            this.TCPPort                      = NTSKEPort                    ?? IPPort.NTSKE;
            this.UDPPort                      = NTSPort                      ?? IPPort.NTP;
            this.ExternalURLs                 = ExternalURLs                 ?? [ URL.Parse($"udp://localhost:{this.UDPPort}") ];
            this.DNSClient                    = DNSClient                    ?? new DNSClient();
            this.ListenIPAddress              = ListenIPAddress              ?? System.Net.IPAddress.Any;
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

            if (KeyPair is not null)
            {

                this.currentKeyPair   = KeyPair;
                this.currentPublicKey = KeyPair.ToPublicKey();

                this.keyPairs.TryAdd(KeyPair.Id, KeyPair);

            }

            try
            {

                var invalidAfter = Timestamp.Now + this.MasterKeyRotationGracePeriod;

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
                             ListenIPAddress.AddressFamily,
                             SocketType,
                             ProtocolType
                         );

            if (ListenIPAddress.AddressFamily == AddressFamily.InterNetworkV6 &&
                EnableDualStack)
            {
                socket.DualMode = true;
            }

            return socket;

        }

        #endregion

        #region (private) BuildNTSKEResponseRecords(NTSKERequest, C2SKey, S2CKey)

        private IEnumerable<NTSKE_Record> BuildNTSKEResponseRecords(IEnumerable<NTSKE_Record>  NTSKERequest,
                                                                    Byte[]                    C2SKey,
                                                                    Byte[]                    S2CKey)
        {

            var ntsKERecords = new List<NTSKE_Record> {
                                   NTSKE_Record.NTSNextProtocolNegotiation,
                                   NTSKE_Record.AEADAlgorithmNegotiation()
                               };

            if (advertiseExternalURLs)
            {
                foreach (var externalURL in ExternalURLs.Where(url => url.Protocol == URLProtocols.udp))
                {

                    var hostname = externalURL.Hostname.Name.Trim('[', ']');

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
                        NumberOfCookies:   7,
                        C2SKey:            C2SKey,
                        S2CKey:            S2CKey,
                        AEADAlgorithm:     AEADAlgorithms.AES_SIV_CMAC_256,
                        IsCritical:        false
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

            var now = Timestamp.Now;

            if (currentMasterKey is null ||
                currentMasterKey.Value.NotBefore > now ||
                currentMasterKey.Value.NotAfter  <= now)
            {
                lock (currentMasterKeyLock)
                {

                    now = Timestamp.Now;

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

            udpSocket = CreateSocket(SocketType.Dgram, ProtocolType.Udp);

            udpSocket.Bind(
                new IPEndPoint(
                    ListenIPAddress,
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
                        var remoteEP        = new IPEndPoint(System.Net.IPAddress.Any, 0);

                        var udpPacket       = await udpSocket.ReceiveFromAsync(
                                                        new ArraySegment<Byte>(buffer),
                                                        SocketFlags.None,
                                                        remoteEP,
                                                        cts.Token
                                                    );

                        // Local copy to pass into the Task
                        var udpPacketLocal  = udpPacket;


                        if (!await ntpRequestSemaphore.WaitAsync(0, cts.Token).ConfigureAwait(false))
                        {
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

                                    var responsePacket1  = BuildResponse(
                                                               requestPacket,
                                                               toBeSigned
                                                           );

                                    await udpSocket.SendToAsync(
                                               new ArraySegment<Byte>(responsePacket1.ToByteArray()),
                                               SocketFlags.None,
                                               udpPacketLocal.RemoteEndPoint,
                                               cts.Token
                                           );

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
                    ListenIPAddress,
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

                        if (!await ntskeConnectionSemaphore.WaitAsync(0, cts.Token).ConfigureAwait(false))
                        {
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
                                var tlsServer            = new NTSKE_TLSService ();

                                await Task.Run(
                                          () => tlsServerProtocol.Accept(tlsServer),
                                          requestCTS.Token
                                      ).WaitAsync(NTSKEHandshakeTimeout, requestCTS.Token).
                                        ConfigureAwait(false);

                                var c2sKey               = tlsServer.NTS_C2S_Key ?? [];
                                var s2cKey               = tlsServer.NTS_S2C_Key ?? [];


                                var (requestBytes, errorMessage) = await NTSKEMessageReader.ReadAsync(
                                                                        tlsServerProtocol.Stream,
                                                                        NTSKERequestTimeout,
                                                                        MaxNTSKERequestSize,
                                                                        requestCTS.Token
                                                                    ).ConfigureAwait(false);

                                if (requestBytes is not null)
                                {

                                    if (NTSKE_Record.TryParse(requestBytes, out var ntsKERequest, out var errorResponse))
                                    {

                                        var ntsKERecords = BuildNTSKEResponseRecords(
                                                               ntsKERequest,
                                                               c2sKey,
                                                               s2cKey
                                                           );

                                        await tlsServerProtocol.Stream.WriteAsync(ntsKERecords.ToByteArray(), requestCTS.Token).
                                                                          ConfigureAwait(false);
                                        await tlsServerProtocol.Stream.FlushAsync(requestCTS.Token).
                                                                          ConfigureAwait(false);

                                    }
                                    else
                                    {
                                        DebugX.Log($"Invalid NTS-KE response: {errorResponse}");
                                    }

                                }
                                else
                                {
                                    DebugX.Log($"Invalid NTS-KE request: {errorMessage}");
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


            var receiveTimestamp  = NTPPacket.GetCurrentNTPTimestamp();
            var transmitTimestamp = NTPPacket.GetCurrentNTPTimestamp();

            var response1 = new NTPPacket(

                                 Mode:                4, // 4 (Server)
                                 Stratum:             2,
                                 Poll:                RequestPacket.Poll,
                                 Precision:           RequestPacket.Precision,
                                 ReferenceTimestamp:  transmitTimestamp,
                                 OriginateTimestamp:  RequestPacket.TransmitTimestamp ?? 0,
                                 ReceiveTimestamp:    receiveTimestamp,
                                 TransmitTimestamp:   transmitTimestamp

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
