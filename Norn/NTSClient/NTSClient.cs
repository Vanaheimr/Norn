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

        public const    UInt16   DefaultNTSKE_Port  = 4460;
        public const    UInt16   DefaultNTP_Port    = 123;
        public readonly TimeSpan DefaultTimeout     = TimeSpan.FromSeconds(3);

        #endregion

        #region Properties
        public UInt16                                                         Id                            { get; }
        public String                                                         Host                          { get; }
        public UInt16                                                         NTSKE_Port                    { get; }
        public UInt16                                                         NTP_Port                      { get; }
        public RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient>?  RemoteCertificateValidator    { get; }
        public TimeSpan?                                                      Timeout                       { get; set; }
        public Byte[]                                                         C2S_Key                       { get; set; } = [];
        public Byte[]                                                         S2C_Key                       { get; set; } = [];
        public DNSClient                                                      DNSClient                     { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new NTS client.
        /// </summary>
        /// <param name="Host">The hostname or IP address of the NTS server.</param>
        /// <param name="NTSKE_Port">An optional NTS-KE port (default: 4460).</param>
        /// <param name="NTP_Port">An optional NTP port (default: 123).</param>
        /// <param name="Id">An optional unique identifier for the client.</param>
        /// <param name="RemoteCertificateValidator">An optional remote certificate validator.</param>
        /// <param name="Timeout">An optional timeout for the NTS-KE/NTS requests.</param>
        /// <param name="DNSClient">An optional DNS client to use.</param>
        public NTSClient(String                                                         Host,
                         UInt16                                                         NTSKE_Port                   = NTSClient.DefaultNTSKE_Port,
                         UInt16                                                         NTP_Port                     = NTSClient.DefaultNTP_Port,
                         UInt16?                                                        Id                           = null,
                         RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient>?  RemoteCertificateValidator   = null,
                         DNSClient?                                                     DNSClient                    = null,
                         TimeSpan?                                                      Timeout                      = null)
        {

            this.Id                          = Id      ?? RandomExtensions.RandomUInt16();
            this.Host                        = Host;
            this.NTSKE_Port                  = NTSKE_Port;
            this.NTP_Port                    = NTP_Port;
            this.RemoteCertificateValidator  = RemoteCertificateValidator;
            this.Timeout                     = Timeout ?? DefaultTimeout;
            this.DNSClient                   = DNSClient ?? new DNSClient();

        }

        #endregion


        #region (private) BuildNTSKERequest (RequestNTSPublicKeys = false)

        /// <summary>
        /// Create a new NTS-KE request.
        /// </summary>
        /// <param name="RequestNTSPublicKeys">Whether to request the public keys used for NTS response signing.</param>
        private static Byte[] BuildNTSKERequest(Boolean RequestNTSPublicKeys = false)
        {

            var records = new List<NTSKE_Record>() {
                              NTSKE_Record.NTSNextProtocolNegotiation,
                              NTSKE_Record.AEADAlgorithmNegotiation()
                          };

            if (RequestNTSPublicKeys)
                records.Add(NTSKE_Record.NTSRequestPublicKey());

            records.Add(NTSKE_Record.EndOfMessage);

            return records.ToByteArray();

        }

        #endregion

        #region GetNTSKERecords (RequestNTSPublicKeys = false, Timeout = null)

        /// <summary>
        /// Get NTS-KE records from the server.
        /// </summary>
        /// <param name="RequestNTSPublicKeys">Whether to request the public keys used for NTS response signing.</param>
        /// <param name="Timeout">An optional timeout.</param>
        public NTSKE_Response GetNTSKERecords(Boolean    RequestNTSPublicKeys   = false,
                                              TimeSpan?  Timeout                = null)
        {
            try
            {

                var timeout              = Timeout ?? this.Timeout ?? DefaultTimeout;

                using var tcpClient      = new TcpClient(Host, NTSKE_Port) {
                                               ReceiveTimeout = (Int32) timeout.TotalMilliseconds
                                           };

                using var networkStream  = tcpClient.GetStream();

                var tlsClientProtocol    = new TlsClientProtocol(networkStream);
                var ntsTlsClient         = new NTSKE_TLSClient  (RemoteCertificateValidator);

                tlsClientProtocol.Connect(ntsTlsClient);

                C2S_Key                  = ntsTlsClient.NTS_C2S_Key ?? [];
                S2C_Key                  = ntsTlsClient.NTS_S2C_Key ?? [];

                var ntsKERequest = BuildNTSKERequest(RequestNTSPublicKeys);
                tlsClientProtocol.Stream.Write(ntsKERequest, 0, ntsKERequest.Length);
                tlsClientProtocol.Stream.Flush();

                var buffer               = new Byte[4096];

                var readTask             = Task.Run(() => tlsClientProtocol.Stream.Read(buffer, 0, buffer.Length));
                if (!readTask.Wait(timeout))
                    return new NTSKE_Response("Read operation timed out.");

                var bytesRead            = readTask.Result;
                if (bytesRead > 0)
                {

                    Array.Resize(ref buffer, bytesRead);

                    if (NTSKE_Record.TryParse(buffer, out var records, out var errorResponse))
                        return new NTSKE_Response(
                                   records,
                                   C2S_Key,
                                   S2C_Key
                               );

                }
                else
                {
                    return new NTSKE_Response($"No response received from {Host}!");
                }

            }
            catch (Exception ex)
            {
                return new NTSKE_Response(ex.Message);
            }

            return new NTSKE_Response("Unknown error!");

        }

        #endregion


        #region (private) BuildNTSRequest (NTSKEResponse = null, UniqueId = null)

        /// <summary>
        /// Builds an NTP mode=3 request with minimal NTS EFs:
        ///   1) Unique ID (0104)
        ///   2) NTS Cookie (0204)
        ///   3) NTS Auth & Encrypted (0404) - with placeholder AEAD data
        /// </summary>
        private static NTPRequest BuildNTSRequest(NTSKE_Response?     NTSKEResponse           = null,
                                                  Byte[]?             UniqueId                = null,
                                                  Byte[]?             Plaintext               = null,
                                                  SignedResponseMode  RequestSignedResponse   = SignedResponseMode.None,
                                                  UInt16              SignedResponseKeyId     = 1)
        {

            var ntpPacket1  = new NTPRequest(
                                  TransmitTimestamp: NTPPacket.GetCurrentNTPTimestamp()
                              );

            var extensions  = new List<NTPExtension>();

            if (NTSKEResponse is not null &&
                NTSKEResponse.Cookies.Any() &&
                NTSKEResponse.C2SKey.Length > 0)
            {

                var uniqueIdExtension  = NTPExtension.UniqueIdentifier(UniqueId);
                var cookieExtension    = NTPExtension.NTSCookie(NTSKEResponse.Cookies.First());

                extensions.Add(
                    uniqueIdExtension
                );

                extensions.Add(
                    NTPExtension.NTSCookie(NTSKEResponse.Cookies.First())
                );

                var extensionBytes = new List<Byte[]>() {
                                         ntpPacket1.       ToByteArray(),
                                         uniqueIdExtension.ToByteArray(),
                                         cookieExtension.  ToByteArray()
                                     };

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

        #region QueryTime (Timeout = null, NTSKEResponse = null, SignedResponseMode = None, SignedResponseKeyId = 1, ...)

        /// <summary>
        /// Sends a single NTP request (mode=3) with NTS extension fields:
        ///   1) Unique Identifier extension field
        ///   2) NTS Cookie extension field (cleartext for server)
        ///   3) NTS Authenticator & Encrypted extension field (placeholder)
        /// and reads a single response.
        /// </summary>
        public async Task<NTPPacket?> QueryTime(TimeSpan?           Timeout               = null,
                                                NTSKE_Response?     NTSKEResponse         = null,
                                                SignedResponseMode  SignedResponseMode    = SignedResponseMode.None,
                                                UInt16              SignedResponseKeyId   = 1,
                                                CancellationToken   CancellationToken     = default)
        {

            if (NTSKEResponse?.ErrorMessage is not null)
                return new NTPPacket(NTSKEResponse?.ErrorMessage ?? "Unknown error!");

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

            var requestPacket  = BuildNTSRequest(
                                     NTSKEResponse,
                                     RandomNumberGenerator.GetBytes(32),
                                     Plaintext:              null,
                                     RequestSignedResponse:  SignedResponseMode,
                                     SignedResponseKeyId:    SignedResponseKeyId
                                 );

            var requestData    = requestPacket.ToByteArray();

            using (var udpClient = new UdpClient())
            {

                try
                {

                    await udpClient.SendAsync(
                              requestData,
                              Host,
                              NTP_Port,
                              CancellationToken
                          );

                    var timeout         = Timeout ?? this.Timeout ?? DefaultTimeout;

                    var receiveTask1    = udpClient.ReceiveAsync(CancellationToken).AsTask();
                    var timeoutTask1    = Task.Delay(timeout, CancellationToken);
                    var finishedTask1   = await Task.WhenAny(receiveTask1, timeoutTask1);

                    if (finishedTask1 == timeoutTask1)
                        return new NTPPacket($"No 1st NTP response within {Math.Round(timeout.TotalSeconds, 2)} seconds timeout!");

                    var receiveResult1  = await receiveTask1;

                    if (NTPResponse.TryParse(receiveResult1.Buffer,
                                             out var ntpResponse1,
                                             out var errorResponse1,
                                             Request:           requestPacket,
                                             NTSKey:            NTSKEResponse?.S2CKey,
                                             ExpectedUniqueId:  requestPacket.UniqueIdentifier()))
                    {

                        #region A 2nd signed response was announced

                        if (ntpResponse1.NTSSignedResponseAnnouncement()?.IsScheduled == true)
                        {

                            var receiveTask2    = udpClient.ReceiveAsync(CancellationToken).AsTask();
                            var timeoutTask2    = Task.Delay(timeout, CancellationToken);
                            var finishedTask2   = await Task.WhenAny(receiveTask2, timeoutTask2);

                            if (finishedTask2 == timeoutTask2)
                                return new NTPPacket($"No 2nd NTP response within {Math.Round(timeout.TotalSeconds, 2)} seconds timeout!");

                            var receiveResult2  = await receiveTask2;

                            if (!receiveResult1.Buffer.IsPrefixOf(receiveResult2.Buffer))
                                return new NTPPacket("2nd NTP response is not a prefix of the 1st NTP response!");

                            if (NTPResponse.TryParse(receiveResult2.Buffer,
                                                     out var ntpResponse2,
                                                     out var errorResponse2,
                                                     Request:           requestPacket,
                                                     NTSKey:            NTSKEResponse?.S2CKey,
                                                     ExpectedUniqueId:  requestPacket.UniqueIdentifier()))
                            {
                                return ntpResponse2;
                            }

                            return new NTPPacket("NTP 2nd response error: " + errorResponse2);

                        }

                        #endregion

                        return ntpResponse1;

                    }
                    else
                        return new NTPPacket("NTP 1st response error: " + errorResponse1);

                }
                catch (Exception e)
                {
                    return new NTPPacket("NTP receive exception: " + e.Message);
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
        public static Boolean TryValidateNTSAuthenticatorExtension(Byte[]         ReceivedValue,
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


    }

}
