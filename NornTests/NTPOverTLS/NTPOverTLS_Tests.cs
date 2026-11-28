/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Norn <https://www.github.com/Vanaheimr/Norn>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using Org.BouncyCastle.Tls;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPOverTLS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTPOverTLS
{

    /// <summary>
    /// NTP over TLS after BSI TR-03109-5 § 7, Norn's client against Norn's server.
    /// </summary>
    [TestFixture]
    public class NTPOverTLS_Tests
    {

        #region Data

        private static readonly RemoteTLSServerCertificateValidationHandler<NTPOverTLS_TLSClient> AcceptAnyServer
            = (sender, certificate, chain, client, policyErrors) => TLSValidationResult.Success();

        #endregion


        #region (private) StartServer(...)

        private static Task<NTSServer> StartServer(RemoteTLSClientCertificateValidationHandler<NTSServer>?  ClientCertificateValidator  = null,
                                                   TimeSpan?                                                IdleTimeout                 = null,
                                                   Byte?                                                    LeapIndicator               = null)

            => FreePorts.Start(() => new NTSServer(NTSKEPort:                             FreePorts.TCP(),
                                                   NTSPort:                               FreePorts.UDP(),
                                                   MasterKeysFilePath:                    null,
                                                   LeapIndicator:                         LeapIndicator,
                                                   NTPOverTLSPort:                        FreePorts.TCP(),
                                                   NTPOverTLSClientCertificateValidator:  ClientCertificateValidator,
                                                   NTPOverTLSIdleTimeout:                 IdleTimeout));

        private static NTPOverTLSClient ClientOf(NTSServer                                                           Server,
                                                 RemoteTLSServerCertificateValidationHandler<NTPOverTLS_TLSClient>?  Validator          = null,
                                                 Boolean                                                             UseDefaultValidation = false,
                                                 Org.BouncyCastle.X509.X509Certificate?                              ClientCertificate  = null,
                                                 Org.BouncyCastle.Crypto.AsymmetricKeyParameter?                     ClientPrivateKey   = null,
                                                 Boolean                                                             DataMinimization   = true)

            => new ("127.0.0.1",
                    Server.NTPOverTLSPort,
                    UseDefaultValidation ? null : Validator ?? AcceptAnyServer,
                    ClientCertificate,
                    ClientPrivateKey,
                    Timeout:           TimeSpan.FromSeconds(10),
                    DataMinimization:  DataMinimization);

        #endregion


        #region NoPortByDefault()

        [Test]
        public void NoPortByDefault()
        {

            using var server = new NTSServer(MasterKeysFilePath: null);

            Assert.That(server.NTPOverTLSPort,                       Is.Null);
            Assert.That(server.NTPOverTLSRequiresClientCertificate,  Is.False);

        }

        #endregion

        #region AValidatorWithoutAPort_IsRefused()

        [Test]
        public void AValidatorWithoutAPort_IsRefused()
        {

            Assert.That(() => new NTSServer(MasterKeysFilePath:                    null,
                                            NTPOverTLSClientCertificateValidator:  (sender, certificate, chain, server, errors) => TLSValidationResult.Success()),
                        Throws.ArgumentException);

        }

        #endregion


        #region TheTimeIsHadOverTLS13([Values] DataMinimization)

        [Test]
        public async Task TheTimeIsHadOverTLS13([Values] Boolean DataMinimization)
        {

            var server = await StartServer();

            try
            {

                var result = await ClientOf(server, DataMinimization: DataMinimization).QueryTime();

                Assert.That(result.Success,                            Is.True,  result.ToString());
                Assert.That(result.TLSVersion,                         Is.EqualTo("TLS 1.3"));
                Assert.That(result.ClockOffset!.Value.Duration(),      Is.LessThan(TimeSpan.FromSeconds(1)));
                Assert.That(result.RoundTripDelay!.Value,              Is.GreaterThanOrEqualTo(TimeSpan.Zero));
                Assert.That(result.RequestBytes,                       Has.Length.EqualTo(48));
                Assert.That(result.ResponseBytes,                      Has.Length.EqualTo(48));
                Assert.That(result.ClientCertificateRequested,         Is.False);
                Assert.That(server.Metrics.NTPOverTLSResponsesSent,    Is.EqualTo(1), server.Metrics.ToString());
                Assert.That(server.Metrics.NTPRequestsReceived,        Is.Zero,       "NTP over TLS is counted apart from NTP over UDP");

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region AMinimizedRequest_SaysNoMoreThanTable71()

        /// <summary>
        /// REQ.TA.NTP.BuildRequest.40 and Table 7.1: version 4, mode 3, a precision of 32, a
        /// random transmit timestamp, and zero everywhere else.
        /// </summary>
        [Test]
        public async Task AMinimizedRequest_SaysNoMoreThanTable71()
        {

            var server = await StartServer();

            try
            {

                var result  = await ClientOf(server).QueryTime();
                var request = result.RequestBytes!;

                Assert.That(result.Success,                Is.True, result.ToString());
                Assert.That(request[0],                    Is.EqualTo((4 << 3) | 3));
                Assert.That(request[1],                    Is.Zero, "stratum");
                Assert.That(request[2],                    Is.Zero, "poll");
                Assert.That(request[3],                    Is.EqualTo(32), "precision");
                Assert.That(request.AsSpan(4, 36).ToArray(), Is.All.Zero, "root delay, root dispersion, reference ID and the reference, origin and receive timestamps");
                Assert.That(request.AsSpan(40, 8).ToArray(), Is.Not.All.Zero, "the transmit timestamp is a nonce");

                // The server echoes the nonce, and the offset is right all the same: T1 is the
                // client's own, not the echo.
                Assert.That(result.ResponseBytes!.AsSpan(24, 8).ToArray(), Is.EqualTo(request.AsSpan(40, 8).ToArray()));

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region AnUnsynchronizedServer_IsIgnored()

        /// <summary>
        /// REQ.TA.NTP.ProcessResponse.50: a server that says leap indicator 3.
        /// </summary>
        [Test]
        public async Task AnUnsynchronizedServer_IsIgnored()
        {

            var server = await StartServer(LeapIndicator: 3);

            try
            {

                var result = await ClientOf(server).QueryTime();

                Assert.That(result.Success,    Is.False);
                Assert.That(result.IgnoredBy,  Is.EqualTo("REQ.TA.NTP.ProcessResponse.50"), result.ToString());

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region ASelfSignedServer_IsRefusedWithoutAValidator()

        /// <summary>
        /// REQ.TA.TLS.Handshake.130/160: the server's certificate has to chain to a trusted
        /// root, and Norn's self-signed one does not.
        /// </summary>
        [Test]
        public async Task ASelfSignedServer_IsRefusedWithoutAValidator()
        {

            var server = await StartServer();

            try
            {

                var result = await ClientOf(server, UseDefaultValidation: true).QueryTime();

                Assert.That(result.Success,                  Is.False);
                Assert.That(result.ErrorMessage,             Does.Contain("handshake"), result.ToString());
                Assert.That(result.CertificatePolicyErrors,  Is.Not.EqualTo(System.Net.Security.SslPolicyErrors.None));

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion


        #region AClientCertificate_IsRequiredWhereAValidatorIsGiven()

        [Test]
        public async Task AClientCertificate_IsRequiredWhereAValidatorIsGiven()
        {

            var server = await StartServer((sender, certificate, chain, ntsServer, errors) => TLSValidationResult.Success());

            try
            {

                var result = await ClientOf(server).QueryTime();

                Assert.That(result.Success,                                Is.False, "no certificate, no time");
                Assert.That(result.ClientCertificateRequested,             Is.True);
                Assert.That(result.ClientCertificateSent,                  Is.False);
                Assert.That(server.Metrics.NTPOverTLSResponsesSent,        Is.Zero);

                await WaitFor(() => server.Metrics.NTPOverTLSHandshakeFailures == 1);

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region AClientCertificate_IsShownToTheValidator()

        [Test]
        public async Task AClientCertificate_IsShownToTheValidator()
        {

            var (certificate, privateKey) = NTSKE_TLSService.GenerateSelfSignedServerCertificate("CN=cls-adapter.test", [ "cls-adapter.test" ]);

            X509Certificate2? seen = null;

            var server = await StartServer((sender, clientCertificate, chain, ntsServer, errors) => {
                                               seen = clientCertificate;
                                               return TLSValidationResult.Success();
                                           });

            try
            {

                var result = await ClientOf(server, ClientCertificate: certificate, ClientPrivateKey: privateKey).QueryTime();

                Assert.That(result.Success,                Is.True, result.ToString());
                Assert.That(result.ClientCertificateSent,  Is.True);
                Assert.That(seen?.Subject,                 Is.EqualTo("CN=cls-adapter.test"));

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region AClientCertificateTheValidatorRefuses_GetsNoTime()

        [Test]
        public async Task AClientCertificateTheValidatorRefuses_GetsNoTime()
        {

            var (certificate, privateKey) = NTSKE_TLSService.GenerateSelfSignedServerCertificate("CN=stranger.test", [ "stranger.test" ]);

            var server = await StartServer((sender, clientCertificate, chain, ntsServer, errors)
                                               => new TLSValidationResult(false, null));

            try
            {

                var result = await ClientOf(server, ClientCertificate: certificate, ClientPrivateKey: privateKey).QueryTime();

                Assert.That(result.Success,                          Is.False);
                Assert.That(server.Metrics.NTPOverTLSResponsesSent,  Is.Zero);

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion


        #region OneConnection_CarriesManyRequests()

        /// <summary>
        /// The server answers as many requests as one connection brings, each with the origin
        /// timestamp of its own.
        /// </summary>
        [Test]
        public async Task OneConnection_CarriesManyRequests()
        {

            var server = await StartServer();

            try
            {

                using var tcp      = new TcpClient();
                await tcp.ConnectAsync(System.Net.IPAddress.Loopback, server.NTPOverTLSPort!.Value.ToUInt16());
                tcp.Client.ReceiveTimeout = 10_000;

                var protocol       = new TlsClientProtocol(tcp.GetStream());
                protocol.Connect(new NTPOverTLS_TLSClient(AcceptAnyServer, ExpectedIPAddress: System.Net.IPAddress.Loopback));

                for (UInt64 nonce = 1; nonce <= 3; nonce++)
                {

                    var request  = new Byte[48];
                    request[0]   = (4 << 3) | 3;
                    System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(request.AsSpan(40), nonce * 0x0123456789ABCDEFUL);

                    protocol.Stream.Write(request);
                    protocol.Stream.Flush();

                    var response = new Byte[48];
                    protocol.Stream.ReadExactly(response);

                    Assert.That(response[0] & 0x07,                                                         Is.EqualTo(4), "mode 4");
                    Assert.That(System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(response.AsSpan(24)), Is.EqualTo(nonce * 0x0123456789ABCDEFUL));

                }

                protocol.Close();

                Assert.That(server.Metrics.NTPOverTLSResponsesSent, Is.EqualTo(3));

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region ANonClientMessage_ClosesTheConnection([Values(1, 4)] Mode)

        [Test]
        public async Task ANonClientMessage_ClosesTheConnection([Values(1, 4)] Int32 Mode)
        {

            var server = await StartServer();

            try
            {

                using var tcp      = new TcpClient();
                await tcp.ConnectAsync(System.Net.IPAddress.Loopback, server.NTPOverTLSPort!.Value.ToUInt16());
                tcp.Client.ReceiveTimeout = 10_000;

                var protocol       = new TlsClientProtocol(tcp.GetStream());
                protocol.Connect(new NTPOverTLS_TLSClient(AcceptAnyServer, ExpectedIPAddress: System.Net.IPAddress.Loopback));

                var request  = new Byte[48];
                request[0]   = (Byte) ((4 << 3) | Mode);

                protocol.Stream.Write(request);
                protocol.Stream.Flush();

                Assert.That(protocol.Stream.Read(new Byte[48], 0, 48), Is.Zero, "no answer, and the connection closed");

                await WaitFor(() => server.Metrics.NTPOverTLSRequestsInvalid == 1);

                Assert.That(server.Metrics.NTPOverTLSResponsesSent, Is.Zero);

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region AnIdleConnection_IsClosed()

        [Test]
        public async Task AnIdleConnection_IsClosed()
        {

            var server = await StartServer(IdleTimeout: TimeSpan.FromMilliseconds(500));

            try
            {

                using var tcp      = new TcpClient();
                await tcp.ConnectAsync(System.Net.IPAddress.Loopback, server.NTPOverTLSPort!.Value.ToUInt16());
                tcp.Client.ReceiveTimeout = 10_000;

                var protocol       = new TlsClientProtocol(tcp.GetStream());
                protocol.Connect(new NTPOverTLS_TLSClient(AcceptAnyServer, ExpectedIPAddress: System.Net.IPAddress.Loopback));

                var started = System.Diagnostics.Stopwatch.StartNew();

                // Closed cleanly, with close_notify, or torn down: either way nothing more comes.
                var read = -1;

                try
                {
                    read = protocol.Stream.Read(new Byte[48], 0, 48);
                }
                catch (IOException)
                {
                    read = 0;
                }

                Assert.That(read, Is.Zero, "the server closes a silent connection");

                Assert.That(started.Elapsed, Is.LessThan(TimeSpan.FromSeconds(9)));

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion


        #region (private static) WaitFor(Condition)

        private static async Task WaitFor(Func<Boolean> Condition)
        {

            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);

            while (!Condition())
            {

                if (DateTime.UtcNow > deadline)
                    Assert.Fail("The condition did not come true within 10 s.");

                await Task.Delay(20);

            }

        }

        #endregion

    }

}
