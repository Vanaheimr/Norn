/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Norn <https://www.github.com/Vanaheimr/Norn>
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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.Monitoring
{

    /// <summary>
    /// A server measured with its key exchange over SSH - the subsystem
    /// "ntske/1@open.charging.cloud" of the white paper "NTS Key Establishment
    /// over SSH" - on the connection its endpoint makes: a time server a node
    /// reaches by its SSH host key and a key of its own, without a certificate.
    /// </summary>
    /// <remarks>
    /// Against a server of Norn's own with an SSH listener of its own, on the
    /// loopback interface. The endpoint's NTS-KE port over TLS is one nobody
    /// listens on, so that a key exchange that went over TLS after all fails.
    /// </remarks>
    [TestFixture]
    [Category("LocalIntegration")]
    public class MeasurementEngine_SSH_Tests
    {

        #region Data

        private static readonly IPPort       tlsPort      = FindFreeTCPPort();
        private static readonly IPPort       sshPort      = FindFreeTCPPort();
        private static readonly IPPort       ntpPort      = FindFreeUDPPort();
        private static readonly IPPort       nobodysPort  = FindFreeTCPPort();

        private static readonly DomainName   loopback     = DomainName.Parse("127.0.0.1");

        private static readonly ISshHostKey  clientKey    = SshHostKey.GenerateEd25519();
        private static readonly ISshHostKey  strangerKey  = SshHostKey.GenerateEd25519();

        private NTSServer? ntsServer;

        #endregion

        #region Setup / TearDown

        [OneTimeSetUp]
        public async Task StartNTSServer()
        {

            ntsServer = new NTSServer(
                            NTSKEPort:           tlsPort,
                            NTSPort:             ntpPort,
                            MasterKeysFilePath:  null,
                            SSHPort:             sshPort,
                            SSHAuthenticator:    SshUserAuthenticator.ForAuthorizedKeys(clientKey.PublicKeyBlob)
                        );

            await ntsServer.Start();

        }

        [OneTimeTearDown]
        public async Task StopNTSServer()
        {
            if (ntsServer is not null)
                await ntsServer.ShutdownAsync();
        }

        #endregion


        #region (helpers) Engine() / Endpoint(Key, HostKeyBelieved) / NoNameServers()

        private static MeasurementEngine Engine()

            => new (new MonitoringConfig {
                        DroneId       = "engine-ssh-tests",
                        NTPTimeout    = TimeSpan.FromSeconds(5),
                        NTSKETimeout  = TimeSpan.FromSeconds(10)
                    });

        /// <summary>
        /// The server at 127.0.0.1, its key exchange over SSH: signed in with the
        /// given key, its host key believed where it is the server's - or never.
        /// </summary>
        private NTSServerEndpoint Endpoint(ISshHostKey  Key,
                                           Boolean      HostKeyBelieved = true)
        {

            var hostKey = ntsServer!.SSHHostKeys[0].PublicKeyBlob;

            return new NTSServerEndpoint(loopback, nobodysPort, ntpPort) {
                       ConnectOverSSH = cancellationToken => SshClient.ConnectAsync(
                                                                 "127.0.0.1",
                                                                 sshPort.ToUInt16(),
                                                                 new SshClientOptions {
                                                                     Username       = "ntske",
                                                                     Credentials    = [ Key ],
                                                                     VerifyHostKey  = blob => HostKeyBelieved && blob.AsSpan().SequenceEqual(hostKey)
                                                                 },
                                                                 cancellationToken
                                                             )
                   };

        }

        private static DNSClient NoNameServers()

            => new (SearchForIPv4DNSServers: false,
                    SearchForIPv6DNSServers: false);

        #endregion


        #region AServerIsMeasuredWithItsKeyExchangeOverSSH()

        /// <summary>
        /// The key exchange goes over the SSH connection of the endpoint, never
        /// to its port of NTS-KE over TLS; the cookies it brought are used for
        /// NTP, the host key the server showed is kept with it, and the next
        /// measurement reuses it.
        /// </summary>
        [Test]
        public async Task AServerIsMeasuredWithItsKeyExchangeOverSSH()
        {

            var engine    = Engine();
            var endpoint  = Endpoint(clientKey);

            var first     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());
            var second    = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            var hostKey   = SshFingerprint.Sha256(ntsServer!.SSHHostKeys[0].PublicKeyBlob);

            Assert.Multiple(() => {

                Assert.That(first.Success,                                   Is.True,  first.ErrorMessage?.ToString());
                Assert.That(first.NTSKE?.Success,                            Is.True,  first.NTSKE?.ErrorMessage?.ToString());
                Assert.That(first.NTSKE?.SSHHostKey,                         Is.EqualTo(hostKey));
                Assert.That(first.NTSKE?.CertificateInfo,                    Is.Null,  "a certificate, over SSH");
                Assert.That(first.NTP,                                       Is.Not.Null, "the server was not asked for the time");

                Assert.That(engine.KeyExchanges.TryGetValue(loopback, out var kept), Is.True, "the key exchange was not kept");
                Assert.That(kept?.SSHHostKey,                                Is.EqualTo(hostKey));
                Assert.That(kept?.NTSClient?.CookiePoolPolicy.RenegotiateWhenExhausted, Is.False,
                            "the client would renew its cookies over TLS by itself");

                Assert.That(second.Success,                                  Is.True,  second.ErrorMessage?.ToString());
                Assert.That(second.NTSKEFromCache,                           Is.True,  "the key exchange was made again");

            });

        }

        #endregion

        #region AConnectionThatIsSharedStaysOpen()

        /// <summary>
        /// A connection the endpoint shares - the SSH connection of OCPP,
        /// section 8.3 of the white paper - carries the key exchange as one more
        /// channel and is left open after it: the next key exchange goes over
        /// the same connection. One of the endpoint's own is closed after its
        /// key exchange.
        /// </summary>
        [Test]
        public async Task AConnectionThatIsSharedStaysOpen()
        {

            var hostKey         = ntsServer!.SSHHostKeys[0].PublicKeyBlob;

            await using var shared = await SshClient.ConnectAsync(
                                               "127.0.0.1",
                                               sshPort.ToUInt16(),
                                               new SshClientOptions {
                                                   Username       = "ntske",
                                                   Credentials    = [ clientKey ],
                                                   VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(hostKey)
                                               }
                                           );

            var connections = 0;

            var engine          = Engine();
            var endpoint        = new NTSServerEndpoint(loopback, nobodysPort, ntpPort) {
                                      ConnectOverSSH         = cancellationToken => { connections++; return ValueTask.FromResult(shared); },
                                      SSHConnectionIsShared  = true
                                  };

            var first           = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());
            engine.ForgetKeyExchange(loopback);
            var second          = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            SshClient? own      = null;
            var ownEndpoint     = Endpoint(clientKey);
            var connect         = ownEndpoint.ConnectOverSSH!;
            ownEndpoint.ConnectOverSSH = async cancellationToken => own = await connect(cancellationToken);

            var third           = await Engine().MeasureSingleServer(ownEndpoint, Guid.NewGuid(), NoNameServers());

            Assert.Multiple(() => {

                Assert.That(first.NTSKE?.Success,           Is.True,  first. NTSKE?.ErrorMessage?.ToString());
                Assert.That(second.NTSKE?.Success,          Is.True,  second.NTSKE?.ErrorMessage?.ToString());
                Assert.That(second.NTSKEFromCache,          Is.False, "the second key exchange was not made");
                Assert.That(connections,                    Is.EqualTo(2));
                Assert.That(shared.Closed.IsCompleted,      Is.False, "the shared connection was closed");

                Assert.That(third.NTSKE?.Success,           Is.True,  third. NTSKE?.ErrorMessage?.ToString());
                Assert.That(own,                            Is.Not.Null);
                Assert.That(own!.Closed.IsCompleted,        Is.True,  "the endpoint's own connection was left open");

            });

        }

        #endregion

        #region AHostKeyThatIsNotBelievedIsNoKeyExchange()

        /// <summary>
        /// A host key the endpoint does not believe ends the connection before
        /// any key exchange: the measurement fails as one of SSH, the server is
        /// not asked for the time, and nothing is kept.
        /// </summary>
        [Test]
        public async Task AHostKeyThatIsNotBelievedIsNoKeyExchange()
        {

            var engine  = Engine();
            var result  = await engine.MeasureSingleServer(Endpoint(clientKey, HostKeyBelieved: false), Guid.NewGuid(), NoNameServers());

            Assert.Multiple(() => {
                Assert.That(result.Success,                             Is.False);
                Assert.That(result.NTSKE?.Success,                      Is.False);
                Assert.That(result.NTSKE?.ErrorCategory,                Is.EqualTo(MonitoringErrorCategory.SSH));
                Assert.That(result.NTSKE?.ErrorMessage?.ToString(),     Does.Contain("NTS-KE over SSH"));
                Assert.That(result.NTP,                                 Is.Null,  "the server was asked for the time");
                Assert.That(engine.KeyExchanges.ContainsKey(loopback),  Is.False, "a key exchange that failed was kept");
            });

        }

        #endregion

        #region AClientTheServerDoesNotLetInMakesNoKeyExchange()

        /// <summary>
        /// A key the server does not know is no key exchange either.
        /// </summary>
        [Test]
        public async Task AClientTheServerDoesNotLetInMakesNoKeyExchange()
        {

            var engine  = Engine();
            var result  = await engine.MeasureSingleServer(Endpoint(strangerKey), Guid.NewGuid(), NoNameServers());

            Assert.Multiple(() => {
                Assert.That(result.NTSKE?.Success,                      Is.False);
                Assert.That(result.NTSKE?.ErrorCategory,                Is.EqualTo(MonitoringErrorCategory.SSH));
                Assert.That(engine.KeyExchanges.ContainsKey(loopback),  Is.False);
            });

        }

        #endregion


        #region (private static) FindFreeTCPPort() / FindFreeUDPPort()

        private static IPPort FindFreeTCPPort()
        {

            using var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);

            listener.Start();

            return IPPort.Parse(((IPEndPoint) listener.LocalEndpoint).Port);

        }

        private static IPPort FindFreeUDPPort()
        {

            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            return IPPort.Parse(((IPEndPoint) udpClient.Client.LocalEndPoint!).Port);

        }

        #endregion

    }

}
