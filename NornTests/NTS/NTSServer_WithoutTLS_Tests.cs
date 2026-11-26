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

using System.Net;
using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// A server whose key exchange goes over SSH alone (<see cref="NTSServer.NTSKEOverTLS"/> no):
    /// NTP over UDP and NTS-KE over SSH as ever, and no TCP port for NTS-KE over TLS.
    /// </summary>
    [TestFixture]
    public class NTSServer_WithoutTLS_Tests
    {

        #region Data

        private static readonly ISshHostKey  clientKey  = SshHostKey.GenerateEd25519();

        private NTSServer?  ntsServer;
        private IPPort      tlsPort;

        #endregion

        #region Start/stop the NTS server

        [OneTimeSetUp]
        public async Task StartNTSServer()
        {

            ntsServer = await FreePorts.Start(() => new NTSServer(
                                                        NTSKEPort:           FreePorts.TCP(),
                                                        NTSPort:             FreePorts.UDP(),
                                                        MasterKeysFilePath:  null,
                                                        SSHPort:             FreePorts.TCP(),
                                                        SSHAuthenticator:    SshUserAuthenticator.ForAuthorizedKeys(clientKey.PublicKeyBlob),
                                                        NTSKEOverTLS:        false
                                                    ));

            tlsPort = ntsServer.TCPPort;

        }

        [OneTimeTearDown]
        public async Task StopNTSServer()
        {
            if (ntsServer is not null)
                await ntsServer.ShutdownAsync();
        }

        #endregion


        #region SaysItHasNoKeyExchangeOverTLS()

        [Test]
        public void SaysItHasNoKeyExchangeOverTLS()
        {
            Assert.That(ntsServer!.NTSKEOverTLS,                    Is.False);
            Assert.That(new NTSServer(MasterKeysFilePath: null).NTSKEOverTLS, Is.True, "the default is RFC 8915's key exchange over TLS");
        }

        #endregion

        #region BindsNoPortForTheKeyExchangeOverTLS()

        /// <summary>
        /// Nothing listens on the port the key exchange over TLS would have had: the port can be
        /// bound by somebody else while the server runs.
        /// </summary>
        [Test]
        public void BindsNoPortForTheKeyExchangeOverTLS()
        {

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            Assert.That(() => socket.Bind(new IPEndPoint(System.Net.IPAddress.Any, tlsPort.ToUInt16())),
                        Throws.Nothing,
                        $"port {tlsPort} is bound although NTS-KE over TLS is off");

        }

        #endregion

        #region StoppedRightAfterItStarted_StopsWithoutComplaint()

        /// <summary>
        /// Stopped at once after it started - a time server switched on and off again, a start
        /// that fails just after: the loop that never got to run is no failure of the stop. It
        /// used to throw "A task was canceled." where the stop came before the loop began.
        /// </summary>
        [Test]
        public async Task StoppedRightAfterItStarted_StopsWithoutComplaint()
        {

            for (var i = 0; i < 100; i++)
            {

                // FreePorts.Start rather than a bare Start: a hundred ports found free and let
                // go again are a hundred chances for a parallel test to take one in between.
                var server = await FreePorts.Start(() => new NTSServer(
                                                             NTSPort:             FreePorts.UDP(),
                                                             MasterKeysFilePath:  null,
                                                             NTSKEOverTLS:        false
                                                         ));

                Assert.That(async () => await server.ShutdownAsync(), Throws.Nothing, $"the stop {i + 1} complained");

            }

        }

        #endregion

        #region KeyExchangeOverSSH_ThenNTP()

        [Test]
        [Category("LocalIntegration")]
        public async Task KeyExchangeOverSSH_ThenNTP()
        {

            var hostKey                = ntsServer!.SSHHostKeys[0].PublicKeyBlob;

            await using var sshClient  = await SSHClient.Connect(
                                                   "127.0.0.1",
                                                   ntsServer.SSHPort!.Value,
                                                   new SSHClientOptions {
                                                       Username       = User_Id.Parse("ntske"),
                                                       Credentials    = [ clientKey ],
                                                       VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(hostKey)
                                                   }
                                               );

            var ntsClient              = new NTSClient(
                                             Hermod.DNS.DomainName.Localhost,
                                             NTP_Port:             ntsServer.UDPPort,
                                             IPVersionPreference:  IPVersionPreference.IPv4Only
                                         );

            var ntsKEResult            = await ntsClient.GetNTSKERecordsOverSSH(sshClient);

            Assert.That(ntsKEResult.Success,  Is.True, ntsKEResult.ErrorMessage);

            var ntsQueryResult         = await ntsClient.QueryTime(NTSKEResponse: ntsKEResult.Response!,
                                                                   Timeout:       TimeSpan.FromSeconds(10));

            Assert.That(ntsQueryResult.Success,        Is.True, ntsQueryResult.ErrorMessage);
            Assert.That(ntsQueryResult.ErrorCategory,  Is.EqualTo(NTSQueryErrorCategory.None));

        }

        #endregion

    }

}
