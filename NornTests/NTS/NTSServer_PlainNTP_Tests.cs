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
    /// A server of NTS alone (<see cref="NTSServer.PlainNTP"/> no): a plain NTP request gets no
    /// answer, NTS goes on as ever, and a request that tried NTS and failed is still told so.
    /// </summary>
    [TestFixture]
    public class NTSServer_PlainNTP_Tests
    {

        #region Data

        private static readonly ISshHostKey  clientKey  = SshHostKey.GenerateEd25519();

        private NTSServer?  ntsOnly;
        private NTSServer?  both;

        #endregion

        #region Start/stop the NTS servers

        [OneTimeSetUp]
        public async Task StartNTSServers()
        {

            ntsOnly = await FreePorts.Start(() => new NTSServer(
                                                      NTSPort:             FreePorts.UDP(),
                                                      MasterKeysFilePath:  null,
                                                      SSHPort:             FreePorts.TCP(),
                                                      SSHAuthenticator:    SshUserAuthenticator.ForAuthorizedKeys(clientKey.PublicKeyBlob),
                                                      NTSKEOverTLS:        false,
                                                      PlainNTP:            false
                                                  ));

            both    = await FreePorts.Start(() => new NTSServer(
                                                      NTSPort:             FreePorts.UDP(),
                                                      MasterKeysFilePath:  null,
                                                      NTSKEOverTLS:        false
                                                  ));

        }

        [OneTimeTearDown]
        public async Task StopNTSServers()
        {

            if (ntsOnly is not null)
                await ntsOnly.ShutdownAsync();

            if (both is not null)
                await both.ShutdownAsync();

        }

        #endregion


        #region SaysWhetherItAnswersPlainNTP()

        [Test]
        public void SaysWhetherItAnswersPlainNTP()
        {
            Assert.That(ntsOnly!.PlainNTP, Is.False);
            Assert.That(both!.   PlainNTP, Is.True, "the default answers plain NTP, as RFC 8915 § 5.7 has it");
        }

        #endregion

        #region APlainRequest_GetsNoAnswer()

        [Test]
        public async Task APlainRequest_GetsNoAnswer()
        {

            var ignoredBefore = ntsOnly!.Metrics.NTPPlainRequestsIgnored;

            Assert.That(await AskAsync(ntsOnly.UDPPort, PlainRequest()), Is.Null, "a server of NTS alone answered plain NTP");

            // Counted on a worker, after the datagram was taken in.
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (ntsOnly.Metrics.NTPPlainRequestsIgnored == ignoredBefore && DateTime.UtcNow < deadline)
                await Task.Delay(20);

            Assert.That(ntsOnly.Metrics.NTPPlainRequestsIgnored, Is.EqualTo(ignoredBefore + 1), ntsOnly.Metrics.ToString());

        }

        #endregion

        #region APlainRequest_IsAnswered_ByDefault()

        [Test]
        public async Task APlainRequest_IsAnswered_ByDefault()
        {

            var answer = await AskAsync(both!.UDPPort, PlainRequest());

            Assert.That(answer,              Is.Not.Null, "the default server answered no plain NTP");
            Assert.That(answer![0] & 0x07,   Is.EqualTo(4), "not a server's answer");
            Assert.That(answer[1],           Is.Not.Zero,   "a kiss instead of the time");
            Assert.That(both.Metrics.NTPPlainRequestsIgnored, Is.Zero);

        }

        #endregion

        #region AFailedNTSRequest_IsStillToldSo()

        /// <summary>
        /// A request that carries a Unique Identifier and nothing else tried NTS: it gets the
        /// NTS NAK of RFC 8915 § 5.7 - a kiss "NTSN" - and not silence, so that its client knows
        /// to make a new key exchange.
        /// </summary>
        [Test]
        public async Task AFailedNTSRequest_IsStillToldSo()
        {

            var request = new Byte[48 + 36];
            PlainRequest().CopyTo(request, 0);

            // RFC 8915 § 5.3: Unique Identifier, type 0x0104, 4 octets of header and 32 of value.
            request[48] = 0x01;
            request[49] = 0x04;
            request[50] = 0x00;
            request[51] = 36;
            Random.Shared.NextBytes(request.AsSpan(52, 32));

            var answer = await AskAsync(ntsOnly!.UDPPort, request);

            Assert.That(answer,                                        Is.Not.Null,     "a failed NTS request was not told");
            Assert.That(answer![1],                                    Is.Zero,         "not a kiss");
            Assert.That(System.Text.Encoding.ASCII.GetString(answer, 12, 4), Is.EqualTo("NTSN"));

        }

        #endregion

        #region KeyExchangeOverSSH_ThenNTP()

        [Test]
        [Category("LocalIntegration")]
        public async Task KeyExchangeOverSSH_ThenNTP()
        {

            var hostKey                = ntsOnly!.SSHHostKeys[0].PublicKeyBlob;

            await using var sshClient  = await SSHClient.Connect(
                                                   "127.0.0.1",
                                                   ntsOnly.SSHPort!.Value,
                                                   new SSHClientOptions {
                                                       Username       = User_Id.Parse("ntske"),
                                                       Credentials    = [ clientKey ],
                                                       VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(hostKey)
                                                   }
                                               );

            var ntsClient              = new NTSClient(
                                             Hermod.DNS.DomainName.Localhost,
                                             NTP_Port:             ntsOnly.UDPPort,
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


        #region (private static) PlainRequest()

        /// <summary>
        /// A plain NTP request: RFC 5905, version 4, mode 3, a transmit timestamp.
        /// </summary>
        private static Byte[] PlainRequest()
        {

            var request  = new Byte[48];
            request[0]   = 0x23;
            Random.Shared.NextBytes(request.AsSpan(40, 8));

            return request;

        }

        #endregion

        #region (private static) AskAsync(NTPPort, Request)

        /// <summary>
        /// The request from 127.0.0.1, and the answer, or null when none came within two seconds.
        /// </summary>
        private static async Task<Byte[]?> AskAsync(IPPort  NTPPort,
                                                    Byte[]  Request)
        {

            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            await udpClient.SendAsync(Request, new IPEndPoint(System.Net.IPAddress.Loopback, NTPPort.ToUInt16()));

            try
            {
                return (await udpClient.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(2))).Buffer;
            }
            catch (TimeoutException)
            {
                return null;
            }

        }

        #endregion

    }

}
