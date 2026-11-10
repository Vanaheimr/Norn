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
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using IPAddress = System.Net.IPAddress;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// The access list of RFC 8633 § 5.1: which addresses it allows, which lists it refuses to
    /// make, and a server that answers an address it denies nowhere - over NTP, over NTS-KE and
    /// over its own SSH listener.
    /// </summary>
    [TestFixture]
    public class NTPAccessList_Tests
    {

        #region The list

        [Test]
        public void Everyone_AllowsEveryAddress_AndOneThatCannotBeTold()
        {

            var everyone = NTPAccessList.Everyone;

            Assert.Multiple(() => {
                Assert.That(everyone.IsEveryone,                                  Is.True);
                Assert.That(everyone.Allows(IPAddress.Parse("192.0.2.7")),        Is.True);
                Assert.That(everyone.Allows(IPAddress.Parse("2001:db8::7")),      Is.True);
                Assert.That(everyone.Allows(null),                                Is.True);
                Assert.That(new NTPAccessList().IsEveryone,                       Is.True);
                Assert.That(everyone.ToString(),                                  Is.EqualTo("everyone"));
            });

        }


        [TestCase(false)]
        [TestCase(true)]
        public void TheMostSpecificNetworkDecides_InWhateverOrderTheyAreGiven(Boolean Reversed)
        {

            IEnumerable<IPNetwork> deny   = [ .. Networks("all"), .. Networks("10.66.0.0/16") ];
            IEnumerable<IPNetwork> allow  = Networks("10.0.0.0/8,2001:db8::/32");

            var list = Reversed
                           ? new NTPAccessList(Allow: allow.Reverse(), Deny: deny.Reverse())
                           : new NTPAccessList(Allow: allow,           Deny: deny);

            Assert.Multiple(() => {
                Assert.That(list.Allows(IPAddress.Parse("10.1.2.3")),       Is.True,   "inside the allowed 10.0.0.0/8");
                Assert.That(list.Allows(IPAddress.Parse("10.66.1.1")),      Is.False,  "inside the denied 10.66.0.0/16, inside the allowed 10.0.0.0/8");
                Assert.That(list.Allows(IPAddress.Parse("192.0.2.7")),      Is.False,  "only inside the denied 0.0.0.0/0");
                Assert.That(list.Allows(IPAddress.Parse("2001:db8::7")),    Is.True,   "inside the allowed 2001:db8::/32");
                Assert.That(list.Allows(IPAddress.Parse("2001:db9::7")),    Is.False,  "only inside the denied ::/0");
            });

        }


        [Test]
        public void AnAddressNoNetworkContains_IsAllowed()
        {

            var list = new NTPAccessList(Deny: Networks("192.0.2.0/24"));

            Assert.Multiple(() => {
                Assert.That(list.IsEveryone,                                 Is.False);
                Assert.That(list.Allows(IPAddress.Parse("192.0.2.7")),       Is.False);
                Assert.That(list.Allows(IPAddress.Parse("198.51.100.7")),    Is.True);
                Assert.That(list.Allows(IPAddress.Parse("2001:db8::7")),     Is.True);
            });

        }


        [Test]
        public void AnIPv4AddressFromADualStackSocket_IsMatchedAsIPv4()
        {

            var list = new NTPAccessList(Deny: Networks("192.0.2.0/24"));

            Assert.That(list.Allows(IPAddress.Parse("::ffff:192.0.2.7")),    Is.False);
            Assert.That(list.Allows(IPAddress.Parse("::ffff:198.51.100.7")), Is.True);

        }


        [Test]
        public void AnAddressThatCannotBeTold_IsDenied_ByAListOfNetworks()
        {
            Assert.That(new NTPAccessList(Deny: Networks("192.0.2.0/24")).Allows(null), Is.False);
        }


        [TestCase("",              "10.0.0.0/8",              "everything that is not denied is allowed")]
        [TestCase("all",           "10.0.0.0/8,10.1.0.0/16",  "10.0.0.0/8 around it is allowed already")]
        [TestCase("10.0.0.0/8,10.1.0.0/16", "",               "10.0.0.0/8 around it is denied already")]
        [TestCase("all",           "0.0.0.0/0",               "both allowed and denied")]
        [TestCase("::ffff:0:0/96", "",                        "IPv4 written as IPv6")]
        public void ANetworkThatChangesNothing_IsRefused(String  Deny,
                                                          String  Allow,
                                                          String  Reason)
        {

            Assert.That(() => new NTPAccessList(Allow:  Allow.Length > 0 ? Networks(Allow) : null,
                                                Deny:   Deny. Length > 0 ? Networks(Deny)  : null),
                        Throws.ArgumentException.With.Message.Contains(Reason));

        }


        [Test]
        public void TheList_ReadsAsItWasMeant()
        {

            var list = new NTPAccessList(Allow: Networks("10.0.0.0/8"), Deny: Networks("all"));

            Assert.That(list.ToString(), Is.EqualTo("deny 0.0.0.0/0, ::/0; allow 10.0.0.0/8"));

        }

        #endregion

        #region Networks as an operator writes them

        [TestCase("all",                       "0.0.0.0/0", "::/0")]
        [TestCase("192.0.2.7",                 "192.0.2.7/32")]
        [TestCase("2001:db8::7",               "2001:db8::7/128")]
        [TestCase("10.0.0.0/8, 2001:db8::/32", "10.0.0.0/8", "2001:db8::/32")]
        [TestCase("0.0.0.0/0",                 "0.0.0.0/0")]
        public void Networks_AreRead(String Text, params String[] Expected)
        {
            Assert.That(NTPAccessList.ParseNetworks(Text).Select(network => network.ToString()),
                        Is.EqualTo(Expected));
        }


        [TestCase("10.1.2.3/8",     "bits set beyond its prefix: the network is 10.0.0.0/8, the address alone is 10.1.2.3/32")]
        [TestCase("10.0.0.0/33",    "from 0 to 32")]
        [TestCase("2001:db8::/129", "from 0 to 128")]
        [TestCase("10.0.0.0/-1",    "from 0 to 32")]
        [TestCase("10.0.0.0/",      "from 0 to 32")]
        [TestCase("time.example",   "not an IP address")]
        [TestCase("",               "not an IP address")]
        [TestCase("fe80::1%3",      "not an IP address")]
        public void WhatIsNotANetwork_IsRefused(String Text, String Reason)
        {
            Assert.That(() => NTPAccessList.ParseNetworks(Text),
                        Throws.InstanceOf<FormatException>().With.Message.Contains(Reason));
        }

        #endregion


        #region A server that denies an address

        [Test]
        [Category("LocalIntegration")]
        public async Task ADeniedAddress_GetsNoNTPAnswer_NotEvenAKiss()
        {

            var (server, _, ntpPort, _) = await StartServerAsync(new NTPAccessList(Deny: Networks("127.0.0.0/8")));

            try
            {

                var response = await AskForTheTimeAsync(ntpPort);

                Assert.Multiple(() => {
                    Assert.That(response,                               Is.Null,         "a denied address was answered");
                    Assert.That(server.Metrics.NTPRequestsDenied,       Is.EqualTo(1),   server.Metrics.ToString());
                    Assert.That(server.Metrics.NTPRequestsRateLimited,  Is.Zero);
                    Assert.That(server.Metrics.NTPKissesOfDeathSent,    Is.Zero);
                    Assert.That(server.Metrics.NTPResponsesSent,        Is.Zero);
                });

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }


        [Test]
        [Category("LocalIntegration")]
        public async Task ADeniedAddress_IsClosedBeforeTheTLSHandshake()
        {

            var (server, kePort, _, _) = await StartServerAsync(new NTPAccessList(Deny: Networks("127.0.0.0/8")));

            try
            {

                // A TLS server waits for the ClientHello, so an allowed client that sends nothing
                // is kept until the handshake times out. A denied one is closed at once.
                using var tcpClient  = new TcpClient();
                await tcpClient.ConnectAsync(IPAddress.Loopback, kePort.ToUInt16());

                var buffer           = new Byte[1];
                var read             = -1;

                try
                {
                    read = await tcpClient.GetStream().ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
                }
                catch (IOException)
                {
                    read = 0;    // closed with a reset rather than a FIN
                }

                Assert.Multiple(() => {
                    Assert.That(read,                                   Is.Zero,  "the connection was not closed");
                    Assert.That(server.Metrics.NTSKEConnectionsDenied,  Is.EqualTo(1),  server.Metrics.ToString());
                    Assert.That(server.Metrics.NTSKEHandshakeFailures,  Is.Zero,  "a handshake was begun");
                    Assert.That(server.Metrics.NTSKEResponsesSent,      Is.Zero);
                });

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }


        [Test]
        [Category("LocalIntegration")]
        public async Task ADeniedAddress_IsTurnedAwayByTheSSHListener()
        {

            var (server, _, ntpPort, sshPort) = await StartServerAsync(new NTPAccessList(Deny: Networks("127.0.0.0/8")),
                                                                       WithSSH: true);

            try
            {

                Assert.That(async () => {
                                await using var sshClient = await ConnectAsync(server, sshPort);
                                var result = await NewNTSClient(ntpPort).GetNTSKERecordsOverSSH(sshClient, Timeout: TimeSpan.FromSeconds(5));
                                if (!result.Success)
                                    throw new Exception(result.ErrorMessage);
                            },
                            Throws.Exception);

                Assert.Multiple(() => {
                    Assert.That(server.Metrics.NTSKEConnectionsDenied,  Is.EqualTo(1),  server.Metrics.ToString());
                    Assert.That(server.Metrics.NTSKEResponsesSent,      Is.Zero);
                });

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }


        /// <summary>
        /// The control: the same server, with the one address allowed inside everything denied,
        /// answers it everywhere.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task AnAllowedAddress_InsideEverythingDenied_IsAnsweredEverywhere()
        {

            var (server, kePort, ntpPort, sshPort) = await StartServerAsync(new NTPAccessList(Allow: Networks("127.0.0.1"),
                                                                                              Deny:  Networks("all")),
                                                                            WithSSH: true);

            try
            {

                var ntpResponse   = await AskForTheTimeAsync(ntpPort);

                var ntsClient     = NewNTSClient(ntpPort, kePort);
                var overTLS       = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: false);
                var query         = overTLS.Success
                                        ? await ntsClient.QueryTime(NTSKEResponse: overTLS.Response!, Timeout: TimeSpan.FromSeconds(5))
                                        : null;

                await using var sshClient = await ConnectAsync(server, sshPort);
                var overSSH       = await NewNTSClient(ntpPort).GetNTSKERecordsOverSSH(sshClient);

                Assert.Multiple(() => {
                    Assert.That(ntpResponse,                            Is.Not.Null,  "NTP was not answered");
                    Assert.That(overTLS.Success,                        Is.True,      overTLS.ErrorMessage);
                    Assert.That(query?.Success,                         Is.True,      query?.ErrorMessage);
                    Assert.That(overSSH.Success,                        Is.True,      overSSH.ErrorMessage);
                    Assert.That(server.Metrics.NTPRequestsDenied,       Is.Zero);
                    Assert.That(server.Metrics.NTSKEConnectionsDenied,  Is.Zero);
                });

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion


        #region (private static) Networks(Text)

        private static IReadOnlyList<IPNetwork> Networks(String Text)
            => NTPAccessList.ParseNetworks(Text);

        #endregion

        #region (private static) StartServerAsync(AccessList, WithSSH = false)

        private static readonly ISshHostKey clientKey = SshHostKey.GenerateEd25519();

        private static async Task<(NTSServer Server, IPPort KEPort, IPPort NTPPort, IPPort SSHPort)>

            StartServerAsync(NTPAccessList  AccessList,
                             Boolean        WithSSH  = false)

        {

            var kePort   = FindFreeTCPPort();
            var ntpPort  = FindFreeUDPPort();
            var sshPort  = FindFreeTCPPort();

            var server   = new NTSServer(
                               NTSKEPort:           kePort,
                               NTSPort:             ntpPort,
                               MasterKeysFilePath:  null,
                               SSHPort:             WithSSH ? sshPort : null,
                               SSHAuthenticator:    WithSSH ? SshUserAuthenticator.ForAuthorizedKeys(clientKey.PublicKeyBlob) : null,
                               AccessList:          AccessList
                           );

            await server.Start();

            return (server, kePort, ntpPort, sshPort);

        }

        #endregion

        #region (private static) AskForTheTimeAsync(NTPPort)

        /// <summary>
        /// A plain NTP request (RFC 5905: version 4, mode 3) from 127.0.0.1, and the answer, or
        /// null when none came within two seconds.
        /// </summary>
        private static async Task<Byte[]?> AskForTheTimeAsync(IPPort NTPPort)
        {

            using var udpClient  = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));

            var request          = new Byte[48];
            request[0]           = 0x23;
            Random.Shared.NextBytes(request.AsSpan(40, 8));

            await udpClient.SendAsync(request, new IPEndPoint(IPAddress.Loopback, NTPPort.ToUInt16()));

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

        #region (private static) NewNTSClient(NTPPort, KEPort = null)

        private static NTSClient NewNTSClient(IPPort   NTPPort,
                                              IPPort?  KEPort = null)

            => new (
                   Hermod.DNS.DomainName.Localhost,
                   NTSKE_Port:                  KEPort,
                   NTP_Port:                    NTPPort,
                   IPVersionPreference:         IPVersionPreference.IPv4Only,
                   RemoteCertificateValidator:  (sender, certificate, chain, client, errors) => TLSValidationResult.Success()
               );

        #endregion

        #region (private static) ConnectAsync(Server, SSHPort)

        private static Task<SshClient> ConnectAsync(NTSServer  Server,
                                                    IPPort     SSHPort)
        {

            var hostKey = Server.SSHHostKeys[0].PublicKeyBlob;

            return SshClient.ConnectAsync(
                       "127.0.0.1",
                       SSHPort.ToUInt16(),
                       new SshClientOptions {
                           Username       = "ntske",
                           Credentials    = [ clientKey ],
                           VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(hostKey)
                       }
                   ).AsTask();

        }

        #endregion

        #region (private static) FindFreeTCPPort() / FindFreeUDPPort()

        private static IPPort FindFreeTCPPort()
        {

            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();

            var port = ((IPEndPoint) listener.LocalEndpoint).Port;
            listener.Stop();

            return IPPort.Parse(port);

        }

        private static IPPort FindFreeUDPPort()
        {

            using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));

            return IPPort.Parse(((IPEndPoint) udpClient.Client.LocalEndPoint!).Port);

        }

        #endregion

    }

}
