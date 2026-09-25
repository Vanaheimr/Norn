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
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.Monitoring
{

    /// <summary>
    /// What a measurement engine hands the client that makes a key exchange:
    /// the server's own certificate validator, and the name servers of the
    /// round - and when it makes a key exchange again.
    /// </summary>
    /// <remarks>
    /// Against a server of Norn's own on the loopback interface, as the NTS
    /// server's own tests are: the question is what the engine passes on, and
    /// a public time server would only add the internet to the answer. Its
    /// certificate is issued for ntpKE.example.org, so a key exchange with it
    /// at 127.0.0.1 is one the usual rule refuses - which is what makes a
    /// validator that is not asked impossible to miss.
    /// </remarks>
    [TestFixture]
    [Category("LocalIntegration")]
    public class MeasurementEngine_Tests
    {

        #region Data

        private static readonly IPPort      ntsKEPort  = FindFreeTCPPort();
        private static readonly IPPort      ntpPort    = FindFreeUDPPort();

        private static readonly DomainName  loopback   = DomainName.Parse("127.0.0.1");

        private NTSServer? ntsServer;

        #endregion

        #region Setup / TearDown

        [OneTimeSetUp]
        public async Task StartNTSServer()
        {

            ntsServer = new NTSServer(
                            NTSKEPort:           ntsKEPort,
                            NTSPort:             ntpPort,
                            MasterKeysFilePath:  null,
                            KeyPair:             new KeyPair(
                                                     Id:                  1,
                                                     PrivateKey:          "2bs8BuOqUr5I9b8ksVdW3xTu8KmDr1fHLvusDxI34J4=".FromBASE64(),
                                                     PublicKey:           "BNJ9BLZTcAeuPMHDDDXA0RiVNse8WH4b+/r/bA9HhDsDtTSBsrvmjbnA3w3JlC7ipvhHEkdGbFEIH+ZT0ZEekTA=".FromBASE64(),
                                                     Description:         I18NString.Create(Languages.en, "Test public key"),
                                                     EllipticCurve:       "secp256r1",
                                                     SignatureAlgorithm:  "SHA256withECDSA",
                                                     NotBefore:           Timestamp.Now,
                                                     NotAfter:            Timestamp.Now.AddMonths(1)
                                                 )
                        );

            await ntsServer.Start();

        }

        [OneTimeTearDown]
        public void ShutdownNTSServer()
        {
            ntsServer?.Shutdown();
        }

        #endregion


        #region (helper) Engine() / Endpoint(Hostname, Validator) / NoNameServers()

        private static MeasurementEngine Engine()

            => new (new MonitoringConfig {
                        DroneId       = "engine-tests",
                        NTPTimeout    = TimeSpan.FromSeconds(5),
                        NTSKETimeout  = TimeSpan.FromSeconds(10)
                    });

        private static NTSServerEndpoint Endpoint(DomainName                                                     Hostname,
                                                  RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient>?  Validator)

            => new (
                   Hostname,
                   ntsKEPort,
                   ntpPort,
                   RemoteCertificateValidator: Validator
               );

        /// <summary>
        /// A resolver with nobody to ask, for a server addressed by its address:
        /// what the round resolves beside the key exchange then fails at once
        /// rather than going out onto the network.
        /// </summary>
        private static DNSClient NoNameServers()

            => new (SearchForIPv4DNSServers: false,
                    SearchForIPv6DNSServers: false);

        #endregion


        #region TheServersOwnValidatorIsAskedAtTheKeyExchange()

        /// <summary>
        /// The validator of the endpoint decides the key exchange, and is asked
        /// once for it.
        /// </summary>
        /// <remarks>
        /// The engine used to make its client without one, so a validator on
        /// the endpoint was never asked - and a certificate for another name
        /// failed the usual rule, which this one accepts.
        /// </remarks>
        [Test]
        public async Task TheServersOwnValidatorIsAskedAtTheKeyExchange()
        {

            var asked   = 0;
            var subject = "";

            var engine  = Engine();
            var result  = await engine.MeasureSingleServer(
                                    Endpoint(loopback, (sender, certificate, chain, client, errors) => {
                                        asked++;
                                        subject = certificate?.Subject ?? "";
                                        return TLSValidationResult.Success();
                                    }),
                                    Guid.NewGuid(),
                                    NoNameServers()
                                );

            Assert.Multiple(() => {
                Assert.That(result.NTSKE?.Success,                     Is.True,  result.ErrorMessage?.ToString());
                Assert.That(asked,                                     Is.EqualTo(1));
                Assert.That(subject,                                   Does.Contain("ntpKE.example.org"));
                Assert.That(engine.KeyExchanges.ContainsKey(loopback), Is.True,  "the key exchange was not kept");
            });

        }

        #endregion

        #region AKeyExchangeTheValidatorRefusesIsNotMade()

        /// <summary>
        /// A certificate the validator refuses ends the key exchange, and the
        /// server is not asked for the time.
        /// </summary>
        [Test]
        public async Task AKeyExchangeTheValidatorRefusesIsNotMade()
        {

            var asked   = 0;

            var engine  = Engine();
            var result  = await engine.MeasureSingleServer(
                                    Endpoint(loopback, (sender, certificate, chain, client, errors) => {
                                        asked++;
                                        return TLSValidationResult.Failed("Not the certificate this server is held to.");
                                    }),
                                    Guid.NewGuid(),
                                    NoNameServers()
                                );

            Assert.Multiple(() => {
                Assert.That(asked,                                     Is.EqualTo(1));
                Assert.That(result.Success,                            Is.False);
                Assert.That(result.NTSKE?.Success,                     Is.False);
                Assert.That(result.NTP,                                Is.Null,   "the server was asked for the time");
                Assert.That(engine.KeyExchanges.ContainsKey(loopback), Is.False,  "a refused key exchange was kept");
            });

        }

        #endregion

        #region AForgottenKeyExchangeIsMadeAgain()

        /// <summary>
        /// A key exchange is reused until it is forgotten, and made again - and
        /// judged again - after that.
        /// </summary>
        [Test]
        public async Task AForgottenKeyExchangeIsMadeAgain()
        {

            var asked     = 0;
            var engine    = Engine();
            var endpoint  = Endpoint(loopback, (sender, certificate, chain, client, errors) => {
                                asked++;
                                return TLSValidationResult.Success();
                            });

            var first     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());
            var second    = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            Assert.Multiple(() => {
                Assert.That(first. NTSKEFromCache,  Is.False,        first. ErrorMessage?.ToString());
                Assert.That(second.NTSKEFromCache,  Is.True,         second.ErrorMessage?.ToString());
                Assert.That(asked,                  Is.EqualTo(1),   "a reused key exchange was judged again");
            });

            Assert.That(engine.ForgetKeyExchange(loopback),                              Is.True);
            Assert.That(engine.ForgetKeyExchange(DomainName.Parse("time.example.org")),  Is.False,  "forgot one that was never made");

            var third     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            Assert.Multiple(() => {
                Assert.That(third.NTSKEFromCache,   Is.False,        third.ErrorMessage?.ToString());
                Assert.That(asked,                  Is.EqualTo(2),   "the new key exchange was not judged");
            });

        }

        #endregion

        #region TheKeyExchangeResolvesWithTheRoundsDNSClient()

        /// <summary>
        /// The key exchange finds its server with the name servers the round was
        /// handed, as the round's own lookup does.
        /// </summary>
        /// <remarks>
        /// The name is one that only this resolver knows, from its cache. The
        /// client of the key exchange used to make a resolver of its own, which
        /// asked the machine's name servers - for a name they cannot know - and
        /// went past a resolver that was configured, or switched off, on purpose.
        /// </remarks>
        [Test]
        public async Task TheKeyExchangeResolvesWithTheRoundsDNSClient()
        {

            var hostname  = DomainName.Parse("nts-under-test.example");

            // Somebody to ask, so that the cache is consulted at all - at a port
            // nothing listens on, so that asking fails at once.
            var dns       = new DNSClient(
                                IPv4Address.Localhost,
                                IPPort.Parse(9),
                                QueryTimeout: TimeSpan.FromSeconds(1)
                            );

            dns.DNSCache.Add(
                DNSServiceName.Parse(hostname.ToString()),
                new A(hostname, DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Localhost)
            );

            var result    = await Engine().MeasureSingleServer(
                                      Endpoint(hostname, (sender, certificate, chain, client, errors) => TLSValidationResult.Success()),
                                      Guid.NewGuid(),
                                      dns
                                  );

            Assert.That(result.NTSKE?.Success,  Is.True,  result.ErrorMessage?.ToString());

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
