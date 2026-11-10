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
    /// the server's own certificate validator, the AEAD algorithms its endpoint
    /// names, and the name servers of the round - and when it makes a key
    /// exchange again.
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
            // nothing listens on. Nobody is asked, though: the name has an A
            // record in the cache, and no AAAA record, cached as well. A port
            // nothing listens on does not fail at once everywhere - on Windows a
            // datagram to it is dropped without a word - and the key exchange
            // asks for both, so an AAAA query left to the network took its whole
            // budget there.
            var dns       = new DNSClient(
                                IPv4Address.Localhost,
                                IPPort.Parse(9),
                                QueryTimeout: TimeSpan.FromSeconds(1)
                            );

            dns.DNSCache.Add(
                DNSServiceName.Parse(hostname.ToString()),
                new A(hostname, DNSQueryClasses.IN, TimeSpan.FromHours(1), IPv4Address.Localhost)
            );

            dns.DNSCache.AddNoData(
                DNSServiceName.Parse(hostname.ToString()),
                DNSResourceRecordTypes.AAAA,
                TimeSpan.FromHours(1)
            );

            var result    = await Engine().MeasureSingleServer(
                                      Endpoint(hostname, (sender, certificate, chain, client, errors) => TLSValidationResult.Success()),
                                      Guid.NewGuid(),
                                      dns
                                  );

            Assert.That(result.NTSKE?.Success,  Is.True,  result.ErrorMessage?.ToString());

        }

        #endregion


        #region TheKeyExchangeDoesNotWaitForAnAAAAAnswerOnceItHasTheAAnswer()

        /// <summary>
        /// The key exchange asks for AAAA and A at once, and once the A answer is
        /// there it waits for the AAAA answer the Resolution Delay of RFC 8305,
        /// 50 ms, and no longer.
        /// </summary>
        /// <remarks>
        /// Only the A record is cached here; the AAAA query goes to a port nothing
        /// listens on, which on Windows drops the datagram without a word. Waiting
        /// for both answers, the key exchange waited for the AAAA answer until its
        /// budget of 10 s was spent, twice over with the name server asked again,
        /// and failed - with the address it needed in the cache all along.
        /// </remarks>
        [Test]
        public async Task TheKeyExchangeDoesNotWaitForAnAAAAAnswerOnceItHasTheAAnswer()
        {

            var hostname  = DomainName.Parse("nts-a-only.example");

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

            Assert.That(result.NTSKE?.Success,        Is.True,  result.ErrorMessage?.ToString());
            Assert.That(result.NTSKE!.TotalDuration,  Is.LessThan(TimeSpan.FromSeconds(3)), "not the budget of the key exchange");

        }

        #endregion

        #region AServerAddressedByItsAddressIsNoQuestionForTheNameServers()

        /// <summary>
        /// A server addressed by its address is that address: the round's step of
        /// name resolution names it without asking anybody, and the round does not
        /// wait for name servers that do not answer.
        /// </summary>
        /// <remarks>
        /// The step used to ask the name servers for the A and AAAA records of
        /// "127.0.0.1" - and waited, where they did not answer, for as long as
        /// they were given, server after server, and only then went on to the key
        /// exchange, which needed no name server at all. A node whose name servers
        /// were out of reach took more than 20 s for a round of one server on its
        /// own loopback interface. The name server here is one from the
        /// documentation's range (RFC 5737), where nothing answers: a port nothing
        /// listens on on the loopback interface is refused at once, and would not
        /// show the waiting.
        /// </remarks>
        [Test]
        public async Task AServerAddressedByItsAddressIsNoQuestionForTheNameServers()
        {

            var dns     = new DNSClient(
                              IPv4Address.Parse("192.0.2.53"),
                              IPPort.DNS,
                              QueryTimeout: TimeSpan.FromSeconds(3)
                          );

            var result  = await Engine().MeasureSingleServer(
                                    Endpoint(loopback, (sender, certificate, chain, client, errors) => TLSValidationResult.Success()),
                                    Guid.NewGuid(),
                                    dns
                                );

            Assert.Multiple(() => {
                Assert.That(result.Success,              Is.True,  result.ErrorMessage?.ToString());
                Assert.That(result.DNS?.Success,         Is.True,  result.DNS?.ErrorMessage?.ToString());
                Assert.That(result.DNS?.IPv4Addresses,   Is.EqualTo(new[] { IPv4Address.Localhost }));
                Assert.That(result.DNS?.IPv6Addresses,   Is.Empty);
                Assert.That(result.DNS?.Duration,        Is.LessThan(TimeSpan.FromSeconds(1)), "the name servers were asked");
                Assert.That(result.TotalDuration,        Is.LessThan(TimeSpan.FromSeconds(3)), "not the budget of the name servers");
            });

        }

        #endregion

        #region TheKeyExchangeOffersWhatTheEndpointNames()

        /// <summary>
        /// An endpoint that names its AEAD algorithms is offered those and no
        /// others, and one that names none the client's own list.
        /// </summary>
        /// <remarks>
        /// The server here agrees to both of the client's, and chooses from the
        /// client's list in the client's order (RFC 8915 § 4.1.5): offered the
        /// whole list, it agrees on AES-128-GCM-SIV, and offered AES-SIV-CMAC-256
        /// alone, on that one. The engine used to make its client without the
        /// endpoint's list, so an endpoint naming AES-SIV-CMAC-256 got
        /// AES-128-GCM-SIV.
        /// </remarks>
        [Test]
        public async Task TheKeyExchangeOffersWhatTheEndpointNames()
        {

            var named     = Endpoint(loopback, (sender, certificate, chain, client, errors) => TLSValidationResult.Success());
            named.OfferedAEADAlgorithms = [ AEADAlgorithms.AES_SIV_CMAC_256 ];

            var unnamed   = Endpoint(loopback, (sender, certificate, chain, client, errors) => TLSValidationResult.Success());

            var engine1   = Engine();
            var result1   = await engine1.MeasureSingleServer(named,   Guid.NewGuid(), NoNameServers());

            var engine2   = Engine();
            var result2   = await engine2.MeasureSingleServer(unnamed, Guid.NewGuid(), NoNameServers());

            Assert.Multiple(() => {
                Assert.That(result1.Success,                                       Is.True,  result1.ErrorMessage?.ToString());
                Assert.That(engine1.KeyExchanges[loopback].NTSKEResponse?.AEADAlgorithm,
                            Is.EqualTo(AEADAlgorithms.AES_SIV_CMAC_256),            "the endpoint's algorithm was not the one offered");
                Assert.That(result2.Success,                                       Is.True,  result2.ErrorMessage?.ToString());
                Assert.That(engine2.KeyExchanges[loopback].NTSKEResponse?.AEADAlgorithm,
                            Is.EqualTo(AEADAlgorithms.AES_128_GCM_SIV),             "an endpoint naming none was not offered the client's list");
            });

        }

        #endregion

        #region AKeyExchangeOnAnAlgorithmNoLongerOfferedIsMadeAgain()

        /// <summary>
        /// A key exchange that agreed on an algorithm the endpoint no longer
        /// offers is not reused: the next round makes a new one, on what it
        /// offers now, and reuses that.
        /// </summary>
        [Test]
        public async Task AKeyExchangeOnAnAlgorithmNoLongerOfferedIsMadeAgain()
        {

            var engine    = Engine();
            var endpoint  = Endpoint(loopback, (sender, certificate, chain, client, errors) => TLSValidationResult.Success());

            var first     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());
            var before    = engine.KeyExchanges[loopback].NTSKEResponse?.AEADAlgorithm;

            endpoint.OfferedAEADAlgorithms = [ AEADAlgorithms.AES_SIV_CMAC_256 ];

            var second    = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());
            var after     = engine.KeyExchanges[loopback].NTSKEResponse?.AEADAlgorithm;

            var third     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            Assert.Multiple(() => {
                Assert.That(first. Success,          Is.True,                             first. ErrorMessage?.ToString());
                Assert.That(before,                  Is.EqualTo(AEADAlgorithms.AES_128_GCM_SIV));
                Assert.That(second.NTSKEFromCache,   Is.False,                            "the key exchange on the other algorithm was reused");
                Assert.That(second.Success,          Is.True,                             second.ErrorMessage?.ToString());
                Assert.That(after,                   Is.EqualTo(AEADAlgorithms.AES_SIV_CMAC_256));
                Assert.That(third. NTSKEFromCache,   Is.True,                             "the new key exchange was not reused");
            });

        }

        #endregion

        #region (class) ShiftedClock / FixedRandom

        /// <summary>
        /// The machine's clock, moved on by whatever a test says: a key exchange
        /// due in hours is due now, while the server and the packets keep to
        /// real time.
        /// </summary>
        private sealed class ShiftedClock : TimeProvider
        {
            public TimeSpan Shift { get; set; }
            public override DateTimeOffset GetUtcNow() => base.GetUtcNow() + Shift;
        }

        /// <summary>
        /// A random number that is always the same one.
        /// </summary>
        private sealed class FixedRandom(Double Value) : Random
        {
            public override Double NextDouble() => Value;
        }

        #endregion

        #region AKeyExchangeIsMadeAgainOnceItsEndpointsRefreshIsDue()

        /// <summary>
        /// A key exchange is reused until the endpoint's refresh is due, and made
        /// again after that.
        /// </summary>
        [Test]
        public async Task AKeyExchangeIsMadeAgainOnceItsEndpointsRefreshIsDue()
        {

            var clock     = new ShiftedClock();
            var engine    = new MeasurementEngine(new MonitoringConfig { NTPTimeout = TimeSpan.FromSeconds(5), NTSKETimeout = TimeSpan.FromSeconds(10) }, clock);
            var endpoint  = Endpoint(loopback, (sender, certificate, chain, client, errors) => TLSValidationResult.Success());

            endpoint.MinRefresh = TimeSpan.FromHours(12);
            endpoint.MaxRefresh = TimeSpan.FromHours(12);

            var first     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            clock.Shift   = TimeSpan.FromHours(11);
            var second    = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            clock.Shift   = TimeSpan.FromHours(12) + TimeSpan.FromMinutes(1);
            var third     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            Assert.Multiple(() => {
                Assert.That(first. Success,          Is.True,   first. ErrorMessage?.ToString());
                Assert.That(second.NTSKEFromCache,   Is.True,   "made again before its refresh was due");
                Assert.That(third. NTSKEFromCache,   Is.False,  "reused after its refresh was due");
                Assert.That(third. Success,          Is.True,   third. ErrorMessage?.ToString());
            });

        }

        #endregion

        #region TheNextKeyExchangeIsDueAtARandomTimeBetweenMinAndMaxRefresh()

        /// <summary>
        /// The next key exchange is due at a random time between the endpoint's
        /// MinRefresh and MaxRefresh: halfway, for a random number of one half.
        /// </summary>
        [Test]
        public async Task TheNextKeyExchangeIsDueAtARandomTimeBetweenMinAndMaxRefresh()
        {

            var clock     = new ShiftedClock();
            var engine    = new MeasurementEngine(new MonitoringConfig { NTPTimeout = TimeSpan.FromSeconds(5), NTSKETimeout = TimeSpan.FromSeconds(10) }, clock, new FixedRandom(0.5));
            var endpoint  = Endpoint(loopback, (sender, certificate, chain, client, errors) => TLSValidationResult.Success());

            endpoint.MinRefresh = TimeSpan.FromHours(12);
            endpoint.MaxRefresh = TimeSpan.FromHours(24);

            var first     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());
            var due       = engine.KeyExchanges[loopback].RefreshAt - engine.KeyExchanges[loopback].LastRefreshed;

            clock.Shift   = TimeSpan.FromHours(17) + TimeSpan.FromMinutes(59);
            var second    = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            clock.Shift   = TimeSpan.FromHours(18) + TimeSpan.FromMinutes(1);
            var third     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            Assert.Multiple(() => {
                Assert.That(first. Success,          Is.True,                         first. ErrorMessage?.ToString());
                Assert.That(due,                     Is.EqualTo(TimeSpan.FromHours(18)));
                Assert.That(second.NTSKEFromCache,   Is.True,                         "made again before it was due");
                Assert.That(third. NTSKEFromCache,   Is.False,                        "reused after it was due");
            });

        }

        #endregion

        #region TheOffsetCorrectionIsWhatThePathIsKnownToDo()

        /// <summary>
        /// The correction of an offset: the DelayAsymmetry as it is, and the
        /// DelayVarAsymmetry times how much longer the delay was than the
        /// shortest - by -0.5 times it where the hold-up was all on the way
        /// there, which made the offset too large by half of it. Nothing where
        /// the delay was the shortest, and never more than half the hold-up.
        /// </summary>
        [Test]
        public void TheOffsetCorrectionIsWhatThePathIsKnownToDo()
        {

            static TimeSpan ms(Double milliseconds) => TimeSpan.FromMilliseconds(milliseconds);

            Assert.Multiple(() => {
                Assert.That(MeasurementEngine.OffsetCorrection(null,     null,  ms(10), ms(4)),  Is.EqualTo(TimeSpan.Zero));
                Assert.That(MeasurementEngine.OffsetCorrection(ms(-0.05), null, ms(10), ms(4)),  Is.EqualTo(ms(-0.05)));
                Assert.That(MeasurementEngine.OffsetCorrection(null,     -0.5,  ms(10), ms(4)),  Is.EqualTo(ms(-3)));
                Assert.That(MeasurementEngine.OffsetCorrection(null,      0.5,  ms(10), ms(4)),  Is.EqualTo(ms(3)));
                Assert.That(MeasurementEngine.OffsetCorrection(null,      0.25, ms(10), ms(4)),  Is.EqualTo(ms(1.5)));
                Assert.That(MeasurementEngine.OffsetCorrection(null,     -0.5,  ms(4),  ms(4)),  Is.EqualTo(TimeSpan.Zero),  "no hold-up");
                Assert.That(MeasurementEngine.OffsetCorrection(null,      0.9,  ms(10), ms(4)),  Is.EqualTo(ms(3)),          "never more than half the hold-up");
                Assert.That(MeasurementEngine.OffsetCorrection(ms(1),    -0.5,  ms(10), ms(4)),  Is.EqualTo(ms(-2)));
            });

        }

        #endregion

        #region TheDelayAsymmetryIsAddedToTheMeasuredOffset()

        /// <summary>
        /// A measurement's offset is the measured one plus the endpoint's
        /// DelayAsymmetry, and says both.
        /// </summary>
        [Test]
        public async Task TheDelayAsymmetryIsAddedToTheMeasuredOffset()
        {

            var engine    = Engine();
            var endpoint  = Endpoint(loopback, (sender, certificate, chain, client, errors) => TLSValidationResult.Success());

            endpoint.DelayAsymmetry = TimeSpan.FromMilliseconds(50);

            var result    = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());
            var ntp       = result.NTP;

            Assert.Multiple(() => {
                Assert.That(result.Success,         Is.True,  result.ErrorMessage?.ToString());
                Assert.That(ntp?.OffsetCorrection,  Is.EqualTo(TimeSpan.FromMilliseconds(50)));
                Assert.That(ntp?.Offset,            Is.EqualTo(ntp?.MeasuredOffset + TimeSpan.FromMilliseconds(50)));
            });

        }

        #endregion

        #region AHoldUpIsCorrectedAgainstTheShortestOfTheLastDelays()

        /// <summary>
        /// The DelayVarAsymmetry corrects a measurement by how much longer its
        /// delay was than the shortest of the server's last ones: nothing for
        /// the first, which is the shortest so far, and for the next ones what
        /// their delays say.
        /// </summary>
        [Test]
        public async Task AHoldUpIsCorrectedAgainstTheShortestOfTheLastDelays()
        {

            var engine    = Engine();
            var endpoint  = Endpoint(loopback, (sender, certificate, chain, client, errors) => TLSValidationResult.Success());

            endpoint.DelayVarAsymmetry = -0.5;

            var results   = new List<NTPMeasurementResult>();

            for (var i = 0; i < 4; i++)
            {
                var result = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());
                Assert.That(result.Success, Is.True, result.ErrorMessage?.ToString());
                results.Add(result.NTP!);
            }

            Assert.Multiple(() => {

                Assert.That(results[0].OffsetCorrection,  Is.EqualTo(TimeSpan.Zero),  "the first is the shortest so far");

                for (var i = 1; i < results.Count; i++)
                {
                    var shortest = results.Take(i + 1).Min(result => result.RoundTripDelay);
                    Assert.That(results[i].OffsetCorrection,
                                Is.EqualTo(MeasurementEngine.OffsetCorrection(null, -0.5, results[i].RoundTripDelay, shortest)),
                                $"measurement {i + 1}");
                    Assert.That(results[i].Offset,
                                Is.EqualTo(results[i].MeasuredOffset + results[i].OffsetCorrection));
                }

            });

        }

        #endregion

        #region APreflightSendsTheQueryOnceMoreBeforeTheMeasuredOne()

        /// <summary>
        /// With Preflight, a measurement sends its query a first time and ignores
        /// the answer: two cookies spent instead of one, and no fewer left, as
        /// each answer brings a new one. Without, one.
        /// </summary>
        [Test]
        public async Task APreflightSendsTheQueryOnceMoreBeforeTheMeasuredOne()
        {

            var engine    = Engine();
            var endpoint  = Endpoint(loopback, (sender, certificate, chain, client, errors) => TLSValidationResult.Success());

            var first     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());
            var second    = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers(), Preflight: true);
            var third     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            Assert.Multiple(() => {
                Assert.That(first. Success,                                                   Is.True,  first. ErrorMessage?.ToString());
                Assert.That(second.Success,                                                   Is.True,  second.ErrorMessage?.ToString());
                Assert.That(first. PreflightSent,                                             Is.False);
                Assert.That(second.PreflightSent,                                             Is.True);
                Assert.That(second.NTP?.CookiesConsumed - first. NTP?.CookiesConsumed,        Is.EqualTo(2),  "the query was not sent a first time");
                Assert.That(third. NTP?.CookiesConsumed - second.NTP?.CookiesConsumed,        Is.EqualTo(1));
                Assert.That(second.NTP?.RemainingCookiesAfterQuery,                           Is.EqualTo(first.NTP?.RemainingCookiesAfterQuery),  "the first answer brought no cookie");
            });

        }

        #endregion

        #region AGroupSendsAPreflightToTheServersItAsks()

        /// <summary>
        /// A group asked with Preflight has its servers sent their queries a
        /// first time, and one asked without does not.
        /// </summary>
        [Test]
        public async Task AGroupSendsAPreflightToTheServersItAsks()
        {

            var engine    = Engine();
            var group     = new org.GraphDefined.Vanaheimr.Norn.TimeSync.TimeSourceGroup(
                                "legal",
                                [ Endpoint(loopback, (sender, certificate, chain, client, errors) => TLSValidationResult.Success()) ]
                            );

            var without   = await group.Measure(engine, NoNameServers());
            var with      = await group.Measure(engine, NoNameServers(), Preflight: true);

            Assert.Multiple(() => {
                Assert.That(without.Results.Select(result => result.PreflightSent),  Is.EqualTo(new[] { false }));
                Assert.That(with.   Results.Select(result => result.PreflightSent),  Is.EqualTo(new[] { true  }));
                Assert.That(with.   Results.Select(result => result.Success),        Is.EqualTo(new[] { true  }));
            });

        }

        #endregion

        #region AKeyExchangeRequestAsksForTheRequestedNTPServerOnBothTransports()

        /// <summary>
        /// A client told to ask for an NTP server sends an NTPv4 Server
        /// Negotiation record naming it - not critical, before the end of the
        /// message - over TLS and over SSH alike; one not told sends none.
        /// </summary>
        [Test]
        public void AKeyExchangeRequestAsksForTheRequestedNTPServerOnBothTransports()
        {

            static NTSKE_Record[] Records(Byte[] Request)
            {
                Assert.That(NTSKE_Record.TryParse(Request, out var records, out var error), Is.True, error);
                return [.. records!];
            }

            var asking   = new NTSClient(DomainName.Parse("ntske.example.org"), RequestedNTPServer: DomainName.Parse("ntp.example.org"));
            var plain    = new NTSClient(DomainName.Parse("ntske.example.org"));

            var tls      = Records(asking.BuildNTSKERequest());
            var ssh      = Records(asking.BuildNTSKERequest(OverSSH: true));
            var none     = Records(plain. BuildNTSKERequest());

            Assert.Multiple(() => {

                foreach (var (records, transport) in new[] { (tls, "TLS"), (ssh, "SSH") })
                {
                    var asked = records.Where(record => record.Type == NTSKE_RecordTypes.NTPv4ServerNegotiation).ToArray();
                    Assert.That(asked,                                                   Has.Length.EqualTo(1),  transport);
                    Assert.That(System.Text.Encoding.ASCII.GetString(asked[0].Body),    Is.EqualTo("ntp.example.org"),  transport);
                    Assert.That(asked[0].IsCritical,                                     Is.False,  transport);
                    Assert.That(records[^1].Type,                                        Is.EqualTo(NTSKE_RecordTypes.EndOfMessage),  $"{transport}: the end of the message is not last");
                }

                Assert.That(none.Select(record => record.Type),  Has.None.EqualTo(NTSKE_RecordTypes.NTPv4ServerNegotiation));

            });

        }

        #endregion

        #region AnEndpointWithAKeyExchangeServerOfItsOwnIsMeasuredThroughIt()

        /// <summary>
        /// An endpoint whose host name no resolver knows, but which names a key
        /// exchange server of its own, makes its key exchange there - and, the
        /// response naming no NTP server, asks that server for the time. The key
        /// exchange is kept by the endpoint's host name.
        /// </summary>
        [Test]
        public async Task AnEndpointWithAKeyExchangeServerOfItsOwnIsMeasuredThroughIt()
        {

            var engine    = Engine();
            var unknown   = DomainName.Parse("time.example.invalid");
            var endpoint  = Endpoint(unknown, (sender, certificate, chain, client, errors) => TLSValidationResult.Success());

            var without   = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            endpoint.NTSKEHost = loopback;

            var with      = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            Assert.Multiple(() => {
                Assert.That(without.Success,                      Is.False,  "a host name nobody knows was reached");
                Assert.That(with.   Success,                      Is.True,   with.ErrorMessage?.ToString());
                Assert.That(engine.KeyExchanges.ContainsKey(unknown),  Is.True,  "the key exchange is not kept by the endpoint's host name");
            });

        }

        #endregion

        #region AnEndpointAskingForSignedResponsesGetsOneAfterEachMeasurement()

        /// <summary>
        /// An endpoint asking for signed responses gets one after each
        /// measurement, signed with the server's key 1 and checked against the
        /// public key its key exchange named - and costing no cookie. One not
        /// asking gets none.
        /// </summary>
        [Test]
        public async Task AnEndpointAskingForSignedResponsesGetsOneAfterEachMeasurement()
        {

            var engine    = Engine();
            var endpoint  = Endpoint(loopback, (sender, certificate, chain, client, errors) => TLSValidationResult.Success());

            var plain     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            endpoint.SignedResponses = true;

            var first     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());
            var second    = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            Assert.Multiple(() => {
                Assert.That(plain. SignedResponse,                       Is.Null);
                Assert.That(first. NTSKEFromCache,                       Is.False,  "a key exchange without the public keys was reused");
                Assert.That(first. SignedResponse?.Success,              Is.True,   first.SignedResponse?.ErrorMessage);
                Assert.That(first. SignedResponse?.KeyId,                Is.EqualTo(1));
                Assert.That(first. SignedResponse?.Verified,             Is.True,   "the signature was not the key's");
                Assert.That(first. SignedResponse?.Packet?.Length,       Is.GreaterThan(48));
                Assert.That(second.NTSKEFromCache,                       Is.True);
                Assert.That(second.SignedResponse?.Verified,             Is.True);
                Assert.That(second.NTP?.RemainingCookiesAfterQuery,      Is.EqualTo(first.NTP?.RemainingCookiesAfterQuery),  "a signed response cost a cookie");
            });

        }

        #endregion

        #region AnEndpointWithoutARefreshOfItsOwnHasTheEnginesInterval()

        /// <summary>
        /// An endpoint that names no refresh has the engine's refresh interval,
        /// as every endpoint had before - half an hour, unless configured.
        /// </summary>
        [Test]
        public async Task AnEndpointWithoutARefreshOfItsOwnHasTheEnginesInterval()
        {

            var clock     = new ShiftedClock();
            var engine    = new MeasurementEngine(new MonitoringConfig { NTPTimeout = TimeSpan.FromSeconds(5), NTSKETimeout = TimeSpan.FromSeconds(10) }, clock);
            var endpoint  = Endpoint(loopback, (sender, certificate, chain, client, errors) => TLSValidationResult.Success());

            var first     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            clock.Shift   = TimeSpan.FromMinutes(29);
            var second    = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            clock.Shift   = TimeSpan.FromMinutes(31);
            var third     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            Assert.Multiple(() => {
                Assert.That(first. Success,          Is.True,   first. ErrorMessage?.ToString());
                Assert.That(second.NTSKEFromCache,   Is.True,   "made again within the engine's interval");
                Assert.That(third. NTSKEFromCache,   Is.False,  "reused beyond the engine's interval");
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
