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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.Monitoring
{

    /// <summary>
    /// The versions of NTP a server is measured in (NTSServerEndpoint.NTPVersions, the
    /// Versions of the Secure Time Synchronization white paper): offered by the key exchange
    /// in their order, and the server then measured in the first one it agreed to - in NTPv5
    /// under NTS where that is NTPv5.
    /// </summary>
    [TestFixture]
    public class MeasurementEngine_NTPv5Measurement_Tests
    {

        #region Data

        private static readonly DomainName  loopback = DomainName.Parse("127.0.0.1");

        private NTSServer?  withNTPv5;
        private NTSServer?  withoutNTPv5;

        #endregion

        #region Setup / TearDown

        [OneTimeSetUp]
        public async Task StartServers()
        {

            withNTPv5     = await FreePorts.Start(() => new NTSServer(NTSKEPort:           FreePorts.TCP(),
                                                                      NTSPort:             FreePorts.UDP(),
                                                                      MasterKeysFilePath:  null,
                                                                      NTPv5:               NTPv5Support.Draft));

            withoutNTPv5  = await FreePorts.Start(() => new NTSServer(NTSKEPort:           FreePorts.TCP(),
                                                                      NTSPort:             FreePorts.UDP(),
                                                                      MasterKeysFilePath:  null));

        }

        [OneTimeTearDown]
        public async Task StopServers()
        {

            foreach (var running in new[] { withNTPv5, withoutNTPv5 })
                if (running is not null)
                    await running.ShutdownAsync();

        }

        #endregion


        #region TheEndpoint_OffersItsVersionsInTheirOrder()

        /// <summary>
        /// The versions become next protocols in their order, NTPv4 alone by default, where
        /// signed responses are asked for, and where no version this engine speaks is named;
        /// after a key exchange the first version agreed to is the one asked in.
        /// </summary>
        [Test]
        [Category("Unit")]
        public void TheEndpoint_OffersItsVersionsInTheirOrder()
        {

            var byDefault  = new NTSServerEndpoint(loopback);
            var v5First    = new NTSServerEndpoint(loopback, NTPVersions: [ 5, 4 ]);
            var v4First    = new NTSServerEndpoint(loopback, NTPVersions: [ 4, 5 ]);
            var v5Only     = new NTSServerEndpoint(loopback, NTPVersions: [ 5 ]);
            var signed     = new NTSServerEndpoint(loopback, SignedResponses: true, NTPVersions: [ 5, 4 ]);
            var strange    = new NTSServerEndpoint(loopback, NTPVersions: [ 3 ]);

            Assert.Multiple(() => {

                Assert.That(byDefault.NextProtocolsOffered,  Is.EqualTo(new UInt16[] { 0 }));
                Assert.That(v5First.  NextProtocolsOffered,  Is.EqualTo(new UInt16[] { 0x8001, 0 }));
                Assert.That(v4First.  NextProtocolsOffered,  Is.EqualTo(new UInt16[] { 0, 0x8001 }));
                Assert.That(v5Only.   NextProtocolsOffered,  Is.EqualTo(new UInt16[] { 0x8001 }));
                Assert.That(signed.   NextProtocolsOffered,  Is.EqualTo(new UInt16[] { 0 }),  "a signed response is an extension of NTPv4");
                Assert.That(strange.  NextProtocolsOffered,  Is.EqualTo(new UInt16[] { 0 }));

                Assert.That(v5First.OffersNTPv5,    Is.True);
                Assert.That(signed. OffersNTPv5,    Is.False);

                Assert.That(v5First.NTPVersionAfter([ 0, 0x8001 ]),  Is.EqualTo((Byte) 5));
                Assert.That(v4First.NTPVersionAfter([ 0, 0x8001 ]),  Is.EqualTo((Byte) 4));
                Assert.That(v5First.NTPVersionAfter([ 0 ]),          Is.EqualTo((Byte) 4));
                Assert.That(v5Only. NTPVersionAfter([ 0 ]),          Is.Null);

            });

        }

        #endregion

        #region TheKeyExchange_OffersTheNextProtocolsAskedFor()

        /// <summary>
        /// The NTS Next Protocol Negotiation record of a request lists what the client is
        /// asked to offer, in that order, with the draft record of § 11 wherever NTPv5 may be
        /// offered; NTPv5 asked for without NTPv5 enabled is not offered.
        /// </summary>
        [Test]
        [Category("Unit")]
        public void TheKeyExchange_OffersTheNextProtocolsAskedFor()
        {

            static (UInt16[] Protocols, Boolean DraftRecord) Offered(NTSClient Client)
            {

                Assert.That(NTSKE_Record.TryParse(Client.BuildNTSKERequest(), out var parsed, out var problem), Is.True, problem);

                var records    = parsed!.ToArray();
                var next       = records.First(record => record.Type == NTSKE_RecordTypes.NTSNextProtocolNegotiation).Body;
                var protocols  = Enumerable.Range(0, next.Length / 2).Select(i => (UInt16) ((next[2 * i] << 8) | next[2 * i + 1])).ToArray();

                return (protocols, records.Any(record => (UInt16) record.Type == NTPv5Draft.NTSKEDraftRecordType));

            }

            using var v4First   = new NTSClient(loopback) { NTPv5 = NTPv5Support.Draft,    OfferedNextProtocols = [ 0, 0x8001 ] };
            using var v5Only    = new NTSClient(loopback) { NTPv5 = NTPv5Support.Draft,    OfferedNextProtocols = [ 0x8001 ] };
            using var disabled  = new NTSClient(loopback) { NTPv5 = NTPv5Support.Disabled, OfferedNextProtocols = [ 0x8001 ] };
            using var draft     = new NTSClient(loopback) { NTPv5 = NTPv5Support.Draft };

            Assert.Multiple(() => {
                Assert.That(Offered(v4First),   Is.EqualTo((new UInt16[] { 0, 0x8001 }, true)));
                Assert.That(Offered(v5Only),    Is.EqualTo((new UInt16[] { 0x8001 },    true)));
                Assert.That(Offered(disabled),  Is.EqualTo((new UInt16[] { 0 },         false)), "NTPv5 is offered only where it is enabled");
                Assert.That(Offered(draft),     Is.EqualTo((new UInt16[] { 0x8001, 0 }, true)),  "as before");
            });

        }

        #endregion


        #region AServerOfTheDraft_AskedInNTPv5First_IsMeasuredInNTPv5()

        /// <summary>
        /// Asked in NTPv5 first, a server of the draft agrees to NTPv5 and is measured in it,
        /// authenticated, with the cookies of the same key exchange - the second time from the
        /// cache, and with a preflight in NTPv5 as well.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task AServerOfTheDraft_AskedInNTPv5First_IsMeasuredInNTPv5()
        {

            using var dns           = NoNameServers();
            await using var engine  = Engine();

            var endpoint            = Endpoint(withNTPv5!, [ 5, 4 ]);

            var first               = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), dns);
            var second              = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), dns, Preflight: true);

            Assert.That(first.Success, Is.True, first.ErrorMessage?.ToString());

            Assert.Multiple(() => {

                Assert.That(first.NTSKE?.NTPVersion,                  Is.EqualTo((Byte) 5));
                Assert.That(first.NTP?.NTPVersion,                    Is.EqualTo((Byte) 5));
                Assert.That(first.NTP?.NTSAuthenticationValid,        Is.True);
                Assert.That(first.NTP?.Stratum,                       Is.EqualTo((Byte) 1));
                Assert.That(first.NTP?.LeapIndicator,                 Is.EqualTo((Byte) 0));
                Assert.That(first.NTP?.Offset.Duration(),             Is.LessThan(TimeSpan.FromMilliseconds(50)));
                Assert.That(first.NTP?.T4_ClientReceive,              Is.GreaterThanOrEqualTo(first.NTP!.T1_ClientSend));
                Assert.That(first.NTP?.NewCookieReceived,             Is.True);

                Assert.That(second.Success,                           Is.True, second.ErrorMessage?.ToString());
                Assert.That(second.NTSKEFromCache,                    Is.True);
                Assert.That(second.PreflightSent,                     Is.True);
                Assert.That(second.NTP?.NTPVersion,                   Is.EqualTo((Byte) 5));

                Assert.That(withNTPv5!.Metrics.NTPv5AuthenticatedResponsesSent, Is.GreaterThanOrEqualTo(3), "two measurements and a preflight");

            });

        }

        #endregion

        #region AServerOfTheDraft_AskedInNTPv4First_IsMeasuredInNTPv4()

        /// <summary>
        /// Asked in NTPv4 first and NTPv5 second, a server of the draft is measured in NTPv4:
        /// whatever it agrees to, NTPv4 is among it and comes first.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task AServerOfTheDraft_AskedInNTPv4First_IsMeasuredInNTPv4()
        {

            using var dns           = NoNameServers();
            await using var engine  = Engine();

            var result              = await engine.MeasureSingleServer(Endpoint(withNTPv5!, [ 4, 5 ]), Guid.NewGuid(), dns);

            Assert.That(result.Success, Is.True, result.ErrorMessage?.ToString());

            Assert.Multiple(() => {
                Assert.That(result.NTSKE?.NTPVersion,  Is.EqualTo((Byte) 4));
                Assert.That(result.NTP?.NTPVersion,    Is.EqualTo((Byte) 4));
            });

        }

        #endregion

        #region AServerWithoutNTPv5_IsMeasuredInNTPv4_OrNotAtAll()

        /// <summary>
        /// A server without NTPv5 agrees to NTPv4: asked in NTPv5 first, it is measured in
        /// NTPv4; asked in NTPv5 alone, it agrees to nothing - an empty next protocol record,
        /// as RFC 8915 § 4.1.2 has a server say that it supports none of those offered - and
        /// the key exchange failed, saying so.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task AServerWithoutNTPv5_IsMeasuredInNTPv4_OrNotAtAll()
        {

            using var dns           = NoNameServers();
            await using var engine  = Engine();

            var fallsBack           = await engine.MeasureSingleServer(Endpoint(withoutNTPv5!, [ 5, 4 ]), Guid.NewGuid(), dns);

            await using var other   = Engine();

            var refused             = await other. MeasureSingleServer(Endpoint(withoutNTPv5!, [ 5 ]),    Guid.NewGuid(), dns);

            Assert.That(fallsBack.Success, Is.True, fallsBack.ErrorMessage?.ToString());

            Assert.Multiple(() => {
                Assert.That(fallsBack.NTSKE?.NTPVersion,         Is.EqualTo((Byte) 4));
                Assert.That(fallsBack.NTP?.NTPVersion,           Is.EqualTo((Byte) 4));
                Assert.That(refused.Success,                     Is.False);
                Assert.That(refused.ErrorCategory,               Is.EqualTo(MonitoringErrorCategory.NTSKEProtocol));
                Assert.That(refused.ErrorMessage?.ToString(),    Does.Contain("next protocol"));
                Assert.That(refused.NTP,                         Is.Null, "nothing was asked");
            });

        }

        #endregion

        #region AnEndpointChangedToNTPv5_GetsANewKeyExchangeAtOnce()

        /// <summary>
        /// The key exchange held for a server asked in NTPv4 is not reused once it is to be
        /// asked in NTPv5 first: the next measurement makes a new one, and is in NTPv5.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task AnEndpointChangedToNTPv5_GetsANewKeyExchangeAtOnce()
        {

            using var dns           = NoNameServers();
            await using var engine  = Engine();

            var endpoint            = Endpoint(withNTPv5!, [ 4 ]);

            var before              = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), dns);

            endpoint.NTPVersions    = [ 5, 4 ];

            var after               = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), dns);

            Assert.Multiple(() => {
                Assert.That(before.NTP?.NTPVersion,  Is.EqualTo((Byte) 4), before.ErrorMessage?.ToString());
                Assert.That(after. NTSKEFromCache,   Is.False);
                Assert.That(after. NTP?.NTPVersion,  Is.EqualTo((Byte) 5), after.ErrorMessage?.ToString());
            });

        }

        #endregion


        #region (private static) Engine() / Endpoint(...) / NoNameServers()

        private static MeasurementEngine Engine()

            => new (new MonitoringConfig {
                        DroneId       = "engine-ntpv5-measurement-tests",
                        NTPTimeout    = TimeSpan.FromSeconds(2),
                        NTSKETimeout  = TimeSpan.FromSeconds(10)
                    });

        private static NTSServerEndpoint Endpoint(NTSServer    Server,
                                                  IEnumerable<Byte>  Versions)

            => new (loopback,
                    Server.TCPPort,
                    Server.UDPPort,
                    RemoteCertificateValidator:  (sender, certificate, chain, client, errors) => TLSValidationResult.Success(),
                    NTPVersions:                 Versions);

        private static DNSClient NoNameServers()

            => new (SearchForIPv4DNSServers: false,
                    SearchForIPv6DNSServers: false);

        #endregion

    }

}
