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

using Newtonsoft.Json.Linq;
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
    /// The NTPv5 probe of the <see cref="MeasurementEngine"/>: what a server of the draft
    /// shows in each of the three ways, what one without NTPv5 shows, and that the probe is
    /// held for its interval and asked for per endpoint.
    /// </summary>
    [TestFixture]
    [Category("LocalIntegration")]
    public class MeasurementEngine_NTPv5_Tests
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


        #region AServerOfTheDraft_ShowsNTPv5_InAllThreeWays()

        /// <summary>
        /// § 12, § 7.6 and § 11: the magic echoed, a plain NTPv5 answer with its Server
        /// Information, and a key exchange that agrees to NTPv5 with an authenticated query.
        /// </summary>
        [Test]
        public async Task AServerOfTheDraft_ShowsNTPv5_InAllThreeWays()
        {

            using var dns    = NoNameServers();
            await using var engine = Engine();

            var probe = await engine.ProbeNTPv5(Endpoint(withNTPv5!, ProbeNTPv5: true), dns);

            Assert.Multiple(() => {
                Assert.That(probe.AdvertisedInNTPv4,                  Is.True,  probe.NTPv4Error);
                Assert.That(probe.PlainNTPv5,                         Is.True,  probe.PlainNTPv5Error);
                Assert.That(probe.PlainUnusable,                      Is.EqualTo(NTPv5Unusable.None));
                Assert.That(probe.SupportedVersions!.Value & (1 << 4), Is.Not.Zero, "NTPv5 among the versions");
                Assert.That(probe.SupportedFlags!.Value.HasFlag(NTPv5Flags.InterleavedMode), Is.True);
                Assert.That(probe.Stratum,                            Is.EqualTo(1));
                Assert.That(probe.Offset!.Value.Duration(),           Is.LessThan(TimeSpan.FromMilliseconds(50)));
                Assert.That(probe.NTSNegotiated,                      Is.True,  probe.NTSError);
                Assert.That(probe.NTSQuery,                           Is.True,  probe.NTSError);
                Assert.That(probe.SupportsNTPv5,                      Is.True);
                Assert.That(probe.FromCache,                          Is.False);
            });

        }

        #endregion

        #region AServerWithoutNTPv5_ShowsNone()

        /// <summary>
        /// No echo, no valid NTPv5 answer - it answers in NTPv4, as it always did, which a
        /// client of § 12 drops - and a key exchange that agrees to NTPv4.
        /// </summary>
        [Test]
        public async Task AServerWithoutNTPv5_ShowsNone()
        {

            using var dns    = NoNameServers();
            await using var engine = Engine();

            var probe = await engine.ProbeNTPv5(Endpoint(withoutNTPv5!, ProbeNTPv5: true), dns);

            Assert.Multiple(() => {
                Assert.That(probe.AdvertisedInNTPv4,  Is.False, probe.NTPv4Error);
                Assert.That(probe.PlainNTPv5,         Is.False);
                Assert.That(probe.PlainNTPv5Error,    Is.Not.Null);
                Assert.That(probe.NTSNegotiated,      Is.False, probe.NTSError);
                Assert.That(probe.NTSQuery,           Is.Null, "nothing to query under");
                Assert.That(probe.SupportsNTPv5,      Is.False);
            });

            var json = probe.ToJSON();

            Assert.That(json["supportsNTPv5"]!.Value<Boolean>(), Is.False);
            Assert.That(json["advertisedInNTPv4"]!.Value<Boolean>(), Is.False);
            Assert.That(json.ContainsKey("ntsQuery"), Is.False);

        }

        #endregion

        #region AMeasurement_CarriesTheProbe_HeldForItsInterval()

        /// <summary>
        /// Asked for by the endpoint, the probe comes with the measurement, the first time
        /// fresh and then from the cache until the interval is over; an endpoint that does not
        /// ask gets none.
        /// </summary>
        [Test]
        public async Task AMeasurement_CarriesTheProbe_HeldForItsInterval()
        {

            using var dns           = NoNameServers();
            await using var engine  = Engine();

            var probed              = Endpoint(withNTPv5!, ProbeNTPv5: true);
            var notProbed           = Endpoint(withNTPv5!, ProbeNTPv5: false);

            var first               = await engine.MeasureSingleServer(probed,    Guid.NewGuid(), dns);
            var second              = await engine.MeasureSingleServer(probed,    Guid.NewGuid(), dns);
            var without             = await engine.MeasureSingleServer(notProbed, Guid.NewGuid(), dns);

            Assert.That(first.Success,  Is.True, first.ErrorMessage?.ToString());

            Assert.Multiple(() => {
                Assert.That(first.NTPv5,                 Is.Not.Null);
                Assert.That(first.NTPv5!.FromCache,      Is.False);
                Assert.That(first.NTPv5.SupportsNTPv5,   Is.True);
                Assert.That(second.NTPv5!.FromCache,     Is.True);
                Assert.That(second.NTPv5.Timestamp,      Is.EqualTo(first.NTPv5.Timestamp));
                Assert.That(without.NTPv5,               Is.Null);
                Assert.That(engine.NTPv5Capabilities.ContainsKey(loopback), Is.True);
                Assert.That(first.ToJSON()["ntpv5"]?["supportsNTPv5"]?.Value<Boolean>(), Is.True);
                Assert.That(without.ToJSON().ContainsKey("ntpv5"), Is.False);
            });

            await using var eager   = Engine(ProbeInterval: TimeSpan.Zero);

            var again1              = await eager.MeasureSingleServer(probed, Guid.NewGuid(), dns);
            var again2              = await eager.MeasureSingleServer(probed, Guid.NewGuid(), dns);

            Assert.That(again1.NTPv5!.FromCache, Is.False);
            Assert.That(again2.NTPv5!.FromCache, Is.False, "an interval of zero probes every time");

        }

        #endregion


        #region (private static) Engine(...) / Endpoint(...) / NoNameServers()

        private static MeasurementEngine Engine(TimeSpan? ProbeInterval = null)

            => new (new MonitoringConfig {
                        DroneId             = "engine-ntpv5-tests",
                        NTPTimeout          = TimeSpan.FromSeconds(2),
                        NTSKETimeout        = TimeSpan.FromSeconds(10),
                        NTPv5ProbeInterval  = ProbeInterval ?? TimeSpan.FromHours(1)
                    });

        private static NTSServerEndpoint Endpoint(NTSServer  Server,
                                                  Boolean    ProbeNTPv5)

            => new (loopback,
                    Server.TCPPort,
                    Server.UDPPort,
                    RemoteCertificateValidator:  (sender, certificate, chain, client, errors) => TLSValidationResult.Success(),
                    ProbeNTPv5:                  ProbeNTPv5);

        private static DNSClient NoNameServers()

            => new (SearchForIPv4DNSServers: false,
                    SearchForIPv6DNSServers: false);

        #endregion

    }

}
