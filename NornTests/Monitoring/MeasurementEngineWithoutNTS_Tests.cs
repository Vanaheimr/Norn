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
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;
using org.GraphDefined.Vanaheimr.Norn.TimeSync;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;
using org.GraphDefined.Vanaheimr.Norn.NTPOverTLS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.Monitoring
{

    /// <summary>
    /// The servers a measurement engine asks without NTS - <see cref="NTSServerEndpoint.Protection"/>:
    /// NTP without authentication over UDP, in the versions the endpoint names, and NTP over
    /// TLS; and a server of NTP over SSH that nothing hands a connection to, which is no time
    /// and is not asked over UDP instead.
    /// </summary>
    /// <remarks>
    /// Against a server of Norn's own on the loopback interface that speaks the draft of NTPv5
    /// and NTP over TLS, and makes no key exchange.
    /// </remarks>
    [TestFixture]
    [Category("LocalIntegration")]
    public class MeasurementEngineWithoutNTS_Tests
    {

        #region Data

        private static readonly DomainName  loopback  = DomainName.Parse("127.0.0.1");

        private static readonly RemoteTLSServerCertificateValidationHandler<NTPOverTLS_TLSClient> AcceptAnyServer
            = (sender, certificate, chain, client, policyErrors) => TLSValidationResult.Success();

        private NTSServer?  server;

        #endregion

        #region Setup / TearDown

        [OneTimeSetUp]
        public async Task StartTheServer()
        {

            server = await FreePorts.Start(() => new NTSServer(NTSKEPort:           FreePorts.TCP(),
                                                               NTSPort:             FreePorts.UDP(),
                                                               MasterKeysFilePath:  null,
                                                               NTSKEOverTLS:        false,
                                                               NTPv5:               NTPv5Support.Draft,
                                                               NTPOverTLSPort:      FreePorts.TCP()));

        }

        [OneTimeTearDown]
        public void StopTheServer()
        {
            server?.Dispose();
        }

        #endregion

        #region (helper) Engine() / Endpoint(Protection, Versions) / NoNameServers()

        private static MeasurementEngine Engine()

            => new (new MonitoringConfig {
                        DroneId       = "engine-tests",
                        NTPTimeout    = TimeSpan.FromSeconds(5),
                        NTSKETimeout  = TimeSpan.FromSeconds(10)
                    });

        private NTSServerEndpoint Endpoint(NTPProtection  Protection,
                                           params Byte[]  Versions)

            => new (loopback,
                    NTPPort:      Protection == NTPProtection.NTPOverTLS ? server!.NTPOverTLSPort : server!.UDPPort,
                    NTPVersions:  Versions.Length > 0 ? Versions : null,
                    Protection:   Protection) {
                   NTPOverTLSCertificateValidator = AcceptAnyServer
               };

        private static DNSClient NoNameServers()

            => new (SearchForIPv4DNSServers: false,
                    SearchForIPv6DNSServers: false);

        #endregion


        #region NTPWithoutAuthenticationIsMeasuredInTheVersionsNamed()

        /// <summary>
        /// NTPv4, NTPv5, and NTPv4 offering NTPv5 - NTPv5 from the round after the server
        /// echoed the offer. No key exchange, and an answer that counts though nothing
        /// authenticated it: its endpoint was configured so.
        /// </summary>
        [Test]
        public async Task NTPWithoutAuthenticationIsMeasuredInTheVersionsNamed()
        {

            await using var engine  = Engine();

            var v4        = await engine.MeasureSingleServer(Endpoint(NTPProtection.None),        Guid.NewGuid(), NoNameServers());
            var v5        = await engine.MeasureSingleServer(Endpoint(NTPProtection.None, 5),     Guid.NewGuid(), NoNameServers());

            await using var other   = Engine();
            var both      = Endpoint(NTPProtection.None, 5, 4);
            var offered   = await other.MeasureSingleServer(both, Guid.NewGuid(), NoNameServers());
            var taken     = await other.MeasureSingleServer(both, Guid.NewGuid(), NoNameServers());

            Assert.Multiple(() => {

                Assert.That(v4.Success,                        Is.True,  v4.ErrorMessage?.ToString());
                Assert.That(v4.NTP?.NTPVersion,                Is.EqualTo(4));
                Assert.That(v4.NTP?.Protection,                Is.EqualTo(NTPProtection.None));
                Assert.That(v4.NTP?.NTSAuthenticationValid,    Is.False);
                Assert.That(v4.NTSKE,                          Is.Null,  "a key exchange");
                Assert.That(TimeSyncVerdict.CanBeTrusted(v4),  Is.True,  "configured without authentication, and taken so");

                Assert.That(v5.Success,                        Is.True,  v5.ErrorMessage?.ToString());
                Assert.That(v5.NTP?.NTPVersion,                Is.EqualTo(5));

                Assert.That(offered.Success,                   Is.True,  offered.ErrorMessage?.ToString());
                Assert.That(offered.NTP?.NTPVersion,           Is.EqualTo(4), "NTPv5 before the server echoed the offer");
                Assert.That(taken.Success,                     Is.True,  taken.ErrorMessage?.ToString());
                Assert.That(taken.NTP?.NTPVersion,             Is.EqualTo(5), "NTPv4 after the echo");

                Assert.That(engine.KeyExchanges,               Is.Empty);

            });

        }

        #endregion

        #region NTPOverTLSIsMeasuredWithItsValidator()

        /// <summary>
        /// NTP over TLS asks the endpoint's validator about the certificate, in NTPv4 and in
        /// NTPv5 (section 6.1 of the white paper), and is no time where it refuses: the server
        /// is then not asked over UDP instead.
        /// </summary>
        [Test]
        public async Task NTPOverTLSIsMeasuredWithItsValidator()
        {

            await using var engine  = Engine();

            var asked     = 0;
            var endpoint  = Endpoint(NTPProtection.NTPOverTLS);

            endpoint.NTPOverTLSCertificateValidator = (sender, certificate, chain, client, errors) => { asked++; return TLSValidationResult.Success(); };

            var measured  = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

            var overTLSv5 = Endpoint(NTPProtection.NTPOverTLS, 5);
            var inV5      = await engine.MeasureSingleServer(overTLSv5, Guid.NewGuid(), NoNameServers());

            endpoint.NTPOverTLSCertificateValidator = (sender, certificate, chain, client, errors) => TLSValidationResult.Failed("not this one");

            var udpBefore = server!.Metrics.NTPRequestsReceived;
            var refused   = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());
            var udpAfter  = server.Metrics.NTPRequestsReceived;

            Assert.Multiple(() => {

                Assert.That(measured.Success,                        Is.True,  measured.ErrorMessage?.ToString());
                Assert.That(measured.NTP?.Protection,                Is.EqualTo(NTPProtection.NTPOverTLS));
                Assert.That(measured.NTP?.NTPVersion,                Is.EqualTo(4));
                Assert.That(asked,                                   Is.EqualTo(1));
                Assert.That(inV5.Success,                            Is.True,  inV5.ErrorMessage?.ToString());
                Assert.That(inV5.NTP?.NTPVersion,                    Is.EqualTo(5), "NTPv5 over TLS");
                Assert.That(TimeSyncVerdict.CanBeTrusted(measured),  Is.True);

                Assert.That(refused.Success,                         Is.False);
                Assert.That(udpAfter,                                Is.EqualTo(udpBefore), "asked over UDP instead");

            });

        }

        #endregion

        #region NTPOverSSHWithoutAConnectionIsNoTime()

        /// <summary>
        /// NTP over SSH with nothing to hand out a connection: no time, an SSH failure, and
        /// nothing sent over UDP in its place (section 10.7 of "NTS Key Establishment over
        /// SSH").
        /// </summary>
        [Test]
        public async Task NTPOverSSHWithoutAConnectionIsNoTime()
        {

            await using var engine  = Engine();

            var udpBefore = server!.Metrics.NTPRequestsReceived;
            var result    = await engine.MeasureSingleServer(Endpoint(NTPProtection.NTPOverSSH), Guid.NewGuid(), NoNameServers());
            var failing   = Endpoint(NTPProtection.NTPOverSSH);

            failing.ConnectOverSSH = _ => throw new InvalidOperationException("no way to it");

            var failed    = await engine.MeasureSingleServer(failing, Guid.NewGuid(), NoNameServers());
            var udpAfter  = server.Metrics.NTPRequestsReceived;

            Assert.Multiple(() => {
                Assert.That(result.Success,         Is.False);
                Assert.That(result.ErrorCategory,   Is.EqualTo(MonitoringErrorCategory.SSH));
                Assert.That(failed.Success,         Is.False);
                Assert.That(failed.ErrorMessage?.ToString(), Does.Contain("no way to it"));
                Assert.That(udpAfter,               Is.EqualTo(udpBefore), "asked over UDP instead");
            });

        }

        #endregion

        #region AnNTSAnswerThatDidNotAuthenticateIsStillNotTrusted()

        /// <summary>
        /// The trust in answers without NTS is the endpoint's configuration, never an NTS
        /// answer's that failed to authenticate.
        /// </summary>
        [Test]
        public void AnNTSAnswerThatDidNotAuthenticateIsStillNotTrusted()
        {

            static NTSMeasurementResult Of(NTPProtection Protection)

                => new (loopback, Guid.NewGuid()) {
                       Success  = true,
                       NTP      = new NTPMeasurementResult {
                                      Success                 = true,
                                      Protection              = Protection,
                                      NTSAuthenticationValid  = false
                                  }
                   };

            Assert.Multiple(() => {
                Assert.That(TimeSyncVerdict.CanBeTrusted(Of(NTPProtection.NTS)),         Is.False);
                Assert.That(TimeSyncVerdict.CanBeTrusted(Of(NTPProtection.NTPOverSSH)),  Is.True);
                Assert.That(TimeSyncVerdict.CanBeTrusted(Of(NTPProtection.NTPOverTLS)),  Is.True);
                Assert.That(TimeSyncVerdict.CanBeTrusted(Of(NTPProtection.None)),        Is.True);
            });

        }

        #endregion

    }

}
