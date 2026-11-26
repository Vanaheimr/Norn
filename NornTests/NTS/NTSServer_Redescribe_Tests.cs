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
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// The description of the clock of an NTS server - stratum, reference, root delay and
    /// dispersion, leap indicator - changed while it runs, as a server following upstream
    /// servers changes it with every round.
    /// </summary>
    [TestFixture]
    public class NTSServer_Redescribe_Tests
    {

        #region ARunningServerReportsTheNewDescription_AndItsClientsGoOn()

        /// <summary>
        /// Every response after the call reports the new description, and a client goes on
        /// with the cookies of its key exchange from before: the server was not made anew.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task ARunningServerReportsTheNewDescription_AndItsClientsGoOn()
        {

            var server = await FreePorts.Start(() => new NTSServer(NTSKEPort:  FreePorts.TCP(),
                                                                   NTSPort:    FreePorts.UDP()));

            try
            {

                var client       = ClientOf(server.TCPPort, server.UDPPort);
                var keyExchange  = await client.GetNTSKERecords(RequestNTSPublicKeys: false);

                Assert.That(keyExchange.Success, Is.True, keyExchange.ErrorMessage);

                var before       = await client.QueryTime(NTSKEResponse:  keyExchange.Response,
                                                          Timeout:        TimeSpan.FromSeconds(10));

                Assert.That(before.Success,                         Is.True, before.ErrorMessage);
                Assert.That(before.Response!.Stratum,               Is.EqualTo(1));
                Assert.That(before.Response!.ReferenceIdentifier,   Is.EqualTo(ReferenceIdentifier.From("LOCL")));

                server.Redescribe(Stratum:              3,
                                  ReferenceIdentifier:  ReferenceIdentifier.From("GPS"),
                                  RootDelay:            TimeSpan.FromMilliseconds(20),
                                  RootDispersion:       TimeSpan.FromMilliseconds(5),
                                  LeapIndicator:        1);

                var after        = await client.QueryTime(NTSKEResponse:  keyExchange.Response,
                                                          Timeout:        TimeSpan.FromSeconds(10));

                Assert.That(after.Success, Is.True, after.ErrorMessage);

                Assert.Multiple(() => {
                    Assert.That(after.Response!.Stratum,              Is.EqualTo(3));
                    Assert.That(after.Response!.ReferenceIdentifier,  Is.EqualTo(ReferenceIdentifier.From("GPS")));
                    // RFC 5905 § 6, 16.16 fixed point: 20 ms are 1311 of 65536, 5 ms 328.
                    Assert.That(after.Response!.RootDelay,            Is.EqualTo(1311u));
                    Assert.That(after.Response!.RootDispersion,       Is.EqualTo(328u));
                    Assert.That(after.Response!.LI,                   Is.EqualTo(1));
                });

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region WhatIsLeftOutIsItsDefault_NotWhatItWas()

        /// <summary>
        /// A call says the whole description: what it leaves out is the default of the
        /// constructor, not what the server said before - nothing of an earlier description
        /// lingers.
        /// </summary>
        [Test]
        public void WhatIsLeftOutIsItsDefault_NotWhatItWas()
        {

            var server = new NTSServer(Stratum:              2,
                                       ReferenceIdentifier:  ReferenceIdentifier.From("UPST"),
                                       RootDelay:            TimeSpan.FromMilliseconds(10),
                                       RootDispersion:       TimeSpan.FromMilliseconds(7),
                                       LeapIndicator:        2,
                                       ClockResolution:      TimeSpan.FromMilliseconds(1));

            server.Redescribe(Stratum: 4);

            Assert.Multiple(() => {
                Assert.That(server.Stratum,              Is.EqualTo(4));
                Assert.That(server.ReferenceIdentifier,  Is.EqualTo(ReferenceIdentifier.From("LOCL")));
                Assert.That(server.RootDelay,            Is.EqualTo(TimeSpan.Zero));
                Assert.That(server.RootDispersion,       Is.EqualTo(TimeSpan.FromMilliseconds(2)));
                Assert.That(server.LeapIndicator,        Is.EqualTo(0));
            });

        }

        #endregion

        #region RootDelayAndDispersion_AreRoundedUp()

        /// <summary>
        /// The 16.16 fixed point of RFC 5905 § 6 rounds up: what goes into the root distance
        /// is never made smaller on the way - 30 ms are 1967 of 65536, where rounding to the
        /// nearest gave 1966, a little under 30 ms; 100 ns are one unit, not none. Whole units
        /// stay exact, nothing below zero is negative, and what is too large saturates.
        /// </summary>
        [Test]
        public void RootDelayAndDispersion_AreRoundedUp()
        {

            Assert.Multiple(() => {
                Assert.That(NTSServer.ToShortFormat(TimeSpan.FromMilliseconds(30)),   Is.EqualTo(1967u), "30 ms rounded down");
                Assert.That(NTSServer.ToShortFormat(TimeSpan.FromTicks(1)),           Is.EqualTo(1u),    "100 ns made none");
                Assert.That(NTSServer.ToShortFormat(TimeSpan.FromMilliseconds(20)),   Is.EqualTo(1311u));
                Assert.That(NTSServer.ToShortFormat(TimeSpan.FromSeconds(1)),         Is.EqualTo(65536u), "a whole second is not exactly one");
                Assert.That(NTSServer.ToShortFormat(TimeSpan.FromSeconds(0.5)),       Is.EqualTo(32768u));
                Assert.That(NTSServer.ToShortFormat(TimeSpan.Zero),                   Is.EqualTo(0u));
                Assert.That(NTSServer.ToShortFormat(TimeSpan.FromSeconds(-1)),        Is.EqualTo(0u));
                Assert.That(NTSServer.ToShortFormat(TimeSpan.FromTicks(655_359_900_000)), Is.EqualTo(4294966641u));
                Assert.That(NTSServer.ToShortFormat(TimeSpan.FromSeconds(65536)),     Is.EqualTo(UInt32.MaxValue), "too large wraps");
                Assert.That(NTSServer.ToShortFormat(TimeSpan.FromDays(10)),           Is.EqualTo(UInt32.MaxValue), "too large wraps");
            });

        }

        #endregion

        #region ALeapIndicatorBeyondTwoBitsIsRefused()

        /// <summary>
        /// The leap indicator has two bits in the header: a larger one is refused, by the
        /// constructor and by Redescribe, and the description before it stays.
        /// </summary>
        [Test]
        public void ALeapIndicatorBeyondTwoBitsIsRefused()
        {

            Assert.Throws<ArgumentOutOfRangeException>(() => new NTSServer(LeapIndicator:    4,
                                                                           ClockResolution:  TimeSpan.FromMilliseconds(1)));

            var server = new NTSServer(Stratum:          2,
                                       ClockResolution:  TimeSpan.FromMilliseconds(1));

            Assert.Throws<ArgumentOutOfRangeException>(() => server.Redescribe(Stratum: 5, LeapIndicator: 4));

            Assert.That(server.Stratum,        Is.EqualTo(2));
            Assert.That(server.LeapIndicator,  Is.EqualTo(0));

            server.Redescribe(LeapIndicator: 3);

            Assert.That(server.LeapIndicator,  Is.EqualTo(3));

        }

        #endregion


        #region (private static) ClientOf(NTSKEPort, NTPPort)

        private static NTSClient ClientOf(IPPort  NTSKEPort,
                                          IPPort  NTPPort)

            => new (Hermod.DNS.DomainName.Localhost,
                    NTSKE_Port:                  NTSKEPort,
                    NTP_Port:                    NTPPort,
                    IPVersionPreference:         IPVersionPreference.IPv4Only,
                    RemoteCertificateValidator:  (sender, serverCertificate, certificateChain, ntsKETLSClient, sslPolicyErrors) => TLSValidationResult.Success());

        #endregion

    }

}
