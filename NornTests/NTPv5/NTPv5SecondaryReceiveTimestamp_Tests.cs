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
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTPv5
{

    /// <summary>
    /// The Secondary Receive Timestamp of draft-ietf-ntp-ntpv5-10 § 7.10, without a network:
    /// the field, the exact shift into another timescale, and what the responder answers.
    /// </summary>
    [TestFixture]
    public class NTPv5SecondaryReceiveTimestamp_Tests
    {

        #region Data

        private static readonly TimeSpan TAIOffset = TimeSpan.FromSeconds(37);

        #endregion


        #region TheField_IsFigure13()

        /// <summary>
        /// Figure 13: timescale, era, two reserved octets, the timestamp - 16 octets in all.
        /// </summary>
        [Test]
        public void TheField_IsFigure13()
        {

            var field = NTPv5ExtensionField.SecondaryReceiveTimestamp(NTPv5Timescale.TAI, 1, 0x0102030405060708UL);

            Assert.That(field.Length, Is.EqualTo(NTPv5ExtensionField.SecondaryReceiveTimestampLength));
            Assert.That(field.Value,  Is.EqualTo(new Byte[] { 1, 1, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8 }));

            Assert.That(field.TryReadSecondaryReceiveTimestamp(out var timescale, out var era, out var timestamp), Is.True);
            Assert.That((timescale, era, timestamp), Is.EqualTo((NTPv5Timescale.TAI, (Byte) 1, 0x0102030405060708UL)));

            Assert.That(NTPv5ExtensionField.SecondaryReceiveTimestamp(NTPv5Timescale.UT1).Value, Is.EqualTo(new Byte[] { 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }), "a request: zeros");
            Assert.That(new NTPv5ExtensionField(NTPv5ExtensionTypes.SecondaryReceiveTimestamp, new Byte[8]).TryReadSecondaryReceiveTimestamp(out _, out _, out _), Is.False, "not 16 octets");

        }

        #endregion

        #region AShift_IsExact_AndCrossesEras()

        /// <summary>
        /// In steps of 2^-32 s: 37 s move the seconds by 37 and the fraction not at all, across
        /// the rollover of 2036 into the next era, and not before era 0 or past era 255.
        /// </summary>
        [Test]
        public void AShift_IsExact_AndCrossesEras()
        {

            Assert.That(NTPv5Packet.TryShift(0, 0x0000_0100_1234_5678UL, TAIOffset, out var era, out var shifted), Is.True);
            Assert.That((era, shifted), Is.EqualTo(((Byte) 0, 0x0000_0125_1234_5678UL)));

            Assert.That(NTPv5Packet.TryShift(0, 0xFFFF_FFF0_8000_0000UL, TAIOffset, out era, out shifted), Is.True);
            Assert.That((era, shifted), Is.EqualTo(((Byte) 1, 0x0000_0015_8000_0000UL)), "16 s before the rollover, 21 s after it");

            Assert.That(NTPv5Packet.TryShift(0,   0x0000_0010_0000_0000UL, -TAIOffset,                  out _, out _), Is.False, "before era 0");
            Assert.That(NTPv5Packet.TryShift(255, 0xFFFF_FFFF_0000_0000UL,  TAIOffset,                  out _, out _), Is.False, "after era 255");
            Assert.That(NTPv5Packet.TryShift(3,   0x0000_0001_0000_0000UL,  TimeSpan.FromSeconds(-1.5), out era, out shifted), Is.True);
            Assert.That((era, shifted), Is.EqualTo(((Byte) 2, 0xFFFF_FFFF_8000_0000UL)));

        }

        #endregion

        #region TheResponder_AnswersEachSupportedTimescale_Once()

        /// <summary>
        /// § 7.10: a timescale the server supports is answered, with zero where it cannot
        /// convert; one it does not support is ignored; and a timescale asked for twice is
        /// answered once. The response is as long as the request (§ 10).
        /// </summary>
        [Test]
        public void TheResponder_AnswersEachSupportedTimescale_Once()
        {

            var request  = NTPv5Packet.Request(ExtensionFields: [
                               NTPv5ExtensionField.SecondaryReceiveTimestamp(NTPv5Timescale.TAI),
                               NTPv5ExtensionField.SecondaryReceiveTimestamp(NTPv5Timescale.UT1),
                               NTPv5ExtensionField.SecondaryReceiveTimestamp(NTPv5Timescale.UTC),
                               NTPv5ExtensionField.SecondaryReceiveTimestamp(NTPv5Timescale.TAI),
                               NTPv5ExtensionField.SecondaryReceiveTimestamp((NTPv5Timescale) 7)
                           ]).ToByteArray();

            var clock    = new NTPv5ServerClock(1, TimeSpan.Zero, TimeSpan.FromMilliseconds(1), true, -20, 0);
            var now      = DateTime.UtcNow;
            var receive  = NTPv5Client_Tests.Timestamp(now) | 0x1234;

            NTPv5Packet Respond(NTPv5ServerClock Clock)
            {
                Assert.That(NTPv5Responder.TryRespond(request, receive, now, Clock, () => receive + 1, out var response, out var error), Is.EqualTo(NTPv5RequestOutcome.Answered), error);
                Assert.That(response!.Length, Is.EqualTo(request.Length));
                Assert.That(NTPv5Packet.TryParse(response, out var packet, out var parseError), Is.True, parseError);
                return packet!;
            }

            var configured = Respond(clock with { SecondaryTimescales = new Dictionary<NTPv5Timescale, TimeSpan?> {
                                                                            [NTPv5Timescale.UTC] = TimeSpan.Zero,
                                                                            [NTPv5Timescale.TAI] = TAIOffset,
                                                                            [NTPv5Timescale.UT1] = null
                                                                        } });

            var times      = NTPv5Client.SecondaryReceiveTimesOf(configured);

            Assert.Multiple(() => {
                Assert.That(configured.ExtensionFields.Count(field => field.Type == NTPv5ExtensionTypes.SecondaryReceiveTimestamp), Is.EqualTo(3), "TAI once, UT1, UTC");
                Assert.That(times.Keys,                                                 Is.EquivalentTo(new[] { NTPv5Timescale.TAI, NTPv5Timescale.UT1, NTPv5Timescale.UTC }));
                Assert.That(times[NTPv5Timescale.UT1],                                  Is.Null, "supported, but not converted");
                Assert.That(NTPv5Client.TimescaleOffset(configured, NTPv5Timescale.TAI), Is.EqualTo(TAIOffset), "exactly");
                Assert.That(NTPv5Client.TimescaleOffset(configured, NTPv5Timescale.UTC), Is.EqualTo(TimeSpan.Zero));
                Assert.That(NTPv5Client.TimescaleOffset(configured, NTPv5Timescale.UT1), Is.Null);
                Assert.That(times[NTPv5Timescale.UTC],                                  Is.EqualTo(NTPv5Client.ReceiveTime(configured)));
            });

            var byDefault  = NTPv5Client.SecondaryReceiveTimesOf(Respond(clock));

            Assert.That(byDefault.Keys, Is.EquivalentTo(new[] { NTPv5Timescale.UTC }), "UTC alone by default");

        }

        #endregion

    }


    /// <summary>
    /// The Secondary Receive Timestamp on the wire of a running <see cref="NTSServer"/>.
    /// </summary>
    [TestFixture]
    [Category("LocalIntegration")]
    public class NTSServer_NTPv5SecondaryReceiveTimestamp_Tests
    {

        #region Data

        private NTSServer? server;

        #endregion

        #region Start/stop the server

        [OneTimeSetUp]
        public async Task StartServer()
        {

            server = await FreePorts.Start(() => new NTSServer(NTSKEPort:           FreePorts.TCP(),
                                                               NTSPort:             FreePorts.UDP(),
                                                               MasterKeysFilePath:  null,
                                                               NTPv5:               NTPv5Support.Draft));

        }

        [OneTimeTearDown]
        public async Task StopServer()
        {
            if (server is not null)
                await server.ShutdownAsync();
        }

        #endregion


        #region TheServer_GivesTAI_OnceItKnowsTheOffset()

        /// <summary>
        /// By default the server knows UTC alone and ignores a request for TAI; described with
        /// the offset of TAI, it gives the receive timestamp in TAI too, plain and under NTS,
        /// and the client reads the 37 s from it.
        /// </summary>
        [Test]
        public async Task TheServer_GivesTAI_OnceItKnowsTheOffset()
        {

            using var client = new NTSClient(Hermod.DNS.DomainName.Localhost,
                                             NTSKE_Port:                  server!.TCPPort,
                                             NTP_Port:                    server.UDPPort,
                                             IPVersionPreference:         IPVersionPreference.IPv4Only,
                                             RemoteCertificateValidator:  (sender, serverCertificate, certificateChain, ntsKETLSClient, sslPolicyErrors) => TLSValidationResult.Success()) {
                                   NTPv5 = NTPv5Support.Draft
                               };

            NTPv5ExtensionField[] AskForTAI() => [ NTPv5ExtensionField.SecondaryReceiveTimestamp(NTPv5Timescale.TAI) ];

            server.Redescribe();

            var before = await client.QueryNTPv5(ExtensionFields: AskForTAI());

            Assert.That(before.Success,                                Is.True, before.ErrorMessage);
            Assert.That(before.SecondaryReceiveTimes,                  Is.Empty, "TAI is not known by default");
            Assert.That(before.TimescaleOffset(NTPv5Timescale.TAI),    Is.Null);

            server.Redescribe(NTPv5Timescales: new Dictionary<NTPv5Timescale, TimeSpan?> { [NTPv5Timescale.TAI] = TimeSpan.FromSeconds(37) });

            var plain  = await client.QueryNTPv5(ExtensionFields: AskForTAI());

            var ke     = await client.GetNTSKERecords();
            Assert.That(ke.Success, Is.True, ke.ErrorMessage);

            var nts    = await client.QueryNTPv5(NTSKEResponse: ke.Response, ExtensionFields: AskForTAI());

            Assert.Multiple(() => {
                Assert.That(plain.Success,                              Is.True, plain.ErrorMessage);
                Assert.That(plain.TimescaleOffset(NTPv5Timescale.TAI),  Is.EqualTo(TimeSpan.FromSeconds(37)));
                Assert.That(plain.Response!.Timescale,                  Is.EqualTo(NTPv5Timescale.UTC), "the header stays UTC");
                Assert.That(nts.Success,                                Is.True, nts.ErrorMessage);
                Assert.That(nts.IsAuthenticated,                        Is.True);
                Assert.That(nts.TimescaleOffset(NTPv5Timescale.TAI),    Is.EqualTo(TimeSpan.FromSeconds(37)));
            });

            server.Redescribe();

        }

        #endregion

    }

}
