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

using System.Net;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

using IPAddress = System.Net.IPAddress;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTPv5
{

    /// <summary>
    /// The Time Sources Request and Response of draft-ietf-ntp-ntpv5-10 § 7.5, without a
    /// network: the wire format, what fits, what is ignored, and the responder.
    /// </summary>
    [TestFixture]
    public class NTPv5TimeSources_Tests
    {

        #region Data

        private static readonly NTPv5TimeSource IPv6  = NTPv5TimeSource.Of(IPAddress.Parse("2001:db8::123"), 0.5, Authenticated: true);
        private static readonly NTPv5TimeSource IPv4  = NTPv5TimeSource.Of(IPAddress.Parse("192.0.2.1"),     0.25);
        private static readonly NTPv5TimeSource GPS   = NTPv5TimeSource.OfReferenceClock("GPS",              1.0);
        private static readonly NTPv5TimeSource Other = NTPv5TimeSource.Unidentified(0.125);

        #endregion


        #region ASource_IsWrittenAsFigure8HasIt()

        /// <summary>
        /// Figure 8: share, flags, type and length, then the identifier - 4 octets for IPv4 and
        /// reference IDs, 16 for IPv6, none for "None"; the share encoded as in § 7.4.
        /// </summary>
        [Test]
        public void ASource_IsWrittenAsFigure8HasIt()
        {

            Assert.That(NTPv5TimeSources.TryAnswer([ IPv4, IPv6, GPS, Other ], NTPv5TimeSources.Request(DataLength: 60), out var response), Is.True);

            Assert.That(response!.Type,  Is.EqualTo(NTPv5ExtensionTypes.TimeSourcesResponse));
            Assert.That(response.Value,  Has.Length.EqualTo(8 + 20 + 8 + 4));

            Assert.That(response.Value[..8],   Is.EqualTo(new Byte[] { 32, 0x00, 1, 4, 192, 0, 2, 1 }), "25 % is 32, IPv4");
            Assert.That(response.Value[8..12], Is.EqualTo(new Byte[] { 16, 0x01, 2, 16 }),          "50 % is 16, authenticated, IPv6");
            Assert.That(response.Value[28..36], Is.EqualTo(new Byte[] { 0, 0x00, 3, 4, (Byte) 'G', (Byte) 'P', (Byte) 'S', 0 }));
            Assert.That(response.Value[36..],  Is.EqualTo(new Byte[] { 48, 0x00, 0, 0 }),            "12.5 % is 48, no identifier");

            Assert.That(NTPv5TimeSources.TryRead(response.Value, out var read), Is.True);

            Assert.Multiple(() => {
                Assert.That(read,                            Is.EqualTo(new[] { IPv4, IPv6, GPS, Other }));
                Assert.That(read[0].IPAddress,               Is.EqualTo(IPAddress.Parse("192.0.2.1")));
                Assert.That(read[1].IPAddress,               Is.EqualTo(IPAddress.Parse("2001:db8::123")));
                Assert.That(read[1].IsAuthenticated,         Is.True);
                Assert.That(read[1].DecodedShare,            Is.EqualTo(0.5));
                Assert.That(read[2].ReferenceIdentifierCode, Is.EqualTo("GPS"));
                Assert.That(read[3].IdType,                  Is.EqualTo(NTPv5TimeSourceIdType.None));
            });

        }

        #endregion

        #region TheResponse_FitsTheRequest_AndSkipsNothing()

        /// <summary>
        /// § 7.5: the response is no longer than the request, starts at its index, and "MUST NOT
        /// skip sources in its list, e.g. to put a shorter identifier at the end".
        /// </summary>
        [Test]
        public void TheResponse_FitsTheRequest_AndSkipsNothing()
        {

            IReadOnlyList<NTPv5TimeSource> Answer(Byte Index, Int32 DataLength, params NTPv5TimeSource[] Sources)
            {
                Assert.That(NTPv5TimeSources.TryAnswer(Sources, NTPv5TimeSources.Request(Index, DataLength), out var response), Is.True);
                Assert.That(response!.Value.Length, Is.LessThanOrEqualTo(DataLength), "no longer than the request");
                Assert.That(NTPv5TimeSources.TryRead(response.Value, out var sources), Is.True);
                return sources;
            }

            Assert.Multiple(() => {
                Assert.That(Answer(0, 20, IPv6, IPv4), Is.EqualTo(new[] { IPv6 }),        "an IPv6 source fills 20");
                Assert.That(Answer(0, 28, IPv6, IPv4), Is.EqualTo(new[] { IPv6, IPv4 }));
                Assert.That(Answer(0, 24, IPv6, IPv4, Other), Is.EqualTo(new[] { IPv6 }), "the IPv4 does not fit, and the shorter one after it is not put in its place");
                Assert.That(Answer(1, 20, IPv6, IPv4, Other), Is.EqualTo(new[] { IPv4, Other }), "from the index on");
                Assert.That(Answer(2, 20, IPv6, IPv4),        Is.Empty, "an index past the list: empty");
                Assert.That(Answer(0, 20),                    Is.Empty, "no sources: empty");
            });

        }

        #endregion

        #region ARequestTooShortOrUneven_IsNoRequest()

        /// <summary>
        /// § 7.5: the data of a request "MUST be at least 20 octets ... and be divisible by 4";
        /// one that is not gets no response field.
        /// </summary>
        [Test]
        public void ARequestTooShortOrUneven_IsNoRequest()
        {

            Assert.That(NTPv5TimeSources.TryAnswer([ IPv4 ], new NTPv5ExtensionField(NTPv5ExtensionTypes.TimeSourcesRequest, new Byte[16]), out _), Is.False);
            Assert.That(NTPv5TimeSources.TryAnswer([ IPv4 ], new NTPv5ExtensionField(NTPv5ExtensionTypes.TimeSourcesRequest, new Byte[22]), out _), Is.False);
            Assert.That(NTPv5TimeSources.TryAnswer([ IPv4 ], new NTPv5ExtensionField(NTPv5ExtensionTypes.TimeSourcesRequest, new Byte[24]), out _), Is.True);

            Assert.That(() => NTPv5TimeSources.Request(DataLength: 18), Throws.InstanceOf<ArgumentOutOfRangeException>());
            Assert.That(() => NTPv5TimeSource.OfReferenceClock("TOOLONG", 1), Throws.ArgumentException);

        }

        #endregion

        #region AMalformedResponse_DoesNotRead()

        /// <summary>
        /// A truncated source, or a known type with the wrong length, does not read; an
        /// unknown type is kept by its length.
        /// </summary>
        [Test]
        public void AMalformedResponse_DoesNotRead()
        {

            Assert.That(NTPv5TimeSources.TryRead(new Byte[] { 0, 0, 1, 4, 192, 0 },        out _), Is.False, "truncated");
            Assert.That(NTPv5TimeSources.TryRead(new Byte[] { 0, 0, 1, 2, 192, 0 },        out _), Is.False, "IPv4 in 2 octets");
            Assert.That(NTPv5TimeSources.TryRead(new Byte[] { 0, 0 },                      out _), Is.False, "half a header");

            Assert.That(NTPv5TimeSources.TryRead(new Byte[] { 0, 0, 9, 2, 0xAB, 0xCD },    out var unknown), Is.True);
            Assert.That(unknown[0].IdType,     Is.EqualTo((NTPv5TimeSourceIdType) 9));
            Assert.That(unknown[0].Identifier, Is.EqualTo(new Byte[] { 0xAB, 0xCD }));

        }

        #endregion

        #region TheResponder_AnswersTimeSources_OnlyWhereEnabled()

        /// <summary>
        /// § 7.5: "If the Time Sources Request Extension Field is supported and enabled on the
        /// server" it is answered - here, where the clock has a list - and the response is as
        /// long as the request (§ 10).
        /// </summary>
        [Test]
        public void TheResponder_AnswersTimeSources_OnlyWhereEnabled()
        {

            var request  = NTPv5Packet.Request(ExtensionFields: [ NTPv5TimeSources.Request(DataLength: 40) ]).ToByteArray();
            var clock    = new NTPv5ServerClock(1, TimeSpan.Zero, TimeSpan.FromMilliseconds(1), true, -20, 0);

            Byte[] Respond(NTPv5ServerClock Clock)
            {
                Assert.That(NTPv5Responder.TryRespond(request, 0x1_0000_0000UL, DateTime.UtcNow, Clock, () => 0x2_0000_0000UL, out var response, out var error), Is.EqualTo(NTPv5RequestOutcome.Answered), error);
                return response!;
            }

            var disabled = Respond(clock);
            var enabled  = Respond(clock with { TimeSources = [ IPv4, GPS ] });

            Assert.That(NTPv5Packet.TryParse(disabled, out var plain,    out _), Is.True);
            Assert.That(NTPv5Packet.TryParse(enabled,  out var answered, out _), Is.True);

            Assert.Multiple(() => {
                Assert.That(plain!.Find(NTPv5ExtensionTypes.TimeSourcesResponse), Is.Null, "not enabled, not answered");
                Assert.That(NTPv5Client.TimeSourcesOf(answered!),                 Is.EqualTo(new[] { IPv4, GPS }));
                Assert.That(enabled.Length,                                       Is.EqualTo(request.Length));
                Assert.That(disabled.Length,                                      Is.EqualTo(request.Length));
            });

        }

        #endregion

    }


    /// <summary>
    /// Time Sources on the wire of a running <see cref="NTSServer"/>, plain and under NTS.
    /// </summary>
    [TestFixture]
    [Category("LocalIntegration")]
    public class NTSServer_NTPv5TimeSources_Tests
    {

        #region Data

        private NTSServer?  server;

        private static readonly NTPv5TimeSource[] Sources = [
                                                       NTPv5TimeSource.OfReferenceClock("PPS", 0.75),
                                                       NTPv5TimeSource.Of(IPAddress.Parse("198.51.100.7"), 0.25, Authenticated: true)
                                                   ];

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


        #region TheServer_TellsItsSources_OnlyOnceItWasGivenThem()

        /// <summary>
        /// By default the request is not answered; once the server is described with its
        /// sources, a plain and an NTS query both get them - the NTS one under the authenticator.
        /// </summary>
        [Test]
        public async Task TheServer_TellsItsSources_OnlyOnceItWasGivenThem()
        {

            using var client = new NTSClient(Hermod.DNS.DomainName.Localhost,
                                             NTSKE_Port:                  server!.TCPPort,
                                             NTP_Port:                    server.UDPPort,
                                             IPVersionPreference:         IPVersionPreference.IPv4Only,
                                             RemoteCertificateValidator:  (sender, serverCertificate, certificateChain, ntsKETLSClient, sslPolicyErrors) => TLSValidationResult.Success()) {
                                   NTPv5 = NTPv5Support.Draft
                               };

            NTPv5ExtensionField[] AskForSources() => [ NTPv5TimeSources.Request(DataLength: 32) ];

            server.Redescribe();

            var before = await client.QueryNTPv5(ExtensionFields: AskForSources());

            Assert.That(before.Success,      Is.True, before.ErrorMessage);
            Assert.That(before.TimeSources,  Is.Null, "not answered by default");
            Assert.That(server.NTPv5TimeSources, Is.Null);

            server.Redescribe(NTPv5TimeSources: Sources);

            var plain  = await client.QueryNTPv5(ExtensionFields: AskForSources());

            var ke     = await client.GetNTSKERecords();
            Assert.That(ke.Success, Is.True, ke.ErrorMessage);

            var nts    = await client.QueryNTPv5(NTSKEResponse: ke.Response, ExtensionFields: AskForSources());

            Assert.Multiple(() => {
                Assert.That(plain.Success,      Is.True, plain.ErrorMessage);
                Assert.That(plain.TimeSources,  Is.EqualTo(Sources));
                Assert.That(nts.Success,        Is.True, nts.ErrorMessage);
                Assert.That(nts.IsAuthenticated, Is.True);
                Assert.That(nts.TimeSources,    Is.EqualTo(Sources));
            });

            server.Redescribe();

        }

        #endregion

    }

}
