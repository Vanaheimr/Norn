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

using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTPv5
{

    /// <summary>
    /// The client side of draft-ietf-ntp-ntpv5-10 § 8 and § 9, without a network: requests,
    /// validity, usability, eras, corrections, the interleaved mode, loops, the poll field and
    /// the version negotiation of § 12.
    /// </summary>
    [TestFixture]
    public class NTPv5Client_Tests
    {

        #region Data

        private static readonly DateTime Now = new (2026, 11, 28, 12, 0, 0, DateTimeKind.Utc);

        #endregion


        #region ARequest_IsAsSection9Has_IT()

        /// <summary>
        /// § 9 step 2: version 5, mode 3, the timescale, a fresh client cookie, the Draft
        /// Identification - and the server cookie only in the interleaved mode.
        /// </summary>
        [Test]
        public void ARequest_IsAsSection9HasIt()
        {

            var a  = NTPv5Client.BuildRequest(Timescale: NTPv5Timescale.TAI, ServerCookie: 42);
            var b  = NTPv5Client.BuildRequest();

            Assert.That(NTPv5Packet.TryParse(a.Datagram, out var parsed, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(parsed!.Mode,          Is.EqualTo(NTPv5Packet.RequestMode));
                Assert.That(parsed.Timescale,      Is.EqualTo(NTPv5Timescale.TAI));
                Assert.That(parsed.ServerCookie,   Is.Zero, "no server cookie outside the interleaved mode");
                Assert.That(parsed.ClientCookie,   Is.Not.Zero);
                Assert.That(parsed.ClientCookie,   Is.Not.EqualTo(b.ClientCookie), "a new cookie every poll");
                Assert.That(parsed.Flags,          Is.EqualTo(NTPv5Flags.None), "no NAK asked for without NTS");
                Assert.That(NTPv5Draft.IsThisDraft(parsed.DraftIdentification), Is.True);
                Assert.That(a.IsNTS,               Is.False);
            });

            var interleaved = NTPv5Client.BuildRequest(Flags: NTPv5Flags.InterleavedMode, ServerCookie: 42);
            Assert.That(interleaved.Packet.ServerCookie, Is.EqualTo(42));

        }

        #endregion

        #region TheCorrection_IsLast_EvenAfterTheAuthenticator()

        /// <summary>
        /// § 7.7: the Correction is "the last extension field in the NTP message" - under NTS
        /// behind the authenticator, which it is the exception to. An NTS request asks for an
        /// Authentication NAK.
        /// </summary>
        [Test]
        public void TheCorrection_IsLast_EvenAfterTheAuthenticator()
        {

            var plain  = NTPv5Client.BuildRequest(RequestCorrection: true, RequestReferenceIds: true);

            Assert.That(plain.Packet.ExtensionFields[^1].Type, Is.EqualTo(NTPv5ExtensionTypes.Correction));
            Assert.That(plain.CorrectionRequested,             Is.True);
            Assert.That(plain.ReferenceIdsRequested,           Is.True);
            Assert.That(plain.Packet.Find(NTPv5ExtensionTypes.ReferenceIDsRequest)!.Value, Has.Length.EqualTo(32 * 8), "all 32 entries at once");

            var nts    = NTPv5Client.BuildRequest(RequestCorrection: true,
                                                  NTS: new NTPv5ClientNTS(RandomNumberGenerator.GetBytes(32),
                                                                          RandomNumberGenerator.GetBytes(32),
                                                                          AEADAlgorithms.AES_SIV_CMAC_256,
                                                                          RandomNumberGenerator.GetBytes(100),
                                                                          Placeholders: 1));

            var types  = nts.Packet.ExtensionFields.Select(field => field.Type).ToArray();

            Assert.Multiple(() => {
                Assert.That(types[^1],               Is.EqualTo(NTPv5ExtensionTypes.Correction));
                Assert.That(types[^2],               Is.EqualTo(NTPv5ExtensionTypes.NTSAuthenticator));
                Assert.That(types,                   Does.Contain(NTPv5ExtensionTypes.NTSCookiePlaceholder));
                Assert.That(nts.Flags,               Is.EqualTo(NTPv5Flags.AuthenticationNAK));
                Assert.That(nts.UniqueIdentifier,    Has.Length.EqualTo(32));
                Assert.That(nts.Packet.Find(NTPv5ExtensionTypes.UniqueIdentifier)!.Value, Is.EqualTo(nts.UniqueIdentifier));
            });

        }

        #endregion

        #region OnlyAValidResponse_IsValid()

        /// <summary>
        /// § 9.4: version 5, mode 4, the request's client cookie, only known flags and none the
        /// request did not set - and, beyond § 9.4, the request's draft.
        /// </summary>
        [Test]
        public void OnlyAValidResponse_IsValid()
        {

            var request = NTPv5Client.BuildRequest(Flags: NTPv5Flags.Unsynchronized);

            NTPv5ResponseStatus StatusOf(NTPv5Packet Response)
                => NTPv5Client.Validate(Response.ToByteArray(), request).Status;

            Assert.Multiple(() => {

                Assert.That(StatusOf(Response(request)),                                                       Is.EqualTo(NTPv5ResponseStatus.Valid));
                Assert.That(StatusOf(Response(request, Flags: NTPv5Flags.Unsynchronized)),                     Is.EqualTo(NTPv5ResponseStatus.Valid), "a flag the request set");
                Assert.That(StatusOf(Response(request, Mode: 3)),                                              Is.EqualTo(NTPv5ResponseStatus.NotAResponse));
                Assert.That(StatusOf(Response(request, ClientCookie: request.ClientCookie ^ 1)),               Is.EqualTo(NTPv5ResponseStatus.WrongClientCookie));
                Assert.That(StatusOf(Response(request, ClientCookie: 0)),                                      Is.EqualTo(NTPv5ResponseStatus.WrongClientCookie), "§ 12: an NTPv4 server's answer");
                Assert.That(StatusOf(Response(request, Flags: NTPv5Flags.InterleavedMode)),                    Is.EqualTo(NTPv5ResponseStatus.UnrequestedFlags));
                Assert.That(StatusOf(Response(request, Flags: (NTPv5Flags) 0x8)),                              Is.EqualTo(NTPv5ResponseStatus.UnknownFlags));
                Assert.That(StatusOf(Response(request, Draft: "draft-ietf-ntp-ntpv5-09")),                     Is.EqualTo(NTPv5ResponseStatus.OtherDraft));

                Assert.That(NTPv5Client.Validate(new Byte[47], request).Status,                                Is.EqualTo(NTPv5ResponseStatus.Malformed));

            });

        }

        #endregion

        #region AValidResponse_IsUsable_OnlyWithinTheLimits()

        /// <summary>
        /// § 9.5: synchronized, stratum 1 to 15, root delay and dispersion at most 4 s, the
        /// timescale asked for, and both timestamps set.
        /// </summary>
        [Test]
        public void AValidResponse_IsUsable_OnlyWithinTheLimits()
        {

            var request = NTPv5Client.BuildRequest(Flags: NTPv5Flags.Unsynchronized);

            NTPv5Unusable UsabilityOf(NTPv5Packet Response, NTPv5UsabilityLimits? Limits = null)
                => NTPv5Client.CheckUsable(Response, request, Limits);

            Assert.Multiple(() => {

                Assert.That(UsabilityOf(Response(request)),                                                     Is.EqualTo(NTPv5Unusable.None));
                Assert.That(UsabilityOf(Response(request, Flags: NTPv5Flags.Unsynchronized)),                   Is.EqualTo(NTPv5Unusable.Unsynchronized));
                Assert.That(UsabilityOf(Response(request, Stratum: 0)),                                         Is.EqualTo(NTPv5Unusable.Stratum));
                Assert.That(UsabilityOf(Response(request, Stratum: 16)),                                        Is.EqualTo(NTPv5Unusable.Stratum));
                Assert.That(UsabilityOf(Response(request, Stratum: 16), new NTPv5UsabilityLimits(MaximumStratum: 16)), Is.EqualTo(NTPv5Unusable.None), "a configured maximum");
                Assert.That(UsabilityOf(Response(request, RootDelay: Time32.FromTimeSpan(TimeSpan.FromSeconds(5)))),      Is.EqualTo(NTPv5Unusable.RootDelay));
                Assert.That(UsabilityOf(Response(request, RootDelay: Time32.Infinity)),                         Is.EqualTo(NTPv5Unusable.RootDelay));
                Assert.That(UsabilityOf(Response(request, RootDispersion: Time32.FromTimeSpan(TimeSpan.FromSeconds(4.5)))), Is.EqualTo(NTPv5Unusable.RootDispersion));
                Assert.That(UsabilityOf(Response(request, Timescale: NTPv5Timescale.TAI)),                      Is.EqualTo(NTPv5Unusable.Timescale));
                Assert.That(UsabilityOf(Response(request, Receive: 0)),                                         Is.EqualTo(NTPv5Unusable.MissingTimestamps));
                Assert.That(UsabilityOf(Response(request, Transmit: 0)),                                        Is.EqualTo(NTPv5Unusable.MissingTimestamps));
                Assert.That(UsabilityOf(Response(request, Era: 255)),                                           Is.EqualTo(NTPv5Unusable.Era));

            });

        }

        #endregion

        #region TheEra_PlacesTheTimestamps()

        /// <summary>
        /// § 9 step 6: the era of the response places the receive timestamp; the transmit
        /// timestamp, which has no era of its own, goes with it - across the 2036 rollover too.
        /// </summary>
        [Test]
        public void TheEra_PlacesTheTimestamps()
        {

            var rollover   = new DateTime(2036, 2, 7, 6, 28, 16, DateTimeKind.Utc);

            Assert.That(NTPv5Client.ExpandTimestamp(1, 0x0000_0001_8000_0000UL), Is.EqualTo(rollover.AddSeconds(1.5)));
            Assert.That(NTPv5Client.ExpandTimestamp(0, 0x0000_0001_8000_0000UL), Is.EqualTo(NTPPacket.NTPEpoch.AddSeconds(1.5)));
            Assert.That(NTPv5Client.ExpandTimestamp(0, Timestamp(Now)),           Is.EqualTo(Now));

            // Received a second before the rollover, sent a second after it.
            var request    = NTPv5Client.BuildRequest();
            var response   = Response(request,
                                      Era:       0,
                                      Receive:   0xFFFF_FFFF_0000_0000UL,
                                      Transmit:  0x0000_0001_0000_0000UL);

            Assert.That(NTPv5Client.ReceiveTime (response), Is.EqualTo(rollover.AddSeconds(-1)));
            Assert.That(NTPv5Client.TransmitTime(response), Is.EqualTo(rollover.AddSeconds( 1)));

            // A clock before 2026 is no reason to doubt an era the server gives.
            var early      = new DateTime(1990, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var past       = Response(request, Era: 0, Receive: Timestamp(early), Transmit: Timestamp(early.AddSeconds(1)));

            Assert.That(NTPv5Client.TransmitTime(past), Is.EqualTo(early.AddSeconds(1)));

        }

        #endregion

        #region TheMeasurement_IsThatOfSection4()

        /// <summary>
        /// § 4.1: offset = ((T2 + T3) - (T4 + T1)) / 2 and delay = |(T4 - T1) - (T3 - T2)|.
        /// </summary>
        [Test]
        public void TheMeasurement_IsThatOfSection4()
        {

            // The server 10 ms ahead, 4 ms each way, 1 ms in the server.
            var t1           = Now;
            var t2           = t1.AddMilliseconds(14);
            var t3           = t2.AddMilliseconds(1);
            var t4           = t1.AddMilliseconds(9);

            var request      = NTPv5Client.BuildRequest();
            var measurement  = NTPv5Client.Measure(t1, Response(request, Receive: Timestamp(t2), Transmit: Timestamp(t3)), t4, request);

            Assert.That(measurement, Is.Not.Null);
            Assert.That(measurement!.Offset,       Is.EqualTo(TimeSpan.FromMilliseconds(10)));
            Assert.That(measurement.Delay,         Is.EqualTo(TimeSpan.FromMilliseconds(8)));
            Assert.That(measurement.Interleaved,   Is.False);
            Assert.That(measurement.Correction,    Is.Null, "no Correction asked for");

        }

        #endregion

        #region TheCorrections_ImproveTheMeasurement_OnlyWhenTheyPassTheirChecks()

        /// <summary>
        /// § 8: offset_c = offset + (Cd - Co) / 2 and delay_c = delay - (Cd + Co - Drx - Dtx) * (1 - FC),
        /// refused where any of delay_c, Co and Cd is negative.
        /// </summary>
        [Test]
        public void TheCorrections_ImproveTheMeasurement_OnlyWhenTheyPassTheirChecks()
        {

            static Int64 Nanoseconds(Double ns) => (Int64) (ns * NTPv5Client.CorrectionUnitsPerNanosecond);

            Assert.That(NTPv5Client.CorrectionToTimeSpan(Nanoseconds(1_000_000)),     Is.EqualTo(TimeSpan.FromMilliseconds(1)));
            Assert.That(NTPv5Client.CorrectionToTimeSpan(Nanoseconds(-250)),          Is.EqualTo(TimeSpan.FromTicks(-3)), "rounded to ticks, away from zero");
            Assert.That(NTPv5Client.CorrectionToTimeSpan(NTPv5Client.CorrectionOverflow), Is.Null);

            // 3 ms of queueing on the way there, 1 ms on the way back, as the switches say.
            var correction = new NTPv5Correction(OriginCorrection:   Nanoseconds(3_000_000),
                                                 OriginPathId:       1,
                                                 DelayCorrection:    Nanoseconds(1_000_000),
                                                 PathId:             1,
                                                 ChecksumComplement: 0);

            var corrected  = NTPv5Client.Correct(TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(8), correction,
                                                 new NTPv5CorrectionParameters(FrequencyError: 0));

            Assert.That(corrected, Is.Not.Null);
            Assert.That(corrected!.Value.Offset, Is.EqualTo(TimeSpan.FromMilliseconds(9)),  "10 + (1 - 3) / 2");
            Assert.That(corrected.Value.Delay,   Is.EqualTo(TimeSpan.FromMilliseconds(4)),  "8 - (1 + 3)");

            var withFrames = NTPv5Client.Correct(TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(8), correction,
                                                 new NTPv5CorrectionParameters(FrequencyError: 0, ReceiveFrameTime: TimeSpan.FromMilliseconds(0.5)));

            Assert.That(withFrames!.Value.Delay, Is.EqualTo(TimeSpan.FromMilliseconds(5)), "Dtx is Drx where unknown: 8 - (4 - 0.5 - 0.5)");

            Assert.Multiple(() => {
                Assert.That(NTPv5Client.Correct(TimeSpan.Zero, TimeSpan.FromMilliseconds(8), correction with { OriginCorrection = -1 }), Is.Null, "Co negative");
                Assert.That(NTPv5Client.Correct(TimeSpan.Zero, TimeSpan.FromMilliseconds(8), correction with { DelayCorrection  = -1 }), Is.Null, "Cd negative");
                Assert.That(NTPv5Client.Correct(TimeSpan.Zero, TimeSpan.FromMilliseconds(3), correction),                                Is.Null, "delay_c negative");
                Assert.That(NTPv5Client.Correct(TimeSpan.Zero, TimeSpan.FromMilliseconds(8), correction with { DelayCorrection  = NTPv5Client.CorrectionOverflow }), Is.Null, "too big to be represented");
            });

        }

        #endregion

        #region ACorrection_IsRead_OnlyWhereItWasAskedFor_AndLast()

        /// <summary>
        /// § 7.7: a client "MUST ignore an unexpected Correction Extension Field in the
        /// response", and one that is not last is not where the draft puts it.
        /// </summary>
        [Test]
        public void ACorrection_IsRead_OnlyWhereItWasAskedFor_AndLast()
        {

            var asked      = NTPv5Client.BuildRequest(RequestCorrection: true);
            var notAsked   = NTPv5Client.BuildRequest();
            var correction = NTPv5ExtensionField.Correction(new NTPv5Correction(5, 6, 7, 8, 9));

            Assert.That(NTPv5Client.CorrectionOf(Response(asked,    Fields: [ correction ]), asked),    Is.EqualTo(new NTPv5Correction(5, 6, 7, 8, 9)));
            Assert.That(NTPv5Client.CorrectionOf(Response(notAsked, Fields: [ correction ]), notAsked), Is.Null);
            Assert.That(NTPv5Client.CorrectionOf(Response(asked,    Fields: [ correction, NTPv5ExtensionField.Padding(4) ]), asked), Is.Null);

        }

        #endregion

        #region TheInterleavedMode_CompletesThePreviousExchange()

        /// <summary>
        /// Figure 15: the first exchange is in the basic mode; an interleaved response gives the
        /// accurate transmit timestamp of the previous one, completing (t1, t2, t3, t4); a basic
        /// response to an interleaved request is a measurement of its own; and too many lost
        /// responses give up the server cookie.
        /// </summary>
        [Test]
        public void TheInterleavedMode_CompletesThePreviousExchange()
        {

            var association = new NTPv5InterleavedAssociation(MaxUnansweredRequests: 1);

            Assert.That(association.NextServerCookie, Is.Zero);

            // Exchange 1, basic: t1 .. t4, t3' less accurate.
            var t1  = Now;
            var t2  = t1.AddMilliseconds(5);
            var t3a = t2.AddMilliseconds(2);              // t3'
            var t3  = t2.AddMilliseconds(1);              // t3, accurate, delivered later
            var t4  = t1.AddMilliseconds(8);

            var request1   = NTPv5Client.BuildRequest(Flags: NTPv5Flags.InterleavedMode, ServerCookie: association.NextServerCookie);
            var response1  = Response(request1, Receive: Timestamp(t2), Transmit: Timestamp(t3a), ServerCookie: 1111);
            var first      = association.RecordValidResponse(request1, response1, t1, t4);

            Assert.That(first!.Interleaved, Is.False);
            Assert.That(first.T3,           Is.EqualTo(t3a));
            Assert.That(association.NextServerCookie, Is.EqualTo(1111));

            // Exchange 2, interleaved: its transmit timestamp is t3.
            var t5         = t1.AddSeconds(16);
            var t6         = t5.AddMilliseconds(5);
            var t8         = t5.AddMilliseconds(9);

            var request2   = NTPv5Client.BuildRequest(Flags: NTPv5Flags.InterleavedMode, ServerCookie: association.NextServerCookie);
            var response2  = Response(request2, Flags: NTPv5Flags.InterleavedMode, Receive: Timestamp(t6), Transmit: Timestamp(t3), ServerCookie: 2222);
            var second     = association.RecordValidResponse(request2, response2, t5, t8);

            Assert.Multiple(() => {
                Assert.That(second!.Interleaved, Is.True);
                Assert.That(second.T1,           Is.EqualTo(t1));
                Assert.That(second.T2,           Is.EqualTo(t2));
                Assert.That(second.T3,           Is.EqualTo(t3));
                Assert.That(second.T4,           Is.EqualTo(t4));
                Assert.That(association.NextServerCookie, Is.EqualTo(2222));
            });

            // Exchange 3: the server no longer has the timestamp and answers in the basic mode.
            var t9         = t5.AddSeconds(16);
            var t10        = t9.AddMilliseconds(5);
            var t11        = t10.AddMilliseconds(1);
            var t12        = t9.AddMilliseconds(7);

            var request3   = NTPv5Client.BuildRequest(Flags: NTPv5Flags.InterleavedMode, ServerCookie: association.NextServerCookie);
            var third      = association.RecordValidResponse(request3, Response(request3, Receive: Timestamp(t10), Transmit: Timestamp(t11), ServerCookie: 3333), t9, t12);

            Assert.That(third!.Interleaved, Is.False);
            Assert.That(third.T1,           Is.EqualTo(t9));
            Assert.That(association.BasicResponses,       Is.EqualTo(2));
            Assert.That(association.InterleavedResponses, Is.EqualTo(1));

            // An interleaved response for a cookie this client did not send completes nothing.
            var stray      = NTPv5Client.BuildRequest(Flags: NTPv5Flags.InterleavedMode, ServerCookie: 9999);
            Assert.That(association.RecordValidResponse(stray, Response(stray, Flags: NTPv5Flags.InterleavedMode, ServerCookie: 4444), t9, t12), Is.Null);

            // Lost responses: one is survived, two give up the cookie.
            Assert.That(association.RecordUnansweredRequest(), Is.True);
            Assert.That(association.RecordUnansweredRequest(), Is.False);
            Assert.That(association.NextServerCookie,          Is.Zero);

        }

        #endregion

        #region AServerListingThisClient_IsALoop()

        /// <summary>
        /// § 7.4 and § 9: a server whose reference IDs contain the client's own is not to be
        /// selected; a configured share may be tolerated.
        /// </summary>
        [Test]
        public void AServerListingThisClient_IsALoop()
        {

            var own      = NTPv5ReferenceIds.NewReferenceId();
            var other    = NTPv5ReferenceIds.NewReferenceId();

            var listed   = NTPv5ReferenceIds.Of(other, [ new NTPv5ReferenceIdSource(1.0, [ new NTPv5ReferenceIdEntry(NTPv5ReferenceIds.FullShare, own) ]) ]);
            var unlisted = NTPv5ReferenceIds.Of(other, []);

            Assert.Multiple(() => {
                Assert.That(NTPv5Client.IsLoop(listed.Entries,   own), Is.True);
                Assert.That(NTPv5Client.IsLoop(unlisted.Entries, own), Is.False);
                Assert.That(NTPv5Client.IsLoop(listed.Entries,   own, MaximumShare: 0.6), Is.False, "a 50 % share tolerated");
                Assert.That(NTPv5Client.IsLoop(listed.Entries,   0),   Is.False, "no reference ID, no loop");
            });

        }

        #endregion

        #region ThePollField_SupersedesRateAndDeny()

        /// <summary>
        /// § 6 and § 9: the poll field is the minimum polling interval, followed up to 2^15
        /// without authentication and 2^18 with it; 127 ends the association - and where it came
        /// unauthenticated on an NTS association, a new key exchange may follow after a backoff.
        /// </summary>
        [Test]
        public void ThePollField_SupersedesRateAndDeny()
        {

            var now    = new DateTimeOffset(Now);

            var plain  = new NTPServerAccessState();
            Assert.That(plain.ApplyNTPv5Poll(6, now), Is.True);
            Assert.That(plain.MayQuery(now.AddSeconds(63)), Is.False);
            Assert.That(plain.MayQuery(now.AddSeconds(64)), Is.True);

            var capped = new NTPServerAccessState();
            capped.ApplyNTPv5Poll(30, now);
            Assert.That(capped.NTPv5MinimumPoll, Is.EqualTo(15));

            var sealedCap = new NTPServerAccessState();
            sealedCap.ApplyNTPv5Poll(30, now, NTPKissTrust.Authenticated);
            Assert.That(sealedCap.NTPv5MinimumPoll, Is.EqualTo(18));

            var goAway = new NTPServerAccessState();
            Assert.That(goAway.ApplyNTPv5Poll(NTPv5Packet.PollGoAway, now), Is.False);
            Assert.That(goAway.Demobilized, Is.True);

            var forged = new NTPServerAccessState(UnauthenticatedDenyPause: TimeSpan.FromMinutes(5));
            Assert.That(forged.ApplyNTPv5Poll(NTPv5Packet.PollGoAway, now, NTPKissTrust.Unauthenticated), Is.False);
            Assert.That(forged.Demobilized, Is.True);
            Assert.That(forged.MayQuery(now.AddDays(365)), Is.False);
            Assert.That(forged.MayRerunKeyExchange(now.AddMinutes(5)), Is.True);

        }

        #endregion

        #region TheVersionNegotiation_FollowsSection12()

        /// <summary>
        /// § 12: NTPv4 with the magic first; NTPv5 once echoed; back to NTPv4 after two
        /// unanswered NTPv5 requests, without the magic for 256 requests, then advertising again.
        /// </summary>
        [Test]
        public void TheVersionNegotiation_FollowsSection12()
        {

            var negotiation = new NTPv5VersionNegotiation(BackoffRequests: 3);

            Assert.That(negotiation.Version,            Is.EqualTo(NTPv5NegotiatedVersion.NTPv4Advertising));
            Assert.That(negotiation.ReferenceTimestamp, Is.EqualTo(0x4E54503544524654UL), "NTP5DRFT");

            Assert.That(negotiation.RecordNTPv4Response(0),                             Is.EqualTo(NTPv5NegotiatedVersion.NTPv4Advertising));
            Assert.That(negotiation.RecordNTPv4Response(NTPv5Draft.NegotiationMagic),   Is.EqualTo(NTPv5NegotiatedVersion.NTPv5));

            Assert.That(negotiation.RecordNTPv5Result(false), Is.EqualTo(NTPv5NegotiatedVersion.NTPv5), "one miss is not enough");
            Assert.That(negotiation.RecordNTPv5Result(true),  Is.EqualTo(NTPv5NegotiatedVersion.NTPv5));
            Assert.That(negotiation.RecordNTPv5Result(false), Is.EqualTo(NTPv5NegotiatedVersion.NTPv5), "the count starts over after a valid one");
            Assert.That(negotiation.RecordNTPv5Result(false), Is.EqualTo(NTPv5NegotiatedVersion.NTPv4Only));
            Assert.That(negotiation.ReferenceTimestamp,       Is.Zero, "no magic while sticking with NTPv4");

            Assert.That(negotiation.RecordNTPv4Response(NTPv5Draft.NegotiationMagic), Is.EqualTo(NTPv5NegotiatedVersion.NTPv4Only), "an echo it did not ask for");

            Assert.That(negotiation.RecordNTPv4Request(), Is.EqualTo(NTPv5NegotiatedVersion.NTPv4Only));
            Assert.That(negotiation.RecordNTPv4Request(), Is.EqualTo(NTPv5NegotiatedVersion.NTPv4Only));
            Assert.That(negotiation.RecordNTPv4Request(), Is.EqualTo(NTPv5NegotiatedVersion.NTPv4Advertising));

            Assert.That(new NTPv5VersionNegotiation().BackoffRequests, Is.EqualTo(256));

        }

        #endregion


        #region (internal static) Response(Request, ...)

        /// <summary>
        /// A response to the given request: stratum 1, synchronized, its timescale, now as both
        /// timestamps, its Draft Identification back - each of which can be spoiled.
        /// </summary>
        internal static NTPv5Packet Response(NTPv5ClientRequest                 Request,
                                             Byte                               Mode            = NTPv5Packet.ResponseMode,
                                             Byte                               Stratum         = 1,
                                             SByte                              Poll            = 4,
                                             UInt32                             RootDelay       = 0,
                                             UInt32                             RootDispersion  = 0,
                                             NTPv5Timescale?                    Timescale       = null,
                                             Byte?                              Era             = null,
                                             NTPv5Flags                         Flags           = NTPv5Flags.None,
                                             UInt64                             ServerCookie    = 0,
                                             UInt64?                            ClientCookie    = null,
                                             UInt64?                            Receive         = null,
                                             UInt64?                            Transmit        = null,
                                             String?                            Draft           = null,
                                             IEnumerable<NTPv5ExtensionField>?  Fields          = null)

            => new (Mode:               Mode,
                    Stratum:            Stratum,
                    Poll:               Poll,
                    RootDelay:          RootDelay,
                    RootDispersion:     RootDispersion,
                    Timescale:          Timescale    ?? Request.Timescale,
                    Era:                Era          ?? NTPv5Packet.EraOf(Now),
                    Flags:              Flags,
                    ServerCookie:       ServerCookie,
                    ClientCookie:       ClientCookie ?? Request.ClientCookie,
                    ReceiveTimestamp:   Receive      ?? Timestamp(Now),
                    TransmitTimestamp:  Transmit     ?? Timestamp(Now),
                    ExtensionFields:    [ NTPv5ExtensionField.DraftIdentification(Draft), .. Fields ?? [] ]);

        #endregion

        #region (internal static) Timestamp(Time)

        /// <summary>
        /// The timestamp64 of a date, era aside.
        /// </summary>
        internal static UInt64 Timestamp(DateTime Time)
        {

            var ticks    = (Time - NTPPacket.NTPEpoch).Ticks;
            var seconds  = ticks / TimeSpan.TicksPerSecond;
            var fraction = (UInt64) (ticks % TimeSpan.TicksPerSecond) * 0x1_0000_0000UL / (UInt64) TimeSpan.TicksPerSecond;

            // Rounded up, so that converting back by truncation gives the same ticks.
            if ((fraction * (UInt64) TimeSpan.TicksPerSecond) >> 32 < (UInt64) (ticks % TimeSpan.TicksPerSecond))
                fraction++;

            return ((UInt64) (UInt32) seconds << 32) | fraction;

        }

        #endregion

    }

}
