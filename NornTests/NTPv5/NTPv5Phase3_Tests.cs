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

using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTPv5
{

    /// <summary>
    /// The interleaved mode, the reference IDs and the timestamp fields of an NTPv5 server,
    /// draft-ietf-ntp-ntpv5-10 § 7.4, § 7.7 to § 7.9, § 8 and § 10 - without a socket.
    /// </summary>
    [TestFixture]
    public class NTPv5Phase3_Tests
    {

        #region Data

        private const           UInt64            receiveTimestamp   = 0xEC00000080000000UL;
        private const           UInt64            transmitTimestamp  = 0xEC00000090000000UL;
        private const           UInt64            ownReferenceId     = 0x00_1122_3344_5566_77UL;

        private static readonly DateTime          receiveTime        = new (2026, 11, 28, 12, 0, 0, DateTimeKind.Utc);

        private static readonly NTPv5ServerClock  clock              = new (Stratum:         2,
                                                                            RootDelay:       TimeSpan.FromMilliseconds(30),
                                                                            RootDispersion:  TimeSpan.FromMilliseconds(5),
                                                                            Synchronized:    true,
                                                                            Precision:       -20,
                                                                            MinimumPoll:     6) {
                                                                          SupportedFlags      = NTPv5Flags.Unsynchronized | NTPv5Flags.InterleavedMode,
                                                                          ReferenceIds        = NTPv5ReferenceIds.Of(ownReferenceId),
                                                                          ReferenceTimestamp  = 0xEBFFFFFF00000000UL,
                                                                          MonotonicEpochId    = 0xCAFE
                                                                      };

        #endregion

        #region (private static) Respond(Request, Exchange = null, Clock = null)

        private static (NTPv5Packet Request, NTPv5Packet Response, Int32 Length) Respond(NTPv5Packet                         Request,
                                                                                         Func<NTPv5Packet, NTPv5Exchange>?   Exchange  = null,
                                                                                         NTPv5ServerClock?                   Clock     = null)
        {

            var outcome = NTPv5Responder.TryRespond(Request.ToByteArray(),
                                                    receiveTime,
                                                    Clock    ?? clock,
                                                    Exchange ?? (_ => new NTPv5Exchange(receiveTimestamp, transmitTimestamp, MonotonicReceiveTimestamp: 0x0000_0010_8000_0000UL)),
                                                    out var response,
                                                    out var error);

            Assert.That(outcome, Is.EqualTo(NTPv5RequestOutcome.Answered), error);
            Assert.That(NTPv5Packet.TryParse(response, out var parsed, out var parseError), Is.True, parseError);

            return (Request, parsed!, response!.Length);

        }

        #endregion


        #region ReferenceIDs_AreAnswered_AtTheRequestsLength()

        [Test]
        public void ReferenceIDs_AreAnswered_AtTheRequestsLength()
        {

            var (request, response, length) = Respond(NTPv5Packet.Request(ExtensionFields: [ NTPv5ReferenceIds.Request(Entries: 4) ]));

            var field = response.Find(NTPv5ExtensionTypes.ReferenceIDsResponse);

            Assert.That(field,  Is.Not.Null);
            Assert.That(field!.Length, Is.EqualTo(4 + 32));
            Assert.That(NTPv5ReferenceIds.TryRead(field.Value, out var entries), Is.True);

            Assert.Multiple(() => {
                Assert.That(entries[0],        Is.EqualTo(new NTPv5ReferenceIdEntry(0, ownReferenceId)), "entry 0 is the server itself, at 100 %");
                Assert.That(entries.Skip(1),   Is.All.EqualTo(NTPv5ReferenceIdEntry.Unused));
                Assert.That(length,            Is.EqualTo(request.Length));
            });

            // An index that does not fit its length: the field is ignored, the length kept.
            var (outOfRange, outOfRangeResponse, outOfRangeLength) = Respond(NTPv5Packet.Request(ExtensionFields: [ NTPv5ReferenceIds.Request(Index: 31, Entries: 2) ]));

            Assert.That(outOfRangeResponse.Find(NTPv5ExtensionTypes.ReferenceIDsResponse), Is.Null);
            Assert.That(outOfRangeLength, Is.EqualTo(outOfRange.Length));

        }

        #endregion

        #region TheCorrection_IsCopiedToTheOriginFields_AndGoesLast()

        /// <summary>
        /// § 7.7: Delay Correction and Path ID of the request become the Origin ones, the
        /// server's own are zero, and the field is the last of the response - even where the
        /// request had it elsewhere.
        /// </summary>
        [Test]
        public void TheCorrection_IsCopiedToTheOriginFields_AndGoesLast()
        {

            var correction  = NTPv5ExtensionField.Correction(new NTPv5Correction(OriginCorrection:    99,
                                                                                  OriginPathId:        98,
                                                                                  DelayCorrection:     1234 << 16,
                                                                                  PathId:              7,
                                                                                  ChecksumComplement:  0x5555));

            var (request, response, length) = Respond(NTPv5Packet.Request(ExtensionFields: [ correction, NTPv5ExtensionField.ServerInformation(), NTPv5ExtensionField.Padding(16) ]));

            Assert.That(response.ExtensionFields[^1].TryReadCorrection(out var answer), Is.True, "the last field is the Correction");

            Assert.Multiple(() => {
                Assert.That(answer.OriginCorrection,    Is.EqualTo(1234 << 16));
                Assert.That(answer.OriginPathId,        Is.EqualTo(7));
                Assert.That(answer.DelayCorrection,     Is.Zero);
                Assert.That(answer.PathId,              Is.Zero);
                Assert.That(answer.ChecksumComplement,  Is.Zero);
                Assert.That(length,                     Is.EqualTo(request.Length));
                Assert.That(response.ExtensionFields.Count(field => field.Type == NTPv5ExtensionTypes.Correction), Is.EqualTo(1));
            });

            // A Correction field of the wrong length is not one.
            var (_, wrongLength, _) = Respond(NTPv5Packet.Request(ExtensionFields: [ new NTPv5ExtensionField(NTPv5ExtensionTypes.Correction, new Byte[20]) ]));

            Assert.That(wrongLength.Find(NTPv5ExtensionTypes.Correction), Is.Null);

        }

        #endregion

        #region TheReferenceAndMonotonicTimestamps_AreAnswered()

        [Test]
        public void TheReferenceAndMonotonicTimestamps_AreAnswered()
        {

            var (request, response, length) = Respond(NTPv5Packet.Request(ExtensionFields: [ NTPv5ExtensionField.ReferenceTimestamp(),
                                                                                             NTPv5ExtensionField.MonotonicReceiveTimestamp() ]));

            Assert.That(response.Find(NTPv5ExtensionTypes.ReferenceTimestamp)!.TryReadReferenceTimestamp(out var reference), Is.True);
            Assert.That(response.Find(NTPv5ExtensionTypes.MonotonicReceiveTimestamp)!.TryReadMonotonicReceiveTimestamp(out var epoch, out var monotonic), Is.True);

            Assert.Multiple(() => {
                Assert.That(reference,  Is.EqualTo(clock.ReferenceTimestamp));
                Assert.That(epoch,      Is.EqualTo(0xCAFE));
                Assert.That(monotonic,  Is.EqualTo(0x0000_0010_8000_0000UL));
                Assert.That(length,     Is.EqualTo(request.Length));
            });

            // A server that reads no monotonic clock says nothing of one.
            var (_, without, _) = Respond(NTPv5Packet.Request(ExtensionFields: [ NTPv5ExtensionField.MonotonicReceiveTimestamp() ]),
                                          Clock: clock with { MonotonicEpochId = null });

            Assert.That(without.Find(NTPv5ExtensionTypes.MonotonicReceiveTimestamp), Is.Null);

        }

        #endregion

        #region TheInterleavedMode_IsClaimedOnlyWhereAskedAndServed()

        /// <summary>
        /// § 10: the cookie goes to a client that asked for the mode and is served it, even
        /// when this response is not yet interleaved; the flag only on one that is. A client
        /// that did not ask gets neither, whatever the exchange says, and neither does one of
        /// a server that does not serve the mode.
        /// </summary>
        [Test]
        public void TheInterleavedMode_IsClaimedOnlyWhereAskedAndServed()
        {

            NTPv5Exchange Interleaved(NTPv5Packet _) => new (receiveTimestamp, 0x1111, ServerCookie: receiveTimestamp, Interleaved: true);
            NTPv5Exchange First      (NTPv5Packet _) => new (receiveTimestamp, transmitTimestamp, ServerCookie: receiveTimestamp);

            var asking = NTPv5Packet.Request(Flags: NTPv5Flags.InterleavedMode, ServerCookie: 42);

            var (_, first, _) = Respond(asking, First);

            Assert.That(first.Flags,         Is.EqualTo(NTPv5Flags.None));
            Assert.That(first.ServerCookie,  Is.EqualTo(receiveTimestamp), "the cookie for the next request");

            var (_, second, _) = Respond(asking, Interleaved);

            Assert.That(second.Flags,              Is.EqualTo(NTPv5Flags.InterleavedMode));
            Assert.That(second.TransmitTimestamp,  Is.EqualTo(0x1111UL), "the earlier response's transmit timestamp");

            var (_, notAsked, _) = Respond(NTPv5Packet.Request(), Interleaved);

            Assert.That(notAsked.Flags,         Is.EqualTo(NTPv5Flags.None));
            Assert.That(notAsked.ServerCookie,  Is.Zero);

            var (_, notServed, _) = Respond(asking, Interleaved, clock with { SupportedFlags = NTPv5Flags.Unsynchronized });

            Assert.That(notServed.Flags,         Is.EqualTo(NTPv5Flags.None));
            Assert.That(notServed.ServerCookie,  Is.Zero);

        }

        #endregion

        #region ServerInformation_SaysTheInterleavedModeWhereServed()

        [Test]
        public void ServerInformation_SaysTheInterleavedModeWhereServed()
        {

            var request = NTPv5Packet.Request(ExtensionFields: [ NTPv5ExtensionField.ServerInformation() ]);

            Respond(request).Response.Find(NTPv5ExtensionTypes.ServerInformation)!.TryReadServerInformation(out _, out var served);
            Respond(request, Clock: clock with { SupportedFlags = NTPv5Flags.Unsynchronized }).Response.Find(NTPv5ExtensionTypes.ServerInformation)!.TryReadServerInformation(out _, out var notServed);

            Assert.That(served,     Is.EqualTo(NTPv5Flags.Unsynchronized | NTPv5Flags.InterleavedMode));
            Assert.That(notServed,  Is.EqualTo(NTPv5Flags.Unsynchronized));

        }

        #endregion

        #region TheStore_AnswersACookieOnce_WithTheTransmissionItRecorded()

        /// <summary>
        /// § 8 and § 10 on the server's store: a cookie it gave out draws the transmit
        /// timestamp recorded for that response, once; one it did not give out, or gave out
        /// and has answered already, draws the basic mode.
        /// </summary>
        [Test]
        public void TheStore_AnswersACookieOnce_WithTheTransmissionItRecorded()
        {

            var store   = new InterleavedTimestamps(InterleavedModePolicy.Everyone);
            var client  = IPAddress.Parse("192.0.2.1");

            var first   = store.BeginNTPv5Exchange(client, 0x1000_0000_0000UL, 0, TimeProvider.System)!;

            Assert.That(first.IsInterleaved,     Is.False);
            Assert.That(first.ReceiveTimestamp,  Is.EqualTo(0x1000_0000_0000UL), "the cookie of the response");

            first.RecordTransmission(0x1000_0000_0777UL);

            var second  = store.BeginNTPv5Exchange(client, 0x2000_0000_0000UL, first.ReceiveTimestamp, TimeProvider.System)!;

            Assert.That(second.IsInterleaved,      Is.True);
            Assert.That(second.TransmitTimestamp,  Is.EqualTo(0x1000_0000_0777UL));

            var replay  = store.BeginNTPv5Exchange(client, 0x3000_0000_0000UL, first.ReceiveTimestamp, TimeProvider.System)!;

            Assert.That(replay.IsInterleaved, Is.False, "a cookie answers once");

            var stranger = store.BeginNTPv5Exchange(IPAddress.Parse("192.0.2.2"), 0x4000_0000_0000UL, second.ReceiveTimestamp, TimeProvider.System)!;

            Assert.That(stranger.IsInterleaved, Is.False, "a cookie is good from the address it was given to");

            Assert.That(new InterleavedTimestamps(InterleavedModePolicy.AuthenticatedOnly).
                            BeginNTPv5Exchange(client, 1, 0, TimeProvider.System), Is.Null, "nothing NTPv5 sends qualifies under AuthenticatedOnly");

        }

        #endregion

        #region Timestamp64_CountsSecondsAndFractions()

        [Test]
        public void Timestamp64_CountsSecondsAndFractions()
        {
            Assert.That(NTPv5Packet.ToTimestamp64(TimeSpan.FromSeconds(1.5)),  Is.EqualTo(0x0000_0001_8000_0000UL));
            Assert.That(NTPv5Packet.ToTimestamp64(TimeSpan.Zero),              Is.Zero);
        }

        #endregion

    }

}
