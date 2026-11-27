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

using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTPv5
{

    /// <summary>
    /// The server side of draft-ietf-ntp-ntpv5-10 § 10 in the basic mode, without a socket.
    /// </summary>
    [TestFixture]
    public class NTPv5Responder_Tests
    {

        #region Data

        private const           UInt64            receiveTimestamp   = 0xEC00000080000000UL;
        private const           UInt64            transmitTimestamp  = 0xEC00000090000000UL;

        private static readonly DateTime          receiveTime        = new (2026, 11, 27, 12, 0, 0, DateTimeKind.Utc);

        private static readonly NTPv5ServerClock  synchronized       = new (Stratum:         2,
                                                                            RootDelay:       TimeSpan.FromMilliseconds(30),
                                                                            RootDispersion:  TimeSpan.FromMilliseconds(5),
                                                                            Synchronized:    true,
                                                                            Precision:       -20,
                                                                            MinimumPoll:     6);

        #endregion

        #region (private static) Respond(Request, Clock = null)

        private static (NTPv5RequestOutcome Outcome, NTPv5Packet? Response, Int32 Length, String? Error) Respond(NTPv5Packet        Request,
                                                                                                                 NTPv5ServerClock?  Clock = null)
            => Respond(Request.ToByteArray(), Clock);

        private static (NTPv5RequestOutcome Outcome, NTPv5Packet? Response, Int32 Length, String? Error) Respond(Byte[]             Request,
                                                                                                                 NTPv5ServerClock?  Clock = null)
        {

            var outcome = NTPv5Responder.TryRespond(Request,
                                                    receiveTimestamp,
                                                    receiveTime,
                                                    Clock ?? synchronized,
                                                    () => transmitTimestamp,
                                                    out var response,
                                                    out var error);

            if (response is null)
                return (outcome, null, 0, error);

            Assert.That(NTPv5Packet.TryParse(response, out var parsed, out var parseError), Is.True, parseError);

            return (outcome, parsed, response.Length, error);

        }

        #endregion


        #region ARequest_IsAnswered_AsSection10Has()

        /// <summary>
        /// § 10 step 4: version 5, mode 4, the server's clock, the era of the receive timestamp,
        /// the client's cookie back - and step 5, the length of the request.
        /// </summary>
        [Test]
        public void ARequest_IsAnswered_AsSection10Has()
        {

            var request                       = NTPv5Packet.Request();
            var (outcome, response, length, error) = Respond(request);

            Assert.That(outcome, Is.EqualTo(NTPv5RequestOutcome.Answered), error);

            Assert.Multiple(() => {

                Assert.That(response!.Mode,              Is.EqualTo(4));
                Assert.That(response.Reserved,           Is.Zero);
                Assert.That(response.Stratum,            Is.EqualTo(2));
                Assert.That(response.Poll,               Is.EqualTo(6),  "the shortest interval allowed, not an echo");
                Assert.That(response.Precision,          Is.EqualTo(-20));
                Assert.That(response.RootDelay,          Is.EqualTo(Time32.FromTimeSpan(TimeSpan.FromMilliseconds(30))));
                Assert.That(response.RootDispersion,     Is.EqualTo(Time32.FromTimeSpan(TimeSpan.FromMilliseconds(5))));
                Assert.That(response.Timescale,          Is.EqualTo(NTPv5Timescale.UTC));
                Assert.That(response.Era,                Is.EqualTo(0));
                Assert.That(response.Flags,              Is.EqualTo(NTPv5Flags.None));
                Assert.That(response.ServerCookie,       Is.Zero, "no interleaved mode, no server cookie");
                Assert.That(response.ClientCookie,       Is.EqualTo(request.ClientCookie));
                Assert.That(response.ReceiveTimestamp,   Is.EqualTo(receiveTimestamp));
                Assert.That(response.TransmitTimestamp,  Is.EqualTo(transmitTimestamp));
                Assert.That(length,                      Is.EqualTo(request.Length), "§ 10 step 5");

                Assert.That(NTPv5Draft.IsThisDraft(response.DraftIdentification), Is.True, "§ 7.1: the draft named back");

            });

        }

        #endregion

        #region TheResponse_IsAsLongAsTheRequest_WhateverItCarries()

        /// <summary>
        /// § 7 and § 10 step 5: a field the server does not answer is left out and made up for
        /// by Padding, as is the client's own Padding.
        /// </summary>
        [Test]
        public void TheResponse_IsAsLongAsTheRequest_WhateverItCarries()
        {

            var unknown  = new NTPv5ExtensionField((NTPv5ExtensionTypes) 0xF5AA, new Byte[9]);

            var request  = NTPv5Packet.Request(ExtensionFields: [ NTPv5ExtensionField.Padding(100), unknown ]);

            var (outcome, response, length, error) = Respond(request);

            Assert.That(outcome, Is.EqualTo(NTPv5RequestOutcome.Answered), error);

            Assert.Multiple(() => {
                Assert.That(length,                                       Is.EqualTo(request.Length));
                Assert.That(response!.Find((NTPv5ExtensionTypes) 0xF5AA), Is.Null,     "an unknown field is not echoed");
                Assert.That(response.Find(NTPv5ExtensionTypes.Padding),   Is.Not.Null, "what is short is padded");
            });

        }

        #endregion

        #region ServerInformation_SaysVersionsAndFlags()

        /// <summary>
        /// § 7.6, which a server must support: versions 1 to 5, and the one flag it can set.
        /// </summary>
        [Test]
        public void ServerInformation_SaysVersionsAndFlags()
        {

            var request  = NTPv5Packet.Request(ExtensionFields: [ NTPv5ExtensionField.ServerInformation() ]);

            var (outcome, response, length, error) = Respond(request);

            Assert.That(outcome, Is.EqualTo(NTPv5RequestOutcome.Answered), error);
            Assert.That(response!.Find(NTPv5ExtensionTypes.ServerInformation)!.TryReadServerInformation(out var versions, out var flags), Is.True);

            Assert.Multiple(() => {
                Assert.That(versions, Is.EqualTo(0b1_1111), "versions 1 to 5");
                Assert.That(flags,    Is.EqualTo(NTPv5Flags.Unsynchronized));
                Assert.That(length,   Is.EqualTo(request.Length));
            });

        }

        #endregion

        #region ARequestOfNoDraftOrAnother_IsNotAnswered()

        /// <summary>
        /// § 7.1 and § 11: a draft server answers its own draft and nothing else - not a request
        /// naming none, not one naming the revision before, not one naming a longer string.
        /// </summary>
        [TestCase("")]
        [TestCase("draft-ietf-ntp-ntpv5-09")]
        [TestCase("draft-ietf-ntp-ntpv5-10x")]
        [TestCase("draft-ietf-ntp-ntpv5-1")]
        public void ARequestOfNoDraftOrAnother_IsNotAnswered(String Draft)
        {

            var request = Draft.Length == 0
                              ? NTPv5Packet.Request(DraftIdentification: String.Empty)
                              : NTPv5Packet.Request(DraftIdentification: Draft);

            Assert.That(Respond(request).Outcome, Is.EqualTo(NTPv5RequestOutcome.OtherDraft));

        }

        #endregion

        #region OnlyARequest_IsAnswered()

        /// <summary>
        /// § 10 step 3: anything but mode 3 is dropped, or a forged response would be answered.
        /// </summary>
        [TestCase((Byte) 4)]
        [TestCase((Byte) 1)]
        [TestCase((Byte) 0)]
        public void OnlyARequest_IsAnswered(Byte Mode)
        {

            var notARequest = new NTPv5Packet(Mode:             Mode,
                                              ClientCookie:     1,
                                              ExtensionFields:  [ NTPv5ExtensionField.DraftIdentification() ]);

            Assert.That(Respond(notARequest).Outcome, Is.EqualTo(NTPv5RequestOutcome.NotARequest));

        }

        #endregion

        #region AnUnsynchronizedClock_AnswersOnlyWhoAsked()

        /// <summary>
        /// § 10 step 6: a response with a flag the request did not set is dropped. So an
        /// unsynchronized server answers only a client that set Unsynchronized itself.
        /// </summary>
        [Test]
        public void AnUnsynchronizedClock_AnswersOnlyWhoAsked()
        {

            var unsynchronized = synchronized with { Synchronized = false };

            Assert.That(Respond(NTPv5Packet.Request(), unsynchronized).Outcome, Is.EqualTo(NTPv5RequestOutcome.Unsynchronized));

            var (outcome, response, _, error) = Respond(NTPv5Packet.Request(Flags: NTPv5Flags.Unsynchronized), unsynchronized);

            Assert.That(outcome,          Is.EqualTo(NTPv5RequestOutcome.Answered), error);
            Assert.That(response!.Flags,  Is.EqualTo(NTPv5Flags.Unsynchronized));

            // And a synchronized server does not echo the flag: it says something of the clock.
            Assert.That(Respond(NTPv5Packet.Request(Flags: NTPv5Flags.Unsynchronized)).Response!.Flags, Is.EqualTo(NTPv5Flags.None));

        }

        #endregion

        #region FlagsItCannotHonour_AreNotClaimed()

        /// <summary>
        /// § 10 step 3 ignores unknown flags; and the interleaved mode, not served, is neither
        /// claimed nor given a server cookie.
        /// </summary>
        [Test]
        public void FlagsItCannotHonour_AreNotClaimed()
        {

            var request = NTPv5Packet.Request(Flags:         NTPv5Flags.InterleavedMode | NTPv5Flags.AuthenticationNAK | (NTPv5Flags) 0x8000,
                                              ServerCookie:  0x1234);

            var (outcome, response, _, error) = Respond(request);

            Assert.That(outcome,                 Is.EqualTo(NTPv5RequestOutcome.Answered), error);
            Assert.That(response!.Flags,         Is.EqualTo(NTPv5Flags.None));
            Assert.That(response.ServerCookie,   Is.Zero);
            Assert.That(response.TransmitTimestamp, Is.EqualTo(transmitTimestamp), "the basic mode's transmit timestamp");

        }

        #endregion

        #region ATimescaleItDoesNotHave_IsAnsweredInUTC()

        /// <summary>
        /// § 10: the timescale asked for if supported, otherwise any supported one - and the
        /// field says which, for the client to see it is not its own.
        /// </summary>
        [TestCase(NTPv5Timescale.TAI)]
        [TestCase(NTPv5Timescale.UT1)]
        [TestCase((NTPv5Timescale) 200)]
        public void ATimescaleItDoesNotHave_IsAnsweredInUTC(NTPv5Timescale Timescale)
        {

            var (outcome, response, _, error) = Respond(NTPv5Packet.Request(Timescale: Timescale));

            Assert.That(outcome,              Is.EqualTo(NTPv5RequestOutcome.Answered), error);
            Assert.That(response!.Timescale,  Is.EqualTo(NTPv5Timescale.UTC));

        }

        #endregion

        #region ReservedBits_AreIgnored_AndSentAsZero()

        /// <summary>
        /// § 6: the Reserved bits are ignored on receipt.
        /// </summary>
        [Test]
        public void ReservedBits_AreIgnored_AndSentAsZero()
        {

            var bytes  = NTPv5Packet.Request().ToByteArray();
            bytes[0]  |= 0xC0;

            var (outcome, response, _, error) = Respond(bytes);

            Assert.That(outcome,             Is.EqualTo(NTPv5RequestOutcome.Answered), error);
            Assert.That(response!.Reserved,  Is.Zero);

        }

        #endregion

        #region TheEra_IsThatOfTheReceiveTimestamp()

        /// <summary>
        /// § 6: the Era of a response is that of its receive timestamp.
        /// </summary>
        [Test]
        public void TheEra_IsThatOfTheReceiveTimestamp()
        {

            var outcome = NTPv5Responder.TryRespond(NTPv5Packet.Request().ToByteArray(),
                                                    0x0000000100000000UL,
                                                    new DateTime(2036, 2, 7, 6, 28, 17, DateTimeKind.Utc),
                                                    synchronized,
                                                    () => 0x0000000200000000UL,
                                                    out var response,
                                                    out var error);

            Assert.That(outcome, Is.EqualTo(NTPv5RequestOutcome.Answered), error);
            Assert.That(response![13], Is.EqualTo(1), "era 1, a second after the rollover");

        }

        #endregion

        #region AMalformedRequest_IsInvalid()

        [Test]
        public void AMalformedRequest_IsInvalid()
        {

            var bytes = NTPv5Packet.Request().ToByteArray();

            Assert.Multiple(() => {
                Assert.That(Respond(bytes[..47]).Outcome,             Is.EqualTo(NTPv5RequestOutcome.Invalid), "shorter than the header");
                Assert.That(Respond(bytes[..50]).Outcome,             Is.EqualTo(NTPv5RequestOutcome.Invalid), "not a whole number of 4 octets");
                Assert.That(Respond(bytes[..72]).Outcome,             Is.EqualTo(NTPv5RequestOutcome.Invalid), "the draft name cut short");
            });

        }

        #endregion

    }

}
