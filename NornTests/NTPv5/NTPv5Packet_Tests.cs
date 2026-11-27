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

using System.Buffers.Binary;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTPv5
{

    /// <summary>
    /// The wire format of draft-ietf-ntp-ntpv5-10 § 5 to § 7: time32, the header, the
    /// extension field framing, the era.
    /// </summary>
    [TestFixture]
    public class NTPv5Packet_Tests
    {

        #region Time32_RoundsUp_AndWhatDoesNotFitIsInfinity()

        /// <summary>
        /// § 5: 4.28 fixed point. Rounded up as § 6 asks of the root delay and dispersion, so a
        /// bound is not made smaller on the way; 16 s and more are infinity, all ones.
        /// </summary>
        [Test]
        public void Time32_RoundsUp_AndWhatDoesNotFitIsInfinity()
        {

            Assert.Multiple(() => {

                Assert.That(Time32.FromTimeSpan(TimeSpan.Zero),                    Is.EqualTo(0u));
                Assert.That(Time32.FromTimeSpan(TimeSpan.FromSeconds(-1)),         Is.EqualTo(0u),           "nothing below zero");
                Assert.That(Time32.FromTimeSpan(TimeSpan.FromSeconds(1)),          Is.EqualTo(1u << 28),     "one second is 2^28 units");
                Assert.That(Time32.FromTimeSpan(TimeSpan.FromTicks(1)),            Is.EqualTo(27u),          "100 ns are 26.8 units, rounded up");
                Assert.That(Time32.FromTimeSpan(TimeSpan.FromMilliseconds(30)),    Is.EqualTo(8053064u),     "30 ms are 8053063.68 units, rounded up");
                Assert.That(Time32.FromTimeSpan(TimeSpan.FromTicks(16L * TimeSpan.TicksPerSecond - 1)),
                                                                                   Is.LessThan(Time32.Infinity), "a tick under 16 s is still finite");
                Assert.That(Time32.FromTimeSpan(TimeSpan.FromSeconds(16)),         Is.EqualTo(Time32.Infinity));
                Assert.That(Time32.FromTimeSpan(TimeSpan.FromHours(1)),            Is.EqualTo(Time32.Infinity));

                Assert.That(Time32.ToTimeSpan(Time32.Infinity),                    Is.Null,                  "all ones is infinity");
                Assert.That(Time32.ToTimeSpan(1u << 28),                           Is.EqualTo(TimeSpan.FromSeconds(1)));
                Assert.That(Time32.ToTimeSpan(Time32.FromTimeSpan(TimeSpan.FromMilliseconds(30))),
                                                                                   Is.EqualTo(TimeSpan.FromMilliseconds(30)));

            });

        }

        #endregion

        #region Request_IsVersion5Mode3_WithACookie_AndNamesTheDraft()

        /// <summary>
        /// § 9: all of the header zero but version, mode, timescale, flags and cookies; § 7.1:
        /// a draft implementation names its draft in every request, and the name's 23 octets
        /// are padded to 24 for the message but not counted in the field's Length.
        /// </summary>
        [Test]
        public void Request_IsVersion5Mode3_WithACookie_AndNamesTheDraft()
        {

            var request  = NTPv5Packet.Request();
            var bytes    = request.ToByteArray();

            Assert.Multiple(() => {

                Assert.That(bytes[0],                                                Is.EqualTo(0x2B),  "Reserved 0, VN 5, Mode 3");
                Assert.That(bytes.AsSpan(1, 15).ToArray(),                           Is.All.Zero,       "stratum to flags");
                Assert.That(request.ClientCookie,                                    Is.Not.Zero);
                Assert.That(bytes.AsSpan(32, 16).ToArray(),                          Is.All.Zero,       "the timestamps of a request");

                Assert.That(bytes.Length,                                            Is.EqualTo(48 + 28));
                Assert.That(BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(48)),  Is.EqualTo(0xF5FF));
                Assert.That(BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(50)),  Is.EqualTo(4 + 23), "the Length leaves out the padding");
                Assert.That(bytes[75],                                               Is.Zero,           "the padding is zero");

            });

            Assert.That(NTPv5Packet.Request(DraftIdentification: String.Empty).ToByteArray(), Has.Length.EqualTo(48),
                        "without a draft name a request is the bare header");

        }

        #endregion

        #region AMessage_SurvivesTheWire()

        /// <summary>
        /// Every header field goes where § 6 puts it and comes back the same.
        /// </summary>
        [Test]
        public void AMessage_SurvivesTheWire()
        {

            var sent = new NTPv5Packet(Mode:               4,
                                       Stratum:            2,
                                       Poll:               6,
                                       Precision:          -20,
                                       RootDelay:          0x01020304,
                                       RootDispersion:     0x05060708,
                                       Timescale:          NTPv5Timescale.TAI,
                                       Era:                1,
                                       Flags:              NTPv5Flags.Unsynchronized | NTPv5Flags.InterleavedMode,
                                       ServerCookie:       0x1112131415161718,
                                       ClientCookie:       0x2122232425262728,
                                       ReceiveTimestamp:   0x3132333435363738,
                                       TransmitTimestamp:  0x4142434445464748,
                                       ExtensionFields:    [ NTPv5ExtensionField.ServerInformation(0x1F, NTPv5Flags.Unsynchronized),
                                                             NTPv5ExtensionField.Padding(12) ]);

            var bytes = sent.ToByteArray();

            Assert.That(bytes[ 4], Is.EqualTo(0x01), "the root delay starts at octet 4");
            Assert.That(bytes[12], Is.EqualTo(1),    "the timescale is octet 12");
            Assert.That(bytes[13], Is.EqualTo(1),    "the era is octet 13");
            Assert.That(bytes[15], Is.EqualTo(3),    "the flags end at octet 15");
            Assert.That(bytes[24], Is.EqualTo(0x21), "the client cookie starts at octet 24");

            Assert.That(NTPv5Packet.TryParse(bytes, out var received, out var error), Is.True, error);

            Assert.Multiple(() => {

                Assert.That(received!.Mode,               Is.EqualTo(sent.Mode));
                Assert.That(received.Stratum,             Is.EqualTo(sent.Stratum));
                Assert.That(received.Poll,                Is.EqualTo(sent.Poll));
                Assert.That(received.Precision,           Is.EqualTo(sent.Precision));
                Assert.That(received.RootDelay,           Is.EqualTo(sent.RootDelay));
                Assert.That(received.RootDispersion,      Is.EqualTo(sent.RootDispersion));
                Assert.That(received.Timescale,           Is.EqualTo(sent.Timescale));
                Assert.That(received.Era,                 Is.EqualTo(sent.Era));
                Assert.That(received.Flags,               Is.EqualTo(sent.Flags));
                Assert.That(received.ServerCookie,        Is.EqualTo(sent.ServerCookie));
                Assert.That(received.ClientCookie,        Is.EqualTo(sent.ClientCookie));
                Assert.That(received.ReceiveTimestamp,    Is.EqualTo(sent.ReceiveTimestamp));
                Assert.That(received.TransmitTimestamp,   Is.EqualTo(sent.TransmitTimestamp));
                Assert.That(received.ExtensionFields,     Has.Count.EqualTo(2));
                Assert.That(received.Length,              Is.EqualTo(bytes.Length));

                Assert.That(received.ExtensionFields[0].TryReadServerInformation(out var versions, out var flags), Is.True);
                Assert.That(versions,                     Is.EqualTo(0x1F));
                Assert.That(flags,                        Is.EqualTo(NTPv5Flags.Unsynchronized));

            });

        }

        #endregion

        #region TheFramingIsChecked()

        /// <summary>
        /// § 6 and § 7: at least the header, a whole number of 4 octets, version 5, and no
        /// extension field shorter than its header or running past the end.
        /// </summary>
        [Test]
        public void TheFramingIsChecked()
        {

            Byte[] Message(Int32 Length, Byte FirstOctet = 0x2B)
            {
                var message = new Byte[Length];
                message[0]  = FirstOctet;
                return message;
            }

            Byte[] WithField(UInt16 DeclaredLength, Int32 MessageLength)
            {
                var message = Message(MessageLength);
                BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(48), 0xF501);
                BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(50), DeclaredLength);
                return message;
            }

            Assert.Multiple(() => {

                Assert.That(NTPv5Packet.TryParse(Message(48),        out _, out _), Is.True,  "the bare header");
                Assert.That(NTPv5Packet.TryParse(Message(44),        out _, out _), Is.False, "shorter than the header");
                Assert.That(NTPv5Packet.TryParse(Message(50),        out _, out _), Is.False, "not a whole number of 4 octets");
                Assert.That(NTPv5Packet.TryParse(Message(48, 0x23),  out _, out _), Is.False, "version 4");

                Assert.That(NTPv5Packet.TryParse(WithField( 4, 52),  out _, out _), Is.True,  "a field of its header alone");
                Assert.That(NTPv5Packet.TryParse(WithField( 3, 52),  out _, out _), Is.False, "a field shorter than its header");
                Assert.That(NTPv5Packet.TryParse(WithField( 9, 60),  out _, out _), Is.True,  "a field of 9 octets padded to 12");
                Assert.That(NTPv5Packet.TryParse(WithField(13, 60),  out _, out _), Is.False, "a field running past the end once padded");

            });

            Assert.That(NTPv5Packet.TryParse(WithField(9, 60), out var packet, out _), Is.True);
            Assert.That(packet!.ExtensionFields,                 Has.Count.EqualTo(1), "the 9-octet field and its padding are one field");
            Assert.That(packet.ExtensionFields[0].Value.Length,  Is.EqualTo(5),        "the Value ends at the declared Length, not at the padding");

        }

        #endregion

        #region ReservedBits_AreRead_NotRefused()

        /// <summary>
        /// § 6: the two Reserved bits that were the leap indicator are ignored by a receiver.
        /// </summary>
        [Test]
        public void ReservedBits_AreRead_NotRefused()
        {

            var message = new Byte[48];
            message[0]  = 0xEB; // Reserved 3, VN 5, Mode 3

            Assert.That(NTPv5Packet.TryParse(message, out var packet, out var error), Is.True, error);
            Assert.That(packet!.Reserved, Is.EqualTo(3));
            Assert.That(packet.Mode,      Is.EqualTo(3));

        }

        #endregion

        #region TheEra_TurnsOnTheRollover()

        /// <summary>
        /// § 6: era 0 from 1900, era 1 from 2036-02-07T06:28:16Z.
        /// </summary>
        [Test]
        public void TheEra_TurnsOnTheRollover()
        {

            var rollover = new DateTime(2036, 2, 7, 6, 28, 16, DateTimeKind.Utc);

            Assert.Multiple(() => {
                Assert.That(NTPv5Packet.EraOf(new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)), Is.EqualTo(0));
                Assert.That(NTPv5Packet.EraOf(new DateTime(2026, 11, 27, 0, 0, 0, DateTimeKind.Utc)), Is.EqualTo(0));
                Assert.That(NTPv5Packet.EraOf(rollover.AddTicks(-1)), Is.EqualTo(0), "a tick before the rollover");
                Assert.That(NTPv5Packet.EraOf(rollover),              Is.EqualTo(1), "the rollover itself");
            });

        }

        #endregion

        #region TheNegotiationMagic_IsWhatTheDraftSpellsOut()

        /// <summary>
        /// § 12: "NTP5DRFT" for drafts, "NTP5NTP5" once an RFC - and § 12's dates for the final
        /// one, 1941-08-24T01:13:25Z in era 0.
        /// </summary>
        [Test]
        public void TheNegotiationMagic_IsWhatTheDraftSpellsOut()
        {

            var draft = new Byte[8];
            var final = new Byte[8];

            BinaryPrimitives.WriteUInt64BigEndian(draft, NTPv5Draft.NegotiationMagic);
            BinaryPrimitives.WriteUInt64BigEndian(final, NTPv5Draft.FinalNegotiationMagic);

            Assert.Multiple(() => {
                Assert.That(System.Text.Encoding.ASCII.GetString(draft), Is.EqualTo("NTP5DRFT"));
                Assert.That(System.Text.Encoding.ASCII.GetString(final), Is.EqualTo("NTP5NTP5"));
                Assert.That(Norn.NTP.NTPPacket.NTPEpoch.AddSeconds(NTPv5Draft.FinalNegotiationMagic >> 32),
                            Is.EqualTo(new DateTime(1941, 8, 24, 1, 13, 25, DateTimeKind.Utc)));
            });

        }

        #endregion

    }

}
