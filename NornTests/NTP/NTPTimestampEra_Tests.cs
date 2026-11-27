/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Norn <https://www.github.com/Vanaheimr/Norn>
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

using org.GraphDefined.Vanaheimr.Norn.NTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTP
{

    /// <summary>
    /// The era of an NTP timestamp (RFC 5905 § 6), resolved against a clock that may be the
    /// one asking for the time - and so may not have been set yet.
    /// </summary>
    [TestFixture]
    public class NTPTimestampEra_Tests
    {

        #region Data

        private static readonly DateTime unixEpoch = new (1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        #endregion

        #region Helpers

        private static UInt64 OnTheWire(DateTime Instant)
        {
            var seconds = (Int64) (Instant - NTPPacket.NTPEpoch).TotalSeconds;
            return (UInt64) (UInt32) seconds << 32;
        }

        #endregion


        #region AClockResetTo1970_StillPlacesTimesAfter2038InTheirEra()

        /// <summary>
        /// Embedded gear without a battery-backed clock boots at the Unix epoch. Nearest to 1970,
        /// every time after 2038-01-19 lands in era 0 - 1902 for 2038, 1903 for 2040 - and the
        /// client would set itself there. No clock earlier than EraFloor is taken as it is.
        /// </summary>
        [Test]
        public void AClockResetTo1970_StillPlacesTimesAfter2038InTheirEra()
        {

            Assert.Multiple(() => {

                foreach (var instant in new[] {
                                            new DateTime(2026, 11, 27, 12, 0, 0, DateTimeKind.Utc),
                                            new DateTime(2036,  6,  1, 12, 0, 0, DateTimeKind.Utc),
                                            new DateTime(2038,  6,  1, 12, 0, 0, DateTimeKind.Utc),
                                            new DateTime(2040,  1,  1,  0, 0, 0, DateTimeKind.Utc),
                                            new DateTime(2060,  1,  1,  0, 0, 0, DateTimeKind.Utc),
                                            new DateTime(2093, 12, 31,  0, 0, 0, DateTimeKind.Utc)
                                        })
                    Assert.That(NTPPacket.NTPTimestampToDateTime(OnTheWire(instant), unixEpoch), Is.EqualTo(instant), $"{instant:O} against 1970");

                // The client's own timestamps, from that same 1970 clock, stay in 1970.
                Assert.That(NTPPacket.NTPTimestampToDateTime(OnTheWire(unixEpoch), unixEpoch), Is.EqualTo(unixEpoch), "1970 itself against 1970");

            });

        }

        #endregion

        #region AClockAfterTheFloor_IsUsedAsItIs()

        /// <summary>
        /// The floor only lifts a clock that is earlier: one after it decides the era itself, so
        /// a clock in 2060 places 2100 in era 1, where the floor alone would place it in 1964.
        /// </summary>
        [Test]
        public void AClockAfterTheFloor_IsUsedAsItIs()
        {

            var in2060 = new DateTime(2060, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var in2100 = new DateTime(2100, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            Assert.That(NTPPacket.NTPTimestampToDateTime(OnTheWire(in2100), in2060), Is.EqualTo(in2100));

        }

        #endregion

        #region ClockOffset_ResolvesTheEraAgainstTheDestinationTime()

        /// <summary>
        /// The offset of a response is resolved against the client's own clock at T4, not the
        /// machine's: a client in 2060 hearing from a server in 2100 measures 40 years, where
        /// resolving against a machine in 2026 put the server in 1964.
        /// </summary>
        [Test]
        public void ClockOffset_ResolvesTheEraAgainstTheDestinationTime()
        {

            var client = new DateTime(2060, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var server = new DateTime(2100, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            var response = new NTPResponse(OriginateTimestamp:    OnTheWire(client),
                                           ReceiveTimestamp:      OnTheWire(server),
                                           TransmitTimestamp:     OnTheWire(server),
                                           DestinationTimestamp:  OnTheWire(client),
                                           DestinationTime:       client);

            Assert.Multiple(() => {
                Assert.That(response.ClockOffset,    Is.EqualTo(server - client));
                Assert.That(response.RoundTripDelay, Is.EqualTo(TimeSpan.Zero));
            });

        }

        #endregion

    }

}
