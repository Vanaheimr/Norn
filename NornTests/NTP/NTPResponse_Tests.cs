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
    /// NTP response tests.
    /// </summary>
    [TestFixture]
    public class NTPResponse_Tests
    {

        #region TryParse_SetsDestinationTimestamp()

        [Test]
        public void TryParse_SetsDestinationTimestamp()
        {

            var t1 = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 00, DateTimeKind.Utc));
            var t2 = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 05, DateTimeKind.Utc));
            var t3 = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 07, DateTimeKind.Utc));
            var t4 = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 10, DateTimeKind.Utc));

            var buffer = CreateResponseBytes(t1, t2, t3);

            Assert.That(
                NTPResponse.TryParse(
                    buffer,
                    out var response,
                    out var errorResponse,
                    DestinationTimestamp: t4
                ),
                Is.True,
                errorResponse
            );

            Assert.That(response, Is.Not.Null);
            Assert.That(response!.DestinationTimestamp, Is.EqualTo(t4));

        }

        #endregion

        #region ClockOffsetAndRoundTripDelay_AreCalculatedFromRfc5905Timestamps()

        [Test]
        public void ClockOffsetAndRoundTripDelay_AreCalculatedFromRfc5905Timestamps()
        {

            var t1 = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 00, DateTimeKind.Utc));
            var t2 = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 05, DateTimeKind.Utc));
            var t3 = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 07, DateTimeKind.Utc));
            var t4 = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 10, DateTimeKind.Utc));

            var buffer = CreateResponseBytes(t1, t2, t3);

            Assert.That(
                NTPResponse.TryParse(
                    buffer,
                    out var response,
                    out var errorResponse,
                    DestinationTimestamp: t4
                ),
                Is.True,
                errorResponse
            );

            Assert.That(response, Is.Not.Null);
            Assert.That(response!.ClockOffset,     Is.EqualTo(TimeSpan.FromSeconds(1)));
            Assert.That(response.RoundTripDelay,   Is.EqualTo(TimeSpan.FromSeconds(8)));

        }

        #endregion

        #region ClockOffsetAndRoundTripDelay_AreNullWithoutDestinationTimestamp()

        [Test]
        public void ClockOffsetAndRoundTripDelay_AreNullWithoutDestinationTimestamp()
        {

            var t1 = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 00, DateTimeKind.Utc));
            var t2 = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 05, DateTimeKind.Utc));
            var t3 = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 07, DateTimeKind.Utc));

            var buffer = CreateResponseBytes(t1, t2, t3);

            Assert.That(
                NTPResponse.TryParse(
                    buffer,
                    out var response,
                    out var errorResponse
                ),
                Is.True,
                errorResponse
            );

            Assert.That(response, Is.Not.Null);
            Assert.That(response!.ClockOffset,     Is.Null);
            Assert.That(response.RoundTripDelay,   Is.Null);

        }

        #endregion

        #region TryParse_SetsStopwatchTimestamps()

        [Test]
        public void TryParse_SetsStopwatchTimestamps()
        {

            var t1               = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 00, DateTimeKind.Utc));
            var t2               = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 05, DateTimeKind.Utc));
            var t3               = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 07, DateTimeKind.Utc));
            var sendStopwatch    = 1000L;
            var receiveStopwatch = 2500L;

            var buffer = CreateResponseBytes(t1, t2, t3);

            Assert.That(
                NTPResponse.TryParse(
                    buffer,
                    out var response,
                    out var errorResponse,
                    SendStopwatchTimestamp:     sendStopwatch,
                    ReceiveStopwatchTimestamp:  receiveStopwatch
                ),
                Is.True,
                errorResponse
            );

            Assert.That(response, Is.Not.Null);
            Assert.That(response!.SendStopwatchTimestamp,     Is.EqualTo(sendStopwatch));
            Assert.That(response.ReceiveStopwatchTimestamp,   Is.EqualTo(receiveStopwatch));

        }

        #endregion

        #region StopwatchRoundTripTime_IsCalculatedFromStopwatchTimestamps()

        [Test]
        public void StopwatchRoundTripTime_IsCalculatedFromStopwatchTimestamps()
        {

            var response = new NTPResponse(
                               SendStopwatchTimestamp:     1000,
                               ReceiveStopwatchTimestamp:  1000 + System.Diagnostics.Stopwatch.Frequency
                           );

            Assert.That(response.StopwatchRoundTripTime, Is.EqualTo(TimeSpan.FromSeconds(1)));

        }

        #endregion

        #region StopwatchRoundTripTime_IsNullWithoutStopwatchTimestamps()

        [Test]
        public void StopwatchRoundTripTime_IsNullWithoutStopwatchTimestamps()
        {

            var response = new NTPResponse();

            Assert.That(response.StopwatchRoundTripTime, Is.Null);

        }

        #endregion

        #region TryParse_KeepsKissOfDeathPacket()

        [Test]
        public void TryParse_KeepsKissOfDeathPacket()
        {

            var buffer = CreateResponseBytes(1, 0, 0);

            buffer[1]   = 0;
            buffer[12]  = (Byte) 'R';
            buffer[13]  = (Byte) 'A';
            buffer[14]  = (Byte) 'T';
            buffer[15]  = (Byte) 'E';

            Assert.That(
                NTPResponse.TryParse(
                    buffer,
                    out var response,
                    out var errorResponse
                ),
                Is.True,
                errorResponse
            );

            Assert.That(response,          Is.Not.Null);
            Assert.That(response!.Stratum, Is.EqualTo(0));
            Assert.That(response.ReferenceIdentifier.ToString(response.Stratum), Does.Contain("RATE"));

        }

        #endregion


        private static Byte[] CreateResponseBytes(UInt64 OriginateTimestamp,
                                                  UInt64 ReceiveTimestamp,
                                                  UInt64 TransmitTimestamp)
        {

            var buffer = new Byte[48];

            buffer[0] = 0x24;
            buffer[1] = 2;

            WriteUInt64BigEndian(buffer, 24, OriginateTimestamp);
            WriteUInt64BigEndian(buffer, 32, ReceiveTimestamp);
            WriteUInt64BigEndian(buffer, 40, TransmitTimestamp);

            return buffer;

        }

        private static void WriteUInt64BigEndian(Byte[] Buffer,
                                                 Int32  Offset,
                                                 UInt64 Value)
        {

            for (var i = 0; i < 8; i++)
                Buffer[Offset + i] = (Byte) (Value >> (56 - i * 8));

        }

    }

}
