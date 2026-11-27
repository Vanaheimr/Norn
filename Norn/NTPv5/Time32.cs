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

namespace org.GraphDefined.Vanaheimr.Norn.NTPv5
{

    /// <summary>
    /// The time32 format of draft-ietf-ntp-ntpv5-10 § 5, which the Root Delay and Root
    /// Dispersion of NTPv5 are given in: unsigned, 4 integer and 28 fractional bits of a
    /// second, all ones meaning infinity.
    /// </summary>
    /// <remarks>
    /// The NTPv4 short format reached 65536 s; this one ends just short of 16 s, and resolves
    /// to 2^-28 s, about 3.7 ns. What does not fit is infinity, not the largest finite value:
    /// both fields bound an error, and a bound that is too small is no bound.
    /// </remarks>
    public static class Time32
    {

        /// <summary>
        /// All ones: infinity.
        /// </summary>
        public const UInt32  Infinity       = UInt32.MaxValue;

        /// <summary>
        /// The units of one second, 2^28.
        /// </summary>
        public const Int64   UnitsPerSecond = 1L << 28;

        /// <summary>
        /// The largest finite value, one unit under infinity: just under 16 s.
        /// </summary>
        public const UInt32  MaxFinite      = UInt32.MaxValue - 1;


        /// <summary>
        /// The given duration in time32, rounded up, as § 6 asks of the Root Delay and Root
        /// Dispersion of a response. Nothing below zero is negative, and what is too large
        /// for a finite value is <see cref="Infinity"/>.
        /// </summary>
        public static UInt32 FromTimeSpan(TimeSpan Value)
        {

            if (Value <= TimeSpan.Zero)
                return 0;

            // Checked before the product, which stays far from the end of an Int64 below this.
            if (Value.Ticks >= 16L * TimeSpan.TicksPerSecond)
                return Infinity;

            var units = (Value.Ticks * UnitsPerSecond + TimeSpan.TicksPerSecond - 1) / TimeSpan.TicksPerSecond;

            // The last few ticks under 16 s round up onto infinity itself, or past it.
            return units > MaxFinite
                       ? Infinity
                       : (UInt32) units;

        }


        /// <summary>
        /// The given time32 as a duration, or null for <see cref="Infinity"/>. Rounded to
        /// the nearest tick, the finest a TimeSpan holds.
        /// </summary>
        public static TimeSpan? ToTimeSpan(UInt32 Value)

            => Value == Infinity
                   ? null
                   : TimeSpan.FromTicks((Int64) ((Value * (UInt64) TimeSpan.TicksPerSecond + (UInt64) UnitsPerSecond / 2) / (UInt64) UnitsPerSecond));

    }

}
