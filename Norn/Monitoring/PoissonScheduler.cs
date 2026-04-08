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

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// Implements Poisson-process scheduling for measurement rounds.
    ///
    /// Why Poisson?
    ///  - Exponentially distributed inter-arrival times guarantee statistical independence
    ///    between drones WITHOUT any coordination.
    ///  - No aliasing effects with periodic server behaviors (cron jobs, log rotation, network effects, etc.)
    ///  - Memoryless property: knowing when the last measurement occurred gives zero
    ///    information about when the next one will occur.
    ///  - Multiple independent Poisson processes are still Poisson → the aggregate
    ///    traffic from N drones is predictable (rate = N × λ).
    ///
    /// The mean interval is configurable (e.g., 60 seconds).
    /// Actual intervals follow Exp(1/mean), clamped to [min, max] to avoid
    /// unreasonably short bursts or long gaps.
    /// </summary>
    public static class PoissonScheduler
    {

        #region Data

        private static readonly Random random = new();

        #endregion


        #region NextInterval(MeanInterval, MinInterval, MaxInterval)

        /// <summary>
        /// Get the next waiting time in a Poisson process.
        /// </summary>
        /// <param name="MeanInterval">The target mean interval between measurements.</param>
        /// <param name="MinInterval">Minimum clamped interval (default: 10s).</param>
        /// <param name="MaxInterval">Maximum clamped interval (default: 5× mean).</param>
        public static TimeSpan NextInterval(TimeSpan   MeanInterval,
                                            TimeSpan?  MinInterval   = null,
                                            TimeSpan?  MaxInterval   = null)
        {

            var min       = MinInterval ?? TimeSpan.FromSeconds(10);
            var max       = MaxInterval ?? TimeSpan.FromTicks(MeanInterval.Ticks * 5);

            // Exponential distribution: X = -mean × ln(U), where U ~ Uniform(0,1)
            // We use 1 - U to avoid ln(0).
            var u         = 1.0 - random.NextDouble();
            var expValue  = -MeanInterval.TotalSeconds * Math.Log(u);
            var interval  = TimeSpan.FromSeconds(expValue);

            // Clamp to [min, max]
            if (interval < min) interval = min;
            if (interval > max) interval = max;

            return interval;

        }

        #endregion

        #region JitteredInterval(MeanInterval)

        /// <summary>
        /// Get a simple jittered interval (±25% around the mean).
        /// Used as fallback when Poisson timing is not desired.
        /// </summary>
        public static TimeSpan JitteredInterval(TimeSpan MeanInterval)
        {

            var jitter = 0.75 + random.NextDouble() * 0.50;  // [0.75, 1.25]

            return TimeSpan.FromTicks((Int64) (MeanInterval.Ticks * jitter));

        }

        #endregion

    }

}
