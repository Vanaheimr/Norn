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

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// Randomization modes for NTP polling intervals.
    /// </summary>
    public enum NTPRandomizationMode
    {

        /// <summary>
        /// No randomization (pure geometric mean between Min/Max)
        /// </summary>
        None,

        /// <summary>
        /// Uniform randomization between MinPoll and MaxPoll (strong dispersion),
        /// might cause thundering herd if many clients synchronize at the same time
        /// after startup or network recovery!
        /// </summary>
        Uniform,

        /// <summary>
        /// Small random jitter around the normal base interval (± NTS_JitterFactor)
        /// Recommended for most cases (Thundering Herd avoidance)
        /// </summary>
        Jitter,

        /// <summary>
        /// Poisson-like (exponential distribution) produces natural, random intervals
        /// with a constant average rate.
        /// </summary>
        Poisson

    }

}
