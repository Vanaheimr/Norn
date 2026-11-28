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

using System.Diagnostics;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests
{

    /// <summary>
    /// A value read again until it has settled, or until a time is up.
    /// </summary>
    /// <remarks>
    /// The server counts a response after it has sent it, so a client that has just read the
    /// response may look at the counter before the server got to it: on Linux the test was red
    /// time and again with one response fewer than it had read, and green on Windows.
    /// <see cref="Until"/> gives the server that moment; the test asserts the value it returns
    /// as before, so a count that never comes still fails, and one too many fails at once.
    /// </remarks>
    public static class Settled
    {

        /// <summary>
        /// Read the value until it is settled, and give back the last one read.
        /// </summary>
        /// <param name="Read">What to read.</param>
        /// <param name="IsSettled">Whether the value read has settled.</param>
        /// <param name="Timeout">How long to read again at the most; five seconds when not given.</param>
        public static async Task<T> Until<T>(Func<T>          Read,
                                             Func<T, Boolean> IsSettled,
                                             TimeSpan?        Timeout   = null)
        {

            var timeout  = Timeout ?? TimeSpan.FromSeconds(5);
            var watch    = Stopwatch.StartNew();
            var value    = Read();

            while (!IsSettled(value) && watch.Elapsed < timeout)
            {
                await Task.Delay(10);
                value = Read();
            }

            return value;

        }

    }

}
