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
using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.CLI;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.CLI
{

    /// <summary>
    /// The two things about the command line that can only be seen from inside the
    /// process: what an interruption returns, and what reaches the terminal of the
    /// text a server sent. Everything else about it is pinned from the outside, by
    /// the conformance tests that run the executable.
    /// </summary>
    [TestFixture]
    public class NornCLI_Tests
    {

        #region ControlCharactersAreMadeVisible()

        /// <summary>
        /// A certificate subject, a server name or a warning is whatever the server
        /// wrote. An escape sequence in it must be shown, and not carried out.
        /// </summary>
        [Test]
        public void ControlCharactersAreMadeVisible()
        {

            Assert.That(Output.Printable("CN=time.example.org"),                    Is.EqualTo("CN=time.example.org"));
            Assert.That(Output.Printable(""),                                       Is.EqualTo(""));
            Assert.That(Output.Printable("Zürich – 時間"),                           Is.EqualTo("Zürich – 時間"));

            // Clear the screen, then set the window title.
            Assert.That(Output.Printable("CN=evil\u001b[2J\u001b]0;owned\u0007"),   Is.EqualTo(@"CN=evil\x1b[2J\x1b]0;owned\x07"));

            // A line of its own, a carriage return over what was printed, a DEL, and
            // the single-character CSI of the C1 range.
            Assert.That(Output.Printable("a\nb\rc\td"),                             Is.EqualTo(@"a\x0ab\x0dc\x09d"));
            Assert.That(Output.Printable("a\u007fb\u009bc"),                        Is.EqualTo(@"a\x7fb\x9bc"));

        }

        #endregion

        #region WhatIsPrintedHasNoControlCharacters()

        /// <summary>
        /// Not the helper alone: every way a line leaves the program goes through it.
        /// </summary>
        [Test]
        public void WhatIsPrintedHasNoControlCharacters()
        {

            var hostile   = "evil\u001b[2J";
            var stdout    = Console.Out;
            var stderr    = Console.Error;
            var captured  = new StringWriter();

            try
            {

                Console.SetOut  (captured);
                Console.SetError(captured);

                var output = new Output(AsJson: false);

                output.Line (hostile);
                output.Field("Subject", hostile);
                output.Note (hostile);
                output.Error(hostile);

            }
            finally
            {
                Console.SetOut  (stdout);
                Console.SetError(stderr);
            }

            var printed = captured.ToString();

            // Looked for as a character: to a comparison of strings by the rules of a
            // language, an escape has no weight and is "contained" in everything.
            Assert.That(printed.Contains('\u001b'),                                 Is.False);
            Assert.That(printed.Split(@"evil\x1b[2J").Length - 1,                   Is.EqualTo(4));

        }

        #endregion


        #region AnInterruptedQueryIsNotASuccess()

        /// <summary>
        /// Ctrl-C while a query is waiting for its next round. Nothing was reported for
        /// the rounds still to come, so the exit code must not be the one for success.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        [NonParallelizable]
        public async Task AnInterruptedQueryIsNotASuccess()
        {

            var ntsKEPort = FindFreePort(SocketType.Stream, ProtocolType.Tcp);
            var ntpPort   = FindFreePort(SocketType.Dgram,  ProtocolType.Udp);

            var ntsServer = new NTSServer(
                                NTSKEPort:           IPPort.Parse(ntsKEPort),
                                NTSPort:             IPPort.Parse(ntpPort),
                                MasterKeysFilePath:  null
                            );

            await ntsServer.Start();

            try
            {

                using var ctrlC = new CancellationTokenSource(TimeSpan.FromSeconds(3));

                var started  = System.Diagnostics.Stopwatch.GetTimestamp();

                // Two queries, a minute apart: the interruption comes during the wait.
                var exitCode = await Program.Run(
                                         [ "query", "127.0.0.1",
                                           "--port",     ntpPort.  ToString(),
                                           "--ke-port",  ntsKEPort.ToString(),
                                           "--insecure",
                                           "--ipv4",
                                           "--count",    "2",
                                           "--interval", "60" ],
                                         ctrlC.Token
                                     );

                Assert.That(exitCode,                                               Is.EqualTo(Program.ExitInterrupted));
                Assert.That(exitCode,                                               Is.EqualTo(130));
                Assert.That(System.Diagnostics.Stopwatch.GetElapsedTime(started),   Is.LessThan(TimeSpan.FromSeconds(30)));

            }
            finally
            {
                await ntsServer.ShutdownAsync();
            }

        }

        #endregion

        #region AServerToldToStopExitsWithSuccess()

        /// <summary>
        /// For a server, Ctrl-C is how it is meant to end.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        [NonParallelizable]
        public async Task AServerToldToStopExitsWithSuccess()
        {

            using var ctrlC = new CancellationTokenSource(TimeSpan.FromSeconds(2));

            var exitCode = await Program.Run(
                                     [ "serve",
                                       "--listen",   "127.0.0.1",
                                       "--port",     FindFreePort(SocketType.Dgram,  ProtocolType.Udp).ToString(),
                                       "--ke-port",  FindFreePort(SocketType.Stream, ProtocolType.Tcp).ToString() ],
                                     ctrlC.Token
                                 );

            Assert.That(exitCode,                                                   Is.EqualTo(0));

        }

        #endregion


        #region (private) FindFreePort(SocketType, ProtocolType)

        private static Int32 FindFreePort(SocketType SocketType, ProtocolType ProtocolType)
        {

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType, ProtocolType);

            socket.Bind(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            return ((IPEndPoint) socket.LocalEndPoint!).Port;

        }

        #endregion

    }

}
