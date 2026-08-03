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

using System.Reflection;

using org.GraphDefined.Vanaheimr.Norn.CLI.Commands;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.CLI
{

    /// <summary>
    /// The <c>norn</c> command.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Norn was a library and nothing else, which meant that using it at all — to check a
    /// server, to see why a key exchange fails, to stand one up for an afternoon — required
    /// writing a C# project first. Everything the three commands here do was already
    /// implemented; none of it was reachable without a compiler.
    /// </para>
    /// <para>
    /// Three rules hold throughout. Exit codes distinguish "it did not work" from "you typed it
    /// wrong", because a script needs to tell those apart. In <c>--json</c> mode stdout carries
    /// the document and nothing else. And no option silently does nothing: an unrecognized one
    /// is an error, not a shrug.
    /// </para>
    /// </remarks>
    public static class Program
    {

        /// <summary>The operation failed: no answer, a refusal, a validation error.</summary>
        public const Int32 ExitFailure  = 1;

        /// <summary>The command line could not be understood.</summary>
        public const Int32 ExitUsage    = 2;


        private const String TopLevelUsage = """
            norn -- NTP and Network Time Security, from the command line.

            Usage: norn <command> [options]

            Commands:
              query <host>     Measure the clock offset against an NTS or plain NTP server.
              ke <host>        Run the RFC 8915 key exchange and report what was negotiated.
              serve            Run an NTS-KE and NTP server.

            Options:
              --help, -h       This text, or a command's own with 'norn <command> --help'.
              --version        Print the version and exit.

            Exit codes:
              0  success
              1  the operation failed
              2  the command line could not be understood
            """;


        public static async Task<Int32> Main(String[] Arguments)
        {

            // Ctrl-C reaches the commands as a cancellation rather than killing the process, so
            // that a server closes its sockets and a query in flight stops waiting.
            using var cancellation = new CancellationTokenSource();

            Console.CancelKeyPress += (sender, e) => {
                e.Cancel = true;
                cancellation.Cancel();
            };

            var output = new Output(Arguments.Contains("--json"));

            try
            {

                if (Arguments.Length == 0)
                {
                    Console.Out.WriteLine(TopLevelUsage);
                    return ExitUsage;
                }

                var command    = Arguments[0];
                var remainder  = Arguments.Skip(1).ToArray();

                if (command is "--help" or "-h" or "help")
                {
                    Console.Out.WriteLine(TopLevelUsage);
                    return 0;
                }

                if (command is "--version" or "-v")
                {
                    Console.Out.WriteLine(Version);
                    return 0;
                }

                var usage = command switch {
                                "query"  => QueryCommand.Usage,
                                "ke"     => KeyExchangeCommand.Usage,
                                "serve"  => ServeCommand.Usage,
                                _        => null
                            };

                if (usage is null)
                {
                    output.Error($"unknown command '{command}'. Try 'norn --help'.");
                    return ExitUsage;
                }

                // Checked before parsing, so that '--help' works even beside options that would
                // otherwise be rejected — which is when it is most likely to be reached for.
                if (remainder.Contains("--help") || remainder.Contains("-h"))
                {
                    Console.Out.WriteLine(usage);
                    return 0;
                }

                var valued     = command switch {
                                     "query"  => QueryCommand.ValuedOptions,
                                     "ke"     => KeyExchangeCommand.ValuedOptions,
                                     _        => ServeCommand.ValuedOptions
                                 };

                var parsed     = new CommandLine(remainder, valued);

                // Read here so no command has to remember to; it is the one option every command
                // shares and it has already been acted on above.
                parsed.Flag("--json");

                return command switch {
                           "query"  => await QueryCommand.      Run(parsed, output, cancellation.Token),
                           "ke"     => await KeyExchangeCommand.Run(parsed, output, cancellation.Token),
                           _        => await ServeCommand.      Run(parsed, output, cancellation.Token)
                       };

            }

            catch (UsageException e)
            {
                output.Error(e.Message);
                output.Note("Try 'norn --help'.");
                return ExitUsage;
            }

            catch (OperationCanceledException)
            {
                // Interrupted on purpose. Nothing to report, and nothing went wrong.
                return 0;
            }

            catch (Exception e)
            {
                output.Error(e.Message);
                return ExitFailure;
            }

        }


        /// <summary>The version, from the assembly rather than from a constant that drifts.</summary>
        private static String Version

            => typeof(Program).Assembly.
                   GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
                       ?? typeof(Program).Assembly.GetName().Version?.ToString()
                       ?? "unknown";

    }

}
