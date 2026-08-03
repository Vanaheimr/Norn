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

namespace org.GraphDefined.Vanaheimr.Norn.CLI
{

    /// <summary>
    /// Raised when the command line cannot be understood. Distinguished from every other failure
    /// because it exits differently: a script that mistyped an option has a different problem
    /// from one whose server did not answer, and telling them apart is the whole reason exit
    /// codes exist.
    /// </summary>
    public sealed class UsageException(String Message) : Exception(Message);


    /// <summary>
    /// The argument parser.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Hand-written, and small enough to read in one sitting, because Norn depends on nothing
    /// outside Hermod and a command-line parser is a poor reason to start. What it accepts is
    /// deliberately narrow: <c>--name value</c>, <c>--name=value</c>, and <c>--flag</c>.
    /// </para>
    /// <para>
    /// Unknown options are an error rather than something ignored. A tool that silently accepts
    /// <c>--tiemout 30</c> and then waits five seconds has answered a question nobody asked.
    /// </para>
    /// </remarks>
    public sealed class CommandLine
    {

        #region Data

        private readonly Dictionary<String, String?>  options      = new (StringComparer.Ordinal);
        private readonly List<String>                 positionals  = [];
        private readonly HashSet<String>              consumed     = new (StringComparer.Ordinal);

        #endregion

        #region Properties

        /// <summary>The arguments that were not options, in the order given.</summary>
        public IReadOnlyList<String> Positionals
            => positionals;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Parse the given arguments.
        /// </summary>
        /// <param name="Arguments">The arguments, without the command name.</param>
        /// <param name="ValuedOptions">
        /// The options that take a value when written as <c>--name value</c>. Everything else is
        /// a flag.
        /// </param>
        /// <remarks>
        /// The set of valued options has to be known up front, because <c>--json --count 3</c>
        /// and <c>--timeout 3</c> are only distinguishable by knowing which of the two takes a
        /// value. The alternative — guessing from whether the next argument starts with a dash —
        /// misreads a negative number as an option and is the sort of thing that works until
        /// somebody passes one.
        /// </remarks>
        public CommandLine(IEnumerable<String>  Arguments,
                           IEnumerable<String>  ValuedOptions)
        {

            var valued     = new HashSet<String>(ValuedOptions, StringComparer.Ordinal);
            var arguments  = Arguments.ToArray();

            for (var i = 0; i < arguments.Length; i++)
            {

                var argument = arguments[i];

                // Everything after a bare "--" is positional, whatever it looks like.
                if (argument == "--")
                {
                    positionals.AddRange(arguments.Skip(i + 1));
                    break;
                }

                if (!argument.StartsWith("--", StringComparison.Ordinal))
                {
                    positionals.Add(argument);
                    continue;
                }

                var name   = argument;
                String? value = null;

                var equals = argument.IndexOf('=');

                if (equals > 0)
                {
                    name   = argument[..equals];
                    value  = argument[(equals + 1)..];
                }

                else if (valued.Contains(name))
                {

                    if (i + 1 >= arguments.Length)
                        throw new UsageException($"Option '{name}' needs a value.");

                    value = arguments[++i];

                }

                if (options.ContainsKey(name))
                    throw new UsageException($"Option '{name}' was given more than once.");

                options[name] = value;

            }

        }

        #endregion


        #region Flag(Name)

        /// <summary>Whether a flag was given.</summary>
        public Boolean Flag(String Name)
        {

            consumed.Add(Name);

            if (!options.TryGetValue(Name, out var value))
                return false;

            if (value is not null)
                throw new UsageException($"Option '{Name}' is a flag and takes no value.");

            return true;

        }

        #endregion

        #region Value(Name, Default = null)

        /// <summary>The value of an option, or the default when it was not given.</summary>
        public String? Value(String Name, String? Default = null)
        {

            consumed.Add(Name);

            if (!options.TryGetValue(Name, out var value))
                return Default;

            return value
                       ?? throw new UsageException($"Option '{Name}' needs a value.");

        }

        #endregion

        #region UInt16Value(Name, Default) / Int32Value / TimeSpanValue

        /// <summary>The value of an option as a port number.</summary>
        public UInt16? PortValue(String Name)
        {

            var text = Value(Name);

            if (text is null)
                return null;

            return UInt16.TryParse(text, out var port) && port > 0
                       ? port
                       : throw new UsageException($"Option '{Name}' needs a port number between 1 and 65535, but was '{text}'.");

        }


        /// <summary>The value of an option as a count.</summary>
        public Int32 CountValue(String Name, Int32 Default)
        {

            var text = Value(Name);

            if (text is null)
                return Default;

            return Int32.TryParse(text, out var count) && count > 0
                       ? count
                       : throw new UsageException($"Option '{Name}' needs a positive number, but was '{text}'.");

        }


        /// <summary>The value of an option as a number of seconds.</summary>
        /// <remarks>
        /// Seconds rather than a duration string: every other NTP tool takes seconds here, and a
        /// parser that also accepted "1m30s" would be a second syntax to learn for no gain.
        /// Fractions are allowed, because sub-second timeouts are a reasonable thing to want.
        /// </remarks>
        public TimeSpan? SecondsValue(String Name)
        {

            var text = Value(Name);

            if (text is null)
                return null;

            return Double.TryParse(text, System.Globalization.NumberStyles.Float,
                                   System.Globalization.CultureInfo.InvariantCulture,
                                   out var seconds) && seconds > 0
                       ? TimeSpan.FromSeconds(seconds)
                       : throw new UsageException($"Option '{Name}' needs a positive number of seconds, but was '{text}'.");

        }

        #endregion

        #region ThrowOnUnknownOptions()

        /// <summary>
        /// Complain about any option the command never asked for.
        /// </summary>
        /// <remarks>
        /// Called after every option a command understands has been read, so that whatever is
        /// left over is by definition something it does not. Cheaper than declaring the whole
        /// grammar twice and cannot fall out of step with it.
        /// </remarks>
        public void ThrowOnUnknownOptions()
        {

            var unknown = options.Keys.Where(name => !consumed.Contains(name)).Order().ToArray();

            if (unknown.Length > 0)
                throw new UsageException($"Unknown option{(unknown.Length > 1 ? "s" : "")}: {String.Join(", ", unknown)}");

        }

        #endregion

    }

}
