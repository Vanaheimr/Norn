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

using Newtonsoft.Json.Linq;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.CLI
{

    /// <summary>
    /// Where output goes, and in what shape.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One rule decides everything here: in JSON mode, stdout carries the JSON document and
    /// nothing else. Progress, warnings and errors go to stderr. A tool that mixes them has made
    /// itself unpipeable, and the failure shows up as a parse error in whatever consumes it
    /// rather than anywhere near the cause.
    /// </para>
    /// <para>
    /// In human mode both go to stdout, except errors, which stay on stderr in both modes.
    /// </para>
    /// </remarks>
    public sealed class Output(Boolean AsJson)
    {

        /// <summary>
        /// Whether output is meant for a machine.
        /// </summary>
        public Boolean IsJson { get; } = AsJson;


        /// <summary>
        /// A line of human-readable output, suppressed entirely in JSON mode.
        /// </summary>
        public void Line(String Text = "")
        {
            if (!IsJson)
                Console.Out.WriteLine(Text);
        }


        /// <summary>
        /// A labelled value, aligned into a column.
        /// </summary>
        public void Field(String Label, String? Value)
        {
            if (!IsJson && Value is not null)
                Console.Out.WriteLine($"  {Label,-22}{Value}");
        }


        /// <summary>
        /// Something the user should see whichever mode they asked for.
        /// </summary>
        public void Note(String Text)
            => Console.Error.WriteLine(Text);


        /// <summary>
        /// Something that went wrong.
        /// </summary>
        public void Error(String Text)
            => Console.Error.WriteLine($"norn: {Text}");


        /// <summary>
        /// The JSON document, printed only in JSON mode.
        /// </summary>
        public void Json(JObject Document)
        {
            if (IsJson)
                Console.Out.WriteLine(Document.ToString(Newtonsoft.Json.Formatting.Indented));
        }


        /// <summary>
        /// A clock offset in milliseconds, always signed.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The sign is the whole content of an offset — ahead or behind — so it is printed even
        /// when positive, which also keeps a column of them aligned.
        /// </para>
        /// <para>
        /// Six decimal places is a nanosecond. That is far finer than any of these measurements
        /// are accurate, and it is still the right number of digits: the offsets a good local
        /// server produces are microseconds, and rounding to three would print "0.000 ms" for
        /// every one of them.
        /// </para>
        /// </remarks>
        public static String Offset(TimeSpan? Value)

            => Value is null
                   ? "--"
                   : $"{Value.Value.TotalMilliseconds:+0.000000;-0.000000;0.000000} ms";


        /// <summary>
        /// A duration in milliseconds, unsigned.
        /// </summary>
        /// <remarks>
        /// Separate from <see cref="Offset"/> because a leading "+" on a delay reads as though
        /// the value could have been negative and this one happens not to be, which invites the
        /// question of what a negative round-trip would mean.
        /// </remarks>
        public static String Duration(TimeSpan? Value)

            => Value is null
                   ? "--"
                   : $"{Value.Value.TotalMilliseconds:0.000000} ms";

    }

}
