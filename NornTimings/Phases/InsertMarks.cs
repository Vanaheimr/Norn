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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Microsoft.Build.Framework;

/// <summary>
/// Makes the copies of NTSClient.cs and NTSServer.cs that have the marks in them.
/// </summary>
/// <remarks>
/// <para>
/// This is not part of the measuring program. It is a task of its build, compiled by
/// MSBuild from this file (NornTimings.Phases.csproj), which is why it is written against
/// .NET Standard 2.0 and without the usings the other files have for free.
/// </para>
/// <para>
/// A mark is found by the line it stands at, not by its number: by what the line says,
/// whatever it is indented by, and by the lines that follow it where one alone is not
/// unique in the file. A place that is not found exactly once fails the build and names
/// itself, so that a mark cannot move without anyone seeing it.
/// </para>
/// <para>
/// The numbers of the marks are those the reports of Program.cs know the phases by.
/// </para>
/// </remarks>
public sealed class InsertMarks : Microsoft.Build.Utilities.Task
{

    [Required] public String ClientSource     { get; set; }
    [Required] public String ServerSource     { get; set; }
    [Required] public String OutputDirectory  { get; set; }

    private const String Marks = "org.GraphDefined.Vanaheimr.Norn.Timings.Marks";

    #region The client: NTSClient.QueryTime

    private static String C(Int32 Number)
        => Marks + ".C.Mark(markedQuery, " + Number + ");";

    private static readonly Edit[] client = new[] {

        // 0: QueryTime entered
        Edit.Before("var timeout = Timeout ?? this.Timeout ?? DefaultTimeout;",
                    "var markedQuery = " + Marks + ".C.Begin(); " + C(0)),

        // 1: a cookie taken, the placeholders counted
        Edit.Before("var remoteEndPoint     = await NTPRemoteEndPointResolver.ResolveAsync(",
                    C(1)),

        // 2: the remote end point resolved
        Edit.Before("var interleaved        = InterleavedAssociation;",
                    C(2)),

        // 3: the nonces drawn, the receive buffer rented, the socket made
        Edit.Before("var destination        = remoteEndPoint ?? await ResolveBySystemAsync(",
                    C(3)),

        // 4: the socket bound
        Edit.Before("var transmitTimestamp  = interleaved is not null",
                    C(4)),

        // 5: T1 read, the request built and sealed
        Edit.Before("var requestData        = requestPacket.ToByteArray();",
                    C(5)),

        // 6: the request serialised; about to send
        Edit.Before("var sendStopwatchTimestamp = Stopwatch.GetTimestamp();",
                    C(6)),

        // 7: sent
        Edit.After ("var actualRequestTransmit       = NTPPacket.GetCurrentNTPTimestamp(TimeProvider);",
                    C(7)),

        // 8: the response is here
        Edit.Before("var destinationTimestamp1       = NTPPacket.GetCurrentNTPTimestamp(TimeProvider);",
                    C(8)),

        // 9: parsed and opened
        Edit.Before("var responseMode = interleaved is null",
                    C(9)),

        // 10: validated
        Edit.Before("NTSResponseValidationResult? replayValidation1 = null;",
                    C(10)),

        // 11: checked against the announcement and the replay memory
        Edit.Before("AddCookies(ntpResponse1);",
                    C(11)),

        // 12: the cookies kept
        Edit.Before("var measurement = responseMode == InterleavedResponseMode.Interleaved",
                    C(12)),

        // 13: the interleaved association brought up to date, the signature verified
        Edit.Replace("return NTSQueryResult.SuccessResult(\n" +
                     "ntpResponse1,",

                     C(13) + "\n" +
                     "var markedResult = NTSQueryResult.SuccessResult(\n" +
                     "ntpResponse1,"),

        // 14: the result built. What is left is the socket being closed.
        Edit.After ("signature1,\n" +
                    "signatureKeyId1\n" +
                    ");",

                    C(14) + "\n" +
                    "return markedResult;"),


        // The counter-experiment --keep-socket: one socket for all queries.
        Edit.Replace("using (var receiveBuffer = new ReceiveBuffer())\n" +
                     "using (var udpSocket     = new Socket(\n" +
                     "remoteEndPoint?.AddressFamily ?? AddressFamily.InterNetwork,\n" +
                     "SocketType.Dgram,\n" +
                     "ProtocolType.Udp\n" +
                     "))",

                     "var udpSocket = " + Marks + ".KeptSocket ?? new Socket(\n" +
                     "                    remoteEndPoint?.AddressFamily ?? AddressFamily.InterNetwork,\n" +
                     "                    SocketType.Dgram,\n" +
                     "                    ProtocolType.Udp\n" +
                     "                );\n" +
                     "if (" + Marks + ".KeepSocket)\n" +
                     "    " + Marks + ".KeptSocket = udpSocket;\n" +
                     "using (var receiveBuffer = new ReceiveBuffer())\n" +
                     "using (" + Marks + ".KeepSocket ? null : udpSocket)"),

        Edit.Replace("udpSocket.Bind(",
                     "if (!udpSocket.IsBound) udpSocket.Bind("),


        // The counter-experiment --t1-after-the-send: offset and delay computed with the
        // clock as read after the send, in the basic mode as in the interleaved one.
        Edit.Replace("RequestTransmitTimestamp:   interleaved is not null ? actualRequestTransmit : null))",
                     "RequestTransmitTimestamp:   interleaved is not null || " + Marks + ".T1AfterTheSend ? actualRequestTransmit : null))",
                     Times: 2)

    };

    #endregion

    #region The server: one NTS request

    private static String S(Int32 Number)
        => Marks + ".S.Mark(markedRequest, " + Number + ");";

    private static readonly Edit[] server = new[] {

        // 0: the datagram is here
        Edit.Before("var receivedAt      = NTPPacket.GetCurrentNTPTimestamp(TimeProvider);",
                    "var markedRequest = " + Marks + ".S.Begin(); " + S(0)),

        // 1: past the access list, the rate limit and the semaphore, the datagram copied
        Edit.Before("_ = Task.Run(async () => {\n" +
                    "\n" +
                    "try\n" +
                    "{\n" +
                    "\n" +
                    "if (NTPRequest.TryParse(datagram,",
                    S(1)),

        // 2: the worker runs
        Edit.Before("if (NTPRequest.TryParse(datagram,",
                    S(2)),

        // 3: the request parsed, the cookie unsealed, the request opened
        Edit.Before("var signingKeyPair   = requestPacket.NTSRequestSignedResponse() is { Authenticated: true } signatureRequest",
                    S(3)),

        // 4: the signing key chosen, the interleaved exchange begun
        Edit.Before("var responsePacket1  = BuildResponse(",
                    S(4)),

        // 5: the response built and sealed; 6: serialised, about to send
        Edit.Replace("await udpSocket.SendToAsync(\n" +
                     "new ArraySegment<Byte>(responsePacket1.ToByteArray()),",

                     S(5) + "\n" +
                     "var markedResponse = responsePacket1.ToByteArray();\n" +
                     S(6) + "\n" +
                     "await udpSocket.SendToAsync(\n" +
                     "new ArraySegment<Byte>(markedResponse),"),

        // 7: sent
        Edit.Before("exchange.RecordTransmission(NTPPacket.GetCurrentNTPTimestamp(TimeProvider));",
                    S(7)),

        // 8: the transmission recorded, the counters counted
        Edit.Before("if (toBeSigned && signingKeyPair is not null)",
                    S(8))

    };

    #endregion


    public override Boolean Execute()
    {

        Directory.CreateDirectory(OutputDirectory);

        return Apply(ClientSource, client) &
               Apply(ServerSource, server);

    }

    private Boolean Apply(String Source, Edit[] Edits)
    {

        var text     = File.ReadAllText(Source);
        var newLine  = text.Contains("\r\n") ? "\r\n" : "\n";
        var lines    = text.Replace("\r\n", "\n").Split('\n').ToList();
        var ok       = true;

        foreach (var edit in Edits)
        {

            var anchor  = edit.Anchor.Split('\n');
            var places  = new List<Int32>();

            for (var i = 0; i + anchor.Length <= lines.Count; i++)
            {

                var matches = true;

                for (var k = 0; k < anchor.Length && matches; k++)
                    matches = lines[i + k].Trim() == anchor[k];

                if (matches)
                    places.Add(i);

            }

            if (places.Count != edit.Times)
            {

                Log.LogError(
                    "{0}: the line a mark stands at was found {1} times and not {2}: \"{3}\". " +
                    "The code has changed there; InsertMarks.cs has to follow it.",
                    Path.GetFileName(Source),
                    places.Count,
                    edit.Times,
                    anchor[0]
                );

                ok = false;
                continue;

            }

            // From the last place to the first, so that the earlier ones stay where they are.
            foreach (var place in Enumerable.Reverse(places))
            {

                var first     = lines[place];
                var indent    = first.Substring(0, first.Length - first.TrimStart().Length);
                var inserted  = edit.Text.Split('\n').Select(line => line.Length == 0 ? line : indent + line).ToList();

                switch (edit.Kind)
                {

                    case EditKind.Before:
                        lines.InsertRange(place, inserted);
                        break;

                    case EditKind.After:
                        lines.InsertRange(place + anchor.Length, inserted);
                        break;

                    case EditKind.Replace:
                        lines.RemoveRange(place, anchor.Length);
                        lines.InsertRange(place, inserted);
                        break;

                }

            }

        }

        if (ok)
            File.WriteAllText(
                Path.Combine(OutputDirectory, Path.GetFileName(Source)),
                String.Join(newLine, lines),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)
            );

        return ok;

    }


    private enum EditKind
    {
        Before,
        After,
        Replace
    }

    /// <summary>
    /// Lines to put before, after or in the place of the lines of an anchor.
    /// </summary>
    /// <remarks>
    /// An anchor is one line or several that follow each other, each as it reads without
    /// what it is indented by. What is put there is indented like the anchor's first line.
    /// </remarks>
    private sealed class Edit
    {

        public EditKind  Kind    { get; private set; }
        public String    Anchor  { get; private set; }
        public String    Text    { get; private set; }
        public Int32     Times   { get; private set; }

        public static Edit Before (String Anchor, String Text)
            => new Edit { Kind = EditKind.Before,  Anchor = Anchor, Text = Text, Times = 1 };

        public static Edit After  (String Anchor, String Text)
            => new Edit { Kind = EditKind.After,   Anchor = Anchor, Text = Text, Times = 1 };

        public static Edit Replace(String Anchor, String Text, Int32 Times = 1)
            => new Edit { Kind = EditKind.Replace, Anchor = Anchor, Text = Text, Times = Times };

    }

}
