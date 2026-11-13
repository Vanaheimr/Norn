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

using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using IPAddress = System.Net.IPAddress;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Timings
{

    /// <summary>
    /// What a process has allocated and used of the processor up to now.
    /// </summary>
    public readonly record struct Snapshot(Int64 Allocated, TimeSpan User, TimeSpan Kernel, Int32 GCs, TimeSpan Pause)
    {

        public static Snapshot Take()
        {
            using var process = Process.GetCurrentProcess();
            return new Snapshot(
                       GC.GetTotalAllocatedBytes(true),
                       process.UserProcessorTime,
                       process.PrivilegedProcessorTime,
                       GC.CollectionCount(0),
                       GC.GetTotalPauseDuration()
                   );
        }

        public Snapshot Since(Snapshot Earlier)
            => new (Allocated - Earlier.Allocated, User - Earlier.User, Kernel - Earlier.Kernel, GCs - Earlier.GCs, Pause - Earlier.Pause);

        public override String ToString()
            => String.Create(CultureInfo.InvariantCulture, $"{Allocated} {User.Ticks} {Kernel.Ticks} {GCs} {Pause.Ticks}");

        public static Snapshot Parse(String[] Parts, Int32 Offset)
            => new (Int64.Parse(Parts[Offset]),
                    TimeSpan.FromTicks(Int64.Parse(Parts[Offset + 1])),
                    TimeSpan.FromTicks(Int64.Parse(Parts[Offset + 2])),
                    Int32.Parse(Parts[Offset + 3]),
                    TimeSpan.FromTicks(Int64.Parse(Parts[Offset + 4])));

        public String PerQuery(Int32 N)
            => String.Create(CultureInfo.InvariantCulture,
                             $"{Allocated / (Double) N,9:F0} B alloc | CPU user {User.TotalMicroseconds / N,7:F1} µs, kernel {Kernel.TotalMicroseconds / N,7:F1} µs, sum {(User + Kernel).TotalMicroseconds / N,7:F1} µs | gen0 GCs {GCs,5}, GC pause {Pause.TotalMicroseconds / N,6:F2} µs");

    }

    /// <summary>
    /// Where the time and the memory of one NTS query go: the measurements behind
    /// <c>PERFORMANCE.md</c>.
    /// </summary>
    /// <remarks>
    /// A client and a server on the loopback interface, in two processes unless asked
    /// otherwise, and one query after another. Built by <c>NornTimings.csproj</c> this
    /// measures Norn as it is: a query as a whole, and what it reports as offset and delay
    /// against a server that reads the same clock. Built by
    /// <c>Phases/NornTimings.Phases.csproj</c> the same code is compiled together with
    /// copies of the client and of the server that have marks in them, and reports every
    /// phase of a query on both sides.
    /// </remarks>
    public static class Program
    {

        private static readonly Double TicksToMicroseconds = 1_000_000.0 / Stopwatch.Frequency;

        public static async Task<Int32> Main(String[] Arguments)
        {

            CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;

            if (Arguments.Contains("--high-priority"))
            {
                using var self = Process.GetCurrentProcess();
                self.PriorityClass = ProcessPriorityClass.High;
            }

            return Arguments.FirstOrDefault() switch {
                       "query"    => await RunClient(Arguments),
                       "sockets"  => await Sockets.Run(),
                       "server"   => await RunServer(Arguments),   // what "query" starts for itself
                       _          => Usage()
                   };

        }

        private static readonly String[] queryOptions = [
            "--in-process", "--interleaved", "--keep-socket", "--t1-after-the-send", "--high-priority"
        ];

        private static Int32 Usage()
        {

            Console.WriteLine(
                """
                norn-timings query [options]   One NTS query after another against a server on the loopback interface.
                norn-timings sockets           What a UDP socket for every query costs, step by step.

                  --queries=<n>          How many queries are measured (default: 20000).
                  --in-process           The server in the client's process, not in one of its own.
                  --interleaved          The client in the interleaved mode of RFC 9769.
                  --high-priority        Both processes at high priority, for a machine that is not idle.

                Only where the marks are compiled in (Phases/NornTimings.Phases.csproj):

                  --keep-socket          One UDP socket for all queries, not one for each.
                  --t1-after-the-send    Offset and delay computed with the clock as read after the send.
                """);

            return 2;

        }

        #region Server process

        private static NTSServer StartEchoAndServer(Int32 KEPort, Int32 NTPPort, Int32 EchoSyncPort, Int32 EchoAsyncPort)
        {

            var server = new NTSServer(
                             NTSKEPort:           IPPort.Parse(KEPort),
                             NTSPort:             IPPort.Parse(NTPPort),
                             MasterKeysFilePath:  null
                         );

            server.Start().GetAwaiter().GetResult();

            // The floor: a thread that blocks in recvfrom and answers with sendto.
            var echoSync = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            echoSync.Bind(new IPEndPoint(IPAddress.Loopback, EchoSyncPort));

            new Thread(() => {
                var buffer = new Byte[4096];
                EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                while (true)
                {
                    try
                    {
                        var length = echoSync.ReceiveFrom(buffer, ref remote);
                        echoSync.SendTo(buffer, 0, length, SocketFlags.None, remote);
                    }
                    catch (SocketException) { }
                }
            }) { IsBackground = true, Name = "echo-sync" }.Start();

            // The same I/O pattern as the NTS server's UDP loop, with no work in it.
            var echoAsync = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            echoAsync.Bind(new IPEndPoint(IPAddress.Loopback, EchoAsyncPort));

            _ = Task.Run(async () => {
                var buffer = new Byte[4096];
                while (true)
                {
                    try
                    {
                        var packet   = await echoAsync.ReceiveFromAsync(new ArraySegment<Byte>(buffer), SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), CancellationToken.None);
                        var datagram = buffer.AsSpan(0, packet.ReceivedBytes).ToArray();
                        _ = Task.Run(async () => {
                            await echoAsync.SendToAsync(new ArraySegment<Byte>(datagram), SocketFlags.None, packet.RemoteEndPoint, CancellationToken.None);
                        });
                    }
                    catch (SocketException) { }
                }
            });

            return server;

        }

        private static async Task<Int32> RunServer(String[] Arguments)
        {

            StartEchoAndServer(
                Int32.Parse(Arguments[1]),
                Int32.Parse(Arguments[2]),
                Int32.Parse(Arguments[3]),
                Int32.Parse(Arguments[4])
            );

            Console.WriteLine("ok ready");

            var before = Snapshot.Take();

            while (Console.ReadLine() is String line)
            {

                var parts = line.Split(' ');

                switch (parts[0])
                {

                    case "reset":
#if MARKS
                        Marks.S.Reset(Int32.Parse(parts[1]), parts[2] == "1");
#endif
                        before = Snapshot.Take();
                        Console.WriteLine("ok");
                        break;

                    case "dump":
                        var delta = Snapshot.Take().Since(before);
#if MARKS
                        if (Marks.S.Capacity > 0)
                            Marks.S.Save(parts[1]);
                        Marks.S.Reset(0, false);
#endif
                        Console.WriteLine("ok " + delta);
                        break;

                    case "quit":
                        return 0;

                }

            }

            await Task.CompletedTask;
            return 0;

        }

        #endregion

        #region Client process

        private static Int32 FreeTCPPort()
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            return ((IPEndPoint) listener.LocalEndpoint).Port;
        }

        private static Int32 FreeUDPPort()
        {
            using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            return ((IPEndPoint) udpClient.Client.LocalEndPoint!).Port;
        }

        private static async Task<Int32> RunClient(String[] Arguments)
        {

            var inProcess     = Arguments.Contains("--in-process");
            var interleaved   = Arguments.Contains("--interleaved");
            var highPriority  = Arguments.Contains("--high-priority");
            var queries       = 20000;
            var allocRuns     = 4000;

            foreach (var argument in Arguments.Skip(1))
            {

                if (argument.StartsWith("--queries=") &&
                    Int32.TryParse(argument["--queries=".Length..], out var number) &&
                    number > 0)
                {
                    queries = number;
                }

                else if (!queryOptions.Contains(argument))
                {
                    Console.WriteLine($"Unknown option '{argument}'.");
                    return Usage();
                }

            }

#if MARKS
            Marks.KeepSocket      = Arguments.Contains("--keep-socket");
            Marks.T1AfterTheSend  = Arguments.Contains("--t1-after-the-send");
#else
            if (Arguments.Contains("--keep-socket") ||
                Arguments.Contains("--t1-after-the-send"))
            {
                Console.WriteLine("--keep-socket and --t1-after-the-send change the client, which only the build with the marks can: Phases/NornTimings.Phases.csproj.");
                return 2;
            }
#endif

            // Where the server process leaves its marks for this one to read.
            var outDir = Path.Combine(Path.GetTempPath(), $"norn-timings-{Environment.ProcessId}");
            Directory.CreateDirectory(outDir);

            var kePort        = FreeTCPPort();
            var ntpPort       = FreeUDPPort();
            var echoSyncPort  = FreeUDPPort();
            var echoAsyncPort = FreeUDPPort();

            Process?  child = null;

            if (inProcess)
                StartEchoAndServer(kePort, ntpPort, echoSyncPort, echoAsyncPort);

            else
            {

                child = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, $"server {kePort} {ntpPort} {echoSyncPort} {echoAsyncPort}{(highPriority ? " --high-priority" : "")}") {
                            RedirectStandardInput   = true,
                            RedirectStandardOutput  = true,
                            UseShellExecute         = false
                        })!;

                ReadOK(child);

            }

            #region Talking to the server

            var inProcessBefore = default(Snapshot);

            void ServerReset(Int32 Capacity, Boolean Alloc)
            {

                if (child is null)
                {
#if MARKS
                    Marks.S.Reset(Capacity, Alloc);
#endif
                    inProcessBefore = Snapshot.Take();
                    return;
                }

                child.StandardInput.WriteLine($"reset {Capacity} {(Alloc ? 1 : 0)}");
                ReadOK(child);

            }

            (Snapshot? Delta, MarkSet? Marks) ServerDump(String Name)
            {

                if (child is null)
                {
#if MARKS
                    return (null, Marks.S.Capacity > 0 ? Marks.S : null);
#else
                    return (null, null);
#endif
                }

                var path = Path.Combine(outDir, Name + ".bin");
                if (File.Exists(path))
                    File.Delete(path);

                child.StandardInput.WriteLine($"dump {path}");
                var parts = ReadOK(child);

                return (Snapshot.Parse(parts, 1),
                        File.Exists(path) ? MarkSet.Load(path) : null);

            }

            #endregion

            Console.WriteLine($"# NTS timings — {(inProcess ? "server in the client's process" : "server in a process of its own")}, "
#if MARKS
                            + "copies of NTSClient.cs and NTSServer.cs with marks in them"
#else
                            + "Norn as it is, without marks"
#endif
                            + (interleaved  ? ", interleaved mode" : "")
                            + (highPriority ? ", high priority"    : ""));
#if MARKS
            if (Marks.KeepSocket)
                Console.WriteLine("# COUNTER-EXPERIMENT: the client keeps one UDP socket for all queries");
            if (Marks.T1AfterTheSend)
                Console.WriteLine("# COUNTER-EXPERIMENT: offset and delay are computed with the clock as read after the send");
#endif
            Console.WriteLine($"# {Environment.ProcessorCount} logical processors, .NET {Environment.Version}, Stopwatch {Stopwatch.Frequency / 1e6:F0} MHz, server GC: {System.Runtime.GCSettings.IsServerGC}");
            Console.WriteLine();

            var ntsClient = new NTSClient(
                                DomainName.Localhost,
                                NTSKE_Port:                  IPPort.Parse(kePort),
                                NTP_Port:                    IPPort.Parse(ntpPort),
                                IPVersionPreference:         IPVersionPreference.IPv4Only,
                                InterleavedMode:             interleaved,
                                RemoteCertificateValidator:  (sender, certificate, chain, tlsClient, errors) => TLSValidationResult.Success()
                            );

            var keResult = await ntsClient.GetNTSKERecords();

            if (!keResult.Success || keResult.Response is null)
            {
                Console.WriteLine("NTS-KE failed: " + keResult.ErrorMessage);
                child?.Kill();
                return 1;
            }

            var ke = keResult.Response;

            Console.WriteLine($"NTS-KE: {ke.Cookies.Count()} cookies of {ke.Cookies.First().Length} bytes, AEAD {ke.AEADAlgorithm}");

            #region The query loop

            // What the queries report. Client and server read the same clock here, so
            // the true offset is zero and whatever is reported is the error.
            var clockOffsets        = new List<Double>();
            var roundTripDelays     = new List<Double>();
            var stopwatchRoundTrips = new List<Double>();

            // The measurements the interleaved mode completes, one exchange late.
            var interleavedOffsets  = new List<Double>();
            var interleavedDelays   = new List<Double>();

            // --t1-after-the-send: from T1 as it is in the request to the clock as
            // read after the send, and what offset and delay are with the former.
            var sendTook            = new List<Double>();
            var offsetsWithPacketT1 = new List<Double>();
            var delaysWithPacketT1  = new List<Double>();

            async Task<(Int64[] Before, Int64[] After, Int64[] BytesBefore, Int64[] BytesAfter)> Run(Int32 Count, Boolean Alloc = false)
            {

                var before       = new Int64[Count];
                var after        = new Int64[Count];
                var bytesBefore  = new Int64[Alloc ? Count : 0];
                var bytesAfter   = new Int64[Alloc ? Count : 0];

                for (var i = 0; i < Count; i++)
                {

                    if (Alloc)
                        bytesBefore[i] = GC.GetTotalAllocatedBytes(true);

                    before[i] = Stopwatch.GetTimestamp();

                    var result = await ntsClient.QueryTime(NTSKEResponse: ke);

                    after[i]  = Stopwatch.GetTimestamp();

                    if (Alloc)
                        bytesAfter[i] = GC.GetTotalAllocatedBytes(true);

                    if (!result.Success)
                        throw new Exception($"Query {i} failed: {result.ErrorMessage}");

                    if (result.InterleavedMeasurement is InterleavedMeasurement measurement)
                    {
                        interleavedOffsets.Add(measurement.ClockOffset.   TotalMicroseconds);
                        interleavedDelays. Add(measurement.RoundtripDelay.TotalMicroseconds);
                    }

                    // An interleaved response has its offset in the measurement above:
                    // its own timestamps belong to two different exchanges.
                    else if (!interleaved &&
                             result.Response is NTPPacket response &&
                             response.ClockOffset    is TimeSpan clockOffset &&
                             response.RoundTripDelay is TimeSpan roundTripDelay)
                    {

                        clockOffsets.       Add(clockOffset.   TotalMicroseconds);
                        roundTripDelays.    Add(roundTripDelay.TotalMicroseconds);
                        stopwatchRoundTrips.Add(response.StopwatchRoundTripTime?.TotalMicroseconds ?? Double.NaN);

                        // --t1-after-the-send: the client computed with the clock as read
                        // after the send. The request's own T1 came back as the origin.
                        if (response.RequestTransmitTimestamp is UInt64 afterTheSend)
                        {

                            var took = (NTPPacket.NTPTimestampToDateTime(afterTheSend) -
                                        NTPPacket.NTPTimestampToDateTime(response.OriginateTimestamp)).TotalMicroseconds;

                            sendTook.           Add(took);
                            offsetsWithPacketT1.Add(clockOffset.   TotalMicroseconds + took / 2);
                            delaysWithPacketT1. Add(roundTripDelay.TotalMicroseconds + took);

                        }

                    }

                }

                return (before, after, bytesBefore, bytesAfter);

            }

            #endregion

            // Warm up: tiered compilation promotes in the background.
            for (var round = 0; round < 3; round++)
            {
                await Run(3000);
                await Task.Delay(700);
            }

            var firstResult = await ntsClient.QueryTime(NTSKEResponse: ke);
            Console.WriteLine($"Request {firstResult.Response?.Request?.ToByteArray().Length} bytes, response {firstResult.Response?.ResponseBytes?.Length} bytes, cookies in the pool {ntsClient.AvailableCookieCount}");
            Console.WriteLine();

            #region Pass 1: time

            ServerReset(queries, false);
#if MARKS
            Marks.C.Reset(queries, false);
#endif
            GC.Collect();
            foreach (var list in new[] { clockOffsets, roundTripDelays, stopwatchRoundTrips, interleavedOffsets, interleavedDelays, sendTook, offsetsWithPacketT1, delaysWithPacketT1 })
                list.Clear();

            var clientBefore  = Snapshot.Take();
            var wallBefore    = Stopwatch.GetTimestamp();
            var run1          = await Run(queries);
            var wall          = Stopwatch.GetElapsedTime(wallBefore);
            var clientDelta   = Snapshot.Take().Since(clientBefore);
            var (serverDelta, serverMarks) = ServerDump("time");

            Console.WriteLine($"## Pass 1 — time, {queries} queries one after another, {wall.TotalSeconds:F2} s, {queries / wall.TotalSeconds:F0} queries/s");
            Console.WriteLine();
            Header("What the queries took and what they reported", false);
            Line("QueryTime, call to return", Enumerable.Range(0, queries).Select(i => (run1.After[i] - run1.Before[i]) * TicksToMicroseconds).ToArray());

            if (clockOffsets.Count > 0)
            {
                Line("clock offset reported (the true one is 0)",  clockOffsets.       ToArray());
                Line("round-trip delay reported",                  roundTripDelays.    ToArray());
                Line("StopwatchRoundTripTime",                     stopwatchRoundTrips.ToArray());
            }

            if (interleavedOffsets.Count > 0)
            {
                Line($"interleaved: clock offset ({interleavedOffsets.Count} measurements)", interleavedOffsets.ToArray());
                Line("interleaved: round-trip delay",                                        interleavedDelays. ToArray());
            }

            if (sendTook.Count > 0)
            {
                Line("T1 in the request -> the clock after the send",  sendTook.           ToArray());
                Line("clock offset with the T1 in the request",        offsetsWithPacketT1.ToArray());
                Line("round-trip delay with the T1 in the request",    delaysWithPacketT1. ToArray());
            }
            Console.WriteLine();
            Console.WriteLine($"{(inProcess ? "Process" : "Client "),-8}per query: {clientDelta.PerQuery(queries)}");
            if (serverDelta is Snapshot serverSnapshot)
                Console.WriteLine($"Server  per query: {serverSnapshot.PerQuery(queries)}");
            Console.WriteLine();

#if MARKS
            ReportClient(Marks.C, run1.Before, run1.After, null, null, queries);
            if (serverMarks is not null)
            {
                ReportServer(serverMarks, queries, false);
                ReportTimeline(Marks.C, serverMarks, run1.Before, run1.After, queries);
            }
#endif

            #endregion

#if MARKS

            #region Pass 2: allocations

            if (!inProcess)
            {

                ServerReset(allocRuns, true);
                Marks.C.Reset(allocRuns, true);

                var run2 = await Run(allocRuns, Alloc: true);
                var (_, serverAllocMarks) = ServerDump("alloc");

                Console.WriteLine($"## Pass 2 — allocations, {allocRuns} queries (GC.GetTotalAllocatedBytes(precise) at every mark; times of this pass are not used)");
                Console.WriteLine();

                ReportClient(Marks.C, run2.Before, run2.After, run2.BytesBefore, run2.BytesAfter, allocRuns);

                if (serverAllocMarks is not null)
                    ReportServer(serverAllocMarks, allocRuns, true);

                Marks.C.Reset(0, false);

            }

            #endregion

#endif

            await Echo(echoSyncPort, echoAsyncPort, firstResult.Response?.Request?.ToByteArray().Length ?? 228);

            if (child is not null)
            {
                child.StandardInput.WriteLine("quit");
                child.WaitForExit(3000);
            }

            try { Directory.Delete(outDir, recursive: true); } catch (IOException) { }

            return 0;

        }

        private static String[] ReadOK(Process Child)
        {

            while (Child.StandardOutput.ReadLine() is String line)
            {
                if (line.StartsWith("ok"))
                    return line.Split(' ');
            }

            throw new Exception("The server process ended.");

        }

        #endregion

        #region Reports

        public static void Header(String Title, Boolean Alloc)
        {
            Console.WriteLine($"### {Title}");
            Console.WriteLine();
            if (Alloc)
                Console.WriteLine($"{"",-58} {"bytes mean",10} {"median",8}");
            else
                Console.WriteLine($"{"",-58} {"mean µs",8} {"median",8} {"p10",8} {"p90",8} {"p99",8}");
        }

        public static (Double Mean, Double Median) Line(String Name, Double[] Values, Boolean Alloc = false)
        {

            var sorted = (Double[]) Values.Clone();
            Array.Sort(sorted);

            Double Quantile(Double q) => sorted[Math.Min(sorted.Length - 1, (Int32) (q * sorted.Length))];

            var mean   = sorted.Average();
            var median = Quantile(0.5);

            if (Alloc)
                Console.WriteLine($"{Name,-58} {mean,10:F0} {median,8:F0}");
            else
                Console.WriteLine($"{Name,-58} {mean,8:F1} {median,8:F1} {Quantile(0.1),8:F1} {Quantile(0.9),8:F1} {Quantile(0.99),8:F1}");

            return (mean, median);

        }

#if MARKS

        // The phase at index n ends at the client's mark n; the first one begins where
        // QueryTime is called, the last one ends where it has returned. The numbers are
        // those of Phases/InsertMarks.cs.
        private static readonly String[] clientPhases = [
            "call -> QueryTime entered",
            "take a cookie, count the placeholders",
            "resolve the remote end point",
            "nonces, rent the receive buffer, new Socket",
            "where to send to, Bind",
            "T1, build the request (extensions, AEAD seal)",
            "request.ToByteArray()",
            "SendToAsync",
            "wait for the response (CTS + ReceiveFromAsync)",
            "NTPResponse.TryParse (AEAD open, cookies)",
            "NTSResponseValidator.Validate",
            "announcement check, replay memory",
            "AddCookies",
            "interleaved bookkeeping, VerifySignature",
            "NTSQueryResult.SuccessResult (+ diagnostics)",
            "Socket.Dispose, return to the caller"
        ];

        private const Int32 clientCalled        = -1;
        private const Int32 clientAboutToSend   =  6;
        private const Int32 clientHasSent       =  7;
        private const Int32 clientHasDatagram   =  8;
        private const Int32 clientReturned      = 15;

        private static void ReportClient(MarkSet Marks, Int64[] Before, Int64[] After, Int64[]? BytesBefore, Int64[]? BytesAfter, Int32 Count)
        {

            var alloc = BytesBefore is not null;

            Header("Client: NTSClient.QueryTime by phase", alloc);

            Int64 At(Int32 i, Int32 mark)
                => mark switch {
                       clientCalled    => alloc ? BytesBefore![i] : Before[i],
                       clientReturned  => alloc ? BytesAfter! [i] : After [i],
                       _               => alloc ? Marks.Bytes(i, mark) : Marks.Stamp(i, mark)
                   };

            var scale     = alloc ? 1.0 : TicksToMicroseconds;
            var sumMean   = 0.0;
            var sumMedian = 0.0;

            for (var phase = 0; phase < clientPhases.Length; phase++)
            {
                var from = phase - 1;
                var to   = phase;
                var (mean, median) = Line(clientPhases[phase], Enumerable.Range(0, Count).Select(i => (At(i, to) - At(i, from)) * scale).ToArray(), alloc);
                sumMean   += mean;
                sumMedian += median;
            }

            Line("total", Enumerable.Range(0, Count).Select(i => (At(i, clientReturned) - At(i, clientCalled)) * scale).ToArray(), alloc);
            Console.WriteLine($"{"(sum of the phases)",-58} {sumMean,10:F1} {sumMedian,8:F1}");
            Console.WriteLine();

            if (!alloc)
            {
                Line("everything but the wait",                              Enumerable.Range(0, Count).Select(i => ((At(i, clientReturned) - At(i, clientCalled)) - (At(i, clientHasDatagram) - At(i, clientHasSent))) * scale).ToArray());
                Line("  of which before the wait (call -> SendToAsync done)", Enumerable.Range(0, Count).Select(i => (At(i, clientHasSent)  - At(i, clientCalled))      * scale).ToArray());
                Line("  of which after the wait (datagram -> return)",        Enumerable.Range(0, Count).Select(i => (At(i, clientReturned) - At(i, clientHasDatagram)) * scale).ToArray());
                Console.WriteLine();
            }

        }

        // The phase at index n lies between the server's marks n and n + 1.
        private static readonly String[] serverPhases = [
            "loop: timestamp, access list, semaphore, datagram copy",
            "Task.Run -> the worker runs",
            "NTPRequest.TryParse (cookie unseal, AEAD open)",
            "signing key, interleaved exchange",
            "BuildResponse (new cookie(s), AEAD seal)",
            "response.ToByteArray()",
            "SendToAsync",
            "RecordTransmission, counters"
        ];

        private static void ReportServer(MarkSet Marks, Int32 Count, Boolean Alloc)
        {

            Count = Math.Min(Count, Marks.Count);

            Header($"Server: one NTS request by phase ({Count} requests)", Alloc);

            Int64 At(Int32 i, Int32 mark) => Alloc ? Marks.Bytes(i, mark) : Marks.Stamp(i, mark);

            var scale = Alloc ? 1.0 : TicksToMicroseconds;

            for (var phase = 0; phase < serverPhases.Length; phase++)
                Line(serverPhases[phase], Enumerable.Range(0, Count).Select(i => (At(i, phase + 1) - At(i, phase)) * scale).ToArray(), Alloc);

            Line("total: datagram received -> worker done", Enumerable.Range(0, Count).Select(i => (At(i, 8) - At(i, 0)) * scale).ToArray(), Alloc);

            if (Alloc)
                Line("from one request's end to the next one's receipt", Enumerable.Range(0, Count - 1).Select(i => (At(i + 1, 0) - At(i, 8)) * scale).ToArray(), Alloc);
            else
                Line("datagram received -> response handed to the kernel", Enumerable.Range(0, Count).Select(i => (At(i, 7) - At(i, 0)) * scale).ToArray());

            Console.WriteLine();

        }

        private static void ReportTimeline(MarkSet Client, MarkSet Server, Int64[] Before, Int64[] After, Int32 Count)
        {

            Count = Math.Min(Count, Server.Count);

            Header("One query on one time line (both processes read the same performance counter)", false);

            Double[] Span(Func<Int32, Int64> From, Func<Int32, Int64> To)
                => Enumerable.Range(0, Count).Select(i => (To(i) - From(i)) * TicksToMicroseconds).ToArray();

            Line("client: call -> about to send",                           Span(i => Before[i],                           i => Client.Stamp(i, clientAboutToSend)));
            Line("client begins to send -> server has the datagram",        Span(i => Client.Stamp(i, clientAboutToSend),  i => Server.Stamp(i, 0)));
            Line("server: datagram -> about to send the response",          Span(i => Server.Stamp(i, 0),                  i => Server.Stamp(i, 6)));
            Line("server begins to send -> client has the datagram",        Span(i => Server.Stamp(i, 6),                  i => Client.Stamp(i, clientHasDatagram)));
            Line("client: datagram -> return",                              Span(i => Client.Stamp(i, clientHasDatagram),  i => After[i]));
            Line("total",                                                   Span(i => Before[i],                           i => After[i]));
            Console.WriteLine();
            Line("client's wait (SendToAsync done -> datagram)",            Span(i => Client.Stamp(i, clientHasSent),      i => Client.Stamp(i, clientHasDatagram)));
            Line("  server inside that wait (datagram -> sent)",            Span(i => Server.Stamp(i, 0),                  i => Server.Stamp(i, 7)));
            Line("  the rest: kernel, loopback, two threads being woken",   Enumerable.Range(0, Count).Select(i => ((Client.Stamp(i, clientHasDatagram) - Client.Stamp(i, clientHasSent)) - (Server.Stamp(i, 7) - Server.Stamp(i, 0))) * TicksToMicroseconds).ToArray());
            Console.WriteLine();

        }

#endif

        #endregion

        #region Echo: what the I/O pattern alone costs

        private static async Task Echo(Int32 EchoSyncPort, Int32 EchoAsyncPort, Int32 Size)
        {

            const Int32 rounds = 20000;

            var payload    = new Byte[Size];
            var syncEcho   = new IPEndPoint(IPAddress.Loopback, EchoSyncPort);
            var asyncEcho  = new IPEndPoint(IPAddress.Loopback, EchoAsyncPort);

            Console.WriteLine($"## UDP alone — {Size} bytes to an echo in the server process and back, {rounds} rounds each");
            Console.WriteLine();
            Console.WriteLine($"{"",-58} {"mean µs",8} {"median",8} {"p10",8} {"p90",8} {"p99",8}");

            async Task Measure(String Name, Func<Task> Round)
            {

                for (var i = 0; i < 3000; i++)
                    await Round();

                var times   = new Double[rounds];
                var before  = Snapshot.Take();

                for (var i = 0; i < rounds; i++)
                {
                    var start = Stopwatch.GetTimestamp();
                    await Round();
                    times[i] = (Stopwatch.GetTimestamp() - start) * TicksToMicroseconds;
                }

                var delta = Snapshot.Take().Since(before);

                Line(Name, times);
                Console.WriteLine($"{"",-58} {delta.PerQuery(rounds)}");

            }

            // 1. Blocking calls on one connected socket, against the blocking echo.
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Connect(syncEcho);
                var buffer = new Byte[4096];
                await Measure("blocking Send/Receive, one socket, blocking echo", () => {
                    socket.Send(payload);
                    socket.Receive(buffer);
                    return Task.CompletedTask;
                });
            }

            // 2. Async calls on one UdpClient that is kept.
            {
                using var udpClient = new UdpClient(AddressFamily.InterNetwork);
                await Measure("async, one UdpClient kept, blocking echo", async () => {
                    await udpClient.SendAsync(payload, syncEcho, CancellationToken.None);
                    await udpClient.ReceiveAsync(CancellationToken.None);
                });
            }

            // 3. As QueryTime does it: a socket for every query, bound before the send,
            //    a borrowed buffer and a linked CTS with a timer.
            var anyEndPoint = new IPEndPoint(IPAddress.Any, 0);

            async Task LikeQueryTime(IPEndPoint Remote)
            {

                var buffer = ArrayPool<Byte>.Shared.Rent(65536);

                try
                {

                    using var socket = new Socket(Remote.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                    socket.Bind(anyEndPoint);

                    await socket.SendToAsync(payload, SocketFlags.None, Remote, CancellationToken.None);

                    using var timeoutCTS = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken.None);
                    timeoutCTS.CancelAfter(TimeSpan.FromSeconds(3));

                    await socket.ReceiveFromAsync(buffer.AsMemory(), SocketFlags.None, anyEndPoint, timeoutCTS.Token).ConfigureAwait(false);

                }
                finally
                {
                    ArrayPool<Byte>.Shared.Return(buffer);
                }

            }

            await Measure("as QueryTime: socket per query + CTS, blocking echo",     () => LikeQueryTime(syncEcho));
            await Measure("as QueryTime, echo with the server's pattern (Task.Run)", () => LikeQueryTime(asyncEcho));

            // 4. What the socket alone costs.
            await Measure("new UdpClient + Dispose, nothing sent", () => {
                using var udpClient = new UdpClient(AddressFamily.InterNetwork);
                return Task.CompletedTask;
            });

            await Measure("new UdpClient + one SendAsync (binds) + Dispose", async () => {
                using var udpClient = new UdpClient(AddressFamily.InterNetwork);
                await udpClient.SendAsync(payload, syncEcho, CancellationToken.None);
            });

            Console.WriteLine();

        }

        #endregion

    }

}
