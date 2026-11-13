# norn-timings

Where the time and the memory of one NTS query go. This is the program behind
[PERFORMANCE.md](../PERFORMANCE.md): it starts an NTS server on the loopback interface, runs one
`NTSClient.QueryTime` after another against it, and says what a query took, what it allocated,
and what it reported as offset and delay.

It is not a load test. There is one client and one query at a time, so it says where the cost of
a query is and not what a server can carry.

## Two builds of one program

**[NornTimings.csproj](NornTimings.csproj)** references Norn and measures it as it is, from the
outside:

```bash
dotnet run -c Release --project NornTimings -- query
```

- how long a query takes from the call to the return,
- what the client and the server allocate and use of the processor for it,
- the clock offset and the round-trip delay it reports. Client and server read the same clock
  here, so the true offset is zero and what is reported is the error of the measurement.

**[Phases/NornTimings.Phases.csproj](Phases/NornTimings.Phases.csproj)** is the same program with
Norn compiled into it and not referenced, and with marks in the client and in the server: a time
stamp between the phases of a query. It reports all of the above and, for both sides, every phase
by itself, in time and in a second pass in bytes allocated:

```bash
dotnet run -c Release --project NornTimings/Phases -- query
```

The marks are in no file of Norn. The build copies `NTSClient.cs` and `NTSServer.cs`, puts the
marks into the copies and compiles those; [Phases/InsertMarks.cs](Phases/InsertMarks.cs) says
where each one stands, by the line of code it stands at. When that line changes, the build fails
and names the mark, and `InsertMarks.cs` has to follow the code.

A mark costs a few nanoseconds, and the totals of the two builds agree.

## Options

```
norn-timings query [options]   One NTS query after another against a server on the loopback interface.
norn-timings sockets           What a UDP socket for every query costs, step by step.

  --queries=<n>          How many queries are measured (default: 20000).
  --in-process           The server in the client's process, not in one of its own.
  --interleaved          The client in the interleaved mode of RFC 9769.
  --high-priority        Both processes at high priority, for a machine that is not idle.

Only where the marks are compiled in (Phases/NornTimings.Phases.csproj):

  --keep-socket          One UDP socket for all queries, not one for each.
  --t1-after-the-send    Offset and delay computed with the clock as read after the send.
```

The last two are counter-experiments: they change what the client does, to have measured what
would otherwise only be added up. Norn does neither, and [PERFORMANCE.md](../PERFORMANCE.md) says
why.

## Reading the numbers

- Every line is the mean, the median and the 10th, 90th and 99th percentile, in microseconds.
- Client and server run in two processes, so that neither's allocations are counted as the
  other's. The time stamps of both are the performance counter, which is one clock for all
  processes of a machine: that is what puts the marks of both on one time line.
- 9,000 queries are run and thrown away before the first one is measured, for the JIT.
- On a machine that is doing something else the medians of two runs can differ by a factor of
  two. `--high-priority` brings them to within a few percent; the allocations are the same in
  every run either way.
- The pass that counts allocations reads `GC.GetTotalAllocatedBytes(precise: true)` at every
  mark, which is exact and slow. Its times are not reported.

## What it needs

What Norn needs: [Hermod](https://github.com/Vanaheimr/Hermod) and
[Styx](https://github.com/Vanaheimr/Styx) checked out beside this repository.

The figures in `PERFORMANCE.md` are from Windows. The program runs elsewhere, but its one time
line for two processes relies on `Stopwatch.GetTimestamp()` being the same clock in both.
