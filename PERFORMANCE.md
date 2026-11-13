# What an NTS query costs

Where the time and the memory of one `NTSClient.QueryTime` go, in the client and
in the server, measured phase by phase on 2026-11-13.

The short version:

- A query takes 400 to 500 µs and 16 KB in the client, and 60 to 100 µs and
  15.5 KB in the server. The times depend on what else the machine is doing;
  the bytes do not.
- Some 60 % of the client's time is not NTS at all, but the UDP socket that is
  made for every query: creating it, binding it, sending on it for the first
  time and closing it. That is deliberate (see
  [What was not changed, and why](#what-was-not-changed-and-why)).
- The NTS work proper is about 25 µs and 13 KB in the client, and 20 to 25 µs
  and 15 KB in the server.
- Two things were changed on the way, and the tables below are from after
  both (see [What was changed](#what-was-changed)). A query allocated 82 KB in
  the client, 64 of them a receive buffer that is borrowed now. And the client
  read its transmit timestamp before it made the socket, which put 0.1 ms onto
  the offset and 0.2 ms onto the delay; it binds the socket first now.


## How it was measured

|                |                                                                   |
|----------------|-------------------------------------------------------------------|
| Machine        | AMD Ryzen 7 3700X, 8 cores / 16 threads, Windows 11 Pro 10.0.26300 |
| Runtime        | .NET 11.0.0, Release build, workstation GC                        |
| Network        | loopback (127.0.0.1), IPv4                                        |
| Processes      | client and server each in a process of its own                    |
| Key exchange   | once, over TLS 1.3; AES-128-GCM-SIV, 8 cookies of 100 bytes       |
| Query          | no signed response, no interleaved mode; request and response 224 bytes each |
| Steady state   | 8 cookies in the pool: no placeholders, one new cookie a response |
| Load           | 20,000 queries one after another, after 9,000 to warm up the JIT  |

The program is [NornTimings](NornTimings/README.md).

**Time.** Copies of `NTSClient.cs` and `NTSServer.cs` are compiled into it with
a `Stopwatch.GetTimestamp()` between the phases. On Windows that is the
performance counter, which is the same clock in every process, so the marks of
the client and of the server lie on one time line. Its resolution here is
100 ns.

**Memory.** A second pass of 4,000 queries reads
`GC.GetTotalAllocatedBytes(precise: true)` at every mark. That is exact and
slow, so the times of that pass are not used. Client and server are separate
processes so that neither's allocations are counted as the other's.

**CPU time** is the processor time of each process over the whole run, divided
by the number of queries.

**The marks change nothing.** Three runs with them had medians of 433, 429 and
378 µs for a query, two runs of the same program against Norn as it is 483 and
377 µs.

Three things to keep in mind when reading the numbers:

- The machine was never idle, and not equally busy all day. All runs are at
  high process priority; at normal priority, with seven cores busy, the median
  of a run was anywhere between 455 and 1,070 µs. Even so two runs can differ
  by a quarter, as the five above do. The tables of phases are each from
  one run, and say where the ranges of the others are. Allocations are the
  same in every run, whatever the load.
- All figures are medians unless they say otherwise. Medians of phases do not
  add up exactly to the median of the whole.
- This is one machine, one operating system, loopback, and one query at a
  time. It says where the cost is, not what a server can carry.


## The client: `NTSClient.QueryTime`

| Phase                                                        |      µs |  bytes |
|--------------------------------------------------------------|--------:|-------:|
| Take a cookie, resolve the remote end point                  |     2.7 |  1,056 |
| **Borrow the receive buffer, `new Socket`**                  |  **39** |    168 |
| **`Bind`**                                                   | **133** |     40 |
| Read T1, build and serialise the request (extensions, AEAD)  |     8.1 |  5,040 |
| **`SendToAsync`** – the first send on the new socket         |  **69** |    696 |
| Wait for the response                                        |     129 |  1,856 |
| `NTPResponse.TryParse` (AEAD open, cookies)                  |     9.0 |  5,880 |
| Validate, replay memory, keep the cookies, build the result  |     3.7 |  1,448 |
| **`Socket.Dispose`**                                         |  **30** |      0 |
| Total                                                        |   ≈ 424 | 16,184 |

The median of the whole query was 433 µs in this run and 429 and 378 µs in the
two after it; the 10th percentile was 291 to 329 µs, the 90th 571 to 639 µs.

The processor time of the client was 420 to 460 µs a query, of which 305 to
355 µs in the kernel. It ran 38 generation 0 collections in 20,000 queries.

### The socket

The four phases in bold are the price of a socket per query: about 270 µs.
Taken apart on a socket of its own, with blocking calls
(`norn-timings sockets`):

| Step                                          |      µs |
|-----------------------------------------------|--------:|
| `new Socket`                                  |      24 |
| `Bind` to a free port                         |     130 |
| The first `SendTo`                            | 48 – 80 |
| Every later `SendTo`                          | 13 – 16 |
| `Dispose`                                     |      21 |

An unbound socket binds itself on the first send, which then takes 175 µs. On
a socket that is kept, a `SendToAsync` takes 12.5 µs.

**Why `Bind` takes 130 µs was not found out.** The firewall's filtering of new
sockets is a guess; testing it would have meant turning the firewall off.

### The wait

Of the 129 µs the client waits, 72 µs are the server and 55 µs are the kernel,
the loopback and two threads being woken. That last part is close to what UDP
costs at its cheapest on this machine: a blocking send and receive against a
blocking echo takes 40 to 65 µs for the round trip.

### One query on one time line

| From → to                                                         |    µs |
|-------------------------------------------------------------------|------:|
| Client: called → about to send                                    |   183 |
| Client begins to send → server has the datagram                   |    98 |
| Server: has the datagram → about to send the response             |    35 |
| Server begins to send → client has the datagram                   |    64 |
| Client: has the datagram → returned                               |    44 |

The first line contains the socket being made and bound, the second one the
first send on it, and the last one the 30 µs of closing it.

### The same query on a socket that is kept

To have this measured and not only added up, the client was run with one socket
for all queries (`--keep-socket`). Nothing else was changed.

|                                    | Socket per query | Socket kept |
|------------------------------------|-----------------:|------------:|
| `QueryTime`, median                |     378 – 433 µs | 141 – 174 µs |
| Allocated by the client            |          16.2 KB |     14.7 KB |
| Processor time of the client       |     420 – 460 µs | 155 – 171 µs |
| Queries a second, one after another |   2,150 – 2,380 | 5,670 – 6,890 |

What is left then is the wait (100 to 120 µs), a send of 25 to 31 µs and some
20 µs of NTS.


## The server: one NTS request

From the datagram being received to the response being sent. In the same run
as the client's table above:

| Phase                                                              |     µs |  bytes |
|--------------------------------------------------------------------|-------:|-------:|
| Receive loop: timestamp, access list, semaphore, copy of the datagram |  0.5 |    248 |
| `Task.Run` until the worker runs                                   |    9.1 |    448 |
| `NTPRequest.TryParse` (unseal the cookie, AEAD open)               |     12 |  6,840 |
| Signing key, interleaved exchange                                  |    1.0 |    240 |
| `BuildResponse` (a new cookie, AEAD seal)                          |     11 |  7,096 |
| `ToByteArray`                                                      |    0.8 |    632 |
| **`SendToAsync`**                                                  | **36** |      0 |
| Total                                                              |   ≈ 72 | 15,504 |

- The median of the whole was 72 µs in this run and 68 and 60 µs in the two
  after it. In the earlier runs of the day, on a busier machine, it was 70 to
  105 µs.
- Sending is the largest part here as well, about half. That every query comes
  from a new port explains little of it: against a client that keeps its
  socket it was 26 to 32 µs instead of 30 to 36.
- Parsing the request and building the response are 20 to 25 µs together, and
  nearly all of the 15.5 KB.
- The processor time of the server was 180 to 210 µs a query, more than the
  time that passes, because the receive loop, the worker and the completion
  threads are several threads.


## Client and server in one process

As the tests run them (`--in-process`). One query then takes 280 to 340 µs and
the process allocates 31.8 KB for it, which are the client's 16.2 KB and the
server's 15.5 KB.


## What was changed

Each of the two changes was measured right before and right after it, on a
machine that was busier then than for the tables above: the times of this
section are to be compared with each other, not with those.

### The receive buffer is borrowed

`QueryTime` made a `UdpClient` for every query, and a `UdpClient` allocates a
receive buffer of 64 KB for itself. It makes a `Socket` now, and receives into
a buffer borrowed from the `ArrayPool`. The buffer is as large as it was, so
that no datagram is cut short: a smaller one would have a datagram that does
not fit fail the receive, and with it the query, for anyone who can reach the
socket.

|                                              |       Before |        After |
|----------------------------------------------|-------------:|-------------:|
| Allocated by the client, a query             |     81,808 B |     16,096 B |
| Of which for the socket and its buffer       |     65,768 B |        168 B |
| Generation 0 collections in 20,000 queries   |          194 |           38 |
| GC pause, a query                            |       ≈ 5 µs |     ≈ 1.5 µs |
| Making the socket                            |        48 µs |        42 µs |
| `QueryTime`, median                          | 500 – 540 µs | 477 – 508 µs |

The 64 KB themselves cost under 2 µs to allocate; what they cost was the
collections. In one process with the server a query allocated 97.5 KB.

### The socket is bound before T1 is read

Over loopback the client and the server read the same clock, so the offset a
query reports is its own error: the true one is zero.

A client that is not in the interleaved mode has its T1 in the request, so it
reads the clock before it builds the request. It also did so before it made the
socket, and a socket that is not bound binds itself in its first send. Some
290 µs lay between T1 and the datagram: they looked like the way to the server,
and half of the difference to the way back is what the offset is wrong by.

The client binds the socket now before it reads T1, and resolves the address
before that where it still has to. The socket and the port are still new for
every query. A query allocates 50 to 90 bytes more since, 40 of them in the
bind: the 16,184 of the table at the top.

| Median of 20,000 queries, three runs each |   T1 before the socket | T1 after the bind |
|--------------------------------------------|-----------------------:|------------------:|
| Offset reported (true: 0)                  |          +104, +125 µs | +13, +13, +17 µs  |
| 10th to 90th percentile of it              |           73 to 190 µs |     -9 to +43 µs  |
| Delay reported                             |           390, 442 µs  | 221, 224, 253 µs  |
| `StopwatchRoundTripTime`                   |           367, 419 µs  | 242, 243, 278 µs  |

(The first column is two runs. In the runs of the tables at the top the offset
was +12 to +13 µs and the delay 170 to 190 µs.)

What is left has two parts, which the same runs show when the clock is read a
second time right after the send (`--t1-after-the-send`):

- **The client, about +40 µs.** Between T1 and the end of the send there are
  77 to 89 µs: the request being built and sealed, and the first send on a new
  socket, which is three to four times a later one even when the socket is
  bound. With the clock read after the send instead, the offset is -25 to
  -35 µs and the delay 107 to 133 µs.
- **The server, about -30 µs.** It reads T3 before it builds, seals and sends
  the response. That is what the basic mode is, and what the interleaved mode
  of RFC 9769 is for.

The two have opposite signs, which is why +13 µs is better than either part.
In the interleaved mode (`--interleaved`), where both sides use a timestamp
read after the send, the same loopback gives an offset of -0.5 µs (10th to 90th
percentile -5 to +4 µs) and a delay of 56 to 60 µs, which is the 40 to 65 µs a
UDP round trip costs here at all.

**T1 is still read before the send in the basic mode**, and not after it,
although after is the more exact of the two here. A timestamp that is too early
makes the delay too large, and an offset is never wrong by more than half the
delay; one that is too late - a thread that is held up between the send and the
clock - makes the delay too small and the sample look better than it is.


## What was not changed, and why

**The socket is still made for every query.** That is where 270 µs of every
query are, and it is deliberate: a socket of its own is a source port of its
own, which is what RFC 9109 asks of an NTP client, so that someone who cannot
see the traffic has to guess the port as well. NTS authenticates the response,
but not everything a client acts on is authenticated - a Kiss-o'-Death, for
one. Keeping the socket for some queries or some seconds would be a trade of
that protection for time, and is a decision of its own.

Also open:

- Why binding a UDP socket takes 130 µs here.
- The server's `SendToAsync`, at 30 to 50 µs two to four times a send on a
  quiet socket.
- The first send on a new socket, which puts about 40 µs onto every offset of
  the basic mode.
- The 5 to 7 KB each that parsing and building cost on either side.
- Anything but loopback, Windows and one query at a time.


## Measuring it again

```bash
dotnet run -c Release --project NornTimings/Phases -- query --high-priority
```

[NornTimings](NornTimings/README.md) says what the options in brackets above
are, and what the two builds of the program are for.
