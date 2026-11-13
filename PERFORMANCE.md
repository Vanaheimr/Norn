# What an NTS query costs

Where the time and the memory of one `NTSClient.QueryTime` go, in the client and
in the server, measured phase by phase on 2026-11-13.

The short version:

- A query took about 500 µs and 82 KB in the client, and 70 to 105 µs and
  15.5 KB in the server.
- Some 60 % of the client's time and 80 % of its memory were not NTS at all,
  but the UDP socket that is made for every query: creating it, binding it,
  sending on it for the first time and closing it, and the 64 KB receive
  buffer a `UdpClient` allocates for itself.
- The NTS work proper is about 25 µs and 16 KB in the client, and 25 to
  35 µs and 15 KB in the server.
- The 64 KB buffer is gone since (see [What was changed](#what-was-changed)):
  a query allocates 16 KB in the client now. The time is what it was, because
  the socket is still made for every query, and that is deliberate.


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

**Time.** Copies of `NTSClient.cs` and `NTSServer.cs` were compiled into a
harness with a `Stopwatch.GetTimestamp()` between the phases. On Windows that is
the performance counter, which is the same clock in every process, so the marks
of the client and of the server lie on one time line. Its resolution here is
100 ns.

**Memory.** A second pass of 4,000 queries read
`GC.GetTotalAllocatedBytes(precise: true)` at every mark. That is exact and
slow, so the times of that pass are not used. Client and server are separate
processes so that neither's allocations are counted as the other's.

**CPU time** is the processor time of each process over the whole run, divided
by the number of queries.

**The marks change nothing.** The same harness against Norn as it is, without
marks, gave the same totals: 520 µs median and 81.9 KB a query.

Three things to keep in mind when reading the numbers:

- The machine was not idle: unrelated processes kept about seven cores busy.
  At normal priority the median of a run was anywhere between 455 and
  1,070 µs. The figures below are from runs at high process priority, where
  the medians of three runs in a row were 498, 511 and 513 µs. Allocations are the same to the byte
  in every run, whatever the load.
- All figures are medians unless they say otherwise. Medians of phases do not
  add up exactly to the median of the whole.
- This is one machine, one operating system, loopback, and one query at a
  time. It says where the cost is, not what a server can carry.


## The client: `NTSClient.QueryTime`

Before the change, with a `UdpClient` for every query:

| Phase                                                        |     µs |  bytes |
|--------------------------------------------------------------|-------:|-------:|
| Take a cookie, resolve the remote end point                  |    2.9 |  1,000 |
| Build and serialise the request (nonce, extensions, AEAD)    |    8.3 |  4,960 |
| **`new UdpClient`**                                          | **48** | **65,768** |
| **`SendAsync`** – the first send on the new socket, which binds it | **232** | 696 |
| Wait for the response                                        |    160 |  2,000 |
| `NTPResponse.TryParse` (AEAD open, cookies)                  |   10.3 |  5,880 |
| Validate, replay memory, keep the cookies, build the result  |    4.0 |  1,448 |
| **`UdpClient.Dispose`**                                      | **36** |      0 |
| Total                                                        |  ≈ 502 | 81,808 |

Over all runs at high priority the median of the whole query was 500 to 540 µs,
the 10th percentile 455 to 472 µs, the 90th 584 to 675 µs.

The processor time of the client was about 500 µs a query, of which 330 to
360 µs in the kernel.

### The socket

The three phases in bold are the price of a socket per query: about 316 µs.
Taken apart on a socket of its own, with blocking calls:

| Step                                          |      µs |
|-----------------------------------------------|--------:|
| `new Socket`                                  |      24 |
| `Bind` to a free port                         |     130 |
| The first `SendTo`                            | 48 – 80 |
| Every later `SendTo`                          | 13 – 16 |
| `Dispose`                                     |      21 |

An unbound socket binds itself on the first send, which then takes 175 µs. A
`UdpClient` is 6 µs slower to make than the socket inside it; the 64 KB
themselves cost under 2 µs to allocate, but they are why the client ran 194
generation 0 collections in 20,000 queries instead of 38.

On a socket that is kept, a `SendToAsync` takes 12.5 µs.

**Why `Bind` takes 130 µs was not found out.** The firewall's filtering of new
sockets is a guess; testing it would have meant turning the firewall off.

### The wait

Of the 160 µs the client waits, about 100 µs are the server and about 60 µs
are the kernel, the loopback and two threads being woken. That last part is
close to what UDP costs at its cheapest on this machine: a blocking send and
receive against a blocking echo takes 45 to 65 µs for the round trip.

### One query on one time line

| From → to                                                         |    µs |
|-------------------------------------------------------------------|------:|
| Client: called → about to send                                    |  60.5 |
| Client begins to send → server has the datagram                   | 262.5 |
| Server: has the datagram → about to send the response             |  49.7 |
| Server begins to send → client has the datagram                   |  78.6 |
| Client: has the datagram → returned                               |  50.8 |

The second line is the bind and the first send; the last one contains the 36 µs
of closing the socket.

### The same query on a socket that is kept

To have this measured and not only added up, the harness's copy of the client
was run with one `UdpClient` for all queries. Nothing else was changed.

|                                    | Socket per query | Socket kept |
|------------------------------------|-----------------:|------------:|
| `QueryTime`, median                |     500 – 540 µs | 182 – 190 µs |
| Allocated by the client            |          81.9 KB |     14.8 KB |
| Processor time of the client       |         ≈ 500 µs | 168 – 180 µs |
| Queries a second, one after another |         ≈ 1,900 |     ≈ 5,200 |

What is left then is the wait (about 130 µs, 75 of them the server), a send of
32 µs and some 20 µs of NTS.


## The server: one NTS request

From the datagram being received to the response being sent, the median was 70
to 105 µs, depending on the run. In the same run as the client's table above:

| Phase                                                              |     µs |  bytes |
|--------------------------------------------------------------------|-------:|-------:|
| Receive loop: timestamp, access list, semaphore, copy of the datagram |  0.7 |    248 |
| `Task.Run` until the worker runs                                   |     11 |    445 |
| `NTPRequest.TryParse` (unseal the cookie, AEAD open)               |     18 |  6,842 |
| Signing key, interleaved exchange                                  |    1.7 |    240 |
| `BuildResponse` (a new cookie, AEAD seal)                          |     16 |  7,096 |
| `ToByteArray`                                                      |    1.0 |    632 |
| **`SendToAsync`**                                                  | **47** |      0 |
| Total                                                              |  ≈ 100 | 15,504 |

- Sending is the largest part here as well, about half. That every query comes
  from a new port explains little of it: against a client that keeps its
  socket it was 36 µs instead of 47.
- Parsing the request and building the response are 25 to 35 µs together, and
  nearly all of the 15.5 KB.
- The processor time of the server was 200 to 250 µs a query, more than the
  time that passes, because the receive loop, the worker and the completion
  threads are several threads.


## Client and server in one process

As the tests run them. One query then takes 410 to 417 µs and the process
allocates 97.5 KB for it, which are the client's 82 KB and the server's 15.5 KB.


## What was changed

`QueryTime` makes a `Socket` now and no `UdpClient`, and receives into a buffer
borrowed from the `ArrayPool`. The buffer is as large as it was, 64 KB, so that
no datagram is cut short: a smaller one would have a datagram that does not fit
fail the receive, and with it the query, for anyone who can reach the socket.

|                                              |       Before |        After |
|----------------------------------------------|-------------:|-------------:|
| Allocated by the client, a query             |     81,808 B |     16,096 B |
| Of which for the socket and its buffer       |     65,768 B |        168 B |
| Generation 0 collections in 20,000 queries   |          194 |           38 |
| GC pause, a query                            |       ≈ 5 µs |     ≈ 1.5 µs |
| Making the socket                            |        48 µs |        42 µs |
| `QueryTime`, median                          | 500 – 540 µs | 477 – 508 µs |

The 16 KB that are left are the response being parsed (5.9 KB), the request
being built and serialised (5.0 KB), the receive with its timeout (1.8 KB) and
a dozen smaller things.


## What was not changed, and why

**The socket is still made for every query.** That is where 300 µs of every
query are, and it is deliberate: a socket of its own is a source port of its
own, which is what RFC 9109 asks of an NTP client, so that someone who cannot
see the traffic has to guess the port as well. NTS authenticates the response,
but not everything a client acts on is authenticated - a Kiss-o'-Death, for
one. Keeping the socket for some queries or some seconds would be a trade of
that protection for time, and is a decision of its own.

Also open:

- Why binding a UDP socket takes 130 µs here.
- The server's `SendToAsync`, at 36 to 50 µs three to four times a send on a
  quiet socket.
- The 6 to 7 KB each that parsing and building cost on either side.
- Anything but loopback, Windows and one query at a time.

The harness is not part of this repository.
