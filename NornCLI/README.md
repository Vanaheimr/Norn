# norn

NTP and Network Time Security, from the command line.

Norn was a library and nothing else, which meant that using it at all — to check a server, to see
why a key exchange fails, to stand one up for an afternoon — required writing a C# project first.
Everything these three commands do was already implemented; none of it was reachable without a
compiler.

```
norn query <host>     Measure the clock offset against an NTS or plain NTP server.
norn ke    <host>     Run the RFC 8915 key exchange and report what was negotiated.
norn serve            Run an NTS-KE and NTP server.
```

Every command prints its own help with `norn <command> --help`, and `--help` is read before the
rest of the command line — so it still works next to an option that would otherwise be rejected,
which is when it is most likely to be reached for.

## Running it

Until it is published as a .NET tool, from the repository:

```bash
dotnet run --project libs/Norn/NornCLI -- query time.cloudflare.com
```

Everything below writes `norn` for that. To get the short form, publish it once and put the
output directory on your `PATH`:

```bash
dotnet publish libs/Norn/NornCLI -c Release
```

That leaves `norn` (`norn.exe` on Windows) in
`libs/Norn/NornCLI/bin/Release/net10.0/publish/`.

## norn query

The everyday one: how far off is this machine's clock, according to that server.

```console
$ norn query time.cloudflare.com
NTS query to time.cloudflare.com

  Server                [2606:4700:f1::1]:123
  Offset                +9.525700 ms
  Delay                 42.506200 ms
  Network RTT           17.195100 ms
  Stratum               3
  Reference             IPv4/Hash: 10.214.8.5 (0x0AD60805)
  Leap                  none
  Precision             2^-25 s
  Root delay            8.346500 ms
  Root disp.            0.244100 ms
  Mode                  basic
  Cookies left          8
```

NTS is the default: the key exchange runs first, and the reply is authenticated before any of it
is believed. `--plain` skips it for a server that has no NTS, and the header then says `NTP query`
rather than `NTS query` — worth reading, because the numbers look identical whether or not anyone
vouched for them.

**Offset** is what you came for: how far this machine's clock is from the server's, positive when
the local clock is behind. **Delay** is the RFC 5905 round-trip that the offset is derived from,
and **Network RTT** the same journey measured with a stopwatch around the socket. The gap between
them is what this process spent building and opening the packet; a large one means the offset is
noisier than the delay suggests.

| Option | |
|---|---|
| `--port <n>` | NTP port (default 123) |
| `--ke-port <n>` | NTS-KE port (default 4460) |
| `--plain` | Plain NTPv4, without NTS. No key exchange, no authentication |
| `--count <n>` | How many queries to send (default 1) |
| `--interval <s>` | Seconds between queries (default 1) |
| `--timeout <s>` | How long to wait for each leg (default 5) |
| `--interleaved` | RFC 9769 interleaved mode. Needs `--count 2` or more |
| `--ipv4`, `--ipv6` | Force an address family (default: prefer IPv6) |
| `--insecure` | Do not validate the server's TLS certificate |
| `--json` | Emit one JSON object instead of text |

`--interleaved` needs more than one query because the first exchange of an association is always
in the basic mode — the server's accurate transmit timestamp describes a packet that has already
left, so it can only arrive one exchange later. With `--count 1` there is nothing for it to
describe. The `Mode` line says which mode each answer actually came back in.

## norn ke

The key exchange on its own, for when a query fails and the question is where.

```console
$ norn ke time.cloudflare.com
NTS-KE with time.cloudflare.com

  TLS version           TLS 1.3
  Cipher suite          TLS_AES_128_GCM_SHA256
  ALPN                  ntske/1
  Subject               CN=time.cloudflare.com
  Issuer                CN=SSL.com SSL Intermediate CA ECC R2, O=SSL Corp, L=Houston, S=Texas, C=US
  Valid until           2027-02-17 21:30:57Z
  SAN                   time.cloudflare.com, www.time.cloudflare.com
  Resolved              2606:4700:00f1:0000:0000:0000:0000:0001, 2606:4700:00f1:0000:0000:0000:0000:0123, 162.159.200.1, 162.159.200.123
  Connected to          2606:4700:00f1:0000:0000:0000:0000:0001
  DNS                   360.940000 ms
  TCP connect           15.947200 ms
  TLS handshake         673.087900 ms
  NTS-KE                28.502400 ms
  Total                 1238.216000 ms

  Cookies               8
  Cookie size           64 octets

  Records
    critical NTSNextProtocolNegotiation        2 octets
    critical AEADAlgorithmNegotiation          2 octets
             CompliantAES128GCMSIVExporterContext    0 octets
             NewCookieForNTPv4                64 octets
```

The record list is the useful part when something is wrong, because it is what the server actually
sent rather than what was made of it. The four timings are separated for the same reason: a slow
`TLS handshake` and a slow `NTS-KE` mean different things, and `DNS` is usually the surprise.

| Option | |
|---|---|
| `--ke-port <n>` | NTS-KE port (default 4460) |
| `--timeout <s>` | How long to wait (default 10) |
| `--ipv4`, `--ipv6` | Force an address family (default: prefer IPv6) |
| `--insecure` | Do not validate the server's TLS certificate |
| `--public-keys` | Also ask for the public keys used for signed responses |
| `--json` | Emit one JSON object instead of text |

## norn serve

An NTS-KE and NTP server, until interrupted. Ports 123 and 4460 need privileges on most systems;
pick high ones to run it as yourself.

```bash
norn serve --port 12123 --ke-port 14460
```

| Option | |
|---|---|
| `--port <n>` | NTP port to listen on (default 123) |
| `--ke-port <n>` | NTS-KE port to listen on (default 4460) |
| `--listen <address>` | Address to bind (default 0.0.0.0; use `::` for both families) |
| `--cert <file>`, `--key <file>` | TLS certificate and private key, PEM |
| `--advertise <host>` | Host name for the NTPv4 Server Negotiation record |
| `--master-keys <file>` | Where to persist the cookie master keys |
| `--rate-limit <s>` | Average seconds between answers per client address |
| `--burst <n>` | Requests one address may fire back to back (default 8) |
| `--no-interleaved` | Refuse the RFC 9769 interleaved mode |
| `--auth-interleaved` | Offer the interleaved mode only to authenticated clients |
| `--stratum <n>` | Stratum to report (default 1) |
| `--refid <text>` | Reference identifier to report (default `LOCL`) |
| `--quiet` | Do not print per-request logging |

Two defaults are worth knowing before anyone else connects.

**Without `--cert` a fresh self-signed certificate is generated per connection.** That is enough
to talk to `norn query --insecure`, and it is enough for nothing else: a client cannot be told in
advance to trust a certificate that does not exist yet. Real clients need `--cert` and `--key`.

**Without `--master-keys` the cookie master keys live in memory only.** Every restart invalidates
every cookie in the field, so every client has to run the key exchange again. That is the right
default for an afternoon and the wrong one for a service.

`--rate-limit` is RFC 8633 § 5.4: an address that asks faster than the given average is answered
with a `RATE` kiss-o'-death carrying the interval the server will serve, rather than being ignored.
`--burst` is how much of a head start an address gets, so that a client's `iburst` is not the first
thing refused.

## Scripting it

Three rules hold throughout, and they are what make the tool usable from a script.

**Exit codes distinguish failure from mistyping.**

| | |
|---|---|
| `0` | it worked |
| `1` | the operation failed — no answer, a refusal, a validation error |
| `2` | the command line could not be understood |

**`--json` puts the document on stdout and nothing else.** Warnings, notes and human-readable
errors go to stderr — so a pipeline reading stdout always gets one well-formed document, never a
diagnostic mixed into the data.

```console
$ norn query ptbtime1.ptb.de --json
{
  "host": "ptbtime1.ptb.de",
  "nts": true,
  "success": true,
  "answered": 1,
  "sent": 1,
  "measurements": [
    {
      "success": true,
      "server": "[2001:638:610:be01::108]:123",
      "offsetMilliseconds": 8.868,
      "delayMilliseconds": 52.0089,
      "networkRTTMilliseconds": 29.0075,
      "stratum": 1,
      "referenceIdentifier": "'PTB' European telephone modem",
      "leapIndicator": 0,
      "precision": -26,
      "rootDelaySeconds": 0.0001068115234375,
      "rootDispersionSeconds": 1.52587890625E-05,
      "interleaved": false,
      "remainingCookies": 8
    }
  ]
}
```

That holds when the command fails, too. The document says so and says where it got to, the prose
goes to stderr, and the exit code is still 1:

```console
$ norn query nts.example.invalid --json
{
  "host": "nts.example.invalid",
  "success": false,
  "stage": "nts-ke",
  "error": "No IP address found for nts.example.invalid.!",
  "category": "DNS"
}
```

**No option silently does nothing.** An unrecognized one is an error, not a shrug:

```console
$ norn query time.cloudflare.com --nope
norn: Unknown option: --nope
Try 'norn --help'.
$ echo $?
2
```

A failure says what failed and why, on stderr, and exits 1:

```console
$ norn query nts.example.invalid
norn: the key exchange with nts.example.invalid failed: No IP address found for nts.example.invalid.!
$ echo $?
1
```

Ctrl-C is a cancellation rather than a kill: a server closes its sockets and a query in flight
stops waiting, and the exit code is 0 because nothing went wrong.

## Where the behaviour is pinned

`conformance/NTSConformance.CLI.Tests` in the
[conformance suite](https://github.com/Vanaheimr/NTSConformanceTests), which runs `norn` as a
process rather than calling into it — the exit code, the stream a byte came out on, and the shape
of the JSON are all things only a process boundary can check.
