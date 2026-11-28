# NTPv5 compared with NTPv4

This folder holds Norn's NTPv5 client and responder, written after
[`draft-ietf-ntp-ntpv5-10`](https://datatracker.ietf.org/doc/draft-ietf-ntp-ntpv5/).
NTPv5 is still a draft, not an RFC. Everything that belongs to this one revision, such as the
draft name, the provisional codepoints and the negotiation magic, is kept in
[`NTPv5Draft.cs`](NTPv5Draft.cs). Following the next revision should then be a change of that
file, not a search through the code.

This page sums up what changes compared with NTPv4
([RFC 5905](https://www.rfc-editor.org/rfc/rfc5905), [RFC 7822](https://www.rfc-editor.org/rfc/rfc7822)),
as -10 describes it. The section numbers refer to the draft.

The core of the measurement stays the same: four timestamps, then offset and delay. Most
of what surrounds it is new.

## Client/server only (§ 6, § 10)

NTPv4 has symmetric active/passive, broadcast, and the control and private modes 6 and 7.
Mode 7 `monlist` made NTP a well-known DDoS amplifier. NTPv5 keeps only the request (mode 3)
and the response (mode 4), and a response is exactly as long as its request. A client that
expects a larger answer reserves the room with a Padding field (§ 7.2), so a reflected
request gains nothing.

## Cookies instead of timestamps (§ 6, § 9)

In NTPv4 the client sends its transmit timestamp, and the server echoes it as the origin
timestamp. That matches a response to its request, but it also tells everyone on the path
what the client's clock says, which is both a fingerprint and an attack aid.

An NTPv5 request is all zeros apart from the version, the mode, the timescale, the flags and
a **random 64-bit client cookie**, which the server copies. The client gives nothing about its
clock away. The **reference ID** and **reference timestamp** are gone from the header, too.
At stratum ≥ 2 the NTPv4 reference ID gave away the IPv4 address of the server's own source.

## Interleaved mode built in (§ 8)

In NTPv4 interleaved mode is an unofficial extension, implemented by ntpd and chrony. NTPv5
gives it a flag and a **server cookie**. When a client returns the server cookie of the
previous response, the server answers with the *exact* transmit timestamp of that previous
response. That is typically a hardware or kernel TX timestamp that the server could not know
when it sent the packet. Accuracy improves considerably without PTP-specific mechanisms in
the protocol.

## An era field for 2036 (§ 6)

The 64-bit NTPv4 timestamp wraps on 7 February 2036, and from then on the era has to be
guessed. NTPv5 carries an **8-bit era**, so the time is unambiguous.

## A choice of timescale (§ 6, § 7.10)

A **timescale field** selects **UTC, TAI or UT1**. A client that does not want to deal with
leap seconds simply asks for TAI. The two bits that were the leap indicator are reserved in
-10, to be ignored by a receiver. The Secondary Receive Timestamp field carries the receive
time in further timescales.

## Finer root delay and dispersion (§ 5, § 6)

NTPv4 uses 16.16 fixed point, a resolution of about 15 µs, which is coarse for today's
data-centre networks. NTPv5's `time32` has 4 integer and 28 fractional bits: about 3.7 ns
resolution, a range up to 16 s, and all bits set meaning infinity. Values are rounded up.

## Loop detection across sources (§ 7.4)

NTPv4 detects synchronisation loops through the reference ID. That covers one upstream source
only and works sensibly only with IPv4. NTPv5 answers a **Reference IDs request** with a list
of 32 entries, each a 56-bit ID and an 8-bit share. The server's own ID comes first at 100 %,
followed by the IDs of its sources' sources, weighted and halved at every hop. A server can
thus see a loop over several hops and several sources without any addresses being disclosed.

## Extension fields designed in (§ 7)

In NTPv4 extension fields were bolted on later (RFC 7822) and are ambiguous against the legacy
MAC trailer. In NTPv5 they are part of the format from the start, with uniform 4-octet
alignment and a length that counts the header and data but not the padding. New fields
include the following:

- **Server Information** (§ 7.6): which versions and flags the server supports.
- **Correction** (§ 7.7): on-path network elements can add the delay they introduce, much
  like PTP transparent clocks.
- **Reference Timestamp** (§ 7.8): moved out of the header, on request only.
- **Monotonic Receive Timestamp** (§ 7.9): a counter with a stable epoch, for frequency
  estimation even when the server's clock steps.
- **Time Sources** (§ 7.5).

The codepoints (`0xF5xx`) are draft values, not IANA assignments.

## Version negotiation and NTS (§ 11, § 12)

An NTPv4 client can ask whether a server speaks NTPv5 by putting a magic value in the
reference timestamp of an NTPv4 request: `NTP5NTP5` in the final form, `NTP5DRFT` while the
document is a draft. A server that speaks NTPv5 echoes it. This allows a migration without
a flag day.

NTS is part of the design (§ 11). The Unique Identifier, NTS Cookie, Cookie Placeholder and
Authenticator fields carry over from RFC 8915. A failed authentication is signalled by an
**Authentication NAK flag**, where NTPv4 uses a Kiss-o'-Death packet with the code `NTSN`.

## No mandatory algorithms

RFC 5905 specifies clock filter, selection, clustering, combining and the PLL/FLL discipline
in detail. NTPv5 specifies the wire protocol only and leaves synchronisation algorithms to the
implementation, which is what chrony and ntpd-rs do anyway.

## What Norn implements

| Draft | | Where |
|---|---|---|
| § 5, § 6, § 9, § 10 | Header, `time32`, era, timescale, flags, basic client/server exchange | [`NTPv5Packet.cs`](NTPv5Packet.cs), [`Time32.cs`](Time32.cs), [`NTPv5Client.cs`](NTPv5Client.cs), [`NTPv5Responder.cs`](NTPv5Responder.cs) |
| § 7 | Padding, Draft Identification, Server Information, Correction, Reference Timestamp, Monotonic Receive Timestamp | [`NTPv5ExtensionField.cs`](NTPv5ExtensionField.cs), [`NTPv5ExtensionField.Timestamps.cs`](NTPv5ExtensionField.Timestamps.cs) |
| § 7.4 | Reference IDs, combined from weighted sources | [`NTPv5ReferenceIds.cs`](NTPv5ReferenceIds.cs) |
| § 8 | Interleaved mode by server cookie | [`NTPv5InterleavedAssociation.cs`](NTPv5InterleavedAssociation.cs) |
| § 11 | NTS for NTPv5 | [`NTPv5NTS.cs`](NTPv5NTS.cs) |
| § 12 | Version negotiation from NTPv4 | [`NTPv5VersionNegotiation.cs`](NTPv5VersionNegotiation.cs) |
| § 7.3, § 7.5, § 7.10 | MAC, Time Sources, Secondary Receive Timestamp | not yet |

The [NTS conformance suite](https://github.com/Vanaheimr/NTSConformanceTests) tests these
against its own codec, written independently from the text of -10.

## In short

NTPv4 is a protocol from the 1980s with accumulated legacy. NTPv5 has less attack surface and
leaks less about the client. It is more accurate, through first-class interleaved mode, finer
resolution and the Correction field. It is unambiguous past 2036 and can serve TAI directly.
The cost is that it is not finished yet, its codepoints are provisional, and there are hardly
any peers to test against.
