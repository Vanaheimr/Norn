# Norn Test Suites

The default test run is intended to be fast and deterministic:

```powershell
dotnet test NornTests\NornTests.csproj
```

It includes unit-style tests plus local integration tests such as the in-process
NTS server fixture. It does not require public NTP/NTS servers.

## Live Network Tests

Tests under `ExternalServers` talk to public NTP/NTS services such as
Cloudflare, PTB, and `charging.cloud`. They depend on DNS, internet routing,
UDP/123 reachability, TLS certificates, and the current health of those public
servers.

Those fixtures are marked as:

```csharp
[Category("External")]
[Category("LiveNetwork")]
[Explicit]
```

Run them only when live reachability should be verified:

```powershell
dotnet test NornTests\NornTests.csproj --filter "TestCategory=LiveNetwork"
```

Or target one provider while debugging:

```powershell
dotnet test NornTests\NornTests.csproj --filter "FullyQualifiedName~Cloudflare_Tests"
```

Failures in `LiveNetwork` tests are not automatically library regressions.
First check DNS, firewall/NAT behavior, IPv4/IPv6 routing, UDP/123 reachability,
TLS certificate validity, and the public server status.

## Local Integration Tests

Local integration tests use loopback sockets and local TLS/NTS handshakes. They
are deterministic enough for the default run, but they are intentionally
separate from pure packet/parser/crypto unit tests.
