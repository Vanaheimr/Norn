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

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// What a client with bad intentions can and cannot do to the server's shared state:
    /// its rate limiter, its interleaved-mode memory, its NTS-KE slots and its master key.
    /// </summary>
    [TestFixture]
    public class NTSServer_Hardening_Tests
    {

        #region RateLimiter_TheHostsOfOneIPv6PrefixShareABudget()

        /// <summary>
        /// A host has all the addresses of its /64 to choose from.
        /// A new address must not be a new budget.
        /// </summary>
        [Test]
        public void RateLimiter_TheHostsOfOneIPv6PrefixShareABudget()
        {

            var rateLimiter = new NTPRateLimiter(Burst: 4, MinimumInterval: TimeSpan.FromHours(1), Leak: 0);

            var answered    = Enumerable.Range(1, 100).
                                  Count(host => rateLimiter.Check(System.Net.IPAddress.Parse($"2001:db8:1:2::{host:x}")) == RateLimitDecision.Answer);

            Assert.That(answered,                                                                           Is.EqualTo(4));
            Assert.That(rateLimiter.TrackedClients,                                                         Is.EqualTo(1));

            // The neighbouring /64 is somebody else.
            Assert.That(rateLimiter.Check(System.Net.IPAddress.Parse("2001:db8:1:3::1")),                   Is.EqualTo(RateLimitDecision.Answer));

        }

        #endregion

        #region RateLimiter_ThePrefixLengthCanBeChosen()

        [Test]
        public void RateLimiter_ThePrefixLengthCanBeChosen()
        {

            var rateLimiter = new NTPRateLimiter(Burst: 1, MinimumInterval: TimeSpan.FromHours(1), IPv6PrefixLength: 128, Leak: 0);

            Assert.That(rateLimiter.Check(System.Net.IPAddress.Parse("2001:db8::1")),                       Is.EqualTo(RateLimitDecision.Answer));
            Assert.That(rateLimiter.Check(System.Net.IPAddress.Parse("2001:db8::2")),                       Is.EqualTo(RateLimitDecision.Answer));
            Assert.That(rateLimiter.Check(System.Net.IPAddress.Parse("2001:db8::1")),                       Is.Not.EqualTo(RateLimitDecision.Answer));

            Assert.That(NTPRateLimiter.ClientOf(System.Net.IPAddress.Parse("2001:db8:ffff:ffff:ffff::1"), 52).ToString(),
                        Is.EqualTo("2001:db8:ffff:f000::"));

        }

        #endregion

        #region RateLimiter_AnIPv4ClientOnADualStackSocketIsItself()

        /// <summary>
        /// All of IPv4 lies within one /64 of the form ::ffff:a.b.c.d.
        /// Masked like any IPv6 address, every IPv4 client would share one budget.
        /// </summary>
        [Test]
        public void RateLimiter_AnIPv4ClientOnADualStackSocketIsItself()
        {

            var rateLimiter = new NTPRateLimiter(Burst: 1, MinimumInterval: TimeSpan.FromHours(1), Leak: 0);

            Assert.That(rateLimiter.Check(System.Net.IPAddress.Parse("::ffff:192.0.2.1")),                  Is.EqualTo(RateLimitDecision.Answer));
            Assert.That(rateLimiter.Check(System.Net.IPAddress.Parse("::ffff:192.0.2.2")),                  Is.EqualTo(RateLimitDecision.Answer));

            // The same client, whichever way its address is written.
            Assert.That(rateLimiter.Check(System.Net.IPAddress.Parse("192.0.2.1")),                         Is.Not.EqualTo(RateLimitDecision.Answer));

        }

        #endregion

        #region RateLimiter_ALargeTableStaysBounded()

        /// <summary>
        /// The table is kept in parts, each with its own lock. All of them together
        /// must still not hold more than was asked for.
        /// </summary>
        [Test]
        public void RateLimiter_ALargeTableStaysBounded()
        {

            var rateLimiter = new NTPRateLimiter(MaxClients: 4096);

            Parallel.For(0, 50_000, client => {
                rateLimiter.Check(new System.Net.IPAddress([ 10, (Byte) (client >> 16), (Byte) (client >> 8), (Byte) client ]));
            });

            Assert.That(rateLimiter.TrackedClients,                                                         Is.LessThanOrEqualTo(4096));
            Assert.That(rateLimiter.TrackedClients,                                                         Is.GreaterThan(2048));

        }

        #endregion


        #region RateLimiter_SomeRequestsOverTheLimitAreAnsweredAllTheSame()

        /// <summary>
        /// Whoever sends under a client's address spends its budget. The client's own
        /// requests must still have a chance: of those over the limit, one in four.
        /// </summary>
        [Test]
        public void RateLimiter_SomeRequestsOverTheLimitAreAnsweredAllTheSame()
        {

            var rateLimiter = new NTPRateLimiter(Burst: 1, MinimumInterval: TimeSpan.FromHours(1), MaxKissesPerSecond: 0);
            var victim      = System.Net.IPAddress.Parse("192.0.2.9");

            Assert.That(rateLimiter.Leak,                                                                   Is.EqualTo(2));
            Assert.That(rateLimiter.Check(victim),                                                          Is.EqualTo(RateLimitDecision.Answer));

            var answered    = Enumerable.Range(0, 8000).
                                  Count(_ => rateLimiter.Check(victim) == RateLimitDecision.Answer);

            // 2000 expected, with a standard deviation of about 39.
            Assert.That(answered,                                                                           Is.InRange(1700, 2300));

            // And none at all where the operator would rather have it so.
            var strict      = new NTPRateLimiter(Burst: 1, MinimumInterval: TimeSpan.FromHours(1), Leak: 0);

            Assert.That(strict.Check(victim),                                                               Is.EqualTo(RateLimitDecision.Answer));
            Assert.That(Enumerable.Range(0, 2000).Count(_ => strict.Check(victim) == RateLimitDecision.Answer),
                        Is.EqualTo(0));

        }

        #endregion

        #region RateLimiter_AnAddressThatComesBackFindsNoFullBurst()

        /// <summary>
        /// With more addresses than the table holds, every one of them is new again
        /// each time round. It gets the one answer any address gets, not a burst.
        /// </summary>
        [Test]
        public void RateLimiter_AnAddressThatComesBackFindsNoFullBurst()
        {

            var rateLimiter = new NTPRateLimiter(Burst: 8, MinimumInterval: TimeSpan.FromHours(1), MaxClients: 4, Leak: 0);

            Int32 AnsweredOf8(Int32 Client)
                => Enumerable.Range(0, 8).
                       Count(_ => rateLimiter.Check(new System.Net.IPAddress([ 198, 51, 100, (Byte) Client ])) == RateLimitDecision.Answer);

            // While there is room, a newcomer has its whole burst.
            for (var client = 1; client <= 4; client++)
                Assert.That(AnsweredOf8(client),                                                            Is.EqualTo(8));

            // From here on every newcomer pushes somebody out.
            for (var client = 5; client <= 12; client++)
                Assert.That(AnsweredOf8(client),                                                            Is.EqualTo(1));

            // The first ones were pushed out long ago, and are newcomers again.
            Assert.That(AnsweredOf8(1),                                                                     Is.EqualTo(1));

            Assert.That(rateLimiter.TrackedClients,                                                         Is.EqualTo(4));

        }

        #endregion


        #region Interleaved_UnauthenticatedRequestsDoNotDisplaceAuthenticatedOnes()

        /// <summary>
        /// A source address costs nothing to forge. Plain datagrams sent under an NTS
        /// client's address must not take the interleaved mode away from it.
        /// </summary>
        [Test]
        public void Interleaved_UnauthenticatedRequestsDoNotDisplaceAuthenticatedOnes()
        {

            var timestamps  = new InterleavedTimestamps(InterleavedModePolicy.Everyone);
            var client      = System.Net.IPAddress.Parse("192.0.2.7");

            // The NTS client's first request, and this server's answer to it.
            var first       = timestamps.BeginExchange(
                                  client,
                                  1000,
                                  new NTPRequest(OriginateTimestamp: 0, ReceiveTimestamp: 0, TransmitTimestamp: 11),
                                  TimeProvider.System,
                                  Authenticated: true
                              );

            first.RecordTransmission(2000);

            Assert.That(first.IsInterleaved,                                                                Is.False);

            // The flood: far more than the exchanges kept per client, all under its address.
            for (var i = 0UL; i < 64; i++)
                timestamps.BeginExchange(
                    client,
                    5000 + i * 10,
                    new NTPRequest(OriginateTimestamp: 0, ReceiveTimestamp: 0, TransmitTimestamp: 100 + i),
                    TimeProvider.System,
                    Authenticated: false
                ).RecordTransmission(5005 + i * 10);

            // The NTS client's next request names the receive timestamp of its first.
            var second      = timestamps.BeginExchange(
                                  client,
                                  9000,
                                  new NTPRequest(OriginateTimestamp: first.ReceiveTimestamp, ReceiveTimestamp: 21, TransmitTimestamp: 22),
                                  TimeProvider.System,
                                  Authenticated: true
                              );

            Assert.That(second.IsInterleaved,                                                               Is.True);
            Assert.That(second.TransmitTimestamp,                                                           Is.EqualTo(2000));

        }

        #endregion


        #region Cookie_CarriesItsNonceAndMasterKeyIdOnce()

        /// <summary>
        /// 8 + 2 + 32 in the clear, then the 16 octets of the synthetic IV and a body
        /// of 8 + 2 + 32 + 32: 132 octets, where there were 172.
        /// </summary>
        [Test]
        public void Cookie_CarriesItsNonceAndMasterKeyIdOnce()
        {

            var masterKey    = new MasterKey(
                                   Id:         7,
                                   Value:      System.Security.Cryptography.RandomNumberGenerator.GetBytes(32),
                                   NotBefore:  DateTimeOffset.UtcNow.AddMinutes(-1),
                                   NotAfter:   DateTimeOffset.UtcNow.AddDays(1)
                               );

            var c2sKey       = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
            var s2cKey       = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);

            var cookie       = NTSCookie.Create(masterKey, c2sKey, s2cKey);
            var sealedCookie = cookie.Encrypt(masterKey);

            Assert.That(sealedCookie.Length,                                                                Is.EqualTo(132));

            Assert.That(NTSCookie.TryParse(sealedCookie, masterKey, out var parsed, out var errorResponse), Is.True, errorResponse);
            Assert.That(parsed!.MasterKeyId,                                                                Is.EqualTo(7));
            Assert.That(parsed.Nonce,                                                                       Is.EqualTo(cookie.Nonce));
            Assert.That(parsed.C2SKey,                                                                      Is.EqualTo(c2sKey));
            Assert.That(parsed.S2CKey,                                                                      Is.EqualTo(s2cKey));

        }

        #endregion


        #region MasterKey_IsReadWhileItRotates()

        /// <summary>
        /// Many threads ask for the current master key while it expires over and over.
        /// Every one of them gets a key, and none an exception.
        /// </summary>
        [Test]
        public void MasterKey_IsReadWhileItRotates()
        {

            var ntsServer = new NTSServer(
                                MasterKeysFilePath:            null,
                                MasterKeyLifetime:             TimeSpan.FromMilliseconds(1),
                                MasterKeyRotationGracePeriod:  TimeSpan.FromMilliseconds(20)
                            );

            var failures  = new System.Collections.Concurrent.ConcurrentQueue<Exception>();
            var keyIds    = new System.Collections.Concurrent.ConcurrentDictionary<UInt64, Boolean>();
            var until     = DateTime.UtcNow.AddMilliseconds(750);

            Parallel.For(0, 8, _ => {

                while (DateTime.UtcNow < until)
                {
                    try
                    {
                        keyIds.TryAdd(ntsServer.CurrentMasterKeyId, true);
                    }
                    catch (Exception e)
                    {
                        failures.Enqueue(e);
                    }
                }

            });

            Assert.That(failures,                                                                           Is.Empty, failures.FirstOrDefault()?.ToString());
            Assert.That(keyIds.Count,                                                                       Is.GreaterThan(10), "The key was meant to rotate many times during the test.");
            Assert.That(keyIds.Keys,                                                                        Has.None.EqualTo(0UL));

        }

        #endregion


        #region NTSKE_OnlyTLS13IsNegotiated()

        /// <summary>
        /// RFC 8915 § 3: "Implementations MUST NOT negotiate TLS versions earlier than 1.3."
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task NTSKE_OnlyTLS13IsNegotiated()
        {

            await using var server = await RunningServer.Start();

            Exception? refused = null;

            try
            {
                using var tls12 = await server.Connect(SslProtocols.Tls12);
            }
            catch (Exception e)
            {
                refused = e;
            }

            Assert.That(refused,                                                                            Is.InstanceOf<AuthenticationException>().Or.InstanceOf<IOException>(),
                                                                                                            "A TLS 1.2 handshake must not succeed.");

            using var tls13 = await server.Connect(SslProtocols.Tls13);

            Assert.That(tls13.SslProtocol,                                                                  Is.EqualTo(SslProtocols.Tls13));
            Assert.That(tls13.NegotiatedApplicationProtocol,                                                Is.EqualTo(new SslApplicationProtocol("ntske/1")));

        }

        #endregion

        #region NTSKE_ARequestWithoutAEADRecordIsABadRequest()

        /// <summary>
        /// RFC 8915 § 4.1.5: a request offering NTPv4 carries exactly one
        /// AEAD Algorithm Negotiation record.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task NTSKE_ARequestWithoutAEADRecordIsABadRequest()
        {

            await using var server = await RunningServer.Start();

            using var tls = await server.Connect(SslProtocols.Tls13);

            // NTS Next Protocol Negotiation (critical): NTPv4. End of Message (critical).
            await tls.WriteAsync(new Byte[] { 0x80, 0x01, 0x00, 0x02, 0x00, 0x00,
                                              0x80, 0x00, 0x00, 0x00 });
            await tls.FlushAsync();

            var response = new Byte[64];
            var length   = await tls.ReadAtLeastAsync(response, 10, throwOnEndOfStream: false);

            // Error (critical), 2 octets, code 1 = Bad Request. End of Message (critical).
            Assert.That(response[..length],                                                                 Is.EqualTo(new Byte[] { 0x80, 0x02, 0x00, 0x02, 0x00, 0x01,
                                                                                                                                      0x80, 0x00, 0x00, 0x00 }));

        }

        #endregion

        #region NTSKE_ARequestThatContradictsItselfIsABadRequest(Request)

        /// <summary>
        /// RFC 8915 § 4.1.1 to 4.1.6: End of Message and Next Protocol Negotiation are
        /// critical, End of Message is empty, and Error, Warning and New Cookie records
        /// are the server's to send. Each of these requests is complete and would be
        /// served, were it not for the one thing wrong with it.
        /// </summary>
        [TestCase(new Byte[] { 0x00, 0x01, 0x00, 0x02, 0x00, 0x00,                 // Next Protocol, not critical
                               0x80, 0x04, 0x00, 0x02, 0x00, 0x0f,
                               0x80, 0x00, 0x00, 0x00 },                           TestName = "NTSKE_ANextProtocolRecordWithoutCriticalBitIsABadRequest")]
        [TestCase(new Byte[] { 0x80, 0x01, 0x00, 0x02, 0x00, 0x00,
                               0x80, 0x04, 0x00, 0x02, 0x00, 0x0f,
                               0x00, 0x00, 0x00, 0x00 },                           TestName = "NTSKE_AnEndOfMessageWithoutCriticalBitIsABadRequest")]
        [TestCase(new Byte[] { 0x80, 0x01, 0x00, 0x02, 0x00, 0x00,
                               0x80, 0x04, 0x00, 0x02, 0x00, 0x0f,
                               0x80, 0x00, 0x00, 0x01, 0x00 },                     TestName = "NTSKE_AnEndOfMessageWithABodyIsABadRequest")]
        [TestCase(new Byte[] { 0x80, 0x01, 0x00, 0x02, 0x00, 0x00,
                               0x80, 0x04, 0x00, 0x02, 0x00, 0x0f,
                               0x80, 0x02, 0x00, 0x02, 0x00, 0x01,                 // Error: Bad Request
                               0x80, 0x00, 0x00, 0x00 },                           TestName = "NTSKE_ARequestWithAnErrorRecordIsABadRequest")]
        [TestCase(new Byte[] { 0x80, 0x01, 0x00, 0x02, 0x00, 0x00,
                               0x80, 0x04, 0x00, 0x02, 0x00, 0x0f,
                               0x80, 0x03, 0x00, 0x02, 0x00, 0x00,                 // Warning
                               0x80, 0x00, 0x00, 0x00 },                           TestName = "NTSKE_ARequestWithAWarningRecordIsABadRequest")]
        [TestCase(new Byte[] { 0x80, 0x01, 0x00, 0x02, 0x00, 0x00,
                               0x80, 0x04, 0x00, 0x02, 0x00, 0x0f,
                               0x00, 0x05, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,     // New Cookie for NTPv4
                               0x80, 0x00, 0x00, 0x00 },                           TestName = "NTSKE_ARequestWithACookieRecordIsABadRequest")]
        [Category("LocalIntegration")]
        public async Task NTSKE_ARequestThatContradictsItselfIsABadRequest(Byte[] Request)
        {

            await using var server = await RunningServer.Start();

            using var tls = await server.Connect(SslProtocols.Tls13);

            await tls.WriteAsync(Request);
            await tls.FlushAsync();

            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            var response = new Byte[4096];
            var length   = await tls.ReadAtLeastAsync(response, 10, throwOnEndOfStream: false, timeout.Token);

            // Error (critical), 2 octets, code 1 = Bad Request. End of Message (critical).
            Assert.That(response[..length],                                                                 Is.EqualTo(new Byte[] { 0x80, 0x02, 0x00, 0x02, 0x00, 0x01,
                                                                                                                                      0x80, 0x00, 0x00, 0x00 }));

            Assert.That(server.Server.Metrics.NTSKERequestsInvalid,                                         Is.EqualTo(1));

        }

        #endregion

        #region NTSKE_AnAEADRecordWithoutCriticalBitIsServed()

        /// <summary>
        /// The other side of it: § 4.1.5 leaves the critical bit of the
        /// AEAD Algorithm Negotiation record to the sender ("MAY be set").
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task NTSKE_AnAEADRecordWithoutCriticalBitIsServed()
        {

            await using var server = await RunningServer.Start();

            using var tls = await server.Connect(SslProtocols.Tls13);

            await tls.WriteAsync(new Byte[] { 0x80, 0x01, 0x00, 0x02, 0x00, 0x00,
                                              0x00, 0x04, 0x00, 0x02, 0x00, 0x0f,     // AEAD, not critical
                                              0x80, 0x00, 0x00, 0x00 });
            await tls.FlushAsync();

            var response = new Byte[4096];
            var length   = await tls.ReadAtLeastAsync(response, 6, throwOnEndOfStream: false);

            Assert.That(length,                                                                             Is.GreaterThan(100), "Cookies were expected.");
            Assert.That(response[..6],                                                                      Is.EqualTo(new Byte[] { 0x80, 0x01, 0x00, 0x02, 0x00, 0x00 }));

        }

        #endregion

        #region NTSKE_OneClientCannotTakeEverySlot()

        /// <summary>
        /// A client that opens connection after connection and then says nothing
        /// is cut off at its own limit, long before the server runs out of slots.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task NTSKE_OneClientCannotTakeEverySlot()
        {

            await using var server = await RunningServer.Start(MaxNTSKEConnectionsPerClient: 2);

            var silent = new List<TcpClient>();

            try
            {

                for (var i = 0; i < 6; i++)
                {
                    var tcpClient = new TcpClient();
                    await tcpClient.ConnectAsync(System.Net.IPAddress.Loopback, server.NTSKEPort);
                    silent.Add(tcpClient);
                }

                // The server closes the connections beyond the limit at once,
                // and waits for a handshake on the two within it.
                var closed = 0;

                foreach (var tcpClient in silent)
                {

                    using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(750));

                    try
                    {
                        if (await tcpClient.GetStream().ReadAsync(new Byte[1], timeout.Token) == 0)
                            closed++;
                    }
                    catch (OperationCanceledException)
                    { }
                    catch (IOException)
                    {
                        closed++;
                    }

                }

                Assert.That(closed,                                                                         Is.EqualTo(4));
                Assert.That(server.Server.Metrics.NTSKEConnectionsRejected,                                 Is.EqualTo(4));

            }
            finally
            {
                foreach (var tcpClient in silent)
                    tcpClient.Dispose();
            }

            // Once they are gone, the client is welcome again.
            await Task.Delay(200);

            using var tls = await server.Connect(SslProtocols.Tls13);

            Assert.That(tls.SslProtocol,                                                                    Is.EqualTo(SslProtocols.Tls13));

        }

        #endregion


        #region NTSKE_AClientStallingMidRequestIsAnsweredAndLetGo()

        /// <summary>
        /// A client that completes the handshake, sends half a request and stops. The
        /// server gives it its request timeout, tells it so, and the next client is
        /// served as if nothing had been.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task NTSKE_AClientStallingMidRequestIsAnsweredAndLetGo()
        {

            await using var server = await RunningServer.Start(NTSKERequestTimeout: TimeSpan.FromSeconds(1));

            var stalled = new List<SslStream>();

            try
            {

                for (var i = 0; i < 4; i++)
                {

                    var tls = await server.Connect(SslProtocols.Tls13);

                    // The record header of a Next Protocol Negotiation, and not its body.
                    await tls.WriteAsync(new Byte[] { 0x80, 0x01, 0x00, 0x02 });
                    await tls.FlushAsync();

                    stalled.Add(tls);

                }

                // Somebody else, meanwhile, with a whole request.
                using (var tls = await server.Connect(SslProtocols.Tls13))
                {

                    await tls.WriteAsync(new Byte[] { 0x80, 0x01, 0x00, 0x02, 0x00, 0x00,     // Next Protocol: NTPv4
                                                      0x80, 0x04, 0x00, 0x02, 0x00, 0x0f,     // AEAD: AES-SIV-CMAC-256
                                                      0x80, 0x00, 0x00, 0x00 });              // End of Message
                    await tls.FlushAsync();

                    var response = new Byte[4096];
                    var length   = await tls.ReadAtLeastAsync(response, 6, throwOnEndOfStream: false);

                    Assert.That(length,                                                                     Is.GreaterThan(100), "Cookies were expected.");
                    Assert.That(response[..6],                                                              Is.EqualTo(new Byte[] { 0x80, 0x01, 0x00, 0x02, 0x00, 0x00 }));

                }

                // The stalled ones are told that their request was no request.
                foreach (var tls in stalled)
                {

                    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));

                    var response = new Byte[64];
                    var length   = await tls.ReadAtLeastAsync(response, 10, throwOnEndOfStream: false, timeout.Token);

                    Assert.That(response[..length],                                                         Is.EqualTo(new Byte[] { 0x80, 0x02, 0x00, 0x02, 0x00, 0x01,
                                                                                                                                      0x80, 0x00, 0x00, 0x00 }));

                }

            }
            finally
            {
                foreach (var tls in stalled)
                    tls.Dispose();
            }

        }

        #endregion


        #region (private) RunningServer

        private sealed class RunningServer : IAsyncDisposable
        {

            public NTSServer  Server      { get; }
            public Int32      NTSKEPort   { get; }

            private RunningServer(NTSServer Server, Int32 NTSKEPort)
            {
                this.Server     = Server;
                this.NTSKEPort  = NTSKEPort;
            }

            public static async Task<RunningServer> Start(Int32?     MaxNTSKEConnectionsPerClient   = null,
                                                          TimeSpan?  NTSKERequestTimeout            = null)
            {

                var ntsKEPort = FindFreePort(SocketType.Stream, ProtocolType.Tcp);

                var server    = new NTSServer(
                                    NTSKEPort:                     IPPort.Parse(ntsKEPort),
                                    NTSPort:                       IPPort.Parse(FindFreePort(SocketType.Dgram, ProtocolType.Udp)),
                                    MasterKeysFilePath:            null,
                                    MaxNTSKEConnectionsPerClient:  MaxNTSKEConnectionsPerClient,
                                    NTSKERequestTimeout:           NTSKERequestTimeout
                                );

                await server.Start();

                return new RunningServer(server, ntsKEPort);

            }

            public async Task<SslStream> Connect(SslProtocols Protocol)
            {

                var tcpClient = new TcpClient();

                await tcpClient.ConnectAsync(System.Net.IPAddress.Loopback, NTSKEPort);

                var tls       = new SslStream(tcpClient.GetStream(), false, (_, _, _, _) => true);

                try
                {

                    await tls.AuthenticateAsClientAsync(
                              new SslClientAuthenticationOptions {
                                  TargetHost            = "localhost",
                                  EnabledSslProtocols   = Protocol,
                                  ApplicationProtocols  = [ new SslApplicationProtocol("ntske/1") ]
                              }
                          );

                    return tls;

                }
                catch
                {
                    tls.Dispose();
                    throw;
                }

            }

            public async ValueTask DisposeAsync()
            {
                await Server.ShutdownAsync();
            }

            private static Int32 FindFreePort(SocketType SocketType, ProtocolType ProtocolType)
            {

                using var socket = new Socket(AddressFamily.InterNetwork, SocketType, ProtocolType);

                socket.Bind(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

                return ((IPEndPoint) socket.LocalEndPoint!).Port;

            }

        }

        #endregion

    }

}
