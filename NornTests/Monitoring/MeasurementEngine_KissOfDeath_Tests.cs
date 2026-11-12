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
using System.Net.Sockets;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.Monitoring
{

    /// <summary>
    /// What the measurement engine makes of a Kiss-o'-Death, and of a delay that cannot
    /// be: the same rules NTPServerAccessState is tested for on its own, here on the way
    /// through a round against a server.
    /// </summary>
    [TestFixture]
    [Category("LocalIntegration")]
    public class MeasurementEngine_KissOfDeath_Tests
    {

        #region Data

        private static readonly DomainName loopback = DomainName.Parse("127.0.0.1");

        /// <summary>
        /// More than a round of the engine sends, so that a round after Clear() is answered.
        /// </summary>
        private const Int32 Burst = 32;

        #endregion


        #region ARATEKissSlowsTheEngineDownUntilItIsEarnedBack()

        /// <summary>
        /// The server limits this client, and says so. The engine polls it one step
        /// slower, skips the rounds that come too soon, and is back at its own rate
        /// once the server answers again.
        /// </summary>
        [Test]
        public async Task ARATEKissSlowsTheEngineDownUntilItIsEarnedBack()
        {

            var rateLimiter = new NTPRateLimiter(
                                  MinimumInterval:  TimeSpan.FromHours(1),
                                  Burst:            Burst,
                                  KissInterval:     TimeSpan.Zero,
                                  Leak:             0
                              );

            var (ntsServer, endpoint) = await StartServer(RateLimiter: rateLimiter);

            try
            {

                var clock   = new ShiftedClock();
                var engine  = Engine(clock);
                var access  = engine.AccessStateFor(endpoint.Hostname);

                // 64 seconds: the engine's measurement interval of a minute, as a poll exponent.
                Assert.That(access.PollExponent,                         Is.EqualTo(6));

                var answered  = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

                Assert.That(answered.Success,                            Is.True, answered.ErrorMessage?.ToString());
                Assert.That(access.IsRateLimited,                        Is.False);

                // The budget of this client's address is spent: the next request is one too many.
                rateLimiter.Clear();
                Drain(rateLimiter);

                var kissed    = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

                Assert.That(kissed.Success,                              Is.False);
                Assert.That(kissed.NTP?.KissOfDeath,                     Is.True, kissed.ErrorMessage?.ToString());
                Assert.That(kissed.NTP?.KissOfDeathCode,                 Is.EqualTo("RATE"));
                Assert.That(access.PollExponent,                         Is.EqualTo(7), "one step slower, whatever poll value the kiss named");
                Assert.That(access.Demobilized,                          Is.False);

                // Too soon: no packet is sent.
                var received  = ntsServer.Metrics.NTPRequestsReceived;
                var skipped   = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

                Assert.That(skipped.Skipped,                             Is.True);
                Assert.That(skipped.ErrorCategory,                       Is.EqualTo(MonitoringErrorCategory.KissOfDeath));
                Assert.That(ntsServer.Metrics.NTPRequestsReceived,       Is.EqualTo(received));

                // 128 seconds on, the server has room for this client again.
                clock.Shift = TimeSpan.FromSeconds(130);
                rateLimiter.Clear();

                var again     = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

                Assert.That(again.Success,                               Is.True, again.ErrorMessage?.ToString());
                Assert.That(again.Skipped,                               Is.False);
                Assert.That(access.PollExponent,                         Is.EqualTo(6), "an answer takes one step back");
                Assert.That(access.IsRateLimited,                        Is.False);

            }
            finally
            {
                await ntsServer.ShutdownAsync();
            }

        }

        #endregion

        #region AForgedDENYCostsOnePauseAndNotTheServer()

        /// <summary>
        /// Somebody on the path answers the request with "DENY", and the server's own
        /// answer never arrives. The association is an NTS one and the kiss is not
        /// authenticated: the engine pauses, and comes back.
        /// </summary>
        [Test]
        public async Task AForgedDENYCostsOnePauseAndNotTheServer()
        {

            var (ntsServer, endpoint) = await StartServer();

            using var forger = new KissForger("DENY");

            // The key exchange with the real server, the NTP requests to the forger.
            var forged = new NTSServerEndpoint(
                             loopback,
                             endpoint.NTSKEPort,
                             IPPort.Parse(forger.Port),
                             RemoteCertificateValidator: (sender, certificate, chain, client, errors) => TLSValidationResult.Success()
                         );

            try
            {

                var clock   = new ShiftedClock();
                var engine  = Engine(clock);
                var access  = engine.AccessStateFor(forged.Hostname);

                var kissed  = await engine.MeasureSingleServer(forged, Guid.NewGuid(), NoNameServers());

                Assert.That(forger.KissesSent,                           Is.GreaterThan(0));
                Assert.That(kissed.Success,                              Is.False);
                Assert.That(kissed.NTP?.KissOfDeath,                     Is.True, kissed.ErrorMessage?.ToString());
                Assert.That(kissed.NTP?.KissOfDeathCode,                 Is.EqualTo("DENY"));

                Assert.That(access.Demobilized,                          Is.False, "an unauthenticated DENY must not end an NTS association");
                Assert.That(access.NextQueryNotBefore,                   Is.Not.Null);
                Assert.That(access.NextQueryNotBefore!.Value - clock.GetUtcNow(),
                                                                         Is.EqualTo(TimeSpan.FromSeconds(8192)).Within(TimeSpan.FromSeconds(30)));
                Assert.That(access.PollExponent,                         Is.EqualTo(6), "the polling rate is as it was");

                // Within the pause nothing is sent ...
                var sent    = forger.KissesSent;
                var skipped = await engine.MeasureSingleServer(forged, Guid.NewGuid(), NoNameServers());

                Assert.That(skipped.Skipped,                             Is.True);
                Assert.That(skipped.ErrorMessage?.ToString(),            Does.Contain("without NTS authentication"));
                Assert.That(forger.KissesSent,                           Is.EqualTo(sent));

                // ... and after it the server is asked again.
                clock.Shift = TimeSpan.FromSeconds(8200);

                var again   = await engine.MeasureSingleServer(forged, Guid.NewGuid(), NoNameServers());

                Assert.That(again.Skipped,                               Is.False);
                Assert.That(forger.KissesSent,                           Is.GreaterThan(sent));

            }
            finally
            {
                await ntsServer.ShutdownAsync();
            }

        }

        #endregion

        #region ADelayThatCannotBeIsNotKept()

        /// <summary>
        /// A server whose clock runs away between receiving a request and answering it
        /// reports having held the request for longer than the whole exchange took.
        /// RFC 5905 § 8 does not let a negative delay through, and neither does the engine.
        /// </summary>
        [Test]
        public async Task ADelayThatCannotBeIsNotKept()
        {

            var (ntsServer, endpoint) = await StartServer(TimeProvider: new RunawayClock());

            try
            {

                var engine  = Engine(new ShiftedClock());

                for (var round = 0; round < 3; round++)
                {

                    var result = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), NoNameServers());

                    Assert.That(result.Success,                          Is.True, result.ErrorMessage?.ToString());
                    Assert.That(result.NTP,                              Is.Not.Null);
                    Assert.That(result.NTP!.RoundTripDelay,              Is.EqualTo(TimeSpan.Zero));

                }

            }
            finally
            {
                await ntsServer.ShutdownAsync();
            }

        }

        #endregion


        #region (private) Helpers

        private static MeasurementEngine Engine(TimeProvider Clock)

            => new (new MonitoringConfig {
                        DroneId       = "kiss-tests",
                        NTPTimeout    = TimeSpan.FromSeconds(1),
                        NTSKETimeout  = TimeSpan.FromSeconds(10)
                    },
                    Clock);

        private static async Task<(NTSServer, NTSServerEndpoint)> StartServer(NTPRateLimiter?  RateLimiter    = null,
                                                                              TimeProvider?    TimeProvider   = null)
        {

            var ntsKEPort = IPPort.Parse(FindFreePort(SocketType.Stream, ProtocolType.Tcp));
            var ntpPort   = IPPort.Parse(FindFreePort(SocketType.Dgram,  ProtocolType.Udp));

            var ntsServer = new NTSServer(
                                NTSKEPort:           ntsKEPort,
                                NTSPort:             ntpPort,
                                MasterKeysFilePath:  null,
                                RateLimiter:         RateLimiter,
                                TimeProvider:        TimeProvider,

                                // Stated, where the clock is not the machine's: measured on a
                                // clock that jumps, the resolution would come out as its jumps,
                                // and a root dispersion of ten seconds is refused by the client.
                                ClockResolution:     TimeProvider is not null ? TimeSpan.FromMilliseconds(1) : null,
                                RootDispersion:      TimeProvider is not null ? TimeSpan.FromMilliseconds(2) : null
                            );

            await ntsServer.Start();

            return (ntsServer,
                    new NTSServerEndpoint(
                        loopback,
                        ntsKEPort,
                        ntpPort,
                        RemoteCertificateValidator: (sender, certificate, chain, client, errors) => TLSValidationResult.Success()
                    ));

        }

        /// <summary>
        /// Spend the whole budget of this machine's own address, and not one request more:
        /// a request over the limit would draw the kiss meant for the engine.
        /// </summary>
        private static void Drain(NTPRateLimiter RateLimiter)
        {
            for (var i = 0; i < Burst; i++)
                Assert.That(RateLimiter.Check(System.Net.IPAddress.Loopback), Is.EqualTo(org.GraphDefined.Vanaheimr.Norn.NTS.RateLimitDecision.Answer));
        }

        private static DNSClient NoNameServers()

            => new (SearchForIPv4DNSServers: false,
                    SearchForIPv6DNSServers: false);

        private static Int32 FindFreePort(SocketType SocketType, ProtocolType ProtocolType)
        {

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType, ProtocolType);

            socket.Bind(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            return ((IPEndPoint) socket.LocalEndPoint!).Port;

        }

        /// <summary>
        /// The machine's clock, moved on by whatever a test says.
        /// </summary>
        private sealed class ShiftedClock : TimeProvider
        {
            public TimeSpan Shift { get; set; }
            public override DateTimeOffset GetUtcNow() => base.GetUtcNow() + Shift;
        }

        /// <summary>
        /// A clock that is ten seconds further on every time it is read.
        /// </summary>
        private sealed class RunawayClock : TimeProvider
        {

            private Int64 readings;

            public override DateTimeOffset GetUtcNow()
                => base.GetUtcNow() + TimeSpan.FromSeconds(10 * Interlocked.Increment(ref readings));

        }

        /// <summary>
        /// Stands in for the NTP server, and answers every request with a kiss that
        /// anyone who saw the request could have written: no NTS, the right origin.
        /// </summary>
        private sealed class KissForger : IDisposable
        {

            private readonly UdpClient                socket   = new (new IPEndPoint(System.Net.IPAddress.Loopback, 0));
            private readonly CancellationTokenSource  cts      = new ();

            private          Int32                    kissesSent;

            public Int32 Port
                => ((IPEndPoint) socket.Client.LocalEndPoint!).Port;

            public Int32 KissesSent
                => Volatile.Read(ref kissesSent);

            public KissForger(String Code)
            {

                _ = Task.Run(async () => {

                    try
                    {
                        while (!cts.IsCancellationRequested)
                        {

                            var request = await socket.ReceiveAsync(cts.Token);
                            var kiss    = new Byte[48];

                            kiss[0]     = (4 << 3) | 4;     // version 4, mode 4, stratum 0

                            Encoding.ASCII.GetBytes(Code).CopyTo(kiss, 12);

                            // The request's transmit timestamp as the origin.
                            Buffer.BlockCopy(request.Buffer, 40, kiss, 24, 8);

                            await socket.SendAsync(kiss, kiss.Length, request.RemoteEndPoint);

                            Interlocked.Increment(ref kissesSent);

                        }
                    }
                    catch (OperationCanceledException)
                    { }
                    catch (ObjectDisposedException)
                    { }

                });

            }

            public void Dispose()
            {
                cts.Cancel();
                socket.Dispose();
                cts.Dispose();
            }

        }

        #endregion

    }

}
