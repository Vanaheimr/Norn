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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTPv5
{

    /// <summary>
    /// The interleaved mode, the reference IDs and the monotonic timestamps of NTPv5 on the
    /// wire of a running <see cref="NTSServer"/>.
    /// </summary>
    [TestFixture]
    [Category("LocalIntegration")]
    public class NTSServer_NTPv5Phase3_Tests
    {

        #region Data

        private NTSServer?  server;
        private NTSServer?  withoutInterleaving;

        #endregion

        #region Start/stop the servers

        [OneTimeSetUp]
        public async Task StartServers()
        {

            server               = await FreePorts.Start(() => new NTSServer(NTSPort:             FreePorts.UDP(),
                                                                             MasterKeysFilePath:  null,
                                                                             NTSKEOverTLS:        false,
                                                                             NTPv5:               NTPv5Support.Draft));

            withoutInterleaving  = await FreePorts.Start(() => new NTSServer(NTSPort:             FreePorts.UDP(),
                                                                             MasterKeysFilePath:  null,
                                                                             NTSKEOverTLS:        false,
                                                                             InterleavedMode:     InterleavedModePolicy.Disabled,
                                                                             NTPv5:               NTPv5Support.Draft));

        }

        [OneTimeTearDown]
        public async Task StopServers()
        {

            foreach (var running in new[] { server, withoutInterleaving })
                if (running is not null)
                    await running.ShutdownAsync();

        }

        #endregion


        #region TheInterleavedMode_GoesRoundTrip()

        /// <summary>
        /// § 8: the first response gives a cookie and is basic, the second - asked with that
        /// cookie - is interleaved and reports when the first actually left, which is no
        /// earlier than the transmit timestamp the first response could carry itself.
        /// </summary>
        [Test]
        public async Task TheInterleavedMode_GoesRoundTrip()
        {

            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            var first  = await AskAsync(udpClient, server!.UDPPort, NTPv5Packet.Request(Flags: NTPv5Flags.InterleavedMode));

            Assert.That(first,                Is.Not.Null);
            Assert.That(first!.Flags,         Is.EqualTo(NTPv5Flags.None), "nothing to interleave with yet");
            Assert.That(first.ServerCookie,   Is.Not.Zero,                 "but a cookie for the next request");

            var second = await AskAsync(udpClient, server.UDPPort, NTPv5Packet.Request(Flags:         NTPv5Flags.InterleavedMode,
                                                                                       ServerCookie:  first.ServerCookie));

            Assert.That(second,                      Is.Not.Null);
            Assert.That(second!.Flags,               Is.EqualTo(NTPv5Flags.InterleavedMode));
            Assert.That(second.TransmitTimestamp,    Is.GreaterThanOrEqualTo(first.TransmitTimestamp), "when the first response left, read after it did");
            Assert.That(second.TransmitTimestamp,    Is.LessThanOrEqualTo   (second.ReceiveTimestamp), "and before the second request came in");
            Assert.That(second.ServerCookie,         Is.Not.Zero.And.Not.EqualTo(first.ServerCookie));

        }

        #endregion

        #region AServerWithoutTheMode_GivesNoCookie_AndSaysSo()

        [Test]
        public async Task AServerWithoutTheMode_GivesNoCookie_AndSaysSo()
        {

            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            var response = await AskAsync(udpClient, withoutInterleaving!.UDPPort,
                                          NTPv5Packet.Request(Flags:            NTPv5Flags.InterleavedMode,
                                                              ExtensionFields:  [ NTPv5ExtensionField.ServerInformation() ]));

            Assert.That(response,                Is.Not.Null);
            Assert.That(response!.ServerCookie,  Is.Zero);
            Assert.That(response.Flags,          Is.EqualTo(NTPv5Flags.None));
            Assert.That(response.Find(NTPv5ExtensionTypes.ServerInformation)!.TryReadServerInformation(out _, out var flags), Is.True);
            Assert.That(flags,                   Is.EqualTo(NTPv5Flags.Unsynchronized));

            var served = await AskAsync(udpClient, server!.UDPPort,
                                        NTPv5Packet.Request(ExtensionFields: [ NTPv5ExtensionField.ServerInformation() ]));

            Assert.That(served!.Find(NTPv5ExtensionTypes.ServerInformation)!.TryReadServerInformation(out _, out var servedFlags), Is.True);
            Assert.That(servedFlags,             Is.EqualTo(NTPv5Flags.Unsynchronized | NTPv5Flags.InterleavedMode));

        }

        #endregion

        #region TheReferenceIDs_AreTheServersOwn_AndItsSources()

        /// <summary>
        /// § 7.4: the server first, by the ID it says it has; after a Redescribe with sources,
        /// theirs too.
        /// </summary>
        [Test]
        public async Task TheReferenceIDs_AreTheServersOwn_AndItsSources()
        {

            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            var alone = await AskAsync(udpClient, withoutInterleaving!.UDPPort,
                                       NTPv5Packet.Request(ExtensionFields: [ NTPv5ReferenceIds.Request() ]));

            Assert.That(NTPv5ReferenceIds.TryRead(alone!.Find(NTPv5ExtensionTypes.ReferenceIDsResponse)!.Value, out var aloneEntries), Is.True);
            Assert.That(aloneEntries[0],        Is.EqualTo(new NTPv5ReferenceIdEntry(0, withoutInterleaving.NTPv5ReferenceId)));
            Assert.That(aloneEntries.Skip(1),   Is.All.EqualTo(NTPv5ReferenceIdEntry.Unused));

            const UInt64 upstream = 0x00_ABCD_EF01_2345_67UL;

            withoutInterleaving.Redescribe(Stratum:       2,
                                           NTPv5Sources:  [ new NTPv5ReferenceIdSource(1, [ new (0, upstream) ]) ]);

            try
            {

                var relayed = await AskAsync(udpClient, withoutInterleaving.UDPPort,
                                             NTPv5Packet.Request(ExtensionFields: [ NTPv5ReferenceIds.Request(Entries: 2) ]));

                Assert.That(NTPv5ReferenceIds.TryRead(relayed!.Find(NTPv5ExtensionTypes.ReferenceIDsResponse)!.Value, out var relayedEntries), Is.True);
                Assert.That(relayedEntries, Is.EqualTo(new[] { new NTPv5ReferenceIdEntry(0,  withoutInterleaving.NTPv5ReferenceId),
                                                               new NTPv5ReferenceIdEntry(16, upstream) }),
                            "the one source at half the server's share");

            }
            finally
            {
                withoutInterleaving.Redescribe();
            }

        }

        #endregion

        #region TheMonotonicClock_RunsOnInOneEpoch()

        [Test]
        public async Task TheMonotonicClock_RunsOnInOneEpoch()
        {

            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            var request = NTPv5Packet.Request(ExtensionFields: [ NTPv5ExtensionField.MonotonicReceiveTimestamp() ]);

            var first   = await AskAsync(udpClient, server!.UDPPort, request);
            await Task.Delay(20);
            var second  = await AskAsync(udpClient, server.UDPPort, request);

            Assert.That(first!. Find(NTPv5ExtensionTypes.MonotonicReceiveTimestamp)!.TryReadMonotonicReceiveTimestamp(out var firstEpoch,  out var firstReading),  Is.True);
            Assert.That(second!.Find(NTPv5ExtensionTypes.MonotonicReceiveTimestamp)!.TryReadMonotonicReceiveTimestamp(out var secondEpoch, out var secondReading), Is.True);

            Assert.Multiple(() => {
                Assert.That(firstEpoch,     Is.EqualTo(server.NTPv5MonotonicEpochId));
                Assert.That(secondEpoch,    Is.EqualTo(firstEpoch));
                Assert.That(secondReading,  Is.GreaterThan(firstReading + (UInt64) (0.015 * 0x1_0000_0000L)), "20 ms on, at least 15");
            });

        }

        #endregion


        #region (private static) AskAsync(UdpClient, NTPPort, Request)

        /// <summary>
        /// The request from the given client, and the answer, or null when none came within two seconds.
        /// </summary>
        private static async Task<NTPv5Packet?> AskAsync(UdpClient    UdpClient,
                                                         IPPort       NTPPort,
                                                         NTPv5Packet  Request)
        {

            await UdpClient.SendAsync(Request.ToByteArray(), new IPEndPoint(System.Net.IPAddress.Loopback, NTPPort.ToUInt16()));

            try
            {

                var answer = (await UdpClient.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(2))).Buffer;

                Assert.That(NTPv5Packet.TryParse(answer, out var response, out var error), Is.True, error);
                Assert.That(response!.ClientCookie, Is.EqualTo(Request.ClientCookie));
                Assert.That(answer.Length,          Is.EqualTo(Request.Length));

                return response;

            }
            catch (TimeoutException)
            {
                return null;
            }

        }

        #endregion

    }

}
