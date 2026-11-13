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

using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

using IPAddress = System.Net.IPAddress;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Timings
{

    /// <summary>
    /// What a UDP socket per query costs, step by step.
    /// </summary>
    public static class Sockets
    {

        private static readonly Double TicksToMicroseconds = 1_000_000.0 / Stopwatch.Frequency;

        public static async Task<Int32> Run()
        {

            const Int32 rounds = 20000;

            // Somewhere to send to: a bound socket that a thread keeps empty.
            var sink = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            sink.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            var remote = (IPEndPoint) sink.LocalEndPoint!;

            new Thread(() => {
                var buffer = new Byte[4096];
                while (true)
                {
                    try { sink.Receive(buffer); } catch (SocketException) { }
                }
            }) { IsBackground = true }.Start();

            var payload = new Byte[224];

            Console.WriteLine($"## A UDP socket per query, step by step: {rounds} rounds each, 224 bytes to a bound loopback socket");
            Console.WriteLine();

            async Task Steps(String Title, String[] Names, Func<Int64[], Task> Round)
            {

                var stamps = new Int64[Names.Length + 1];

                for (var i = 0; i < 3000; i++)
                    await Round(stamps);

                var times  = new Double[Names.Length + 1][];
                for (var k = 0; k <= Names.Length; k++)
                    times[k] = new Double[rounds];

                var before = Snapshot.Take();

                for (var i = 0; i < rounds; i++)
                {
                    await Round(stamps);
                    for (var k = 0; k < Names.Length; k++)
                        times[k][i] = (stamps[k + 1] - stamps[k]) * TicksToMicroseconds;
                    times[Names.Length][i] = (stamps[Names.Length] - stamps[0]) * TicksToMicroseconds;
                }

                var delta = Snapshot.Take().Since(before);

                Program.Header(Title, false);
                for (var k = 0; k < Names.Length; k++)
                    Program.Line("  " + Names[k], times[k]);
                Program.Line("  total", times[Names.Length]);
                Console.WriteLine($"  {delta.PerQuery(rounds)}");
                Console.WriteLine();

            }

            await Steps("Socket, explicit Bind(0.0.0.0:0), blocking SendTo",
                        [ "new Socket", "Bind(0.0.0.0:0)", "1st SendTo", "2nd SendTo", "Dispose" ],
                        stamps => {
                            stamps[0] = Stopwatch.GetTimestamp();
                            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                            stamps[1] = Stopwatch.GetTimestamp();
                            socket.Bind(new IPEndPoint(IPAddress.Any, 0));
                            stamps[2] = Stopwatch.GetTimestamp();
                            socket.SendTo(payload, remote);
                            stamps[3] = Stopwatch.GetTimestamp();
                            socket.SendTo(payload, remote);
                            stamps[4] = Stopwatch.GetTimestamp();
                            socket.Dispose();
                            stamps[5] = Stopwatch.GetTimestamp();
                            return Task.CompletedTask;
                        });

            await Steps("Socket, explicit Bind(127.0.0.1:0), blocking SendTo",
                        [ "new Socket", "Bind(127.0.0.1:0)", "1st SendTo", "2nd SendTo", "Dispose" ],
                        stamps => {
                            stamps[0] = Stopwatch.GetTimestamp();
                            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                            stamps[1] = Stopwatch.GetTimestamp();
                            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                            stamps[2] = Stopwatch.GetTimestamp();
                            socket.SendTo(payload, remote);
                            stamps[3] = Stopwatch.GetTimestamp();
                            socket.SendTo(payload, remote);
                            stamps[4] = Stopwatch.GetTimestamp();
                            socket.Dispose();
                            stamps[5] = Stopwatch.GetTimestamp();
                            return Task.CompletedTask;
                        });

            await Steps("Socket, no Bind (the first SendTo binds), blocking SendTo",
                        [ "new Socket", "1st SendTo (binds)", "2nd SendTo", "Dispose" ],
                        stamps => {
                            stamps[0] = Stopwatch.GetTimestamp();
                            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                            stamps[1] = Stopwatch.GetTimestamp();
                            socket.SendTo(payload, remote);
                            stamps[2] = Stopwatch.GetTimestamp();
                            socket.SendTo(payload, remote);
                            stamps[3] = Stopwatch.GetTimestamp();
                            socket.Dispose();
                            stamps[4] = Stopwatch.GetTimestamp();
                            return Task.CompletedTask;
                        });

            await Steps("Socket, Connect(remote), blocking Send",
                        [ "new Socket", "Connect", "1st Send", "2nd Send", "Dispose" ],
                        stamps => {
                            stamps[0] = Stopwatch.GetTimestamp();
                            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                            stamps[1] = Stopwatch.GetTimestamp();
                            socket.Connect(remote);
                            stamps[2] = Stopwatch.GetTimestamp();
                            socket.Send(payload);
                            stamps[3] = Stopwatch.GetTimestamp();
                            socket.Send(payload);
                            stamps[4] = Stopwatch.GetTimestamp();
                            socket.Dispose();
                            stamps[5] = Stopwatch.GetTimestamp();
                            return Task.CompletedTask;
                        });

            await Steps("Socket, explicit Bind(0.0.0.0:0), SendToAsync",
                        [ "new Socket", "Bind(0.0.0.0:0)", "1st SendToAsync", "2nd SendToAsync", "Dispose" ],
                        async stamps => {
                            stamps[0] = Stopwatch.GetTimestamp();
                            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                            stamps[1] = Stopwatch.GetTimestamp();
                            socket.Bind(new IPEndPoint(IPAddress.Any, 0));
                            stamps[2] = Stopwatch.GetTimestamp();
                            await socket.SendToAsync(payload, SocketFlags.None, remote, CancellationToken.None);
                            stamps[3] = Stopwatch.GetTimestamp();
                            await socket.SendToAsync(payload, SocketFlags.None, remote, CancellationToken.None);
                            stamps[4] = Stopwatch.GetTimestamp();
                            socket.Dispose();
                            stamps[5] = Stopwatch.GetTimestamp();
                        });

            await Steps("UdpClient, as QueryTime had it: new UdpClient(family), SendAsync",
                        [ "new UdpClient", "1st SendAsync (binds)", "2nd SendAsync", "Dispose" ],
                        async stamps => {
                            stamps[0] = Stopwatch.GetTimestamp();
                            var udpClient = new UdpClient(AddressFamily.InterNetwork);
                            stamps[1] = Stopwatch.GetTimestamp();
                            await udpClient.SendAsync(payload, remote, CancellationToken.None);
                            stamps[2] = Stopwatch.GetTimestamp();
                            await udpClient.SendAsync(payload, remote, CancellationToken.None);
                            stamps[3] = Stopwatch.GetTimestamp();
                            udpClient.Dispose();
                            stamps[4] = Stopwatch.GetTimestamp();
                        });

            // The same socket kept: what a send costs on a socket that is already there.
            {
                var kept = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                kept.Bind(new IPEndPoint(IPAddress.Any, 0));
                await Steps("One socket kept: SendToAsync only",
                            [ "SendToAsync" ],
                            async stamps => {
                                stamps[0] = Stopwatch.GetTimestamp();
                                await kept.SendToAsync(payload, SocketFlags.None, remote, CancellationToken.None);
                                stamps[1] = Stopwatch.GetTimestamp();
                            });
            }

            // What the 64 KB of UdpClient cost by themselves.
            await Steps("new Byte[65536] alone",
                        [ "new Byte[65536]" ],
                        stamps => {
                            stamps[0] = Stopwatch.GetTimestamp();
                            var buffer = new Byte[65536];
                            stamps[1] = Stopwatch.GetTimestamp();
                            GC.KeepAlive(buffer);
                            return Task.CompletedTask;
                        });

            return 0;

        }

    }

}
