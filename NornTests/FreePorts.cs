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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests
{

    /// <summary>
    /// Ports of the loopback interface found free, and a server of a test started on them.
    /// </summary>
    /// <remarks>
    /// A port found free is let go again before the server binds it, and on a machine running
    /// other test suites at the same time somebody else may take it in between: a test then
    /// failed with AddressAlreadyInUse - on Windows also with AccessDenied -, and was green
    /// alone. <see cref="Start"/> makes the server again, on ports found free anew, where -
    /// and only where - a port it was to bind was taken. Any other reason not to start is
    /// the test's.
    /// </remarks>
    internal static class FreePorts
    {

        #region TCP() / UDP()

        /// <summary>
        /// A TCP port of the loopback interface nobody listens on right now.
        /// </summary>
        public static IPPort TCP()
        {

            var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();

            var port = IPPort.Parse(((IPEndPoint) listener.LocalEndpoint).Port);
            listener.Stop();

            return port;

        }

        /// <summary>
        /// A UDP port of the loopback interface nobody has bound right now.
        /// </summary>
        public static IPPort UDP()
        {

            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            return IPPort.Parse(((IPEndPoint) udpClient.Client.LocalEndPoint!).Port);

        }

        #endregion

        #region Start(MakeServer, Attempts = 5)

        /// <summary>
        /// Make a server with the given function and start it - and make it again, at most
        /// Attempts times in all, where a port it was to bind was taken. The function finds its
        /// ports free itself, with <see cref="TCP"/> and <see cref="UDP"/>, so that every
        /// attempt has ports of its own; what a test needs to know of them it reads from the
        /// server it gets back.
        /// </summary>
        /// <param name="MakeServer">Makes the server, on ports found free anew.</param>
        /// <param name="Attempts">How often to make it at most.</param>
        public static async Task<NTSServer> Start(Func<NTSServer>  MakeServer,
                                                  Int32            Attempts = 5)
        {

            for (var attempt = 1; ; attempt++)
            {

                var server = MakeServer();

                try
                {
                    await server.Start();
                    return server;
                }
                catch (Exception e) when (attempt < Attempts && IsAPortTaken(e))
                {
                    // Start binds one port after the other: what it bound before the one
                    // that was taken is let go again.
                    await server.ShutdownAsync();
                }

            }

        }

        #endregion

        #region IsAPortTaken(Exception)

        /// <summary>
        /// Whether the given exception, or one it was thrown for, says that a port to be bound
        /// was taken - however many layers between the socket and the server wrapped it.
        /// </summary>
        /// <remarks>
        /// Windows says AccessDenied (WSAEACCES, 10013) rather than AddressAlreadyInUse where
        /// the port is held by a socket bound for exclusive use - as .NET binds one there - or
        /// lies in a range the system has set aside meanwhile: a port found free and taken
        /// before it was bound, too.
        /// </remarks>
        public static Boolean IsAPortTaken(Exception? Exception)
        {

            for (var e = Exception; e is not null; e = e.InnerException)
            {

                if (e is SocketException { SocketErrorCode: SocketError.AddressAlreadyInUse or
                                                            SocketError.AccessDenied })
                    return true;

                if (e is AggregateException aggregate && aggregate.InnerExceptions.Any(IsAPortTaken))
                    return true;

            }

            return false;

        }

        #endregion

    }

}
