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
using System.Threading.Channels;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Norn.NTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// The client's end of a channel of NTP over SSH, the subsystem
    /// <see cref="NTPOverSSH.SubsystemName"/> of section 10 of the white paper "NTS Key
    /// Establishment over SSH": what <see cref="NTSClient.QueryTimeOverSSH"/>,
    /// <see cref="NTSClient.QueryNTPv5OverSSH"/> and <see cref="NTSClient.QueryNegotiatedOverSSH"/>
    /// send their requests on.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Kept open for as long as the client polls the server (section 10.5), and one per server
    /// and connection. The SSH connection is the caller's: connecting, verifying the host key
    /// and logging in happen before, and the trust placed in that host key is the trust in the
    /// time that comes back. Closing the channel leaves the connection alone, which may carry
    /// OCPP and other channels.
    /// </para>
    /// <para>
    /// The channel is read all the time, not only while a query waits: a response that comes
    /// after its query gave up is read and passed over, rather than left in the stream to be
    /// taken for the answer to the next request.
    /// </para>
    /// </remarks>
    public sealed class NTPOverSSHChannel : IAsyncDisposable
    {

        #region Data

        private readonly SshMuxChannel             channel;
        private readonly Channel<Byte[]>           received;
        private readonly CancellationTokenSource   readerCTS = new ();
        private readonly Task                      readerTask;
        private          Int32                     disposed;

        #endregion

        #region Properties

        /// <summary>
        /// The server as the results of a query name it: the address of the SSH connection, where
        /// it is known.
        /// </summary>
        public IPEndPoint             RemoteEndPoint    { get; }

        /// <summary>
        /// The server as error messages describe it.
        /// </summary>
        public String                 Description       { get; }

        /// <summary>
        /// The longest message accepted from the server; anything longer ends the channel.
        /// </summary>
        public Int32                  MaxMessageLength  { get; }

        /// <summary>
        /// Why the channel ended, once it has: the server's EOF, or a length that broke the stream.
        /// </summary>
        public NTPOverSSHReadStatus?  EndStatus         { get; private set; }

        /// <summary>
        /// Whether the channel is still open to read from.
        /// </summary>
        public Boolean                IsOpen
            => EndStatus is null && Volatile.Read(ref disposed) == 0;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The client's end of an NTP channel that is open already: one the caller opened with
        /// <see cref="SSHClient.OpenSubsystem"/>, e.g. on a connection it shares with OCPP.
        /// </summary>
        /// <param name="Channel">The channel of the subsystem <see cref="NTPOverSSH.SubsystemName"/>.</param>
        /// <param name="RemoteEndPoint">The server, as results name it.</param>
        /// <param name="Description">The server, as error messages describe it.</param>
        /// <param name="MaxMessageLength">The longest message to accept (default: 65,535 octets).</param>
        public NTPOverSSHChannel(SshMuxChannel  Channel,
                                 IPEndPoint?    RemoteEndPoint     = null,
                                 String?        Description        = null,
                                 Int32?         MaxMessageLength   = null)
        {

            this.channel           = Channel;
            this.RemoteEndPoint    = RemoteEndPoint ?? new IPEndPoint(System.Net.IPAddress.IPv6None, 0);
            this.Description       = Description    ?? $"{NTPOverSSH.SubsystemName} at {this.RemoteEndPoint}";
            this.MaxMessageLength  = Math.Clamp(MaxMessageLength ?? UInt16.MaxValue, NTPOverSSH.MinAcceptedMessageLength, UInt16.MaxValue);

            // A few responses at most wait here: the client sends one request at a time, and a
            // server that sends more than it was asked for loses the oldest.
            this.received          = System.Threading.Channels.Channel.CreateBounded<Byte[]>(
                                         new BoundedChannelOptions(16) {
                                             FullMode     = BoundedChannelFullMode.DropOldest,
                                             SingleReader = true,
                                             SingleWriter = true
                                         }
                                     );

            this.readerTask        = Task.Run(ReadLoopAsync);

        }

        #endregion


        #region (static) OpenAsync(SSHClient, CancellationToken = default)

        /// <summary>
        /// Open the subsystem <see cref="NTPOverSSH.SubsystemName"/> on the given SSH connection.
        /// </summary>
        /// <param name="SSHClient">An SSH connection to the time server, authenticated in both directions.</param>
        /// <param name="CancellationToken">A cancellation token.</param>
        /// <exception cref="SshSubsystemRefusedException">
        /// The server does not offer the subsystem to this login. Section 10.2 has the client give
        /// up then, and never ask over UDP instead.
        /// </exception>
        public static async Task<NTPOverSSHChannel> OpenAsync(SSHClient          SSHClient,
                                                              CancellationToken  CancellationToken   = default)
        {

            var channel = await SSHClient.OpenSubsystem(NTPOverSSH.SubsystemName,
                                                        CancellationToken).ConfigureAwait(false);

            var remote  = SSHClient.RemoteSocket is IPSocket socket
                              ? new IPEndPoint(socket.IPAddress.ToDotNet(), socket.Port.ToUInt16())
                              : null;

            return new NTPOverSSHChannel(channel,
                                         remote,
                                         remote is not null
                                             ? $"ssh://{remote} {NTPOverSSH.SubsystemName}"
                                             : null);

        }

        #endregion


        #region (internal) SendAsync(Message, CancellationToken)

        /// <summary>
        /// Send one request: its length and itself, in one write (section 10.3).
        /// </summary>
        internal Task SendAsync(Byte[]             Message,
                                CancellationToken  CancellationToken)
        {

            if (!IsOpen)
                throw new IOException($"The NTP channel to {Description} has ended{(EndStatus is not null ? $" ({EndStatus})" : "")}.");

            return channel.SendDataAsync(NTPOverSSH.Frame(Message), CancellationToken).AsTask();

        }

        #endregion

        #region (internal) DiscardPending()

        /// <summary>
        /// Pass over what came for earlier requests, before the next one is sent.
        /// </summary>
        internal void DiscardPending()
        {
            while (received.Reader.TryRead(out _))
            { }
        }

        #endregion

        #region (internal) ReceiveAsync(Timeout, CancellationToken)

        /// <summary>
        /// The next message from the server, in the shape a datagram is handed out in, or a
        /// timeout. A channel that has ended is an exception, as a socket that fails is.
        /// </summary>
        internal async Task<(UdpReceiveResult? Result, Boolean TimedOut)> ReceiveAsync(TimeSpan           Timeout,
                                                                                      CancellationToken  CancellationToken)
        {

            using var timeoutCTS = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
            timeoutCTS.CancelAfter(Timeout);

            try
            {

                var message = await received.Reader.ReadAsync(timeoutCTS.Token).ConfigureAwait(false);

                return (new UdpReceiveResult(message, RemoteEndPoint), false);

            }
            catch (OperationCanceledException) when (!CancellationToken.IsCancellationRequested)
            {
                return (null, true);
            }
            catch (ChannelClosedException)
            {
                throw new IOException($"The NTP channel to {Description} has ended ({EndStatus?.ToString() ?? "closed"}).");
            }

        }

        #endregion

        #region (private) ReadLoopAsync()

        private async Task ReadLoopAsync()
        {

            try
            {

                while (true)
                {

                    var (status, message) = await NTPOverSSH.ReadMessageAsync(channel.Input,
                                                                              MaxMessageLength,
                                                                              readerCTS.Token).ConfigureAwait(false);

                    if (status != NTPOverSSHReadStatus.Message || message is null)
                    {
                        EndStatus = status;
                        break;
                    }

                    received.Writer.TryWrite(message);

                }

            }
            catch (Exception)
            {
                EndStatus ??= NTPOverSSHReadStatus.EndOfStream;
            }
            finally
            {
                received.Writer.TryComplete();
            }

        }

        #endregion


        #region DisposeAsync()

        /// <summary>
        /// End the channel (section 10.5): EOF and CLOSE, and the connection stays.
        /// </summary>
        public async ValueTask DisposeAsync()
        {

            if (Interlocked.Exchange(ref disposed, 1) != 0)
                return;

            try
            {
                await channel.SendEofAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch
            { }

            try
            {
                await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch
            { }

            readerCTS.Cancel();

            try
            {
                await readerTask.ConfigureAwait(false);
            }
            catch
            { }

            readerCTS.Dispose();

        }

        #endregion

    }

}
