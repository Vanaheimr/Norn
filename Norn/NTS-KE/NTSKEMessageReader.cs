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

using System.Net.Sockets;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// Reads one complete NTS-KE message from a stream.
    /// </summary>
    public static class NTSKEMessageReader
    {

        #region ReadAsync(Stream, Timeout, MaxResponseSize, CancellationToken, WaitForDataOn = null)

        /// <summary>
        /// Read one complete NTS-KE message.
        /// </summary>
        /// <param name="TLSStream">The TLS stream to read from.</param>
        /// <param name="Timeout">How long to wait for the whole message.</param>
        /// <param name="MaxResponseSize">Refuse anything larger than this.</param>
        /// <param name="WaitForDataOn">
        /// The underlying socket. When given, this waits for the socket to become readable
        /// before descending into the TLS stream, so a slow or truncated request expires
        /// without a read ever being interrupted.
        ///
        /// That distinction matters: BouncyCastle marks a TLS connection as failed if a read
        /// throws or is abandoned, and a failed connection cannot be written to — so the
        /// caller would lose the ability to send the Error record RFC 8915 § 4.1.3 requires.
        /// Waiting outside the TLS layer keeps the connection healthy enough to answer.
        /// </param>
        /// <param name="BlockingReadsOnOwnThread">
        /// Read from the TLS stream on a thread of its own instead of one of the pool's.
        ///
        /// The TLS stream of this library has no asynchronous read: ReadAsync is the blocking
        /// Read on a pool thread. Waiting for the socket to become readable keeps that short
        /// for a client that says nothing, but not for one that sends the first octet of a
        /// record and then stops: the read then holds its thread until the socket's receive
        /// timeout. A server sets this, so that such clients cost it threads of their own
        /// and none of those that answer NTP requests.
        /// </param>
        /// <summary>
        /// The maximum plaintext length of a single TLS 1.3 record (RFC 8446 § 5.1) plus one
        /// octet, so one Read drains a complete decrypted TLS record without leaving buffered
        /// plaintext behind while the underlying socket reports zero readable bytes.
        /// </summary>
        private const Int32 ReadBufferSize = 16385;

        /// <summary>
        /// Read one complete NTS-KE message.
        /// </summary>
        public static async Task<(Byte[]? ResponseBytes, String? ErrorMessage)> ReadAsync(Stream             TLSStream,
                                                                                          TimeSpan           Timeout,
                                                                                          Int32              MaxResponseSize,
                                                                                          CancellationToken  CancellationToken          = default,
                                                                                          Socket?            WaitForDataOn              = null,
                                                                                          Boolean            BlockingReadsOnOwnThread   = false)
        {

            var deadline = DateTime.UtcNow + Timeout;

            if (BlockingReadsOnOwnThread)
            {

                // Hold zero threads while a client says nothing at all: only once the first
                // bytes arrive (or the peer closes) do we dedicate a single thread for the
                // remainder of this message, rather than spawning a new OS thread per Read().
                if (WaitForDataOn is not null &&
                    !await WaitForReadableAsync(WaitForDataOn, deadline, CancellationToken).ConfigureAwait(false))
                {
                    return (null, "Read operation timed out.");
                }

                var readTask = Task.Factory.StartNew(
                                   () => ReadBlockingLoop(
                                             TLSStream,
                                             deadline,
                                             MaxResponseSize,
                                             CancellationToken,
                                             WaitForDataOn
                                         ),
                                   CancellationToken,
                                   TaskCreationOptions.LongRunning,
                                   TaskScheduler.Default
                               );

                // When WaitForDataOn is given, Poll() + ReceiveTimeout bound every blocking call
                // cleanly on that thread so it always finishes before we return — avoiding any
                // concurrent read/write race on a non-thread-safe TLS stream.
                if (WaitForDataOn is not null)
                    return await readTask.ConfigureAwait(false);

                var remainingForTask = deadline - DateTime.UtcNow;

                if (remainingForTask <= TimeSpan.Zero)
                    return (null, "Read operation timed out.");

                try
                {
                    return await readTask.WaitAsync(remainingForTask, CancellationToken).ConfigureAwait(false);
                }
                catch (TimeoutException)
                {
                    return (null, "Read operation timed out.");
                }
                catch (OperationCanceledException) when (!CancellationToken.IsCancellationRequested)
                {
                    return (null, "Read operation timed out.");
                }

            }

            using var memoryStream   = new MemoryStream();
            var buffer               = new Byte[ReadBufferSize];
            var scannedOffset        = 0;
            var maybeMoreBuffered    = false;

            while (true)
            {

                var remaining = deadline - DateTime.UtcNow;

                if (remaining <= TimeSpan.Zero)
                    return TimeoutResult(memoryStream.Length);

                if (WaitForDataOn is not null && !maybeMoreBuffered &&
                    !await WaitForReadableAsync(WaitForDataOn, deadline, CancellationToken).ConfigureAwait(false))
                {
                    return TimeoutResult(memoryStream.Length);
                }

                remaining = deadline - DateTime.UtcNow;

                if (remaining <= TimeSpan.Zero)
                    return TimeoutResult(memoryStream.Length);

                Int32 bytesRead;

                try
                {
                    bytesRead = await TLSStream.
                                          ReadAsync(buffer, 0, buffer.Length, CancellationToken).
                                          WaitAsync(remaining, CancellationToken).
                                          ConfigureAwait(false);
                }
                catch (TimeoutException)
                {
                    return TimeoutResult(memoryStream.Length);
                }
                catch (OperationCanceledException) when (!CancellationToken.IsCancellationRequested)
                {
                    return TimeoutResult(memoryStream.Length);
                }
                catch (IOException e) when (e.InnerException is SocketException { SocketErrorCode: SocketError.TimedOut })
                {
                    // A socket-level receive timeout. Unlike an abandoned Task.WaitAsync this
                    // leaves no read pending, so the caller can still write a reply.
                    return TimeoutResult(memoryStream.Length);
                }

                if (bytesRead <= 0)
                    return memoryStream.Length > 0
                               ? (null, "NTS-KE connection closed before EndOfMessage.")
                               : (null, "No response received.");

                maybeMoreBuffered = bytesRead == buffer.Length;

                memoryStream.Write(buffer, 0, bytesRead);

                if (memoryStream.Length > MaxResponseSize)
                    return (null, $"NTS-KE response exceeded the maximum size of {MaxResponseSize} bytes.");

                if (TryFinishCompleteMessage(memoryStream, ref scannedOffset, out var completeMessage, out var errorResponse))
                    return (completeMessage, null);

                if (errorResponse is not null)
                    return (null, errorResponse);

            }

        }

        private static (Byte[]? ResponseBytes, String? ErrorMessage) ReadBlockingLoop(Stream             TLSStream,
                                                                                      DateTime           Deadline,
                                                                                      Int32              MaxResponseSize,
                                                                                      CancellationToken  CancellationToken,
                                                                                      Socket?            WaitForDataOn)
        {

            using var memoryStream   = new MemoryStream();
            var buffer               = new Byte[ReadBufferSize];
            var scannedOffset        = 0;
            var maybeMoreBuffered    = false;

            while (true)
            {

                if (CancellationToken.IsCancellationRequested)
                    CancellationToken.ThrowIfCancellationRequested();

                var remaining = Deadline - DateTime.UtcNow;

                if (remaining <= TimeSpan.Zero)
                    return TimeoutResult(memoryStream.Length);

                if (WaitForDataOn is not null && !maybeMoreBuffered)
                {

                    if (!WaitForReadableBlocking(WaitForDataOn, Deadline, CancellationToken))
                        return TimeoutResult(memoryStream.Length);

                    remaining = Deadline - DateTime.UtcNow;

                    if (remaining <= TimeSpan.Zero)
                        return TimeoutResult(memoryStream.Length);

                }

                if (WaitForDataOn is not null)
                {
                    try
                    {
                        WaitForDataOn.ReceiveTimeout = Math.Max(
                                                           1,
                                                           (Int32) Math.Min(Int32.MaxValue, Math.Ceiling(remaining.TotalMilliseconds))
                                                       );
                    }
                    catch (ObjectDisposedException)
                    {
                        return TimeoutResult(memoryStream.Length);
                    }
                    catch (SocketException)
                    {
                        return TimeoutResult(memoryStream.Length);
                    }
                }

                Int32 bytesRead;

                try
                {
                    bytesRead = TLSStream.Read(buffer, 0, buffer.Length);
                }
                catch (IOException e) when (e.InnerException is SocketException { SocketErrorCode: SocketError.TimedOut })
                {
                    return TimeoutResult(memoryStream.Length);
                }
                catch (SocketException e) when (e.SocketErrorCode == SocketError.TimedOut)
                {
                    return TimeoutResult(memoryStream.Length);
                }

                if (bytesRead <= 0)
                    return memoryStream.Length > 0
                               ? (null, "NTS-KE connection closed before EndOfMessage.")
                               : (null, "No response received.");

                maybeMoreBuffered = bytesRead == buffer.Length;

                memoryStream.Write(buffer, 0, bytesRead);

                if (memoryStream.Length > MaxResponseSize)
                    return (null, $"NTS-KE response exceeded the maximum size of {MaxResponseSize} bytes.");

                if (TryFinishCompleteMessage(memoryStream, ref scannedOffset, out var completeMessage, out var errorResponse))
                    return (completeMessage, null);

                if (errorResponse is not null)
                    return (null, errorResponse);

            }

        }

        private static Boolean WaitForReadableBlocking(Socket             Socket,
                                                       DateTime           Deadline,
                                                       CancellationToken  CancellationToken)
        {

            while (true)
            {

                if (CancellationToken.IsCancellationRequested)
                    CancellationToken.ThrowIfCancellationRequested();

                var remaining = Deadline - DateTime.UtcNow;

                if (remaining <= TimeSpan.Zero)
                    return false;

                var pollMicros = (Int32) Math.Min(250_000, Math.Max(1_000, remaining.TotalMilliseconds * 1000.0));

                try
                {
                    if (Socket.Poll(pollMicros, SelectMode.SelectRead))
                        return true;
                }
                catch (ObjectDisposedException)
                {
                    return false;
                }
                catch (SocketException)
                {
                    return false;
                }

            }

        }

        private static (Byte[]? ResponseBytes, String? ErrorMessage) TimeoutResult(Int64 BytesReceived)

            => BytesReceived > 0
                   ? (null, "Read operation timed out before a complete NTS-KE message arrived.")
                   : (null, "Read operation timed out.");

        private static Boolean TryFinishCompleteMessage(MemoryStream  MemoryStream,
                                                        ref Int32     ScannedOffset,
                                                        out Byte[]?   CompleteMessage,
                                                        out String?   ErrorResponse)
        {

            CompleteMessage  = null;
            ErrorResponse    = null;

            if (!MemoryStream.TryGetBuffer(out var segment) || segment.Array is null)
                return false;

            var buffer       = segment.Array;
            var bufferLength = segment.Offset + segment.Count;
            var offset       = segment.Offset + ScannedOffset;

            while (offset + 4 <= bufferLength)
            {

                var type       = (NTSKE_RecordTypes) (((buffer[offset] & 0x7F) << 8) | buffer[offset + 1]);
                var bodyLength = (UInt16)             ((buffer[offset + 2]     << 8) | buffer[offset + 3]);
                var nextOffset = offset + 4 + bodyLength;

                if (nextOffset > bufferLength)
                {
                    ScannedOffset = offset - segment.Offset;
                    return false;
                }

                offset = nextOffset;

                if (type == NTSKE_RecordTypes.EndOfMessage)
                {
                    var messageLength = offset - segment.Offset;
                    CompleteMessage   = new Byte[messageLength];
                    Buffer.BlockCopy(buffer, segment.Offset, CompleteMessage, 0, messageLength);
                    return true;
                }

            }

            ScannedOffset = offset - segment.Offset;
            return false;

        }

        #endregion

        #region (private) WaitForReadableAsync(Socket, Deadline, CancellationToken)

        /// <summary>
        /// Wait until the socket has data to read, or the deadline passes.
        /// Returns false on timeout or cancellation.
        /// </summary>
        private static async Task<Boolean> WaitForReadableAsync(Socket             Socket,
                                                                DateTime           Deadline,
                                                                CancellationToken  CancellationToken)
        {

            var remaining = Deadline - DateTime.UtcNow;

            if (remaining <= TimeSpan.Zero ||
                CancellationToken.IsCancellationRequested)
            {
                return false;
            }

            using var deadlineCTS = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
            deadlineCTS.CancelAfter(remaining);

            try
            {

                // A receive of zero bytes completes when there is something to read, or when
                // the peer has closed, and takes nothing off the socket; the caller's
                // zero-bytes-read branch handles the latter. Unlike Socket.Poll it holds no
                // thread while it waits: with Poll, every client that connected and then
                // said nothing kept a thread of the pool busy for the length of the timeout.
                await Socket.ReceiveAsync(
                          Memory<Byte>.Empty,
                          SocketFlags.None,
                          deadlineCTS.Token
                      ).ConfigureAwait(false);

                return true;

            }
            catch (OperationCanceledException)
            {
                return false;
            }
            catch (ObjectDisposedException)
            {
                return false;
            }
            catch (SocketException)
            {
                return false;
            }

        }

        #endregion

        #region TryGetCompleteMessageLength(Buffer, BufferLength, out MessageLength, out ErrorResponse)

        public static Boolean TryGetCompleteMessageLength(Byte[]       Buffer,
                                                          Int32        BufferLength,
                                                          out Int32    MessageLength,
                                                          out String?  ErrorResponse)
        {

            MessageLength  = 0;
            ErrorResponse  = null;

            var offset = 0;

            while (offset + 4 <= BufferLength)
            {

                var type        = (NTSKE_RecordTypes) (((Buffer[offset] & 0x7F) << 8) | Buffer[offset + 1]);
                var bodyLength  = (UInt16)             ((Buffer[offset + 2]     << 8) | Buffer[offset + 3]);
                var nextOffset  = offset + 4 + bodyLength;

                if (nextOffset > BufferLength)
                    return false;

                offset = nextOffset;

                if (type == NTSKE_RecordTypes.EndOfMessage)
                {
                    MessageLength = offset;
                    return true;
                }

            }

            return false;

        }

        #endregion

    }

}
