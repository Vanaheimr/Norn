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
        public static async Task<(Byte[]? ResponseBytes, String? ErrorMessage)> ReadAsync(Stream             TLSStream,
                                                                                          TimeSpan           Timeout,
                                                                                          Int32              MaxResponseSize,
                                                                                          CancellationToken  CancellationToken = default,
                                                                                          Socket?            WaitForDataOn     = null)
        {

            using var memoryStream = new MemoryStream();
            var buffer             = new Byte[4096];
            var deadline           = DateTime.UtcNow + Timeout;

            while (true)
            {

                if (WaitForDataOn is not null &&
                    !await WaitForReadableAsync(WaitForDataOn, deadline, CancellationToken).ConfigureAwait(false))
                {
                    return memoryStream.Length > 0
                               ? (null, "Read operation timed out before a complete NTS-KE message arrived.")
                               : (null, "Read operation timed out.");
                }


                Int32 bytesRead;

                try
                {
                    bytesRead = await TLSStream.
                                          ReadAsync(buffer, 0, buffer.Length, CancellationToken).
                                          WaitAsync(Timeout, CancellationToken).
                                          ConfigureAwait(false);
                }
                catch (TimeoutException)
                {
                    return (null, "Read operation timed out.");
                }
                catch (OperationCanceledException) when (!CancellationToken.IsCancellationRequested)
                {
                    return (null, "Read operation timed out.");
                }
                catch (IOException e) when (e.InnerException is SocketException { SocketErrorCode: SocketError.TimedOut })
                {
                    // A socket-level receive timeout. Unlike an abandoned Task.WaitAsync this
                    // leaves no read pending, so the caller can still write a reply.
                    return (null, "Read operation timed out.");
                }

                if (bytesRead <= 0)
                    return memoryStream.Length > 0
                               ? (null, "NTS-KE connection closed before EndOfMessage.")
                               : (null, "No response received.");

                memoryStream.Write(buffer, 0, bytesRead);

                if (memoryStream.Length > MaxResponseSize)
                    return (null, $"NTS-KE response exceeded the maximum size of {MaxResponseSize} bytes.");

                var data = memoryStream.ToArray();

                if (TryGetCompleteMessageLength(data, data.Length, out var messageLength, out var errorResponse))
                {

                    if (messageLength != data.Length)
                        Array.Resize(ref data, messageLength);

                    return (data, null);

                }

                if (errorResponse is not null)
                    return (null, errorResponse);

            }

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

            // Polled in slices rather than one long wait so cancellation stays responsive.
            var slice = TimeSpan.FromMilliseconds(250);

            while (DateTime.UtcNow < Deadline)
            {

                if (CancellationToken.IsCancellationRequested)
                    return false;

                try
                {
                    // Poll reports readable both when data has arrived and when the peer has
                    // closed; the caller's zero-bytes-read branch handles the latter.
                    if (Socket.Poll(slice, SelectMode.SelectRead))
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

                await Task.Yield();

            }

            return false;

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
