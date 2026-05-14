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

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// Reads one complete NTS-KE message from a stream.
    /// </summary>
    public static class NTSKEMessageReader
    {

        #region ReadAsync(Stream, Timeout, MaxResponseSize, CancellationToken)

        public static async Task<(Byte[]? ResponseBytes, String? ErrorMessage)> ReadAsync(Stream             TLSStream,
                                                                                          TimeSpan           Timeout,
                                                                                          Int32              MaxResponseSize,
                                                                                          CancellationToken  CancellationToken = default)
        {

            using var memoryStream = new MemoryStream();
            var buffer             = new Byte[4096];

            while (true)
            {

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
