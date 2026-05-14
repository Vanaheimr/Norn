/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Norn <https://www.github.com/Vanaheimr/Norn>
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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// NTS-KE message reader tests.
    /// </summary>
    [TestFixture]
    public class NTSKEMessageReader_Tests
    {

        #region ReadAsync_Returns_Complete_Fragmented_Message()

        [Test]
        public async Task ReadAsync_Returns_Complete_Fragmented_Message()
        {

            var message = BuildMessage();
            using var stream = new ChunkedReadStream(
                                   message[..3],
                                   message[3..8],
                                   message[8..]
                               );

            var result = await NTSKEMessageReader.ReadAsync(
                                   stream,
                                   TimeSpan.FromSeconds(1),
                                   1024
                               );

            Assert.That(result.ErrorMessage,   Is.Null);
            Assert.That(result.ResponseBytes,  Is.EqualTo(message));

        }

        #endregion

        #region ReadAsync_Ignores_Trailing_Bytes_After_EndOfMessage()

        [Test]
        public async Task ReadAsync_Ignores_Trailing_Bytes_After_EndOfMessage()
        {

            var message = BuildMessage();
            var bytes   = message.Concat(new Byte[] { 0xAA, 0xBB, 0xCC }).ToArray();

            using var stream = new ChunkedReadStream(bytes);

            var result = await NTSKEMessageReader.ReadAsync(
                                   stream,
                                   TimeSpan.FromSeconds(1),
                                   1024
                               );

            Assert.That(result.ErrorMessage,   Is.Null);
            Assert.That(result.ResponseBytes,  Is.EqualTo(message));

        }

        #endregion

        #region ReadAsync_Returns_Error_When_Response_Exceeds_Maximum_Size()

        [Test]
        public async Task ReadAsync_Returns_Error_When_Response_Exceeds_Maximum_Size()
        {

            var message = BuildMessage();
            using var stream = new ChunkedReadStream(
                                   message[..8],
                                   message[8..]
                               );

            var result = await NTSKEMessageReader.ReadAsync(
                                   stream,
                                   TimeSpan.FromSeconds(1),
                                   7
                               );

            Assert.That(result.ResponseBytes,  Is.Null);
            Assert.That(result.ErrorMessage,   Does.Contain("exceeded"));

        }

        #endregion

        #region ReadAsync_Returns_Error_When_Stream_Closes_Before_EndOfMessage()

        [Test]
        public async Task ReadAsync_Returns_Error_When_Stream_Closes_Before_EndOfMessage()
        {

            var incompleteMessage = new [] {
                                        NTSKE_Record.NTSNextProtocolNegotiation
                                    }.ToByteArray();

            using var stream = new ChunkedReadStream(incompleteMessage);

            var result = await NTSKEMessageReader.ReadAsync(
                                   stream,
                                   TimeSpan.FromSeconds(1),
                                   1024
                               );

            Assert.That(result.ResponseBytes,  Is.Null);
            Assert.That(result.ErrorMessage,   Does.Contain("before EndOfMessage"));

        }

        #endregion


        #region (private static) BuildMessage()

        private static Byte[] BuildMessage()

            => new [] {
                   NTSKE_Record.NTSNextProtocolNegotiation,
                   NTSKE_Record.AEADAlgorithmNegotiation(),
                   NTSKE_Record.EndOfMessage
               }.ToByteArray();

        #endregion

        #region (class) ChunkedReadStream

        private sealed class ChunkedReadStream(params Byte[][] Chunks) : Stream
        {

            private readonly Byte[][] chunks       = Chunks;
            private          Int32    chunkIndex;
            private          Int32    chunkOffset;

            public override Boolean CanRead   => true;
            public override Boolean CanSeek   => false;
            public override Boolean CanWrite  => false;
            public override Int64   Length    => throw new NotSupportedException();

            public override Int64 Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override void Flush()
            { }

            public override Int32 Read(Byte[] Buffer, Int32 Offset, Int32 Count)

                => ReadNextChunk(Buffer, Offset, Count);

            public override Task<Int32> ReadAsync(Byte[]             Buffer,
                                                  Int32              Offset,
                                                  Int32              Count,
                                                  CancellationToken  CancellationToken)

                => Task.FromResult(ReadNextChunk(Buffer, Offset, Count));

            public override Int64 Seek(Int64 SeekOffset, SeekOrigin Origin)

                => throw new NotSupportedException();

            public override void SetLength(Int64 Value)

                => throw new NotSupportedException();

            public override void Write(Byte[] Buffer, Int32 Offset, Int32 Count)

                => throw new NotSupportedException();

            private Int32 ReadNextChunk(Byte[] Buffer, Int32 Offset, Int32 Count)
            {

                if (chunkIndex >= chunks.Length)
                    return 0;

                var chunk      = chunks[chunkIndex];
                var available  = chunk.Length - chunkOffset;
                var bytesRead  = Math.Min(available, Count);

                Array.Copy(chunk, chunkOffset, Buffer, Offset, bytesRead);

                chunkOffset += bytesRead;

                if (chunkOffset >= chunk.Length)
                {
                    chunkIndex++;
                    chunkOffset = 0;
                }

                return bytesRead;

            }

        }

        #endregion

    }

}
