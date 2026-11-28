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

using System.Buffers.Binary;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTP
{

    /// <summary>
    /// What came of reading one message of NTP over SSH from a channel.
    /// </summary>
    public enum NTPOverSSHReadStatus
    {

        /// <summary>
        /// A whole message, of an acceptable length.
        /// </summary>
        Message,

        /// <summary>
        /// The channel ended where a message would have begun: the other side is done.
        /// </summary>
        EndOfStream,

        /// <summary>
        /// The channel ended within a length or a message.
        /// </summary>
        Truncated,

        /// <summary>
        /// A length below <see cref="NTPOverSSH.MinMessageLength"/>.
        /// </summary>
        TooShort,

        /// <summary>
        /// A length above what the reader accepts.
        /// </summary>
        TooLong

    }


    /// <summary>
    /// NTP over SSH, section 10 of the white paper "NTS Key Establishment over SSH": NTPv4 and
    /// NTPv5 messages in the channel of the subsystem <see cref="SubsystemName"/>, each behind a
    /// two-octet length in network byte order, as DNS over TCP and DNS over SSH have it.
    /// </summary>
    /// <remarks>
    /// NTP messages do not delimit themselves: on UDP the datagram ends the message, an NTPv4
    /// packet may end in a MAC whose presence RFC 7822 infers from the length of what is left,
    /// and an NTPv5 message has no length field at all. Hence the length.
    /// </remarks>
    public static class NTPOverSSH
    {

        /// <summary>
        /// The subsystem: without a version, as the version of NTP is in every message.
        /// </summary>
        public const String  SubsystemName            = "ntp@open.charging.cloud";

        /// <summary>
        /// The shortest message: the header of NTPv4 and of NTPv5, both 48 octets long.
        /// </summary>
        public const UInt16  MinMessageLength         = 48;

        /// <summary>
        /// The least a reader must accept (section 10.3): the smallest MTU of IPv6.
        /// </summary>
        public const UInt16  MinAcceptedMessageLength = 1280;

        /// <summary>
        /// The shortest idle timeout a server may have (section 10.5): longer than the 1,024
        /// seconds of the longest poll interval clients use by default.
        /// </summary>
        public static readonly TimeSpan MinIdleTimeout = TimeSpan.FromSeconds(1200);


        #region Frame(Message)

        /// <summary>
        /// The message behind its two-octet length, to be written to the channel in one write.
        /// </summary>
        /// <param name="Message">One NTP message, as it would be the payload of a UDP datagram.</param>
        /// <exception cref="ArgumentException">The message is shorter than 48 or longer than 65,535 octets.</exception>
        public static Byte[] Frame(ReadOnlySpan<Byte> Message)
        {

            if (Message.Length < MinMessageLength || Message.Length > UInt16.MaxValue)
                throw new ArgumentException($"An NTP message over SSH has {MinMessageLength} to {UInt16.MaxValue} octets, not {Message.Length}!",
                                            nameof(Message));

            var framed = new Byte[2 + Message.Length];

            BinaryPrimitives.WriteUInt16BigEndian(framed, (UInt16) Message.Length);
            Message.CopyTo(framed.AsSpan(2));

            return framed;

        }

        #endregion

        #region ReadMessageAsync(Input, MaxLength, CancellationToken)

        /// <summary>
        /// Read one length and its message from the byte stream of a channel. SSH packets do not
        /// delimit messages, so this reads as many as it takes, and leaves the rest for the next.
        /// </summary>
        /// <param name="Input">The channel's byte stream.</param>
        /// <param name="MaxLength">The longest message to accept; a longer one is not read.</param>
        /// <param name="CancellationToken">A cancellation token.</param>
        /// <returns>The status, and the message where there is one.</returns>
        public static async Task<(NTPOverSSHReadStatus Status, Byte[]? Message)>

            ReadMessageAsync(Stream             Input,
                             Int32              MaxLength,
                             CancellationToken  CancellationToken)

        {

            var lengthOctets = new Byte[2];

            var read = await ReadFullyAsync(Input, lengthOctets, CancellationToken).ConfigureAwait(false);

            if (read == 0)
                return (NTPOverSSHReadStatus.EndOfStream, null);

            if (read < 2)
                return (NTPOverSSHReadStatus.Truncated, null);

            var length = BinaryPrimitives.ReadUInt16BigEndian(lengthOctets);

            if (length < MinMessageLength)
                return (NTPOverSSHReadStatus.TooShort, null);

            if (length > MaxLength)
                return (NTPOverSSHReadStatus.TooLong, null);

            var message = new Byte[length];

            if (await ReadFullyAsync(Input, message, CancellationToken).ConfigureAwait(false) < length)
                return (NTPOverSSHReadStatus.Truncated, null);

            return (NTPOverSSHReadStatus.Message, message);

        }

        #endregion

        #region (private static) ReadFullyAsync(Input, Buffer, CancellationToken)

        /// <summary>
        /// Fill the buffer, unless the stream ends first: how many octets were read.
        /// </summary>
        private static async Task<Int32> ReadFullyAsync(Stream             Input,
                                                        Byte[]             Buffer,
                                                        CancellationToken  CancellationToken)
        {

            var total = 0;

            while (total < Buffer.Length)
            {

                var read = await Input.ReadAsync(Buffer.AsMemory(total), CancellationToken).ConfigureAwait(false);

                if (read == 0)
                    break;

                total += read;

            }

            return total;

        }

        #endregion

    }

}
