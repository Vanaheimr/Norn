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
using System.Net.Sockets;
using System.Runtime.CompilerServices;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Timings
{

    /// <summary>
    /// What the marks of one side recorded: for every query a time stamp at every mark,
    /// and in a second pass the bytes allocated up to it.
    /// </summary>
    /// <remarks>
    /// The time stamps are <see cref="Stopwatch.GetTimestamp"/>, which on Windows is the
    /// performance counter and the same clock in every process: the marks of a client and
    /// of a server in two processes lie on one time line.
    /// </remarks>
    public sealed class MarkSet
    {

        public const Int32 Slots = 16;

        private Int64[] stamps = [];
        private Int64[] allocs = [];
        private Int32   next   = -1;

        public Int32    Capacity { get; private set; }
        public Boolean  Alloc    { get; private set; }
        public Boolean  Enabled  { get; private set; }

        public Int32    Count    => Math.Min(Volatile.Read(ref next) + 1, Capacity);

        public void Reset(Int32 Capacity, Boolean Alloc)
        {
            Enabled        = false;
            stamps         = new Int64[Capacity * Slots];
            allocs         = Alloc ? new Int64[Capacity * Slots] : [];
            this.Capacity  = Capacity;
            this.Alloc     = Alloc;
            next           = -1;
            Enabled        = Capacity > 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public Int32 Begin()
        {

            if (!Enabled)
                return -1;

            var i = Interlocked.Increment(ref next);

            return i < Capacity ? i : -1;

        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Mark(Int32 Index, Int32 Slot)
        {
            if (Index >= 0)
                MarkSlow(Index, Slot);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private void MarkSlow(Int32 Index, Int32 Slot)
        {

            if (Alloc)
                allocs[Index * Slots + Slot] = GC.GetTotalAllocatedBytes(true);

            stamps[Index * Slots + Slot] = Stopwatch.GetTimestamp();

        }

        public Int64 Stamp(Int32 Index, Int32 Slot) => stamps[Index * Slots + Slot];
        public Int64 Bytes(Int32 Index, Int32 Slot) => allocs[Index * Slots + Slot];

        public void Save(String Path)
        {
            using var writer = new BinaryWriter(File.Create(Path));
            var count = Count;
            writer.Write(count);
            writer.Write(Alloc);
            for (var i = 0; i < count * Slots; i++) writer.Write(stamps[i]);
            if (Alloc)
                for (var i = 0; i < count * Slots; i++) writer.Write(allocs[i]);
        }

        public static MarkSet Load(String Path)
        {
            using var reader = new BinaryReader(File.OpenRead(Path));
            var count = reader.ReadInt32();
            var alloc = reader.ReadBoolean();
            var set   = new MarkSet();
            set.Reset(count, alloc);
            for (var i = 0; i < count * Slots; i++) set.stamps[i] = reader.ReadInt64();
            if (alloc)
                for (var i = 0; i < count * Slots; i++) set.allocs[i] = reader.ReadInt64();
            set.next = count - 1;
            return set;
        }

    }

    /// <summary>
    /// The marks of the client and of the server, and the switches of the experiments.
    /// </summary>
    /// <remarks>
    /// Norn itself knows nothing of this. The copies of <c>NTSClient.cs</c> and
    /// <c>NTSServer.cs</c> that the Phases project compiles have calls to it inserted; see
    /// <c>Phases/InsertMarks.cs</c>.
    /// </remarks>
    public static class Marks
    {
        /// <summary>The client's marks.</summary>
        public static readonly MarkSet C = new();
        /// <summary>The server's marks.</summary>
        public static readonly MarkSet S = new();

        /// <summary>The counter-experiment: one UDP socket for all queries, not one for each.</summary>
        public static Boolean  KeepSocket;

        /// <summary>The socket that is kept.</summary>
        public static Socket?  KeptSocket;

        /// <summary>
        /// The other counter-experiment: a client that is not in the interleaved mode computes
        /// with the clock as it read it after the send, not with the T1 that is in the request.
        /// </summary>
        public static Boolean  T1AfterTheSend;
    }

}
