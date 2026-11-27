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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTPv5
{

    /// <summary>
    /// The list of reference IDs of draft-ietf-ntp-ntpv5-10 § 7.4.
    /// </summary>
    [TestFixture]
    public class NTPv5ReferenceIds_Tests
    {

        private const UInt64 own = 0x00_0102_0304_0506_07UL;
        private const UInt64 a   = 0x00_A0A0_A0A0_A0A0_A0UL;
        private const UInt64 b   = 0x00_B0B0_B0B0_B0B0_B0UL;
        private const UInt64 x   = 0x00_C0C0_C0C0_C0C0_C0UL;


        #region Shares_AreEncodedAsTheDraftsExamples()

        /// <summary>
        /// § 7.4's own examples: 100 % is 0, 96 % is 1, 90 % is 3, 50 % is 16; nothing is 255.
        /// </summary>
        [Test]
        public void Shares_AreEncodedAsTheDraftsExamples()
        {

            Assert.Multiple(() => {
                Assert.That(NTPv5ReferenceIds.EncodeShare(1.00),     Is.EqualTo(0));
                Assert.That(NTPv5ReferenceIds.EncodeShare(0.96),     Is.EqualTo(1));
                Assert.That(NTPv5ReferenceIds.EncodeShare(0.90),     Is.EqualTo(3));
                Assert.That(NTPv5ReferenceIds.EncodeShare(0.50),     Is.EqualTo(16), "a power of two is exact, not one more");
                Assert.That(NTPv5ReferenceIds.EncodeShare(0.25),     Is.EqualTo(32));
                Assert.That(NTPv5ReferenceIds.EncodeShare(0.0),      Is.EqualTo(255));
                Assert.That(NTPv5ReferenceIds.EncodeShare(1e-9),     Is.EqualTo(255), "clamped");
                Assert.That(NTPv5ReferenceIds.EncodeShare(Double.NaN), Is.EqualTo(255));
                Assert.That(NTPv5ReferenceIds.DecodeShare(16),       Is.EqualTo(0.5).Within(1e-12));
                Assert.That(NTPv5ReferenceIds.DecodeShare(0),        Is.EqualTo(1.0));
            });

            // Rounded up: what is encoded never stands for more than it was.
            for (var share = 0.001; share < 1; share += 0.0137)
                Assert.That(NTPv5ReferenceIds.DecodeShare(NTPv5ReferenceIds.EncodeShare(share)), Is.LessThanOrEqualTo(share + 1e-12), $"share {share}");

        }

        #endregion

        #region AnIdIsRandom_NonZero_And56Bits()

        [Test]
        public void AnIdIsRandom_NonZero_And56Bits()
        {

            var ids = Enumerable.Range(0, 1000).Select(_ => NTPv5ReferenceIds.NewReferenceId()).ToArray();

            Assert.That(ids, Is.All.Not.Zero);
            Assert.That(ids, Is.All.LessThanOrEqualTo(NTPv5ReferenceIds.ReferenceIdMask));
            Assert.That(ids.Distinct().Count(), Is.EqualTo(ids.Length));

        }

        #endregion

        #region AServerWithoutSources_ListsItselfAlone()

        /// <summary>
        /// § 7.4: entry 0 is the server itself at 100 %; unused entries are share 255, ID 0.
        /// </summary>
        [Test]
        public void AServerWithoutSources_ListsItselfAlone()
        {

            var list = NTPv5ReferenceIds.Of(own);

            Assert.That(list.Entries,                 Has.Count.EqualTo(32));
            Assert.That(list.Entries[0],              Is.EqualTo(new NTPv5ReferenceIdEntry(0, own)));
            Assert.That(list.Entries.Skip(1),         Is.All.EqualTo(NTPv5ReferenceIdEntry.Unused));
            Assert.That(() => NTPv5ReferenceIds.Of(0), Throws.InstanceOf<ArgumentOutOfRangeException>());

        }

        #endregion

        #region Sources_AreCombinedAsSection74Has()

        /// <summary>
        /// § 7.4: a source's shares scaled by one half and by its part of the weight, an ID
        /// reported twice summed, the largest first. Weights 3 : 1, both sources reporting X at
        /// 50 %: A 0.375, X 0.1875 + 0.0625 = 0.25, B 0.125.
        /// </summary>
        [Test]
        public void Sources_AreCombinedAsSection74Has()
        {

            var list = NTPv5ReferenceIds.Of(own, [
                           new NTPv5ReferenceIdSource(3, [ new (0, a), new (16, x), NTPv5ReferenceIdEntry.Unused ]),
                           new NTPv5ReferenceIdSource(1, [ new (0, b), new (16, x), new (0, own) ]),
                           new NTPv5ReferenceIdSource(5, [])   // an NTPv4 source: weight, no IDs
                       ]);

            // With the NTPv4 source the total weight is 9: A 3/9, B 1/9.
            Assert.Multiple(() => {
                Assert.That(list.Entries[0], Is.EqualTo(new NTPv5ReferenceIdEntry(0, own)));
                Assert.That(list.Entries[1].ReferenceId, Is.EqualTo(a));
                Assert.That(list.Entries[1].Share,       Is.EqualTo(NTPv5ReferenceIds.EncodeShare(0.5 * 3 / 9)));
                Assert.That(list.Entries[2].ReferenceId, Is.EqualTo(x));
                Assert.That(list.Entries[2].Share,       Is.EqualTo(NTPv5ReferenceIds.EncodeShare(0.25 * 3 / 9 + 0.25 * 1 / 9)));
                Assert.That(list.Entries[3].ReferenceId, Is.EqualTo(b));
                Assert.That(list.Entries[3].Share,       Is.EqualTo(NTPv5ReferenceIds.EncodeShare(0.5 * 1 / 9)));
                Assert.That(list.Entries.Skip(4),        Is.All.EqualTo(NTPv5ReferenceIdEntry.Unused), "the server's own ID from a source, and unused entries, are not listed");
            });

        }

        #endregion

        #region MoreThan31_AreCutToThe31Largest()

        [Test]
        public void MoreThan31_AreCutToThe31Largest()
        {

            var sources = Enumerable.Range(1, 40).
                                     Select(i => new NTPv5ReferenceIdSource(i, [ new (0, (UInt64) i) ])).
                                     ToArray();

            var list    = NTPv5ReferenceIds.Of(own, sources);

            Assert.That(list.Entries.Skip(1).Select(entry => entry.ReferenceId),
                        Is.EqualTo(Enumerable.Range(10, 31).Reverse().Select(i => (UInt64) i)),
                        "the heaviest 31, heaviest first");

        }

        #endregion

        #region ARequest_IsAnsweredFromItsIndex_AtItsLength()

        /// <summary>
        /// § 7.4: the response has the length of the request, the entries from its index on;
        /// a request whose index does not fit its length, or of a length that is no whole
        /// number of entries, is ignored.
        /// </summary>
        [Test]
        public void ARequest_IsAnsweredFromItsIndex_AtItsLength()
        {

            var list = NTPv5ReferenceIds.Of(own, [ new NTPv5ReferenceIdSource(1, [ new (0, a) ]) ]);

            Assert.That(list.TryAnswer(NTPv5ReferenceIds.Request(), out var whole), Is.True);
            Assert.That(whole!.Length, Is.EqualTo(4 + 256));
            Assert.That(NTPv5ReferenceIds.TryRead(whole.Value, out var entries), Is.True);
            Assert.That(entries, Is.EqualTo(list.Entries));

            Assert.That(list.TryAnswer(NTPv5ReferenceIds.Request(Index: 1, Entries: 1), out var second), Is.True);
            Assert.That(NTPv5ReferenceIds.TryRead(second!.Value, out var secondEntries), Is.True);
            Assert.That(secondEntries, Is.EqualTo(new[] { list.Entries[1] }));

            Assert.Multiple(() => {
                Assert.That(list.TryAnswer(NTPv5ReferenceIds.Request(Index: 30, Entries: 2), out _), Is.True,  "the last two");
                Assert.That(list.TryAnswer(NTPv5ReferenceIds.Request(Index: 31, Entries: 2), out _), Is.False, "one past the end");
                Assert.That(list.TryAnswer(new NTPv5ExtensionField(NTPv5ExtensionTypes.ReferenceIDsRequest, new Byte[12]), out _), Is.False, "12 octets are no whole number of entries");
                Assert.That(list.TryAnswer(new NTPv5ExtensionField(NTPv5ExtensionTypes.ReferenceIDsRequest, []),           out _), Is.False, "no room for an entry");
            });

        }

        #endregion

    }

}
