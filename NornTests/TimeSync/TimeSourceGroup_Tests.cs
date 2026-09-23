/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Norn <https://www.github.com/Vanaheimr/Norn>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;
using org.GraphDefined.Vanaheimr.Norn.TimeSync;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.TimeSync
{

    /// <summary>
    /// What a group of time sources concludes from a round of measurements.
    /// </summary>
    /// <remarks>
    /// Measurements are built here rather than fetched, because the decision is
    /// the thing under test: a rule about a handful of offsets, one of which is
    /// a liar. Asking real servers would test the internet.
    /// </remarks>
    [TestFixture]
    public class TimeSourceGroup_Tests
    {

        #region (private) Answer(Name, OffsetMilliseconds, Trustworthy)

        private static NTSMeasurementResult Answer(String    Name,
                                                   Double    OffsetMilliseconds,
                                                   Boolean   Authenticated       = true,
                                                   Boolean   Succeeded           = true)

            => new (DomainName.Parse(Name),
                    Guid.Empty) {

                   Success  = Succeeded,
                   NTP      = new NTPMeasurementResult {
                                  Success                 = Succeeded,
                                  NTSAuthenticationValid  = Authenticated,
                                  Offset                  = TimeSpan.FromMilliseconds(OffsetMilliseconds)
                              }

               };

        private static NTSMeasurementResult Silence(String Name)

            => new (DomainName.Parse(Name),
                    Guid.Empty) {
                   Success = false
               };

        private static NTSServerEndpoint Source(String Name, Byte Priority, Boolean Enabled = true)
            => new (DomainName.Parse(Name), Priority: Priority, Enabled: Enabled);

        private static readonly TimeSpan oneMinute = TimeSpan.FromSeconds(60);

        #endregion


        #region OneLiarDoesNotMoveTheAnswer()

        /// <summary>
        /// Three servers, one of them badly wrong.
        /// </summary>
        /// <remarks>
        /// The reason for asking several servers rather than one, and the reason
        /// the median was chosen over the mean: the mean of 10, 12 and 5000 ms is
        /// over 1.6 seconds, which is a clock set by whichever server is most
        /// wrong. The median ignores it for as long as it is outnumbered.
        /// </remarks>
        [Test]
        public void OneLiarDoesNotMoveTheAnswer()
        {

            var verdict = TimeSyncVerdict.From(
                              [ Answer("a", 10), Answer("b", 12), Answer("c", 5000) ],
                              MinServers:    2,
                              MaxDeviation:  oneMinute
                          );

            Assert.Multiple(() =>
            {
                Assert.That(verdict.IsUsable,                       Is.True);
                Assert.That(verdict.Offset?.TotalMilliseconds,      Is.EqualTo(12),    "the mean would have been over 1600 ms");
                Assert.That(verdict.Answered,                       Is.EqualTo(3));
                Assert.That(verdict.Spread?.TotalMilliseconds,      Is.EqualTo(4990),  "and the disagreement is still reported");
            });

        }

        #endregion

        #region AnEvenNumberOfAnswersIsAveragedInTheMiddle()

        [Test]
        public void AnEvenNumberOfAnswersIsAveragedInTheMiddle()
        {

            var verdict = TimeSyncVerdict.From(
                              [ Answer("a", 10), Answer("b", 20), Answer("c", 30), Answer("d", 400) ],
                              MinServers:    2,
                              MaxDeviation:  oneMinute
                          );

            Assert.That(verdict.Offset?.TotalMilliseconds,  Is.EqualTo(25),  "the two in the middle are 20 and 30");

        }

        #endregion

        #region AnUnauthenticatedAnswerIsNotAnAnswer()

        /// <summary>
        /// An NTP reply that did not authenticate is a reply from nobody in
        /// particular, however plausible its number looks.
        /// </summary>
        /// <remarks>
        /// The offsets here are chosen so that counting the unauthenticated one
        /// would change the result rather than merely the count: with it the
        /// median of 10, 11 and 12 is 11, without it the median of 10 and 12 is
        /// also 11 - so instead it is given a value far away, where including it
        /// moves the answer and the test can tell.
        /// </remarks>
        [Test]
        public void AnUnauthenticatedAnswerIsNotAnAnswer()
        {

            var verdict = TimeSyncVerdict.From(
                              [ Answer("a", 10), Answer("b", 12), Answer("liar", 9000, Authenticated: false) ],
                              MinServers:    2,
                              MaxDeviation:  oneMinute
                          );

            Assert.Multiple(() =>
            {
                Assert.That(verdict.Answered,                   Is.EqualTo(2),  "the unauthenticated answer was counted");
                Assert.That(verdict.Offset?.TotalMilliseconds,  Is.EqualTo(11), "the unauthenticated answer reached the median");
            });

        }

        #endregion

        #region TooFewAnswersIsNoTime()

        /// <summary>
        /// A quorum that is not met produces no offset at all, rather than a
        /// worse one.
        /// </summary>
        [Test]
        public void TooFewAnswersIsNoTime()
        {

            var verdict = TimeSyncVerdict.From(
                              [ Answer("a", 10), Silence("b"), Silence("c") ],
                              MinServers:    2,
                              MaxDeviation:  oneMinute
                          );

            Assert.Multiple(() =>
            {
                Assert.That(verdict.Outcome,   Is.EqualTo(TimeSyncOutcome.TooFewServers));
                Assert.That(verdict.IsUsable,  Is.False);
                Assert.That(verdict.Offset,    Is.Null,        "an offset was offered although the quorum failed");
                Assert.That(verdict.Answered,  Is.EqualTo(1));
                Assert.That(verdict.Required,  Is.EqualTo(2));
            });

        }

        #endregion

        #region SilenceIsToldApartFromTooFew()

        /// <summary>
        /// "Nobody answered" and "not enough answered" are different things to
        /// go and look at.
        /// </summary>
        [Test]
        public void SilenceIsToldApartFromTooFew()
        {

            var verdict = TimeSyncVerdict.From(
                              [ Silence("a"), Silence("b") ],
                              MinServers:    2,
                              MaxDeviation:  oneMinute
                          );

            Assert.That(verdict.Outcome,  Is.EqualTo(TimeSyncOutcome.NothingAnswered));

        }

        #endregion

        #region DisagreementIsRecordedButNotRefused()

        /// <summary>
        /// Beyond MaxDeviation the spread must be written down - and the time is
        /// still a time.
        /// </summary>
        /// <remarks>
        /// The white paper asks for the discrepancy to be recorded in the secure
        /// metrological log book. It does not ask for the measurement to be
        /// thrown away, and turning "write this down" into "refuse to
        /// synchronize" would be a stricter rule than the specified one, adopted
        /// quietly. This test is what keeps it from being adopted by accident.
        /// </remarks>
        [Test]
        public void DisagreementIsRecordedButNotRefused()
        {

            var verdict = TimeSyncVerdict.From(
                              [ Answer("a", 0), Answer("b", 90_000) ],
                              MinServers:    2,
                              MaxDeviation:  oneMinute
                          );

            Assert.Multiple(() =>
            {
                Assert.That(verdict.DeviationExceeded,  Is.True,  "90 seconds apart went unrecorded");
                Assert.That(verdict.IsUsable,           Is.True,  "a disagreement to be logged was turned into a refusal");
            });

        }

        #endregion

        #region TheVerdictReadsTheSameUnderEveryCulture()

        /// <summary>
        /// The half sentence a log line ends with keeps its decimal point under
        /// a culture that writes a comma.
        /// </summary>
        /// <remarks>
        /// The sentence is English and goes into log books. Under de-DE it used
        /// to read "+2,5 ms from 3 server(s), spread 2,0 ms".
        /// </remarks>
        [Test]
        [SetCulture("de-DE")]
        public void TheVerdictReadsTheSameUnderEveryCulture()
        {

            var verdict = TimeSyncVerdict.From(
                              [ Answer("a", 1.5), Answer("b", 2.5), Answer("c", 3.5) ],
                              MinServers:    2,
                              MaxDeviation:  oneMinute
                          );

            Assert.That(verdict.ToString(),  Is.EqualTo("+2.5 ms from 3 server(s), spread 2.0 ms"));

        }

        #endregion

        #region BandsAreAskedLowestPriorityFirst()

        /// <summary>
        /// Servers sharing a priority form one band, and the bands run from the
        /// lowest priority upwards.
        /// </summary>
        [Test]
        public void BandsAreAskedLowestPriorityFirst()
        {

            var group = new TimeSourceGroup(
                            "legal",
                            [
                                Source("far1",   9),
                                Source("near1",  1),
                                Source("far2",   9),
                                Source("near2",  1),
                                Source("off",    0, Enabled: false)
                            ],
                            MinServers: 2
                        );

            var bands = group.Bands();

            Assert.Multiple(() =>
            {
                Assert.That(bands,  Has.Count.EqualTo(2),  "the disabled source made a band of its own");

                // Dotted, because a DomainName prints itself fully qualified and
                // the root label is part of that.
                Assert.That(bands[0].Select(source => source.Hostname.ToString()),  Is.EquivalentTo(new[] { "near1.", "near2." }));
                Assert.That(bands[1].Select(source => source.Hostname.ToString()),  Is.EquivalentTo(new[] { "far1.",  "far2."  }));
            });

        }

        #endregion

        #region ABandTooSmallForTheQuorumIsVisibleBeforeItMatters()

        /// <summary>
        /// A single fallback behind a pair, under a quorum of two, can never
        /// answer on its own - and that is readable from the configuration
        /// rather than only from an outage.
        /// </summary>
        [Test]
        public void ABandTooSmallForTheQuorumIsVisibleBeforeItMatters()
        {

            var group = new TimeSourceGroup(
                            "legal",
                            [ Source("a", 1), Source("b", 1), Source("lonely", 2) ],
                            MinServers: 2
                        );

            var bands = group.Bands();

            Assert.Multiple(() =>
            {
                Assert.That(bands,             Has.Count.EqualTo(2));
                Assert.That(bands[1],          Has.Count.LessThan(group.MinServers),  "this is the arrangement the test is about");
                Assert.That(group.ToString(),  Does.Contain("2 band(s)"));
            });

        }

        #endregion

    }

}
