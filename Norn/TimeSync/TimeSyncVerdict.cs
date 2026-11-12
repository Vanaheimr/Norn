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

using System.Globalization;

using org.GraphDefined.Vanaheimr.Norn.Monitoring;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.TimeSync
{

    /// <summary>
    /// Whether a group of time sources produced a time that may be used.
    /// </summary>
    public enum TimeSyncOutcome
    {

        /// <summary>
        /// Nobody answered in a way that could be trusted.
        /// </summary>
        NothingAnswered,

        /// <summary>
        /// Somebody answered, but fewer than the group insists on.
        /// </summary>
        TooFewServers,

        /// <summary>
        /// Enough servers answered, and they do not agree: no majority of them lies
        /// within the group's MaxDeviation of one another, or that majority is
        /// smaller than the number the group insists on. There is no time here -
        /// only several, and nothing to choose between them by.
        /// </summary>
        ServersDisagree,

        /// <summary>
        /// Enough servers answered and agreed well enough to steer a clock by.
        /// </summary>
        Usable

    }


    /// <summary>
    /// What a group of time sources concluded from one round of measurements.
    /// </summary>
    /// <remarks>
    /// Carries both halves on purpose: the answer a clock needs - may I use
    /// this, and by how much am I off - and the individual measurements that
    /// produced it, because a metrological log book records what was asked and
    /// what each one said, not merely the conclusion.
    /// </remarks>
    public class TimeSyncVerdict
    {

        #region Properties

        /// <summary>
        /// Whether this round produced a usable time.
        /// </summary>
        public TimeSyncOutcome                      Outcome            { get; }

        /// <summary>
        /// The offset to apply, or none when there is nothing to apply.
        /// </summary>
        /// <remarks>
        /// The median of the answers rather than their mean. One server that is
        /// wrong - broken, lying, or merely far away through a congested link -
        /// moves a mean by as much as it is wrong, and moves a median by nothing
        /// at all as long as it is outnumbered. That is the entire reason for
        /// asking several servers.
        ///
        /// Where the answers lie further apart than MaxDeviation, it is the median
        /// of those that agree, and there is one only if they are the majority.
        /// </remarks>
        public TimeSpan?                            Offset             { get; }

        /// <summary>
        /// How far apart the answers were: the widest gap between any two.
        /// </summary>
        public TimeSpan?                            Spread             { get; }

        /// <summary>
        /// Whether that gap reached the group's MaxDeviation and must therefore
        /// be recorded in the secure metrological log book.
        /// </summary>
        /// <remarks>
        /// The white paper asks for it to be recorded, and it is recorded whatever
        /// the outcome. Whether there is still a time is another question, and
        /// <see cref="Agreeing"/> answers it: a majority that agrees outvotes the
        /// rest, and the round is usable with this flag set. Without such a
        /// majority the outcome is <see cref="TimeSyncOutcome.ServersDisagree"/>.
        /// This is the "Agreement" rule of section 3.2.3 of the white paper. It
        /// used to ask for the spread to be recorded only: the median of two
        /// servers ninety seconds apart is a time neither of them gave, and
        /// "usable" was the wrong word for it.
        /// </remarks>
        public Boolean                              DeviationExceeded  { get; }

        /// <summary>
        /// How many of the answers agree: the size of the largest set of them that
        /// lie within MaxDeviation of one another. All of them, where the spread
        /// stayed below it.
        /// </summary>
        public Int32                                Agreeing           { get; }

        /// <summary>
        /// How many servers answered in a way that could be trusted.
        /// </summary>
        public Int32                                Answered           { get; }

        /// <summary>
        /// How many the group insisted on.
        /// </summary>
        public Int32                                Required           { get; }

        /// <summary>
        /// Every measurement of this round, trusted or not.
        /// </summary>
        public IReadOnlyList<NTSMeasurementResult>  Results            { get; }


        /// <summary>
        /// Whether a clock may be steered by this.
        /// </summary>
        public Boolean IsUsable
            => Outcome == TimeSyncOutcome.Usable;

        #endregion

        #region Constructor(s)

        private TimeSyncVerdict(TimeSyncOutcome                      Outcome,
                                TimeSpan?                            Offset,
                                TimeSpan?                            Spread,
                                Boolean                              DeviationExceeded,
                                Int32                                Answered,
                                Int32                                Required,
                                IReadOnlyList<NTSMeasurementResult>  Results,
                                Int32?                               Agreeing   = null)
        {

            this.Outcome            = Outcome;
            this.Offset             = Offset;
            this.Spread             = Spread;
            this.DeviationExceeded  = DeviationExceeded;
            this.Answered           = Answered;
            this.Agreeing           = Agreeing ?? Answered;
            this.Required           = Required;
            this.Results            = Results;

        }

        #endregion


        #region (static) CanBeTrusted(Result)

        /// <summary>
        /// Whether one measurement may take part in deciding the time.
        /// </summary>
        /// <remarks>
        /// The authentication check is not a formality here. An NTP answer that
        /// did not authenticate is an answer from nobody in particular, and the
        /// whole point of NTS is that such an answer never reaches the clock -
        /// so it does not reach the median either, however plausible it looks.
        ///
        /// Nor does the answer of a server that says its own clock is not
        /// synchronized - leap indicator 3, or a stratum of 0 or of 16 and
        /// above - although nothing here asks: NTSResponseValidator turns it
        /// into a failed query long before it is a measurement.
        /// </remarks>
        public static Boolean CanBeTrusted(NTSMeasurementResult Result)

            => Result.Success                          &&
               Result.NTP is not null                  &&
               Result.NTP.Success                      &&
               Result.NTP.NTSAuthenticationValid;

        #endregion

        #region (static) From(Results, MinServers, MaxDeviation)

        /// <summary>
        /// Decide what a round of measurements amounts to.
        /// </summary>
        /// <param name="Results">The measurements of one round.</param>
        /// <param name="MinServers">How many trustworthy answers the group insists on.</param>
        /// <param name="MaxDeviation">The gap at which the spread must be written down.</param>
        public static TimeSyncVerdict From(IReadOnlyList<NTSMeasurementResult>  Results,
                                           Byte                                 MinServers,
                                           TimeSpan                             MaxDeviation)
        {

            var required  = Math.Max((Int32) MinServers, 1);
            var offsets   = Results.Where (CanBeTrusted).
                                    Select(result => result.NTP!.Offset).
                                    Order().
                                    ToArray();

            if (offsets.Length == 0)
                return new TimeSyncVerdict(
                           TimeSyncOutcome.NothingAnswered,
                           null,
                           null,
                           false,
                           0,
                           required,
                           Results
                       );

            var spread             = offsets[^1] - offsets[0];
            var deviationExceeded  = spread >= MaxDeviation;

            if (offsets.Length < required)
                return new TimeSyncVerdict(
                           TimeSyncOutcome.TooFewServers,
                           null,
                           spread,
                           deviationExceeded,
                           offsets.Length,
                           required,
                           Results
                       );

            // Those that agree: the longest run of the sorted answers that stays within
            // MaxDeviation from its first to its last. Everything, as a rule.
            var agreeingFrom   = 0;
            var agreeingCount  = offsets.Length;

            if (deviationExceeded)
            {

                agreeingCount = 1;

                for (Int32 first = 0, last = 0; last < offsets.Length; last++)
                {

                    while (offsets[last] - offsets[first] >= MaxDeviation && first < last)
                        first++;

                    if (last - first + 1 > agreeingCount)
                    {
                        agreeingFrom   = first;
                        agreeingCount  = last - first + 1;
                    }

                }

                // They have to be more than half, or it is not they who are outvoted
                // by the rest but the rest by them - and as many as the group insists
                // on, because the others have said nothing that could be used.
                if (agreeingCount * 2 <= offsets.Length ||
                    agreeingCount     <  required)
                {
                    return new TimeSyncVerdict(
                               TimeSyncOutcome.ServersDisagree,
                               null,
                               spread,
                               deviationExceeded,
                               offsets.Length,
                               required,
                               Results,
                               agreeingCount
                           );
                }

            }

            // Sorted above, so the middle one is the median. With an even count
            // there is no middle one and the two either side are averaged, which
            // is the usual reading of a median and keeps two servers from having
            // to agree exactly before their answer can be used.
            var agreeing  = offsets.AsSpan(agreeingFrom, agreeingCount);

            var median    = agreeing.Length % 2 == 1
                                ? agreeing[agreeing.Length / 2]
                                : (agreeing[agreeing.Length / 2 - 1] + agreeing[agreeing.Length / 2]) / 2;

            return new TimeSyncVerdict(
                       TimeSyncOutcome.Usable,
                       median,
                       spread,
                       deviationExceeded,
                       offsets.Length,
                       required,
                       Results,
                       agreeingCount
                   );

        }

        #endregion


        #region (override) ToString()

        /// <summary>
        /// The verdict as the half sentence a log line ends with.
        /// </summary>
        /// <remarks>
        /// Invariant, because the sentence is English and ends up in log books:
        /// under a German culture it read "+702,4 ms from 4 server(s), spread
        /// 0,5 ms", a decimal comma in the middle of an English sentence, and a
        /// log whose numbers change their punctuation with the machine that
        /// wrote them.
        /// </remarks>
        public override String ToString()

            => Outcome switch {
                   TimeSyncOutcome.Usable           => String.Create(CultureInfo.InvariantCulture, $"{Offset!.Value.TotalMilliseconds:+0.0;-0.0} ms from {Answered} server(s), spread {Spread!.Value.TotalMilliseconds:0.0} ms{(DeviationExceeded ? $" - beyond the agreed deviation, {Agreeing} agree" : "")}"),
                   TimeSyncOutcome.ServersDisagree  => String.Create(CultureInfo.InvariantCulture, $"{Answered} server(s) answered and disagree: spread {Spread!.Value.TotalMilliseconds:0.0} ms, {Agreeing} within the agreed deviation"),
                   TimeSyncOutcome.TooFewServers    => $"only {Answered} of {Required} server(s) answered",
                   _                                => "no server answered"
               };

        #endregion

    }

}
