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

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.TimeSync
{

    /// <summary>
    /// A set of time sources asked together, and the rules for believing them.
    /// </summary>
    /// <remarks>
    /// The arrangement described by the Secure Time Synchronization white paper:
    /// servers carry a priority, the lowest priority is asked first, servers
    /// sharing a priority are asked at the same time, and a group needs a
    /// minimum number of trustworthy answers before it has a time at all.
    ///
    /// The white paper names two groups, and the names are worth keeping: a
    /// "legal" group for billing and tariffs, which is asked rarely and held to
    /// a quorum, and a "local" group for load balancing, which is asked often
    /// and may be a single server on the same site. They differ in how often
    /// they are asked and in how much they have to agree, not in mechanism.
    ///
    /// The measuring itself is Norn's existing engine. This adds the part the
    /// engine has no opinion about: which servers to ask first, when to stop
    /// asking, and whether what came back is a time or merely data.
    /// </remarks>
    public class TimeSourceGroup
    {

        #region Data

        private readonly List<NTSServerEndpoint> sources;

        #endregion

        #region Properties

        /// <summary>
        /// What this group is for. "legal" and "local" are the well-known ones.
        /// </summary>
        public String                          Name          { get; }

        /// <summary>
        /// The servers of this group, in no particular order - the priorities
        /// decide the order, not the list.
        /// </summary>
        public IEnumerable<NTSServerEndpoint>  Sources
            => sources;

        /// <summary>
        /// How many servers must answer trustworthily for this group to have a
        /// time.
        /// </summary>
        /// <remarks>
        /// One is a group that believes whoever answers. Two is the smallest
        /// number that can notice a server disagreeing with the world, and the
        /// white paper's recommended value for a legal group.
        /// </remarks>
        public Byte                            MinServers    { get; }

        /// <summary>
        /// The gap between answers at which the disagreement must be written
        /// into the secure metrological log book.
        /// </summary>
        public TimeSpan                        MaxDeviation  { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new group of time sources.
        /// </summary>
        /// <param name="Name">What this group is for, e.g. "legal" or "local".</param>
        /// <param name="Sources">Its servers.</param>
        /// <param name="MinServers">How many must answer for the group to have a time (default: 1).</param>
        /// <param name="MaxDeviation">The gap at which their disagreement is recorded (default: 60 seconds).</param>
        public TimeSourceGroup(String                          Name,
                               IEnumerable<NTSServerEndpoint>  Sources,
                               Byte?                           MinServers     = null,
                               TimeSpan?                       MaxDeviation   = null)
        {

            this.Name          = Name;
            this.sources       = [.. Sources];
            this.MinServers    = MinServers   ?? 1;
            this.MaxDeviation  = MaxDeviation ?? TimeSpan.FromSeconds(60);

        }

        #endregion


        #region Bands()

        /// <summary>
        /// The enabled servers, gathered into the bands they will be asked in.
        /// </summary>
        /// <remarks>
        /// Public because it is worth being able to see what a group would do
        /// before it does it - a configuration whose second band can never meet
        /// the quorum is a thing to discover while reading it, not at three in
        /// the morning when the first band goes away.
        /// </remarks>
        public IReadOnlyList<IReadOnlyList<NTSServerEndpoint>> Bands()

            => [.. sources.
                       Where  (source => source.Enabled).
                       GroupBy(source => source.Priority).
                       OrderBy(band   => band.Key).
                       Select (band   => (IReadOnlyList<NTSServerEndpoint>) [.. band])];

        #endregion

        #region Measure(Engine, DNSClient, CancellationToken)

        /// <summary>
        /// Ask this group for the time.
        /// </summary>
        /// <remarks>
        /// Band by band, stopping at the first one that produces a usable time.
        /// A band that cannot reach the quorum - because it holds fewer servers
        /// than MinServers, or because too few of them answered - is not a
        /// failure of the group; it is a reason to ask the next one. The group
        /// has failed only when the last band has been asked.
        ///
        /// What comes back when every band failed is the verdict of the last
        /// band asked, not an empty one, because "the fallback answered once
        /// and I needed two" is a different thing to debug than "nothing
        /// answered at all", and both are worth telling apart in a log book.
        /// </remarks>
        /// <param name="Engine">The measurement engine doing the asking.</param>
        /// <param name="DNSClient">How names are resolved.</param>
        public async Task<TimeSyncVerdict> Measure(MeasurementEngine  Engine,
                                                   DNSClient          DNSClient,
                                                   CancellationToken  CancellationToken = default)
        {

            TimeSyncVerdict? lastVerdict = null;

            foreach (var band in Bands())
            {

                var round    = await Engine.MeasureServersParallel(band, DNSClient, CancellationToken);
                var verdict  = TimeSyncVerdict.From(round.ServerResults, MinServers, MaxDeviation);

                if (verdict.IsUsable)
                    return verdict;

                lastVerdict = verdict;

            }

            return lastVerdict ?? TimeSyncVerdict.From([], MinServers, MaxDeviation);

        }

        #endregion


        #region (override) ToString()

        public override String ToString()

            => $"'{Name}': {sources.Count(source => source.Enabled)} source(s) in {Bands().Count} band(s), at least {MinServers} must answer";

        #endregion

    }

}
