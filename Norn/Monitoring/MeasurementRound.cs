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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// A measurement round represents one parallel measurement of all monitored servers.
    /// All servers are queried simultaneously to allow meaningful inter-server comparison.
    /// </summary>
    public class MeasurementRound(String                               DroneId,
                                  IReadOnlyList<NTSMeasurementResult>  ServerResults,
                                  Guid?                                RoundId     = null,
                                  DateTimeOffset?                      Timestamp   = null)
    {

        #region Properties

        /// <summary>
        /// Unique identifier for this round.
        /// </summary>
        public Guid                                    RoundId                { get; } = RoundId   ?? UUIDv7.Generate();

        /// <summary>
        /// Timestamp when this round started.
        /// </summary>
        public DateTimeOffset                          Timestamp              { get; } = Timestamp ?? Illias.Timestamp.Now;

        /// <summary>
        /// The drone that performed this measurement.
        /// </summary>
        public String                                  DroneId                { get; } = DroneId;

        /// <summary>
        /// The location tag of this drone (for geographic correlation).
        /// </summary>
        public String?                                 DroneLocation          { get; init; }

        /// <summary>
        /// Individual server measurement results.
        /// </summary>
        public IReadOnlyList<NTSMeasurementResult>     ServerResults          { get; } = ServerResults;

        /// <summary>
        /// Total wall-clock time for the entire round (including the slowest server).
        /// </summary>
        public TimeSpan                                TotalDuration          { get; init; }


        // ──────────── Derived Inter-Server Metrics ──────────────

        /// <summary>
        /// Pairwise offset differences between servers (for consistency check).
        /// Key: "serverA↔serverB", Value: offset difference in ms.
        /// Only computed when both servers succeeded.
        /// </summary>
        public IReadOnlyDictionary<String, TimeSpan>?  InterServerOffsets     { get; init; }

        /// <summary>
        /// Maximum pairwise offset difference between any two servers.
        /// </summary>
        public TimeSpan?                               MaxInterServerDelta    { get; init; }

        /// <summary>
        /// Number of servers that responded successfully.
        /// </summary>
        public UInt16                                  ServersReachable
            => (UInt16) ServerResults.Count(r => r.Success);

        /// <summary>
        /// Number of servers at Stratum 1.
        /// </summary>
        public UInt16                                  ServersAtStratum1
            => (UInt16) ServerResults.Count(r => r.Success && r.NTP?.Stratum == 1);

        #endregion


        #region ComputeInterServerOffsets()

        /// <summary>
        /// Compute pairwise offset differences between all successful server measurements.
        /// Returns a new MeasurementRound with the computed values.
        /// </summary>
        public MeasurementRound WithInterServerMetrics()
        {

            var successfulResults  = ServerResults.Where(r => r.Success && r.NTP is not null).ToList();
            var offsets            = new Dictionary<String, TimeSpan>();
            var maxDelta           = TimeSpan.Zero;

            for (var i = 0; i < successfulResults.Count; i++)
            {
                for (var j = i + 1; j < successfulResults.Count; j++)
                {

                    var a         = successfulResults[i];
                    var b         = successfulResults[j];
                    var key       = $"{a.ServerHostname}↔{b.ServerHostname}";
                    var delta     = TimeSpan.FromMilliseconds(Math.Abs(a.NTP!.Offset.TotalMilliseconds - b.NTP!.Offset.TotalMilliseconds));

                    offsets[key]  = delta;//Math.Round(delta, 6));

                    if (delta > maxDelta)
                        maxDelta = delta;

                }
            }

            return new MeasurementRound(
                       DroneId,
                       ServerResults,
                       RoundId,
                       Timestamp
                   ) {
                       DroneLocation        = this.DroneLocation,
                       TotalDuration        = this.TotalDuration,
                       InterServerOffsets   = offsets,
                       MaxInterServerDelta  = offsets.Count > 0
                                                  ? maxDelta//Math.Round(maxDelta, 6)
                                                  : null
                   };

        }

        #endregion


        #region ToJSON()

        public JObject ToJSON()
        {

            var json = JSONObject.Create(

                                 new JProperty("roundId",                 RoundId.ToString()),
                                 new JProperty("timestamp",               Timestamp.ToString("o")),
                                 new JProperty("droneId",                 DroneId),
                                 new JProperty("totalDurationMs",         Math.Round(TotalDuration.TotalMilliseconds, 3)),
                                 new JProperty("serversReachable",        ServersReachable),
                                 new JProperty("serversAtStratum1",       ServersAtStratum1),
                                 new JProperty("serverResults",           new JArray(ServerResults.Select(ntsMeasurementResult => ntsMeasurementResult.ToJSON()))),

                           DroneLocation is not null
                               ? new JProperty("droneLocation",           DroneLocation)
                               : null,

                           InterServerOffsets is not null && InterServerOffsets.Count > 0
                               ? new JProperty("interServerOffsetsMs",    JObject.FromObject(InterServerOffsets))
                               : null,

                           MaxInterServerDelta.HasValue
                               ? new JProperty("maxInterServerDeltaMs",   MaxInterServerDelta.Value)
                               : null

                       );

            return json;

        }

        #endregion

    }

}
