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
using org.GraphDefined.Vanaheimr.Hermod.DNS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// The complete result of a single NTS measurement against one server.
    /// Captures NTS-KE handshake, NTP query, DNS resolution, and derived metrics.
    /// </summary>
    public class NTSMeasurementResult
    {

        #region Properties

        // ──────────────────────── Identification ────────────────────────

        /// <summary>
        /// Unique ID for this measurement.
        /// </summary>
        public Guid                          MeasurementId             { get; }

        /// <summary>
        /// The hostname of the NTS server that was measured.
        /// </summary>
        public DomainName                    ServerHostname            { get; }

        /// <summary>
        /// Timestamp (UTC) when this measurement was initiated.
        /// </summary>
        public DateTimeOffset                Timestamp                 { get; }

        /// <summary>
        /// The ID of the measurement round this belongs to.
        /// All 4 server measurements in the same round share this ID.
        /// </summary>
        public Guid                          RoundId                   { get; }


        // ──────────────────────── DNS Resolution ────────────────────────

        /// <summary>
        /// DNS resolution result.
        /// </summary>
        public DNSResolutionResult?          DNS                       { get; init; }


        // ──────────────────────── NTS-KE (Key Establishment) ────────────

        /// <summary>
        /// NTS-KE handshake result. Null if we reused cached cookies.
        /// </summary>
        public NTSKEMeasurementResult?       NTSKE                     { get; init; }

        /// <summary>
        /// Whether the NTS-KE result was from cache (reused cookies from prior round).
        /// </summary>
        public Boolean                       NTSKEFromCache            { get; init; }


        // ──────────────────────── NTP Query ─────────────────────────────

        /// <summary>
        /// The NTP query result.
        /// </summary>
        public NTPMeasurementResult?         NTP                       { get; init; }


        // ──────────────────────── Overall Status ────────────────────────

        /// <summary>
        /// Whether the complete measurement (DNS + NTS-KE + NTP) succeeded.
        /// </summary>
        public Boolean                       Success                   { get; init; }

        /// <summary>
        /// Overall error message if something failed.
        /// </summary>
        public String?                       ErrorMessage              { get; init; }

        /// <summary>
        /// Total wall-clock duration of the entire measurement against this server.
        /// </summary>
        public TimeSpan                      TotalDuration             { get; init; }

        #endregion

        #region Constructor(s)

        public NTSMeasurementResult(DomainName       ServerHostname,
                                    Guid             RoundId,
                                    Guid?            MeasurementId   = null,
                                    DateTimeOffset?  Timestamp       = null)
        {

            this.ServerHostname  = ServerHostname;
            this.RoundId         = RoundId;
            this.MeasurementId   = MeasurementId ?? UUIDv7.Generate();
            this.Timestamp       = Timestamp     ?? Illias.Timestamp.Now;

        }

        #endregion


        #region ToJSON()

        public JObject ToJSON()
        {

            var json = JSONObject.Create(

                                 new JProperty("measurementId",     MeasurementId.ToString()),
                                 new JProperty("serverHostname",    ServerHostname),
                                 new JProperty("timestamp",         Timestamp.    ToString("o")),
                                 new JProperty("roundId",           RoundId.      ToString()),
                                 new JProperty("success",           Success),
                                 new JProperty("totalDurationMs",   Math.Round(TotalDuration.TotalMilliseconds, 3)),

                           ErrorMessage is not null
                               ? new JProperty("errorMessage",      ErrorMessage)
                               : null,

                           DNS          is not null
                               ? new JProperty("dns",               DNS.          ToJSON())
                               : null,

                           NTSKE        is not null
                               ? new JProperty("ntsKE",             NTSKE.        ToJSON())
                               : null,

                                 new JProperty("ntsKEFromCache",    NTSKEFromCache),

                           NTP          is not null
                               ? new JProperty("ntp",               NTP.          ToJSON())
                               : null

                       );

            return json;

        }

        #endregion

    }

}
