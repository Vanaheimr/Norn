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

using Newtonsoft.Json;
using System.Diagnostics.CodeAnalysis;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// Configuration for a monitoring.
    /// </summary>
    public class MonitoringConfig
    {

        #region Properties

        /// <summary>
        /// Unique drone identifier.
        /// </summary>
        public String                      DroneId                    { get; set; } = $"drone-{Environment.MachineName.ToLower()}";

        /// <summary>
        /// Human-readable location tag (e.g., "Jena-DE", "AWS-EU-Central-1").
        /// </summary>
        public String?                     DroneLocation              { get; set; }

        /// <summary>
        /// The NTS servers to monitor.
        /// </summary>
        public HashSet<NTSServerEndpoint>  Servers                    { get; }      = [];

        /// <summary>
        /// Base measurement interval between rounds.
        /// Actual interval = Poisson-distributed with this as the mean.
        /// </summary>
        public TimeSpan                    MeasurementInterval        { get; set; } = TimeSpan.FromSeconds(60);

        /// <summary>
        /// NTS-KE refresh interval.
        /// Cookies are cached and only refreshed at this interval to reduce load.
        /// Each NTS-KE provides ~8 cookies; use one per NTP query and refresh when pool is low.
        /// </summary>
        public TimeSpan                    NTSKERefreshInterval       { get; set; } = TimeSpan.FromMinutes(30);

        /// <summary>
        /// DNS resolution check interval (less frequent than NTP queries).
        /// </summary>
        public TimeSpan                    DNSCheckInterval           { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Timeout for individual NTP queries.
        /// </summary>
        public TimeSpan                    NTPTimeout                 { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>
        /// Timeout for NTS-KE handshake (TLS + protocol).
        /// </summary>
        public TimeSpan                    NTSKETimeout               { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Backend URL to POST measurement results.
        /// </summary>
        public String?                     BackendUrl                 { get; set; }

        /// <summary>
        /// Optional API key for backend authentication.
        /// </summary>
        public String?                     BackendAPIKey              { get; set; }

        /// <summary>
        /// Maximum number of rounds to buffer locally when backend is unreachable.
        /// </summary>
        public Int32                       MaxLocalBufferSize         { get; set; } = 10000;

        /// <summary>
        /// Path for local JSON-Lines log of measurement results.
        /// </summary>
        public String                      LocalLogPath               { get; set; } = "measurements.jsonl";

        /// <summary>
        /// Whether to use Poisson-distributed measurement timing (recommended).
        /// If false, uses fixed intervals with ±25% jitter.
        /// </summary>
        public Boolean                     UsePoissonTiming           { get; set; } = true;

        /// <summary>
        /// Alert thresholds for measurement evaluation.
        /// </summary>
        public AlertThresholds             Alerts                     { get; set; } = new();
 

        #endregion


        #region TryLoadFromFile(Path, out MonitoringConfig)

        public static Boolean TryLoadFromFile(String                                     Path,
                                              [NotNullWhen(true)] out MonitoringConfig?  MonitoringConfig)
        {
            try
            {

                MonitoringConfig = JsonConvert.DeserializeObject<MonitoringConfig>(
                                       File.ReadAllText(Path)
                                   );

                return MonitoringConfig is not null;

            }
            catch {
                MonitoringConfig = null;
                return false;
            }

        }

        #endregion

        #region SaveToFile(Path)

        public void SaveToFile(String Path)
        {
            File.WriteAllText(Path, JsonConvert.SerializeObject(this, Formatting.Indented));
        }

        #endregion

    }

}
