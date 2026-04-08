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
    /// Configurable alert thresholds for measurement evaluation.
    ///
    /// All time-based thresholds can be tuned depending on the drone's
    /// network distance to the monitored servers. A drone in the same
    /// data center should use much tighter thresholds than one across
    /// the internet.
    /// </summary>
    public class AlertThresholds
    {
 
        // ──────────── Inter-Server Consistency ──────────────
 
        /// <summary>
        /// Maximum inter-server offset delta considered normal (green).
        /// Default: 30ms — typical jitter for ~110ms RTT to PTB from Germany.
        /// For same-datacenter drones, set to 0.1ms or lower.
        /// </summary>
        public Double    InterServerDeltaWarningMs      { get; set; } = 30.0;
 
        /// <summary>
        /// Maximum inter-server offset delta before critical alert (red).
        /// Default: 60ms — indicates a likely server-side problem.
        /// </summary>
        public Double    InterServerDeltaCriticalMs     { get; set; } = 60.0;
 
 
        // ──────────── Offset (Clock Difference) ──────────────
 
        /// <summary>
        /// Absolute offset above which to warn (yellow).
        /// Note: This measures the drone's own clock vs. the server.
        /// For monitoring the *servers* against each other, use InterServerDelta.
        /// Default: 300ms.
        /// </summary>
        public Double    OffsetWarningMs                { get; set; } = 300.0;
 
        /// <summary>
        /// Absolute offset above which to alert critically (red).
        /// Default: 1000ms.
        /// </summary>
        public Double    OffsetCriticalMs               { get; set; } = 1000.0;
 
 
        // ──────────── Round-Trip Time ──────────────
 
        /// <summary>
        /// RTT above which to warn. Indicates network degradation.
        /// Default: 200ms.
        /// </summary>
        public Double    RTTWarningMs                   { get; set; } = 200.0;
 
        /// <summary>
        /// RTT above which to alert critically.
        /// Default: 1000ms.
        /// </summary>
        public Double    RTTCriticalMs                  { get; set; } = 1000.0;
 
 
        // ──────────── Stratum ──────────────
 
        /// <summary>
        /// Expected stratum for monitored servers.
        /// A server at higher stratum triggers a warning.
        /// Default: 1 (PTB is primary reference).
        /// </summary>
        public Byte      ExpectedStratum                { get; set; } = 1;
 
 
        // ──────────── NTS-KE / TLS ──────────────
 
        /// <summary>
        /// Days until certificate expiry that triggers a warning.
        /// Default: 7 days.
        /// </summary>
        public Int32     CertExpiryWarningDays          { get; set; } = 7;
 
        /// <summary>
        /// Days until certificate expiry that triggers a critical alert.
        /// Default: 3 days.
        /// </summary>
        public Int32     CertExpiryCriticalDays         { get; set; } = 3;
 
        /// <summary>
        /// NTS-KE handshake duration above which to warn.
        /// Default: 5000ms.
        /// </summary>
        public Double    NTSKEDurationWarningMs         { get; set; } = 5000.0;
 
 
        // ──────────── Availability ──────────────
 
        /// <summary>
        /// Minimum number of servers that must be reachable for "OK" status.
        /// Default: 3 (degraded if fewer, critical if 0).
        /// </summary>
        public Int32     MinServersReachable            { get; set; } = 3;
 
        /// <summary>
        /// Minimum number of servers at the expected stratum for "OK" status.
        /// Default: 3.
        /// </summary>
        public Int32     MinServersAtExpectedStratum    { get; set; } = 3;
 
    }

}
