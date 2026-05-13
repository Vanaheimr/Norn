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

using org.GraphDefined.Vanaheimr.Hermod;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// Timing information for a Network Time Security Key Establishment (NTS-KE) exchange.
    /// </summary>
    public class NTSKE_TimingInfo(TimeSpan?                 DNSLookupDuration       = null,
                                  TimeSpan?                 TCPConnectDuration      = null,
                                  TimeSpan?                 TLSHandshakeDuration    = null,
                                  TimeSpan?                 NTSKEProtocolDuration   = null,
                                  TimeSpan?                 TotalDuration           = null,
                                  IEnumerable<IIPAddress>?  ResolvedIPAddresses     = null,
                                  IIPAddress?               ConnectedIPAddress      = null)
    {

        #region Properties

        /// <summary>
        /// The duration of the DNS lookup phase.
        /// </summary>
        public TimeSpan?                 DNSLookupDuration        { get; } = DNSLookupDuration;

        /// <summary>
        /// The duration of the TCP connect phase.
        /// </summary>
        public TimeSpan?                 TCPConnectDuration       { get; } = TCPConnectDuration;

        /// <summary>
        /// The duration of the TLS handshake phase.
        /// </summary>
        public TimeSpan?                 TLSHandshakeDuration     { get; } = TLSHandshakeDuration;

        /// <summary>
        /// The duration of the NTS-KE request/response phase after TLS completed.
        /// </summary>
        public TimeSpan?                 NTSKEProtocolDuration    { get; } = NTSKEProtocolDuration;

        /// <summary>
        /// The total duration of the NTS-KE exchange.
        /// </summary>
        public TimeSpan?                 TotalDuration            { get; } = TotalDuration;

        /// <summary>
        /// The resolved IP addresses used for the TCP connect attempts.
        /// </summary>
        public IEnumerable<IIPAddress>   ResolvedIPAddresses      { get; } = ResolvedIPAddresses ?? [];

        /// <summary>
        /// The IP address used by the successful TCP connection.
        /// </summary>
        public IIPAddress?               ConnectedIPAddress       { get; } = ConnectedIPAddress;

        #endregion

    }

}
