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

using System.Net;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// Structured diagnostics for a single NTS-authenticated NTP query.
    /// </summary>
    public class NTSQueryDiagnostics(IPEndPoint?                   RemoteEndPoint,
                                     String                       RemoteDescription,
                                     Int64?                       SendStopwatchTimestamp,
                                     Int64?                       ReceiveStopwatchTimestamp,
                                     TimeSpan?                    StopwatchRoundTripTime,
                                     UInt64?                      DestinationTimestamp,
                                     Boolean                      NewCookieReceived,
                                     NTSCookiePoolDiagnostics?    CookiePoolDiagnostics,
                                     NTSResponseValidationResult? ResponseValidation)
    {

        #region Properties

        public IPEndPoint?                    RemoteEndPoint             { get; } = RemoteEndPoint;

        public String                         RemoteDescription          { get; } = RemoteDescription;

        public Int64?                         SendStopwatchTimestamp     { get; } = SendStopwatchTimestamp;

        public Int64?                         ReceiveStopwatchTimestamp  { get; } = ReceiveStopwatchTimestamp;

        public TimeSpan?                      StopwatchRoundTripTime     { get; } = StopwatchRoundTripTime;

        public UInt64?                        DestinationTimestamp       { get; } = DestinationTimestamp;

        public Boolean                        NewCookieReceived          { get; } = NewCookieReceived;

        public NTSCookiePoolDiagnostics?      CookiePoolDiagnostics      { get; } = CookiePoolDiagnostics;

        public NTSResponseValidationResult?   ResponseValidation         { get; } = ResponseValidation;

        #endregion

    }

}
