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

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// A point-in-time snapshot of NTS server counters.
    /// </summary>
    public class NTSServerMetrics(Int64 NTPRequestsReceived,
                                  Int64 NTPRequestsRejected,
                                  Int64 NTPRequestsInvalid,
                                  Int64 NTPResponsesSent,
                                  Int64 NTPSignedResponsesSent,
                                  Int64 NTPRequestFailures,
                                  Int64 NTSKEConnectionsAccepted,
                                  Int64 NTSKEConnectionsRejected,
                                  Int64 NTSKEHandshakeFailures,
                                  Int64 NTSKERequestsInvalid,
                                  Int64 NTSKEResponsesSent)
    {

        public Int64 NTPRequestsReceived       { get; } = NTPRequestsReceived;
        public Int64 NTPRequestsRejected       { get; } = NTPRequestsRejected;
        public Int64 NTPRequestsInvalid        { get; } = NTPRequestsInvalid;
        public Int64 NTPResponsesSent          { get; } = NTPResponsesSent;
        public Int64 NTPSignedResponsesSent    { get; } = NTPSignedResponsesSent;
        public Int64 NTPRequestFailures        { get; } = NTPRequestFailures;
        public Int64 NTSKEConnectionsAccepted  { get; } = NTSKEConnectionsAccepted;
        public Int64 NTSKEConnectionsRejected  { get; } = NTSKEConnectionsRejected;
        public Int64 NTSKEHandshakeFailures    { get; } = NTSKEHandshakeFailures;
        public Int64 NTSKERequestsInvalid      { get; } = NTSKERequestsInvalid;
        public Int64 NTSKEResponsesSent        { get; } = NTSKEResponsesSent;

    }

}
