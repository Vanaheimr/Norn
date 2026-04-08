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

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// A single NTS server endpoint to monitor.
    /// </summary>
    public class NTSServerEndpoint
    {

        public String   Hostname     { get; set; }
        public UInt16   NTSKEPort    { get; set; }
        public UInt16   NTPPort      { get; set; }
        public Boolean  Enabled      { get; set; }

        public NTSServerEndpoint(String   Hostname,
                                 UInt16   NTSKEPort   = 4460,
                                 UInt16   NTPPort     = 123,
                                 Boolean  Enabled     = true)
        {

            this.Hostname   = Hostname;
            this.NTSKEPort  = NTSKEPort;
            this.NTPPort    = NTPPort;
            this.Enabled    = Enabled;

        }

        /// <summary>
        /// Parameterless constructor for JSON deserialization
        /// </summary>
        public NTSServerEndpoint()
            : this("")
        { }

    }

}
