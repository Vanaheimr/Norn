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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// Structured diagnostics for a Network Time Security Key Establishment exchange.
    /// </summary>
    public class NTSKEDiagnostics(NTSKE_TimingInfo?   TimingInfo,
                                  NTSKE_TLSInfo?      TLSInfo,
                                  IEnumerable<String> WarningMessages,
                                  IEnumerable<String>     NTPv4ServerNames,
                                  IEnumerable<IPPort>     NTPv4Ports)
    {

        #region Properties

        public NTSKE_TimingInfo?       TimingInfo       { get; } = TimingInfo;

        public NTSKE_TLSInfo?          TLSInfo          { get; } = TLSInfo;

        public IReadOnlyList<String>   WarningMessages  { get; } = [.. WarningMessages];

        public IReadOnlyList<String>     NTPv4ServerNames { get; } = [.. NTPv4ServerNames];

        public IReadOnlyList<IPPort>     NTPv4Ports     { get; } = [.. NTPv4Ports];

        #endregion

    }

}
