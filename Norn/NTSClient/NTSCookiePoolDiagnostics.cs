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
    /// Diagnostics for the NTS cookie pool.
    /// </summary>
    public class NTSCookiePoolDiagnostics
    {

        public Int32    AvailableCookieCount  { get; }

        public Int32    MaxCookiePoolSize     { get; }

        public Int32    LowWatermark          { get; }

        public Int64    SeededCookieCount     { get; }

        public Int64    CookiesReceived       { get; }

        public Int64    CookiesConsumed       { get; }

        public Int64    DroppedCookieCount    { get; }

        public Boolean  IsLow                 { get; }

        public Boolean  IsEmpty               { get; }

        public Boolean  IsFull                { get; }


        public NTSCookiePoolDiagnostics(Int32  AvailableCookieCount,
                                        Int32  MaxCookiePoolSize,
                                        Int32  LowWatermark,
                                        Int64  SeededCookieCount,
                                        Int64  CookiesReceived,
                                        Int64  CookiesConsumed,
                                        Int64  DroppedCookieCount)
        {

            this.AvailableCookieCount  = AvailableCookieCount;
            this.MaxCookiePoolSize     = MaxCookiePoolSize;
            this.LowWatermark          = LowWatermark;
            this.SeededCookieCount     = SeededCookieCount;
            this.CookiesReceived       = CookiesReceived;
            this.CookiesConsumed       = CookiesConsumed;
            this.DroppedCookieCount    = DroppedCookieCount;
            this.IsLow                 = AvailableCookieCount <= LowWatermark;
            this.IsEmpty               = AvailableCookieCount == 0;
            this.IsFull                = AvailableCookieCount >= MaxCookiePoolSize;

        }

    }

}
