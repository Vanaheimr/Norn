﻿/*
 * Copyright (c) 2010-2025 GraphDefined GmbH <achim.friedland@graphdefined.com>
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

namespace org.GraphDefined.Vanaheimr.Norn.NTS.NTSKERecords
{

    /// <summary>
    /// NTS-KE New Cookie for NTPv4
    /// </summary>
    public class NewCookieForNTPv4 : NTSKE_Record
    {

        /// <summary>
        /// Create a new NTS-KE New Cookie for NTPv4 record.
        /// </summary>
        /// <param name="IsCritical">Whether an unrecognized record must cause an error.</param>
        public NewCookieForNTPv4(Boolean IsCritical)

            : base(IsCritical,
                   NTSKE_RecordTypes.NewCookieForNTPv4)

        { }

        /// <summary>
        /// Create a new NTS-KE New Cookie for NTPv4 record.
        /// </summary>
        /// <param name="IsCritical">Whether an unrecognized record must cause an error.</param>
        /// <param name="Body">The binary encoded NTS cookie.</param>
        public NewCookieForNTPv4(Boolean  IsCritical,
                                 Byte[]   Body)

            : base(IsCritical,
                   NTSKE_RecordTypes.NewCookieForNTPv4,
                   Body)

        { }

        /// <summary>
        /// Create a new NTS-KE New Cookie for NTPv4 record.
        /// </summary>
        /// <param name="IsCritical">Whether an unrecognized record must cause an error.</param>
        /// <param name="Cookie">An NTS cookie.</param>
        public NewCookieForNTPv4(Boolean    IsCritical,
                                 NTSCookie  Cookie)

            : base(IsCritical,
                   NTSKE_RecordTypes.NewCookieForNTPv4,
                   Cookie.ToByteArray())

        { }

    }

}
