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

using org.GraphDefined.Vanaheimr.Illias;

namespace org.GraphDefined.Vanaheimr.Norn.NTS.NTSKERecords
{

    /// <summary>
    /// NTS-KE Warning
    /// </summary>
    public class Warning : NTSKE_Record
    {

        /// <summary>
        /// Create a new NTS-KE Warning record.
        /// </summary>
        /// <param name="IsCritical">Whether an unrecognized record must cause an error.</param>
        public Warning(Boolean IsCritical)

            : base(IsCritical,
                   NTSKE_RecordTypes.Warning)

        { }

        /// <summary>
        /// Create a new NTS-KE Warning record.
        /// </summary>
        /// <param name="IsCritical">Whether an unrecognized record must cause an error.</param>
        public Warning(Boolean  IsCritical,
                       Byte[]   Body)

            : base(IsCritical,
                   NTSKE_RecordTypes.Warning,
                   Body)

        { }

        /// <summary>
        /// Create a new NTS-KE Warning record.
        /// </summary>
        /// <remarks>
        /// RFC 8915 § 4.1.4 makes the body "exactly two octets long, consisting of an
        /// unsigned 16-bit integer in network byte order" and requires the Critical Bit,
        /// so a warning is a code rather than a message.
        /// </remarks>
        /// <param name="WarningCode">The warning code.</param>
        public Warning(UInt16 WarningCode)

            : base(true,
                   NTSKE_RecordTypes.Warning,
                   [ (Byte) (WarningCode >> 8), (Byte) WarningCode ])

        { }

    }

}
