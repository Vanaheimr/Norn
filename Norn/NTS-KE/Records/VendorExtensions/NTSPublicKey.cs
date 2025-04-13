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
    /// NTS-KE NTS Public Key
    /// </summary>
    public class NTSPublicKey : NTSKE_Record
    {

        /// <summary>
        /// Create a new NTS-KE NTS Public Key record.
        /// </summary>
        /// <param name="IsCritical">Whether an unrecognized record must cause an error.</param>
        public NTSPublicKey(Boolean IsCritical)

            : base(IsCritical,
                   NTSKE_RecordTypes.NTSPublicKey)

        { }

        /// <summary>
        /// Create a new NTS-KE NTS Public Key record.
        /// </summary>
        /// <param name="IsCritical">Whether an unrecognized record must cause an error.</param>
        public NTSPublicKey(Boolean  IsCritical,
                            Byte[]   Body)

            : base(IsCritical,
                   NTSKE_RecordTypes.NTSPublicKey,
                   Body)

        { }

        /// <summary>
        /// Create a new NTS-KE NTS Public Key record.
        /// </summary>
        /// <param name="IsCritical">Whether an unrecognized record must cause an error.</param>
        /// <param name="PublicKey">The public key.</param>
        public NTSPublicKey(Boolean    IsCritical,
                            PublicKey  PublicKey)

            : base(IsCritical,
                   NTSKE_RecordTypes.NTSPublicKey,
                   PublicKey.ToByteArray())

        { }

    }

}
