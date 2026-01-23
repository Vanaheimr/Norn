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

namespace org.GraphDefined.Vanaheimr.Norn.NTS.NTSKERecords
{

    /// <summary>
    /// NTS-KE AEAD Algorithm Negotiation
    /// </summary>
    public class AEADAlgorithmNegotiation : NTSKE_Record
    {

        /// <summary>
        /// Create a new NTS-KE AEAD Algorithm Negotiation record.
        /// </summary>
        /// <param name="IsCritical">Whether an unrecognized record must cause an error.</param>
        public AEADAlgorithmNegotiation(Boolean IsCritical)

            : base(IsCritical,
                   NTSKE_RecordTypes.AEADAlgorithmNegotiation)

        { }

        /// <summary>
        /// Create a new NTS-KE AEAD Algorithm Negotiation record.
        /// </summary>
        /// <param name="IsCritical">Whether an unrecognized record must cause an error.</param>
        public AEADAlgorithmNegotiation(Boolean  IsCritical,
                                        Byte[]   Body)

            : base(IsCritical,
                   NTSKE_RecordTypes.AEADAlgorithmNegotiation,
                   Body)

        { }

        /// <summary>
        /// Create a new NTS-KE AEAD Algorithm Negotiation record.
        /// </summary>
        /// <param name="IsCritical">Whether an unrecognized record must cause an error.</param>
        /// <param name="Algorithm">The optional AEAD algorithm to be negotiated (default: AES-SIV-CMAC-256).</param>
        public AEADAlgorithmNegotiation(Boolean         IsCritical,
                                        AEADAlgorithms  Algorithm = AEADAlgorithms.AES_SIV_CMAC_256)

            : base(IsCritical,
                   NTSKE_RecordTypes.AEADAlgorithmNegotiation,
                   Algorithm.GetBytes())

        { }

    }

}
