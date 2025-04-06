/*
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

namespace org.GraphDefined.Vanaheimr.Norn.NTP
{

    /// <summary>
    /// The Network Time Security Key Establishment (NTS-KE) response.
    /// </summary>
    public class NTSKE_Response
    {

        #region Properties

        /// <summary>
        /// The enumeration of NTS-KE records.
        /// </summary>
        public IEnumerable<NTSKE_Record>  NTSKERecords    { get; }

        /// <summary>
        /// The TLS client-to-server Key.
        /// </summary>
        public Byte[]                     C2SKey          { get; }

        /// <summary>
        /// The TLS server-to-client Key.
        /// </summary>
        public Byte[]                     S2CKey          { get; }

        /// <summary>
        /// An optional error message.
        /// </summary>
        public String?                    ErrorMessage    { get; }


        /// <summary>
        /// The NTS-KE cookies.
        /// </summary>
        public IEnumerable<Byte[]>        Cookies

            => NTSKERecords.
                   Where (ntsKERecord => ntsKERecord.Type == 5).
                   Select(ntsKERecord => ntsKERecord.Value);

        #endregion

        #region Constructor(s)

        #region NTSKE_Response(NTSKE_Record, C2SKey, S2CKey)

        /// <summary>
        /// Create a new NTS-KE response.
        /// </summary>
        /// <param name="NTSKERecords">The enumeration of NTS-KE records.</param>
        /// <param name="C2SKey">The TLS client-to-server Key.</param>
        /// <param name="S2CKey">The TLS server-to-client Key.</param>
        /// 
        public NTSKE_Response(IEnumerable<NTSKE_Record>  NTSKERecords,
                              Byte[]                     C2SKey,
                              Byte[]                     S2CKey)
        {

            this.NTSKERecords  = NTSKERecords;
            this.C2SKey        = C2SKey;
            this.S2CKey        = S2CKey;

        }

        #endregion

        #region NTSKE_Response(ErrorMessage)

        /// <summary>
        /// Create a new NTS-KE error response.
        /// </summary>
        /// <param name="ErrorMessage">The error message.</param>
        public NTSKE_Response(String ErrorMessage)
        {

            this.NTSKERecords  = [];
            this.C2SKey        = [];
            this.S2CKey        = [];
            this.ErrorMessage  = ErrorMessage;

        }

        #endregion

        #endregion


        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => ErrorMessage is not null

                   ? ErrorMessage

                   : String.Concat(

                         $"{NTSKERecords.Count()} NTS-KE records",

                         C2SKey.Length > 0
                             ? $", C2S-Key: {BitConverter.ToString(C2SKey)}"
                             : "",

                         S2CKey.Length > 0
                             ? $", S2C-Key: {BitConverter.ToString(S2CKey)}"
                             : ""

                     );

        #endregion

    }

}
