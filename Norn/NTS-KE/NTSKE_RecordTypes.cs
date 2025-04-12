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

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    public static class NTSKE_RecordTypesExtensions
    {

        /// <summary>
        /// The type description of the NTS-KE record.
        /// </summary>
        public static String Description(this NTSKE_RecordTypes Type)

            => (Byte) Type switch {

                   0 => "End of Message",
                   1 => "NTS Next Protocol Negotiation",
                   2 => "Error",
                   3 => "Warning",
                   4 => "AEAD Algorithm Negotiation",
                   5 => "New Cookie for NTPv4",
                   6 => "NTPv4 Server Negotiation (ASCII address?)",
                   7 => "NTPv4 Port Negotiation",

                  32 => "NTS Request PublicKey",
                  33 => "NTS PublicKey",

                   _ => "Unknown or custom record type!"

               };

    }


    /// <summary>
    /// NTS-KE Record Types
    /// </summary>
    public enum NTSKE_RecordTypes : UInt16
    {

        /// <summary>
        /// The end of the message
        /// </summary>
        EndOfMessage                = 0,

        /// <summary>
        /// The NTS-KE protocol negotiation
        /// </summary>
        NTSNextProtocolNegotiation  = 1,

        /// <summary>
        /// The error message
        /// </summary>
        Error                       = 2,

        /// <summary>
        /// The warning message
        /// </summary>
        Warning                     = 3,

        /// <summary>
        /// The AEAD algorithm negotiation
        /// </summary>
        AEADAlgorithmNegotiation    = 4,

        /// <summary>
        /// The new cookie for NTPv4
        /// </summary>
        NewCookieForNTPv4           = 5,

        /// <summary>
        /// The NTPv4 server negotiation
        /// </summary>
        NTPv4ServerNegotiation      = 6,

        /// <summary>
        /// The NTPv4 port negotiation
        /// </summary>
        NTPv4PortNegotiation        = 7,


        // "Unknown or custom record types!"


        /// <summary>
        /// NTS Request Public Key
        /// </summary>
        NTSRequestPublicKey        = 32,

        /// <summary>
        /// NTS Public Key
        /// </summary>
        NTSPublicKey               = 33


    }

}
