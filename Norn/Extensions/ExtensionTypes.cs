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

namespace org.GraphDefined.Vanaheimr.Norn.NTP
{

    /// <summary>
    /// Common NTP Extension Types
    /// </summary>
    public enum ExtensionTypes : UInt16
    {

        /// <summary>
        /// Unique Identifier
        /// </summary>
        UniqueIdentifier            = 0x0104,

        /// <summary>
        /// NTS Cookie
        /// </summary>
        NTSCookie                   = 0x0204,

        /// <summary>
        /// NTS Cookie Placeholder
        /// </summary>
        NTSCookiePlaceholder        = 0x0304,

        /// <summary>
        /// Authenticator and Encrypted
        /// </summary>
        AuthenticatorAndEncrypted   = 0x0404,


        /// <summary>
        /// Debug (just for testing)
        /// </summary>
        Debug                       = 0xffff

    }

}
