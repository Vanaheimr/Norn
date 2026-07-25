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
    /// NTS-KE error codes, RFC 8915 § 4.1.3.
    ///
    /// The Error record's body is a two-octet code from this registry — not free text. A peer
    /// has to be able to act on it programmatically, which is the point of there being only
    /// three.
    /// </summary>
    public enum NTSKEErrorCodes : UInt16
    {

        /// <summary>
        /// Unrecognized Critical Record.
        ///
        /// "The server MUST respond with this error code if the request included a record that
        /// the server did not understand and that had its Critical Bit set."
        /// </summary>
        UnrecognizedCriticalRecord  = 0,

        /// <summary>
        /// Bad Request.
        ///
        /// "The server MUST respond with this error if the request is not complete and
        /// syntactically well-formed, or, upon the expiration of an implementation-defined
        /// timeout, it has not yet received such a request."
        /// </summary>
        BadRequest                  = 1,

        /// <summary>
        /// Internal Server Error.
        ///
        /// "The server MUST respond with this error if it is unable to respond properly due to
        /// an internal condition." The client MAY retry.
        /// </summary>
        InternalServerError         = 2

    }


    /// <summary>
    /// NTS-KE warning codes, RFC 8915 § 4.1.4. The registry is currently empty.
    /// </summary>
    public enum NTSKEWarningCodes : UInt16
    { }

}
