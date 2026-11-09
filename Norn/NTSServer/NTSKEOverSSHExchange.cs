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

#region Usings

using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// A key exchange over SSH as the server answered it: who asked, where the keys came from,
    /// how many cookies went out - or why none did.
    /// </summary>
    /// <remarks>
    /// What an administrator asks of a time server (section 8.2 of the white paper "NTS Key
    /// Establishment over SSH"): which clients were served, and when last. Never a key, never a
    /// cookie.
    /// </remarks>
    /// <param name="Timestamp">When the answer went out, or the exchange failed.</param>
    /// <param name="Session">The SSH session of the client: its login name, its key and where it came from.</param>
    /// <param name="Method">Where the keys came from: the exporter of the connection (option A) or a transported secret (option B); null where none were made.</param>
    /// <param name="AEADAlgorithm">The algorithm the keys are for; null where none were made.</param>
    /// <param name="Cookies">How many cookies the answer carried.</param>
    /// <param name="ErrorCode">The Error record of the answer, or null.</param>
    /// <param name="Problem">Why the exchange was refused or failed, or null.</param>
    public sealed record NTSKEOverSSHExchange(DateTimeOffset         Timestamp,
                                              SshSessionInfo         Session,
                                              SSHKeyBindingMethods?  Method,
                                              AEADAlgorithms?        AEADAlgorithm,
                                              Int32                  Cookies,
                                              NTSKEErrorCodes?       ErrorCode,
                                              String?                Problem)
    {

        /// <summary>
        /// Whether the client got keys and cookies.
        /// </summary>
        public Boolean  Succeeded
            => ErrorCode is null && Problem is null && Cookies > 0;

    }

}
