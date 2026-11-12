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
    /// The NTS Signed Response Mode.
    /// </summary>
    /// <remarks>
    /// There is one way a response is signed, and it is the second, scheduled one.
    /// A signature in the first response - there used to be a "Direct" here, which
    /// no request could ask for and no server gave - would have the server sign
    /// between receiving and sending: the time that takes is in the measurement,
    /// and an ECDSA signature is what a small request would cost a server before
    /// anything goes back.
    /// </remarks>
    public enum SignedResponseMode
    {

        /// <summary>
        /// No NTS Signed Response is sent.
        /// </summary>
        None,

        /// <summary>
        /// The NTS Signed Response is sent to the client via a 2nd scheduled response.
        /// </summary>
        Scheduled

    }

}
