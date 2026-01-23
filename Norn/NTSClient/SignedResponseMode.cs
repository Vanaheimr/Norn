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
    public enum SignedResponseMode
    {

        /// <summary>
        /// No NTS Signed Response is sent.
        /// </summary>
        None,

        /// <summary>
        /// The NTS Signed Response is sent directly to the client.
        /// </summary>
        Direct,

        /// <summary>
        /// The NTS Signed Response is sent to the client via a 2nd scheduled response.
        /// </summary>
        Scheduled

    }

}
