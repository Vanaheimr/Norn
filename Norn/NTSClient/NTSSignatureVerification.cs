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
    /// What became of the signature a query asked for.
    /// </summary>
    /// <remarks>
    /// The NTS authenticator says that the server which holds the session keys sent
    /// this time, and says it to the client alone. The signature says it to anyone
    /// who has the server's public key - which is the whole of its worth, and why a
    /// signature that was asked for and not looked at is worth nothing.
    /// </remarks>
    public enum NTSSignatureVerification
    {

        /// <summary>
        /// The query did not ask for a signed response.
        /// </summary>
        NotRequested,

        /// <summary>
        /// The response is signed, and the signature is that of a key the key exchange named.
        /// </summary>
        Verified,

        /// <summary>
        /// The response is signed with a key the key exchange named, and the signature is
        /// not that key's over this response. Such a query has failed.
        /// </summary>
        Invalid,

        /// <summary>
        /// The response is signed with a key the key exchange did not name - because no
        /// public keys were requested there, or because the server signs with another.
        /// Nothing is known about the signature, either way.
        /// </summary>
        UnknownKey,

        /// <summary>
        /// A signed response was asked for, and the response carries no signature: the
        /// server does not sign, or declined to.
        /// </summary>
        NotSigned

    }

}
