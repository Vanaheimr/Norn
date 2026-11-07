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

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// A digitally signed response a server was asked for after a measurement:
    /// the proof the Secure Time Synchronization white paper means for the
    /// secure metrological log book, beside a measurement that is not slowed
    /// down by the signing.
    /// </summary>
    /// <param name="Success">Whether a signed response came.</param>
    /// <param name="Packet">The response as it came, signature included, where one came.</param>
    /// <param name="KeyId">The id of the key it says it was signed with.</param>
    /// <param name="Verified">Whether the signature is that key's over the response: null where the key exchange named no such key.</param>
    /// <param name="ErrorMessage">Why no signed response came, or why it is not one.</param>
    public sealed record SignedResponseResult(Boolean  Success,
                                              Byte[]?  Packet        = null,
                                              UInt16?  KeyId         = null,
                                              Boolean? Verified      = null,
                                              String?  ErrorMessage  = null);

}
