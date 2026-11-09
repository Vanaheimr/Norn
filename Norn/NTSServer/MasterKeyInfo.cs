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
    /// A master key of the cookies as an administrator may see it: its id and when it is valid,
    /// never its value.
    /// </summary>
    /// <param name="Id">The key id, which every cookie sealed with the key carries.</param>
    /// <param name="NotBefore">Since when the key seals cookies.</param>
    /// <param name="NotAfter">Until when the key seals cookies; it opens them for its grace period after.</param>
    /// <param name="IsCurrent">Whether the key seals the cookies made now.</param>
    public sealed record MasterKeyInfo(UInt64          Id,
                                       DateTimeOffset  NotBefore,
                                       DateTimeOffset  NotAfter,
                                       Boolean         IsCurrent);

}
