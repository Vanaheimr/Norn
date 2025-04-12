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

#region Usings

using System.Diagnostics.CodeAnalysis;

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTP
{

    public class DebugExtension(String   Text,
                                Boolean  Authenticated   = false,
                                Boolean  Encrypted       = false)

        : NTPExtension(ExtensionTypes.Debug,
                       Text.ToUTF8Bytes().Pad(16),
                       Authenticated,
                       Encrypted)

    {

        #region Properties

        public String  Text    { get; private set; } = Text;

        #endregion


        public static Boolean TryParse(Byte[]                                    Data,
                                       [NotNullWhen(true)]  out DebugExtension?  DebugExtension,
                                       [NotNullWhen(false)] out String?          ErrorResponse,
                                       Boolean                                   Authenticated   = false,
                                       Boolean                                   Encrypted       = false)
        {

            ErrorResponse  = null;

            DebugExtension = new DebugExtension(
                                 Data.TakeWhile(c => c != 0x00).ToUTF8String(),
                                 Authenticated,
                                 Encrypted
                             );

            return true;

        }

    }

}
