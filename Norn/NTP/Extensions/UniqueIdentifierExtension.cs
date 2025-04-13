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

#region Usings

using System.Diagnostics.CodeAnalysis;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTP
{

    public class UniqueIdentifierExtension(Byte[]   UniqueIdentifier,
                                           Boolean  Authenticated   = false,
                                           Boolean  Encrypted       = false)

        : NTPExtension(ExtensionTypes.UniqueIdentifier,
                       UniqueIdentifier,
                       Authenticated,
                       Encrypted)

    {

        public static Boolean TryParse(Byte[]                                               Data,
                                       [NotNullWhen(true)]  out UniqueIdentifierExtension?  UniqueIdentifierExtension,
                                       [NotNullWhen(false)] out String?                     ErrorResponse,
                                       Boolean                                              Authenticated   = false,
                                       Boolean                                              Encrypted       = false)
        {

            try
            {

                ErrorResponse              = null;
                UniqueIdentifierExtension  = null;

                if (Data is null || Data.Length < 16)
                {
                    ErrorResponse = "Unique Identifier Extension extension value is null or too short!";
                    return false;
                }

                UniqueIdentifierExtension  = new UniqueIdentifierExtension(
                                                 Data,
                                                 Authenticated,
                                                 Encrypted
                                             );

                return true;

            }
            catch (Exception e)
            {
                ErrorResponse              = e.Message;
                UniqueIdentifierExtension  = null;
                return false;
            }

        }

    }

}
