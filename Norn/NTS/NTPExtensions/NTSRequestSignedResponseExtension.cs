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

using org.GraphDefined.Vanaheimr.Norn.NTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    public class NTSRequestSignedResponseExtension : NTPExtension
    {

        public NTSRequestSignedResponseExtension(UInt16   KeyId,
                                                 Boolean  Authenticated   = false,
                                                 Boolean  Encrypted       = false)

            : base(ExtensionTypes.NTSRequestSignedResponse,
                   new Byte[16],
                   Authenticated,
                   Encrypted)

        {

            Value[0] = (Byte) ((KeyId >> 8) & 0xff);
            Value[1] = (Byte)  (KeyId       & 0xff);

        }

        public static Boolean TryParse(Byte[]                                                       Data,
                                       [NotNullWhen(true)]  out NTSRequestSignedResponseExtension?  NTSRequestSignedResponseExtension,
                                       [NotNullWhen(false)] out String?                             ErrorResponse,
                                       Boolean                                                      Authenticated   = false,
                                       Boolean                                                      Encrypted       = false)
        {

            try
            {

                ErrorResponse                      = null;
                NTSRequestSignedResponseExtension  = null;

                if (Data is null || Data.Length < 4)
                {
                    ErrorResponse = "NTS Request Signed Response extension value is null or too short!";
                    return false;
                }

                NTSRequestSignedResponseExtension  = new NTSRequestSignedResponseExtension(
                                                         (UInt16) ((Data[0] << 8) | Data[1]),
                                                         Authenticated,
                                                         Encrypted
                                                     );

                return true;

            }
            catch (Exception e)
            {
                ErrorResponse                      = e.Message;
                NTSRequestSignedResponseExtension  = null;
                return false;
            }

        }

    }

}
