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

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTP
{

    public class NTSSignedResponseAnnouncementExtension(Boolean  IsScheduled,
                                                        Boolean  Authenticated   = false,
                                                        Boolean  Encrypted       = false)

        : NTPExtension(ExtensionTypes.NTSSignedResponseAnnouncement,
                       IsScheduled

                           ? [ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]

                           : [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],

                       Authenticated,
                       Encrypted)

    {

        #region Properties

        /// <summary>
        /// Whether the NTS server is scheduled to send a 2nd signed response.
        /// </summary>
        public Boolean  IsScheduled    { get; } = IsScheduled;

        #endregion


        public static Boolean TryParse(Byte[]                                                            Data,
                                       [NotNullWhen(true)]  out NTSSignedResponseAnnouncementExtension?  NTSSignedResponseAnnouncementExtension,
                                       [NotNullWhen(false)] out String?                                  ErrorResponse,
                                       Boolean                                                           Authenticated   = false,
                                       Boolean                                                           Encrypted       = false)
        {

            try
            {

                ErrorResponse                           = null;
                NTSSignedResponseAnnouncementExtension  = null;

                if (Data is null || Data.Length < 4)
                {
                    ErrorResponse = "NTS Signed Response Announcement extension value is null or too short!";
                    return false;
                }

                NTSSignedResponseAnnouncementExtension  = new NTSSignedResponseAnnouncementExtension(
                                                              Data[0] == 0x80
                                                          );

                return true;

            }
            catch (Exception e)
            {
                ErrorResponse                           = e.Message;
                NTSSignedResponseAnnouncementExtension  = null;
                return false;
            }

        }

    }

}
