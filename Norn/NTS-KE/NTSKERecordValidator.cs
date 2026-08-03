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

using System.Diagnostics.CodeAnalysis;
using System.Text;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// Semantic validation for parsed NTS-KE server response records.
    /// </summary>
    public static class NTSKERecordValidator
    {

        #region ValidateServerResponse(Records, out ErrorMessage, out ErrorCategory)

        public static Boolean ValidateServerResponse(IEnumerable<NTSKE_Record>              Records,
                                                     [NotNullWhen(false)] out String?       ErrorMessage,
                                                     out NTSKEErrorCategory                 ErrorCategory)

            => ValidateServerResponse(
                   Records,
                   out ErrorMessage,
                   out ErrorCategory,
                   out _
               );

        #endregion

        #region ValidateServerResponse(Records, out ErrorMessage, out ErrorCategory, out WarningMessages)

        public static Boolean ValidateServerResponse(IEnumerable<NTSKE_Record>              Records,
                                                     [NotNullWhen(false)] out String?       ErrorMessage,
                                                     out NTSKEErrorCategory                 ErrorCategory,
                                                     out IEnumerable<String>                WarningMessages)
        {

            var records = Records.ToList();

            ErrorMessage     = null;
            ErrorCategory    = NTSKEErrorCategory.None;
            WarningMessages  = records.
                                   Where (record => record.Type == NTSKE_RecordTypes.Warning).
                                   Select(FormatWarning).
                                   ToArray();


            foreach (var record in records)
            {

                if (record.IsCritical &&
                    !IsKnownRecordType(record.Type))
                {

                    ErrorMessage   = $"NTS-KE response contains an unknown critical record type {(UInt16) record.Type}.";
                    ErrorCategory  = NTSKEErrorCategory.UnknownCriticalRecord;
                    return false;

                }

            }


            var errorRecord = records.FirstOrDefault(record => record.Type == NTSKE_RecordTypes.Error);
            if (errorRecord is not null)
            {

                ErrorMessage   = $"NTS-KE server returned an Error record: {FormatRecordBody(errorRecord)}";
                ErrorCategory  = NTSKEErrorCategory.ServerError;
                return false;

            }


            // RFC 8915 § 4.1.4: "Unrecognized warning codes MUST be treated as errors."
            //
            // The IANA "Network Time Security Warning Codes" registry has never assigned a
            // code: 0 to 32767 is unassigned and the rest is reserved for private use. So
            // there is nothing for a conformant client to recognize, and every warning it
            // receives ends the key exchange.
            //
            // Failing closed is the only safe reading of a record type whose entire purpose
            // is to carry meanings defined later. A client that logs an unknown warning and
            // carries on is precisely the client that will ignore the first code IANA ever
            // assigns — which is why the RFC settles the question in advance instead of
            // leaving it to each implementation's judgement.
            //
            // Checked after the Error record so that a server sending both is reported by the
            // one carrying a defined code.
            var warningRecord = records.FirstOrDefault(record => record.Type == NTSKE_RecordTypes.Warning);
            if (warningRecord is not null)
            {

                ErrorMessage   = $"NTS-KE server returned a Warning record: {FormatWarning(warningRecord)}. " +
                                  "No warning code is registered, so it cannot be recognized and the " +
                                  "key exchange must be abandoned.";
                ErrorCategory  = NTSKEErrorCategory.ServerWarning;
                return false;

            }


            var nextProtocolRecords = records.
                                          Where(record => record.Type == NTSKE_RecordTypes.NTSNextProtocolNegotiation).
                                          ToList();

            if (nextProtocolRecords.Count == 0)
            {

                ErrorMessage   = "NTS-KE response did not negotiate a next protocol.";
                ErrorCategory  = NTSKEErrorCategory.MissingRequiredRecord;
                return false;

            }

            if (nextProtocolRecords.Count != 1 ||
                !IsNTPv4NextProtocol(nextProtocolRecords[0]))
            {

                ErrorMessage   = "NTS-KE response negotiated an unsupported next protocol.";
                ErrorCategory  = NTSKEErrorCategory.UnsupportedProtocol;
                return false;

            }


            var aeadRecords = records.
                                  Where(record => record.Type == NTSKE_RecordTypes.AEADAlgorithmNegotiation).
                                  ToList();

            if (aeadRecords.Count == 0)
            {

                ErrorMessage   = "NTS-KE response did not negotiate an AEAD algorithm.";
                ErrorCategory  = NTSKEErrorCategory.MissingRequiredRecord;
                return false;

            }

            if (aeadRecords.Count != 1 ||
                !IsSupportedAEADAlgorithm(aeadRecords[0]))
            {

                ErrorMessage   = "NTS-KE response negotiated an unsupported AEAD algorithm.";
                ErrorCategory  = NTSKEErrorCategory.UnsupportedAlgorithm;
                return false;

            }


            var cookieRecords = records.
                                    Where(record => record.Type == NTSKE_RecordTypes.NewCookieForNTPv4).
                                    ToList();

            if (cookieRecords.Count == 0)
            {

                ErrorMessage   = "NTS-KE response did not provide any NTPv4 cookies.";
                ErrorCategory  = NTSKEErrorCategory.MissingRequiredRecord;
                return false;

            }

            if (cookieRecords.Any(record => record.Body.Length == 0))
            {

                ErrorMessage   = "NTS-KE response contains an empty NTPv4 cookie.";
                ErrorCategory  = NTSKEErrorCategory.Protocol;
                return false;

            }


            return true;

        }

        #endregion


        #region (private static) IsKnownRecordType(Type)

        private static Boolean IsKnownRecordType(NTSKE_RecordTypes Type)

            => Type == NTSKE_RecordTypes.EndOfMessage               ||
               Type == NTSKE_RecordTypes.NTSNextProtocolNegotiation ||
               Type == NTSKE_RecordTypes.Error                      ||
               Type == NTSKE_RecordTypes.Warning                    ||
               Type == NTSKE_RecordTypes.AEADAlgorithmNegotiation   ||
               Type == NTSKE_RecordTypes.NewCookieForNTPv4          ||
               Type == NTSKE_RecordTypes.NTPv4ServerNegotiation     ||
               Type == NTSKE_RecordTypes.NTPv4PortNegotiation       ||
               Type == NTSKE_RecordTypes.NTSRequestPublicKey        ||
               Type == NTSKE_RecordTypes.NTSPublicKey;

        #endregion

        #region (private static) IsNTPv4NextProtocol(Record)

        private static Boolean IsNTPv4NextProtocol(NTSKE_Record Record)

            => Record.Body.Length == 2 &&
               Record.Body[0]    == 0 &&
               Record.Body[1]    == 0;

        #endregion

        #region (private static) IsSupportedAEADAlgorithm(Record)

        private static Boolean IsSupportedAEADAlgorithm(NTSKE_Record Record)
        {

            var expectedBytes = AEADAlgorithms.AES_SIV_CMAC_256.GetBytes();

            return Record.Body.Length == expectedBytes.Length &&
                   Record.Body.SequenceEqual(expectedBytes);

        }

        #endregion

        #region (private static) FormatWarning(Record)

        /// <summary>
        /// Render a Warning record for a human.
        /// </summary>
        /// <remarks>
        /// RFC 8915 § 4.1.4 defines the body as a 16-bit unsigned integer, not as text, so
        /// decoding it as a string yields control characters where the code should be.
        /// </remarks>
        private static String FormatWarning(NTSKE_Record Record)

            => Record.Body.Length == 2
                   ? $"warning code {(UInt16) ((Record.Body[0] << 8) | Record.Body[1])}"
                   : $"malformed warning record ({FormatRecordBody(Record)})";

        #endregion

        #region (private static) FormatRecordBody(Record)

        private static String FormatRecordBody(NTSKE_Record Record)
        {

            if (Record.Body.Length == 0)
                return "<empty>";

            var text = Encoding.UTF8.GetString(Record.Body).TrimEnd('\0');

            return String.IsNullOrWhiteSpace(text)
                       ? BitConverter.ToString(Record.Body)
                       : text;

        }

        #endregion

    }

}
