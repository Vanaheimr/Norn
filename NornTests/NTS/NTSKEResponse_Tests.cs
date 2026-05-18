/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Norn <https://www.github.com/Vanaheimr/Norn>
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

using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTS.NTSKERecords;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// NTS-KE response tests.
    /// </summary>
    [TestFixture]
    public class NTSKEResponse_Tests
    {

        #region Parses_NTPv4Server_And_NTPv4Port_Negotiation()

        [Test]
        public void Parses_NTPv4Server_And_NTPv4Port_Negotiation()
        {

            var response = new NTSKE_Response(
                               [
                                   new NTPv4ServerNegotiation(false, Encoding.ASCII.GetBytes("ntp.example.org")),
                                   new NTPv4PortNegotiation  (false, [ 0x04, 0xD2 ])
                               ],
                               [],
                               []
                           );

            Assert.That(response.NTPv4Servers?.FirstOrDefault()?.ToString().TrimEnd('.'),   Is.EqualTo("ntp.example.org"));
            Assert.That(response.NTPv4Ports?.  FirstOrDefault(),   Is.EqualTo(IPPort.Parse(1234)));

        }

        #endregion

        #region Empty_NTPv4Server_Negotiation_Is_Treated_As_Unset()

        [Test]
        public void Empty_NTPv4Server_Negotiation_Is_Treated_As_Unset()
        {

            var response = new NTSKE_Response(
                               [
                                   new NTPv4ServerNegotiation(false, [])
                               ],
                               [],
                               []
                           );

            Assert.That(response.NTPv4Servers,   Is.Empty);

        }

        #endregion

        #region Zero_NTPv4Port_Negotiation_Is_Treated_As_Unset()

        [Test]
        public void Zero_NTPv4Port_Negotiation_Is_Treated_As_Unset()
        {

            var response = new NTSKE_Response(
                               [
                                   new NTPv4PortNegotiation(false, [ 0x00, 0x00 ])
                               ],
                               [],
                               []
                           );

            Assert.That(response.NTPv4Ports,   Is.Empty);

        }

        #endregion

        #region NTSKEResult_Failed_Carries_Response_And_Category()

        [Test]
        public void NTSKEResult_Failed_Carries_Response_And_Category()
        {

            var result = NTSKEResult.Failed(
                             "No IP address found for example.org!",
                             NTSKEErrorCategory.DNS
                         );

            Assert.That(result.Success,                 Is.False);
            Assert.That(result.ErrorCategory,           Is.EqualTo(NTSKEErrorCategory.DNS));
            Assert.That(result.ErrorMessage,            Is.EqualTo("No IP address found for example.org!"));
            Assert.That(result.Response,                Is.Not.Null);
            Assert.That(result.Response?.ErrorMessage,  Is.EqualTo("No IP address found for example.org!"));

        }

        #endregion

        #region NTSKERecordValidator_Accepts_Valid_Response()

        [Test]
        public void NTSKERecordValidator_Accepts_Valid_Response()
        {

            var records = CreateValidResponseRecords();

            Assert.That(
                NTSKERecordValidator.ValidateServerResponse(
                    records,
                    out var errorMessage,
                    out var errorCategory
                ),
                Is.True,
                errorMessage
            );

            Assert.That(errorCategory, Is.EqualTo(NTSKEErrorCategory.None));

        }

        #endregion

        #region NTSKERecordValidator_Rejects_Critical_Unknown_Record()

        [Test]
        public void NTSKERecordValidator_Rejects_Critical_Unknown_Record()
        {

            var records = CreateValidResponseRecords(
                              new NTSKE_Record(
                                  true,
                                  (NTSKE_RecordTypes) 32767,
                                  [ 0x01 ]
                              )
                          );

            Assert.That(
                NTSKERecordValidator.ValidateServerResponse(
                    records,
                    out var errorMessage,
                    out var errorCategory
                ),
                Is.False
            );

            Assert.That(errorMessage,   Does.Contain("unknown critical"));
            Assert.That(errorCategory,  Is.EqualTo(NTSKEErrorCategory.UnknownCriticalRecord));

        }

        #endregion

        #region NTSKERecordValidator_Rejects_Error_Record()

        [Test]
        public void NTSKERecordValidator_Rejects_Error_Record()
        {

            var records = CreateValidResponseRecords(
                              NTSKE_Record.Error("Server refused request")
                          );

            Assert.That(
                NTSKERecordValidator.ValidateServerResponse(
                    records,
                    out var errorMessage,
                    out var errorCategory
                ),
                Is.False
            );

            Assert.That(errorMessage,   Does.Contain("Error record"));
            Assert.That(errorCategory,  Is.EqualTo(NTSKEErrorCategory.ServerError));

        }

        #endregion

        #region NTSKERecordValidator_Accepts_Warning_Record()

        [Test]
        public void NTSKERecordValidator_Accepts_Warning_Record()
        {

            var records = CreateValidResponseRecords(
                              NTSKE_Record.Warning("Server warning")
                          );

            Assert.That(
                NTSKERecordValidator.ValidateServerResponse(
                    records,
                    out var errorMessage,
                    out var errorCategory,
                    out var warningMessages
                ),
                Is.True,
                errorMessage
            );

            Assert.That(errorCategory,     Is.EqualTo(NTSKEErrorCategory.None));
            Assert.That(warningMessages,   Does.Contain("Server warning"));

            var response = new NTSKE_Response(records, [], []);

            Assert.That(response.WarningMessages, Does.Contain("Server warning"));

        }

        #endregion

        #region NTSKERecordValidator_Rejects_Missing_AEAD_Negotiation()

        [Test]
        public void NTSKERecordValidator_Rejects_Missing_AEAD_Negotiation()
        {

            var records = CreateValidResponseRecords().
                              Where(record => record.Type != NTSKE_RecordTypes.AEADAlgorithmNegotiation);

            Assert.That(
                NTSKERecordValidator.ValidateServerResponse(
                    records,
                    out var errorMessage,
                    out var errorCategory
                ),
                Is.False
            );

            Assert.That(errorMessage,   Does.Contain("AEAD"));
            Assert.That(errorCategory,  Is.EqualTo(NTSKEErrorCategory.MissingRequiredRecord));

        }

        #endregion

        #region NTSKERecordValidator_Rejects_Missing_Cookies()

        [Test]
        public void NTSKERecordValidator_Rejects_Missing_Cookies()
        {

            var records = CreateValidResponseRecords().
                              Where(record => record.Type != NTSKE_RecordTypes.NewCookieForNTPv4);

            Assert.That(
                NTSKERecordValidator.ValidateServerResponse(
                    records,
                    out var errorMessage,
                    out var errorCategory
                ),
                Is.False
            );

            Assert.That(errorMessage,   Does.Contain("cookies"));
            Assert.That(errorCategory,  Is.EqualTo(NTSKEErrorCategory.MissingRequiredRecord));

        }

        #endregion

        #region NTSKERecordValidator_Rejects_Wrong_NextProtocol()

        [Test]
        public void NTSKERecordValidator_Rejects_Wrong_NextProtocol()
        {

            var records = CreateValidResponseRecords().
                              Where(record => record.Type != NTSKE_RecordTypes.NTSNextProtocolNegotiation).
                              Append(new NTSNextProtocolNegotiation(true, [ 0x00, 0x01 ]));

            Assert.That(
                NTSKERecordValidator.ValidateServerResponse(
                    records,
                    out var errorMessage,
                    out var errorCategory
                ),
                Is.False
            );

            Assert.That(errorMessage,   Does.Contain("unsupported next protocol"));
            Assert.That(errorCategory,  Is.EqualTo(NTSKEErrorCategory.UnsupportedProtocol));

        }

        #endregion

        #region NTSKERecordValidator_Rejects_Unsupported_AEAD()

        [Test]
        public void NTSKERecordValidator_Rejects_Unsupported_AEAD()
        {

            var records = CreateValidResponseRecords().
                              Where(record => record.Type != NTSKE_RecordTypes.AEADAlgorithmNegotiation).
                              Append(new AEADAlgorithmNegotiation(true, AEADAlgorithms.AES_128_GCM));

            Assert.That(
                NTSKERecordValidator.ValidateServerResponse(
                    records,
                    out var errorMessage,
                    out var errorCategory
                ),
                Is.False
            );

            Assert.That(errorMessage,   Does.Contain("unsupported AEAD"));
            Assert.That(errorCategory,  Is.EqualTo(NTSKEErrorCategory.UnsupportedAlgorithm));

        }

        #endregion

        #region (private static) CreateValidResponseRecords(AdditionalRecords)

        private static IEnumerable<NTSKE_Record> CreateValidResponseRecords(params NTSKE_Record[] AdditionalRecords)
        {

            var records = new List<NTSKE_Record> {
                              NTSKE_Record.NTSNextProtocolNegotiation,
                              NTSKE_Record.AEADAlgorithmNegotiation(),
                              new NewCookieForNTPv4(false, [ 0x01, 0x02, 0x03 ])
                          };

            records.AddRange(AdditionalRecords);
            records.Add(NTSKE_Record.EndOfMessage);

            return records;

        }

        #endregion

    }

}
