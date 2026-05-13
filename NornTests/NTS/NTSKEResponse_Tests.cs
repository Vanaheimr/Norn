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

            Assert.That(response.NTPv4Servers?.FirstOrDefault(),   Is.EqualTo("ntp.example.org"));
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

    }

}
