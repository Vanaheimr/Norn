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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.Monitoring
{

    /// <summary>
    /// Monitoring result serialization tests.
    /// </summary>
    [TestFixture]
    public class MonitoringResult_Tests
    {

        #region NTSKE_ToJSON_Includes_Network_And_TLS_Diagnostics()

        [Test]
        public void NTSKE_ToJSON_Includes_Network_And_TLS_Diagnostics()
        {

            var result = new NTSKEMeasurementResult {
                             Success                 = true,
                             TotalDuration           = TimeSpan.FromMilliseconds(12),
                             TCPConnectDuration      = TimeSpan.FromMilliseconds(3),
                             TLSHandshakeDuration    = TimeSpan.FromMilliseconds(4),
                             NTSKEProtocolDuration   = TimeSpan.FromMilliseconds(5),
                             NumberOfCookies         = 8,
                             AEADAlgorithm           = "AES-SIV-CMAC-256",
                             NTPServerNegotiated     = DomainName.Parse("time.example.org"),
                             NTPPortNegotiated       = IPPort.Parse(123),
                             ResolvedIPAddresses     = [ "192.0.2.1", "2001:db8::1" ],
                             ConnectedIPAddress      = "2001:db8::1",
                             CookiePoolSize          = 8,
                             CookiePoolMaxSize       = 32,
                             CookiePoolLowWatermark  = 4,
                             SeededCookieCount       = 8,
                             CookiesReceived         = 0,
                             CookiesConsumed         = 0,
                             DroppedCookieCount      = 0,
                             CookiePoolLow           = false,
                             CookiePoolEmpty         = false,
                             TLSCipherSuite          = "TLS_AES_256_GCM_SHA384",
                             TLSVersion              = "TLS 1.3",
                             TLSApplicationProtocol  = "ntske/1",
                             TLSCompliance           = new TLSComplianceResult {
                                                           Status    = MonitoringStatus.OK,
                                                           Warnings  = [],
                                                           Errors    = []
                                                       }
                         };

            var json = result.ToJSON();

            Assert.That(json.Value<String>("ntpServerNegotiated"),       Is.EqualTo("time.example.org"));
            Assert.That(json.Value<UInt16>("ntpPortNegotiated"),         Is.EqualTo(123));
            Assert.That(json["resolvedIPAddresses"]?.Values<String>().Count(), Is.EqualTo(2));
            Assert.That(json.Value<String>("connectedIPAddress"),        Is.EqualTo("2001:db8::1"));
            Assert.That(json.Value<Int32>("cookiePoolSize"),             Is.EqualTo(8));
            Assert.That(json.Value<Int32>("cookiePoolMaxSize"),          Is.EqualTo(32));
            Assert.That(json.Value<Int32>("cookiePoolLowWatermark"),     Is.EqualTo(4));
            Assert.That(json.Value<Int64>("seededCookieCount"),          Is.EqualTo(8));
            Assert.That(json.Value<Int64>("cookiesReceived"),            Is.EqualTo(0));
            Assert.That(json.Value<Int64>("cookiesConsumed"),            Is.EqualTo(0));
            Assert.That(json.Value<Int64>("droppedCookieCount"),         Is.EqualTo(0));
            Assert.That(json.Value<Boolean>("cookiePoolLow"),            Is.False);
            Assert.That(json.Value<Boolean>("cookiePoolEmpty"),          Is.False);
            Assert.That(json.Value<String>("tlsCipherSuite"),            Is.EqualTo("TLS_AES_256_GCM_SHA384"));
            Assert.That(json.Value<String>("tlsVersion"),                Is.EqualTo("TLS 1.3"));
            Assert.That(json.Value<String>("tlsApplicationProtocol"),    Is.EqualTo("ntske/1"));
            Assert.That(json["tlsCompliance"]?.Value<String>("status"),    Is.EqualTo("OK"));

        }

        #endregion

        #region NTP_ToJSON_Includes_Remote_Endpoint_And_Cookie_Diagnostics()

        [Test]
        public void NTP_ToJSON_Includes_Remote_Endpoint_And_Cookie_Diagnostics()
        {

            var now     = new DateTimeOffset(2026, 05, 13, 12, 00, 00, TimeSpan.Zero);

            var result  = new NTPMeasurementResult {
                              Success                     = true,
                              NTSAuthenticationValid      = true,
                              UniqueIdMatched             = true,
                              T1_ClientSend               = now,
                              T2_ServerReceive            = now.AddMilliseconds(1),
                              T3_ServerTransmit           = now.AddMilliseconds(2),
                              T4_ClientReceive            = now.AddMilliseconds(3),
                              Offset                      = TimeSpan.FromMilliseconds(0.5),
                              RoundTripDelay              = TimeSpan.FromMilliseconds(2),
                              StopwatchRTT                = TimeSpan.FromMilliseconds(3),
                              RemoteHost                  = DomainName. Parse("time.example.org"),
                              RemoteAddress               = IPv6Address.Parse("2001:db8::1"),
                              RemotePort                  = IPPort.NTP,
                              ReferenceTimestamp          = now,
                              ReferenceId                 = "IPv4/Hash: 10.165.8.4 (0x0AA50804)",
                              NewCookieReceived           = true,
                              RemainingCookiesAfterQuery  = 7,
                              CookiePoolSize              = 7,
                              CookiePoolMaxSize           = 32,
                              CookiePoolLowWatermark      = 4,
                              SeededCookieCount           = 8,
                              CookiesReceived             = 1,
                              CookiesConsumed             = 2,
                              DroppedCookieCount          = 0,
                              CookiePoolLow               = false,
                              CookiePoolEmpty             = false,
                              ErrorCategory               = MonitoringErrorCategory.None
                          };

            var json    = result.ToJSON();

            Assert.That(json.Value<String>("remoteHost"),                  Is.EqualTo("time.example.org"));
            Assert.That(json.Value<String>("remoteAddress"),               Is.EqualTo("2001:db8::1"));
            Assert.That(json.Value<UInt16>("remotePort"),                  Is.EqualTo(123));
            Assert.That(json.Value<Byte>("remainingCookiesAfterQuery"),    Is.EqualTo(7));
            Assert.That(json.Value<Int32>("cookiePoolSize"),               Is.EqualTo(7));
            Assert.That(json.Value<Int32>("cookiePoolMaxSize"),            Is.EqualTo(32));
            Assert.That(json.Value<Int32>("cookiePoolLowWatermark"),       Is.EqualTo(4));
            Assert.That(json.Value<Int64>("seededCookieCount"),            Is.EqualTo(8));
            Assert.That(json.Value<Int64>("cookiesReceived"),              Is.EqualTo(1));
            Assert.That(json.Value<Int64>("cookiesConsumed"),              Is.EqualTo(2));
            Assert.That(json.Value<Int64>("droppedCookieCount"),           Is.EqualTo(0));
            Assert.That(json.Value<Boolean>("cookiePoolLow"),              Is.False);
            Assert.That(json.Value<Boolean>("cookiePoolEmpty"),            Is.False);
            Assert.That(json.Value<String>("referenceId"),                 Is.EqualTo("IPv4/Hash: 10.165.8.4 (0x0AA50804)"));

        }

        #endregion

        #region FailedResults_Include_ErrorCategory()

        [Test]
        public void FailedResults_Include_ErrorCategory()
        {

            var ntskeResult  = new NTSKEMeasurementResult {
                                   Success        = false,
                                   ErrorMessage   = Error.Create("TLS handshake timed out!"),
                                   ErrorCategory  = MonitoringErrorCategory.TLSHandshake
                               };

            var ntpResult    = new NTPMeasurementResult {
                                   Success        = false,
                                   ErrorMessage   = Error.Create("No 1st NTP response within timeout!"),
                                   ErrorCategory  = MonitoringErrorCategory.NTPTimeout
                               };

            Assert.That(ntskeResult.ToJSON().Value<String>("errorCategory"), Is.EqualTo("TLSHandshake"));
            Assert.That(ntpResult.  ToJSON().Value<String>("errorCategory"), Is.EqualTo("NTPTimeout"));

        }

        #endregion

    }

}
