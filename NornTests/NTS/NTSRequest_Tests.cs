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

using System.Reflection;
using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    [TestFixture]
    public class SerializationDeserialization_Tests
    {

        #region NTSRequest_Test()

        /// <summary>
        /// A NTS Request Serialization/Deserialization test.
        /// </summary>
        [Test]
        public void NTSRequest_Test()
        {

            var key            = new Byte[32];
            var cookie         = new Byte[100];
            var uniqueId       = new Byte[32];
            var message1       = "Hello world!";
            var message2       = "Hallo Welt!";

            RandomNumberGenerator.Fill(key);
            RandomNumberGenerator.Fill(cookie);
            RandomNumberGenerator.Fill(uniqueId);

            var ntsKEResponse  = new NTSKE_Response([ new Norn.NTS.NTSKERecords.NewCookieForNTPv4(true, cookie) ], key, key);
            var plaintext      = new DebugExtension(message1).ToByteArray().Concat(new DebugExtension(message2).ToByteArray()).ToArray();

            // Use reflection...
            var methodInfo     = typeof(NTSClient).GetMethod("BuildNTSRequest", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
            Assert.That(methodInfo,  Is.Not.Null, "The method 'BuildNTSRequest' could not be reflected!");
            // Invoke passes every parameter positionally — optional ones are not filled in — so
            // the list has to match the signature exactly, in order. The three nulls are, in
            // order, the transmit timestamp, and after it the RFC 9769 originate and receive
            // timestamps; the trailing null is the TimeProvider, meaning "read the ambient clock".
            var requestPacket  = methodInfo?.Invoke(null, [ ntsKEResponse, cookie, uniqueId, plaintext, SignedResponseMode.None, (UInt16) 0, null, null, null, (UInt16) 2, (UInt16) cookie.Length, null ]) as NTPRequest;

            var isValid        = NTPRequest.TryParse(requestPacket?.ToByteArray() ?? [], out var ntpPacket, out var errorRequest, ntsKEResponse.C2SKey);
            var uniqueId2      = (ntpPacket?.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.UniqueIdentifier) as UniqueIdentifierExtension)?.Value;
            var cookie2        = (ntpPacket?.Extensions.FirstOrDefault(extension => extension.Type == ExtensionTypes.NTSCookie)        as NTSCookieExtension)?.       Value;
            var debugMessages  =  ntpPacket?.Extensions.Where         (extension => extension.Type == ExtensionTypes.Debug).Cast<DebugExtension>().ToArray() ?? [];

            Assert.That(isValid,                         Is.True);
            Assert.That(uniqueId.ToHexString(),          Is.EqualTo(uniqueId2?.ToHexString()));
            Assert.That(cookie.  ToHexString(),          Is.EqualTo(cookie2?.  ToHexString()));
            Assert.That(ntpPacket?.Extensions.Count(extension => extension.Type == ExtensionTypes.NTSCookiePlaceholder), Is.EqualTo(2));

            Assert.That(debugMessages[0].Authenticated,  Is.True);
            Assert.That(debugMessages[0].Encrypted,      Is.True);
            Assert.That(debugMessages[0].Text,           Is.EqualTo(message1));

            Assert.That(debugMessages[1].Authenticated,  Is.True);
            Assert.That(debugMessages[1].Encrypted,      Is.True);
            Assert.That(debugMessages[1].Text,           Is.EqualTo(message2));

        }

        #endregion

        #region CookiePool_ConsumesSeededCookiesOnlyOnce()

        [Test]
        public void CookiePool_ConsumesSeededCookiesOnlyOnce()
        {

            var cookie1        = Enumerable.Range( 0, 100).Select(value => (Byte) value).ToArray();
            var cookie2        = Enumerable.Range(10, 100).Select(value => (Byte) value).ToArray();
            var key            = new Byte[32];
            var ntsKEResponse  = new NTSKE_Response(
                                     [
                                         new Norn.NTS.NTSKERecords.NewCookieForNTPv4(true, cookie1),
                                         new Norn.NTS.NTSKERecords.NewCookieForNTPv4(true, cookie2)
                                     ],
                                     key,
                                     key
                                 );
            var ntsClient      = new NTSClient(Hermod.DNS.DomainName.Localhost);
            var methodInfo     = typeof(NTSClient).GetMethod("TryTakeCookie", BindingFlags.Instance | BindingFlags.NonPublic);

            Assert.That(methodInfo, Is.Not.Null, "The method 'TryTakeCookie' could not be reflected!");
            Assert.That(ntsClient.AvailableCookieCount, Is.EqualTo(0));

            ntsClient.SeedCookies(ntsKEResponse);
            Assert.That(ntsClient.AvailableCookieCount, Is.EqualTo(2));

            var arguments1     = new Object?[] { ntsKEResponse, null };
            var result1        = methodInfo!.Invoke(ntsClient, arguments1);
            Assert.That(ntsClient.AvailableCookieCount, Is.EqualTo(1));

            var arguments2     = new Object?[] { ntsKEResponse, null };
            var result2        = methodInfo!.Invoke(ntsClient, arguments2);
            Assert.That(ntsClient.AvailableCookieCount, Is.EqualTo(0));

            var arguments3     = new Object?[] { ntsKEResponse, null };
            var result3        = methodInfo!.Invoke(ntsClient, arguments3);

            Assert.That(result1,       Is.EqualTo(true));
            Assert.That(result2,       Is.EqualTo(true));
            Assert.That(result3,       Is.EqualTo(false));
            Assert.That(arguments1[1], Is.EqualTo(cookie1));
            Assert.That(arguments2[1], Is.EqualTo(cookie2));
            Assert.That(arguments3[1], Is.Null);

        }

        #endregion

        #region ResponseHistory_RejectsDuplicateAcceptedResponse()

        [Test]
        public void ResponseHistory_RejectsDuplicateAcceptedResponse()
        {

            var ntsClient  = new NTSClient(Hermod.DNS.DomainName.Localhost);
            var methodInfo = typeof(NTSClient).GetMethod("TryRememberAcceptedResponse", BindingFlags.Instance | BindingFlags.NonPublic);
            var response   = new NTPResponse(
                                 TransmitTimestamp: NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 02, DateTimeKind.Utc))
                             );

            Assert.That(methodInfo, Is.Not.Null, "The method 'TryRememberAcceptedResponse' could not be reflected!");

            Assert.That(methodInfo!.Invoke(ntsClient, [ response, "127.0.0.1:123" ]), Is.EqualTo(true));
            Assert.That(methodInfo.Invoke(ntsClient, [ response, "127.0.0.1:123" ]), Is.EqualTo(false));

        }

        #endregion

        #region CookiePoolPolicy_LimitsPool_And_ExposesDiagnostics()

        [Test]
        public void CookiePoolPolicy_LimitsPool_And_ExposesDiagnostics()
        {

            var cookie1        = Enumerable.Range( 0, 100).Select(value => (Byte) value).ToArray();
            var cookie2        = Enumerable.Range(10, 100).Select(value => (Byte) value).ToArray();
            var cookie3        = Enumerable.Range(20, 100).Select(value => (Byte) value).ToArray();
            var key            = new Byte[32];
            var ntsKEResponse  = new NTSKE_Response(
                                     [
                                         new Norn.NTS.NTSKERecords.NewCookieForNTPv4(true, cookie1),
                                         new Norn.NTS.NTSKERecords.NewCookieForNTPv4(true, cookie2),
                                         new Norn.NTS.NTSKERecords.NewCookieForNTPv4(true, cookie3)
                                     ],
                                     key,
                                     key
                                 );
            var ntsClient      = new NTSClient(
                                     Hermod.DNS.DomainName.Localhost,
                                     CookiePoolPolicy: new NTSCookiePoolPolicy {
                                         MaxCookiePoolSize  = 2,
                                         LowWatermark       = 1
                                     }
                                 );
            var methodInfo     = typeof(NTSClient).GetMethod("TryTakeCookie", BindingFlags.Instance | BindingFlags.NonPublic);

            Assert.That(methodInfo, Is.Not.Null, "The method 'TryTakeCookie' could not be reflected!");

            ntsClient.SeedCookies(ntsKEResponse);
            var seededDiagnostics = ntsClient.CookiePoolDiagnostics;

            Assert.That(seededDiagnostics.AvailableCookieCount,  Is.EqualTo(2));
            Assert.That(seededDiagnostics.MaxCookiePoolSize,     Is.EqualTo(2));
            Assert.That(seededDiagnostics.LowWatermark,          Is.EqualTo(1));
            Assert.That(seededDiagnostics.SeededCookieCount,     Is.EqualTo(2));
            Assert.That(seededDiagnostics.DroppedCookieCount,    Is.EqualTo(1));
            Assert.That(seededDiagnostics.CookiesConsumed,       Is.EqualTo(0));
            Assert.That(seededDiagnostics.IsFull,                Is.True);
            Assert.That(seededDiagnostics.IsLow,                 Is.False);

            var arguments1 = new Object?[] { ntsKEResponse, null };
            var arguments2 = new Object?[] { ntsKEResponse, null };
            methodInfo!.Invoke(ntsClient, arguments1);
            methodInfo!.Invoke(ntsClient, arguments2);

            var consumedDiagnostics = ntsClient.CookiePoolDiagnostics;

            Assert.That(consumedDiagnostics.AvailableCookieCount,  Is.EqualTo(0));
            Assert.That(consumedDiagnostics.CookiesConsumed,       Is.EqualTo(2));
            Assert.That(consumedDiagnostics.IsLow,                 Is.True);
            Assert.That(consumedDiagnostics.IsEmpty,               Is.True);

        }

        #endregion

    }

}
