﻿/*
 * Copyright (c) 2010-2025 GraphDefined GmbH <achim.friedland@graphdefined.com>
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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// Test the NTS client against public NTS server of open.charging.cloud.
    /// </summary>
    [TestFixture]
    public class ChargingCloud_Tests
    {

        private readonly String[] serverNames = [
                                      "time1.charging.cloud",
                                      "time2.charging.cloud",
                                      "time3.charging.cloud"
                                  ];

        private String RandomServer()
            => serverNames[new Random().Next(serverNames.Length)];


        #region TestChargingCloudTime1()

        /// <summary>
        /// Test the NTS client against the public NTS server ptbtime1.ptb.de.
        /// </summary>
        [Test]
        public async Task TestChargingCloudTime1()
        {

            var serverName                 = RandomServer();
            var ntsClient                  = new NTSClient(serverName);

            var ntsKEResponse              = ntsClient.GetNTSKERecords();

            Assert.That(ntsKEResponse,                   Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey,            Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.S2CKey,            Is.Not.Null);
            Assert.That(ntsKEResponse.S2CKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.Cookies.Count(),   Is.GreaterThan(0));


            var ntsResponse                = await ntsClient.QueryTime(NTSKEResponse: ntsKEResponse);

            Assert.That(ntsResponse,  Is.Not.Null);

            if (ntsResponse is not null)
            {

                var request = ntsResponse.Request;

                Assert.That(request,  Is.Not.Null,  ntsResponse.ErrorMessage);

                if (request is not null)
                {

                    Assert.That(request.    UniqueIdentifier(),                                          Is.Not.Null);
                    Assert.That(ntsResponse.UniqueIdentifier(),                                          Is.Not.Null);
                    Assert.That(ntsResponse.UniqueIdentifier()?.ToHexString(),                           Is.EqualTo(request.UniqueIdentifier()?.ToHexString()));

                    Assert.That(request.Extensions.Count(),                                              Is.EqualTo(3));
                    Assert.That(request.Extensions.ElementAt(0) is UniqueIdentifierExtension,            Is.True);
                    Assert.That(request.Extensions.ElementAt(1) is NTSCookieExtension,                   Is.True);
                    Assert.That(request.Extensions.ElementAt(2) is AuthenticatorAndEncryptedExtension,   Is.True);

                }


                // Initially 2, but +1 decrypted extension
                Assert.That(ntsResponse.Extensions.Count(),  Is.EqualTo(3));


                // 1. Check Unique Identifier Extension
                if (ntsResponse.Extensions.ElementAt(0) is UniqueIdentifierExtension uniqueIdentifierExtension)
                {
                    Assert.That(uniqueIdentifierExtension.Authenticated,                          Is.True);
                    Assert.That(uniqueIdentifierExtension.Encrypted,                              Is.False);
                }
                else
                    Assert.Fail("Unique Identifier Extension is invalid!");


                // 2. Check NTS Authenticator and Encrypted Extension
                if (ntsResponse.Extensions.ElementAt(1) is AuthenticatorAndEncryptedExtension authenticatorAndEncryptedExtension)
                {
                    Assert.That(authenticatorAndEncryptedExtension.Authenticated,                 Is.False);
                    Assert.That(authenticatorAndEncryptedExtension.Encrypted,                     Is.False);
                    Assert.That(authenticatorAndEncryptedExtension.EncryptedExtensions.Count(),   Is.EqualTo(1));
                }
                else
                    Assert.Fail("NTS Authenticator and Encrypted Extension is invalid!");


                // 3. Check NTS Cookie Extension
                if (ntsResponse.Extensions.ElementAt(2) is NTSCookieExtension cookieExtension)
                {
                    Assert.That(cookieExtension.Authenticated,                                    Is.True);
                    Assert.That(cookieExtension.Encrypted,                                        Is.True);
                }
                else
                    Assert.Fail("NTS Cookie Extension is invalid!");

            }

        }

        #endregion

        #region TestChargingCloudTime1_RandomBitError()      <<<<<<<<<<<<< It seem's that this will not ALWAYS FAIL!?!

        /// <summary>
        /// Test the NTS client against the public NTS server ptbtime1.ptb.de,
        /// but add a random bit error to the response and check if the response
        /// is still valid.
        /// </summary>
        [Test]
        public async Task TestChargingCloudTime1_RandomBitError()
        {

            var serverName     = RandomServer();
            var ntsClient      = new NTSClient(serverName);

            var ntsKEResponse  = ntsClient.GetNTSKERecords();

            Assert.That(ntsKEResponse,                   Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey,            Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.S2CKey,            Is.Not.Null);
            Assert.That(ntsKEResponse.S2CKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.Cookies.Count(),   Is.GreaterThan(0));


            var ntsResponse    = await ntsClient.QueryTime(NTSKEResponse: ntsKEResponse);
            Assert.That(ntsResponse,    Is.Not.Null);

            if (ntsResponse is not null)
            {

                var request = ntsResponse.Request;
                Assert.That(request,  Is.Not.Null,  ntsResponse.ErrorMessage);
                if (request is not null)
                {

                    var fakeNTSResponseBytes = ntsResponse.ResponseBytes?.ToHexString().FromHEX() ?? [];
                    if (fakeNTSResponseBytes.Length > 0)
                    {
                        var randomIndex = RandomExtensions.RandomUInt32(fakeNTSResponseBytes.Length);
                        var randomBit   = (Byte) (1 << RandomExtensions.RandomInt32(8));
                        fakeNTSResponseBytes[randomIndex] ^= randomBit;
                    }

                    if (!NTPResponse.TryParse(fakeNTSResponseBytes, out _, out var error, NTSKey: ntsKEResponse.S2CKey))
                        Assert.That(error, Is.EqualTo("Authentication failed: SIV mismatch!"));
                    else
                        Assert.Fail("Parsing the fake NTS response should have failed!");

                }

            }

        }

        #endregion

        #region TestChargingCloudTime1_CustomTLSCertificateValidation()

        /// <summary>
        /// Test the NTS client against the public NTS server ptbtime1.ptb.de,
        /// but use a custom TLS certificate validation handler.
        /// </summary>
        [Test]
        public async Task TestChargingCloudTime1_CustomTLSCertificateValidation()
        {

            var serverName                 = RandomServer();
            var ntsClient                  = new NTSClient(
                                                 serverName,
                                                 RemoteCertificateValidator: (sender,
                                                                              serverCertificate,
                                                                              certificateChain,
                                                                              ntsKETLSClient,
                                                                              sslPolicyErrors) => {

                                                                                  var sans = serverCertificate is not null
                                                                                                 ? serverCertificate.DecodeSubjectAlternativeNames()
                                                                                                 : [];

                                                                                  if (serverCertificate?.Subject.Contains(serverName) == true &&
                                                                                      sans.Contains($"DNS-Name={serverName}"))
                                                                                  {
                                                                                      return (true, []);
                                                                                  }

                                                                                  return (false, [ "Wrong server certificate!" ]);

                                                                              }
                                             );

            var ntsKEResponse              = ntsClient.GetNTSKERecords();

            Assert.That(ntsKEResponse,                   Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey,            Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.S2CKey,            Is.Not.Null);
            Assert.That(ntsKEResponse.S2CKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.Cookies.Count(),   Is.GreaterThan(0));


            var ntsResponse                = await ntsClient.QueryTime(NTSKEResponse: ntsKEResponse);
            Assert.That(ntsResponse,     Is.Not.Null);

            if (ntsResponse is not null)
            {

                var request = ntsResponse.Request;

                Assert.That(request,  Is.Not.Null,  ntsResponse.ErrorMessage);

                if (request is not null)
                {

                    Assert.That(request.    UniqueIdentifier(),                                          Is.Not.Null);
                    Assert.That(ntsResponse.UniqueIdentifier(),                                          Is.Not.Null);
                    Assert.That(ntsResponse.UniqueIdentifier()?.ToHexString(),                           Is.EqualTo(request.UniqueIdentifier()?.ToHexString()));

                    Assert.That(request.Extensions.Count(),                                              Is.EqualTo(3));
                    Assert.That(request.Extensions.ElementAt(0) is UniqueIdentifierExtension,            Is.True);
                    Assert.That(request.Extensions.ElementAt(1) is NTSCookieExtension,                   Is.True);
                    Assert.That(request.Extensions.ElementAt(2) is AuthenticatorAndEncryptedExtension,   Is.True);

                }


                // Initially 2, but +1 decrypted extension
                Assert.That(ntsResponse.Extensions.Count(),  Is.EqualTo(3));


                // 1. Check Unique Identifier Extension
                if (ntsResponse.Extensions.ElementAt(0) is UniqueIdentifierExtension uniqueIdentifierExtension)
                {
                    Assert.That(uniqueIdentifierExtension.Authenticated,                          Is.True);
                    Assert.That(uniqueIdentifierExtension.Encrypted,                              Is.False);
                }
                else
                    Assert.Fail("Unique Identifier Extension is invalid!");


                // 2. Check NTS Authenticator and Encrypted Extension
                if (ntsResponse.Extensions.ElementAt(1) is AuthenticatorAndEncryptedExtension authenticatorAndEncryptedExtension)
                {
                    Assert.That(authenticatorAndEncryptedExtension.Authenticated,                 Is.False);
                    Assert.That(authenticatorAndEncryptedExtension.Encrypted,                     Is.False);
                    Assert.That(authenticatorAndEncryptedExtension.EncryptedExtensions.Count(),   Is.EqualTo(1));
                }
                else
                    Assert.Fail("NTS Authenticator and Encrypted Extension is invalid!");


                // 3. Check NTS Cookie Extension
                if (ntsResponse.Extensions.ElementAt(2) is NTSCookieExtension cookieExtension)
                {
                    Assert.That(cookieExtension.Authenticated,                                    Is.True);
                    Assert.That(cookieExtension.Encrypted,                                        Is.True);
                }
                else
                    Assert.Fail("NTS Cookie Extension is invalid!");

            }

        }

        #endregion

        #region TestChargingCloudTime1_CustomTLSCertificateValidation_Failed()

        /// <summary>
        /// Test the NTS client against the public NTS server ptbtime1.ptb.de,
        /// but use a custom TLS certificate validation handler.
        /// </summary>
        [Test]
        public async Task TestChargingCloudTime1_CustomTLSCertificateValidation_Failed()
        {

            var serverName                 = RandomServer();
            var ntsClient                  = new NTSClient(
                                                 serverName,
                                                 RemoteCertificateValidator: (sender,
                                                                              serverCertificate,
                                                                              certificateChain,
                                                                              ntsKETLSClient,
                                                                              sslPolicyErrors) => {
                                                                                  return (false, [ "Wrong server certificate!" ]);
                                                                              }
                                             );

            var ntsKEResponse              = ntsClient.GetNTSKERecords();

            Assert.That(ntsKEResponse.ErrorMessage,   Is.EqualTo("certificate_unknown(46)"));


            var ntsResponse                = await ntsClient.QueryTime(NTSKEResponse: ntsKEResponse);

            Assert.That(ntsResponse,                  Is.Not.Null);
            Assert.That(ntsResponse?.ErrorMessage,    Is.EqualTo("certificate_unknown(46)"));

        }

        #endregion


        #region TestChargingCloudTime1_RequestSignedResponse()

        /// <summary>
        /// Test the NTS client against the public NTS server ptbtime1.ptb.de
        /// using the NTSRequestSignedResponse extension, which should be ignored.
        /// </summary>
        [Test]
        public async Task TestChargingCloudTime1_RequestSignedResponse()
        {

            var serverName                 = RandomServer();
            var ntsClient                  = new NTSClient(serverName);

            var ntsKEResponse              = ntsClient.GetNTSKERecords();

            Assert.That(ntsKEResponse,                   Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey,            Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.S2CKey,            Is.Not.Null);
            Assert.That(ntsKEResponse.S2CKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.Cookies.Count(),   Is.GreaterThan(0));


            var ntsResponse                = await ntsClient.QueryTime(
                                                       NTSKEResponse:       ntsKEResponse,
                                                       SignedResponseMode:  SignedResponseMode.Scheduled
                                                   );

            Assert.That(ntsResponse,  Is.Not.Null);

            if (ntsResponse is not null)
            {

                var request = ntsResponse.Request;

                Assert.That(request,  Is.Not.Null,  ntsResponse.ErrorMessage);

                if (request is not null)
                {

                    Assert.That(request.    UniqueIdentifier(),                                          Is.Not.Null);
                    Assert.That(ntsResponse.UniqueIdentifier(),                                          Is.Not.Null);
                    Assert.That(ntsResponse.UniqueIdentifier()?.ToHexString(),                           Is.EqualTo(request.UniqueIdentifier()?.ToHexString()));

                    Assert.That(request.Extensions.Count(),                                              Is.EqualTo(4));
                    Assert.That(request.Extensions.ElementAt(0) is UniqueIdentifierExtension,            Is.True);
                    Assert.That(request.Extensions.ElementAt(1) is NTSCookieExtension,                   Is.True);
                    Assert.That(request.Extensions.ElementAt(2) is NTSRequestSignedResponseExtension,    Is.True);
                    Assert.That(request.Extensions.ElementAt(3) is AuthenticatorAndEncryptedExtension,   Is.True);

                }


                // Initially 2, but +1 decrypted extension
                Assert.That(ntsResponse.Extensions.Count(),  Is.EqualTo(3));


                // 1. Check Unique Identifier Extension
                if (ntsResponse.Extensions.ElementAt(0) is UniqueIdentifierExtension uniqueIdentifierExtension)
                {
                    Assert.That(uniqueIdentifierExtension.Authenticated,                          Is.True);
                    Assert.That(uniqueIdentifierExtension.Encrypted,                              Is.False);
                }
                else
                    Assert.Fail("Unique Identifier Extension is invalid!");


                // 2. Check NTS Authenticator and Encrypted Extension
                if (ntsResponse.Extensions.ElementAt(1) is AuthenticatorAndEncryptedExtension authenticatorAndEncryptedExtension)
                {
                    Assert.That(authenticatorAndEncryptedExtension.Authenticated,                 Is.False);
                    Assert.That(authenticatorAndEncryptedExtension.Encrypted,                     Is.False);
                    Assert.That(authenticatorAndEncryptedExtension.EncryptedExtensions.Count(),   Is.EqualTo(1));
                }
                else
                    Assert.Fail("NTS Authenticator and Encrypted Extension is invalid!");


                // 3. Check NTS Cookie Extension
                if (ntsResponse.Extensions.ElementAt(2) is NTSCookieExtension cookieExtension)
                {
                    Assert.That(cookieExtension.Authenticated,                                    Is.True);
                    Assert.That(cookieExtension.Encrypted,                                        Is.True);
                }
                else
                    Assert.Fail("NTS Cookie Extension is invalid!");

            }

        }

        #endregion


    }

}
