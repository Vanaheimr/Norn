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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// Test the NTS client against the given NTS server.
    /// </summary>
    /// <param name="ServerName">The NTS Server DNS Name.</param>
    /// <param name="Timeout">An optional timeout for NTS operations.</param>
    public abstract class ANTSServer_Tests(DomainName  ServerName,
                                           String?     ExpectedReferenceIdentifier   = null,
                                           Byte?       ExpectedStratum               = null,
                                           TimeSpan?   Timeout                       = null)
    {

        #region Properties

        /// <summary>
        /// The PTB Server Name.
        /// </summary>
        public DomainName  ServerName    { get; } = ServerName;

        /// <summary>
        /// The timeout for NTS operations.
        /// </summary>
        public TimeSpan?   Timeout       { get; } = Timeout;

        #endregion


        #region TestNTP()

        /// <summary>
        /// Test the NTP client against the public NTP server.
        /// </summary>
        [Test]
        public async Task TestNTP()
        {

            var ntsClient    = new NTSClient(
                                   ServerName,
                                   Timeout:    Timeout,
                                   DNSClient:  new DNSClient(SearchForIPv6DNSServers: false)
                               );

            var ntpResult    = await ntsClient.QueryTime();
            var ntpResponse  = ntpResult.Response;

            Assert.That(ntpResponse,  Is.Not.Null, "No NTP response received!");

            if (ntpResponse is not null)
            {

                if (ExpectedReferenceIdentifier is not null)
                    Assert.That(ntpResponse.ReferenceIdentifier.AsASCII,   Is.EqualTo(ExpectedReferenceIdentifier));

                if (ExpectedStratum             is not null)
                    Assert.That(ntpResponse.Stratum,                       Is.EqualTo(ExpectedStratum));

            }

        }

        #endregion

        #region TestNTSKE()

        /// <summary>
        /// Test the NTS-KE client against the public NTS server.
        /// </summary>
        [Test]
        public async Task TestNTSKE()
        {

            var ntsClient      = new NTSClient(
                                     ServerName,
                                     Timeout:    Timeout,
                                     DNSClient:  new DNSClient(SearchForIPv6DNSServers: false)
                                 );

            var ntsKEResult    = await ntsClient.GetNTSKERecords();

            Assert.That(ntsKEResult.Success,             Is.True, ntsKEResult.ErrorMessage);
            Assert.That(ntsKEResult.ErrorCategory,       Is.EqualTo(NTSKEErrorCategory.None));

            var ntsKEResponse  = ntsKEResult.Response;
            Assert.That(ntsKEResponse,                   Is.Not.Null,          "No NTS-KE response received!");

            if (ntsKEResponse is not null)
            {
                Assert.That(ntsKEResponse,                   Is.Not.Null,          "No NTS-KE response received!");
                Assert.That(ntsKEResponse.C2SKey,            Is.Not.Null,          "No C2S key received in NTS-KE response!");
                Assert.That(ntsKEResponse.C2SKey.Length,     Is.GreaterThan(0));
                Assert.That(ntsKEResponse.S2CKey,            Is.Not.Null,          "No S2C key received in NTS-KE response!");
                Assert.That(ntsKEResponse.S2CKey.Length,     Is.GreaterThan(0));
                Assert.That(ntsKEResponse.Cookies.Count(),   Is.GreaterThan(0),    "No cookies received in NTS-KE response!");
            }

        }

        #endregion

        #region TestNTS()

        /// <summary>
        /// Test the NTS client against the public NTS server.
        /// </summary>
        [Test]
        public async Task TestNTS()
        {

            var ntsClient      = new NTSClient(
                                     ServerName,
                                     Timeout:    Timeout,
                                     DNSClient:  new DNSClient(SearchForIPv6DNSServers: false)
                                 );

            var ntsKEResult    = await ntsClient.GetNTSKERecords();
            var ntsKEResponse  = ntsKEResult.Response!;

            Assert.That(ntsKEResult.Success,          Is.True, ntsKEResult.ErrorMessage);
            Assert.That(ntsKEResult.ErrorCategory,    Is.EqualTo(NTSKEErrorCategory.None));
            Assert.That(ntsKEResponse,                   Is.Not.Null,          "No NTS-KE response received!");
            Assert.That(ntsKEResponse.C2SKey,            Is.Not.Null,          "No C2S key received in NTS-KE response!");
            Assert.That(ntsKEResponse.C2SKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.S2CKey,            Is.Not.Null,          "No S2C key received in NTS-KE response!");
            Assert.That(ntsKEResponse.S2CKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.Cookies.Count(),   Is.GreaterThan(0),    "No cookies received in NTS-KE response!");


            var ntsResult      = await ntsClient.QueryTime(NTSKEResponse: ntsKEResponse);
            var ntsResponse    = ntsResult.Response;

            Assert.That(ntsResponse,  Is.Not.Null, "No NTP+NTS response received!");

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

        #region TestNTS_RandomBitError()

        /// <summary>
        /// Test the NTS client against the public NTS server,
        /// but add a bit error to the authenticated ciphertext and check if the response
        /// is still accepted.
        /// </summary>
        [Test]
        public async Task TestNTS_RandomBitError()
        {

            var ntsClient      = new NTSClient(
                                     ServerName,
                                     Timeout:    Timeout,
                                     DNSClient:  new DNSClient(SearchForIPv6DNSServers: false)
                                 );

            var ntsKEResult    = await ntsClient.GetNTSKERecords();
            var ntsKEResponse  = ntsKEResult.Response!;

            Assert.That(ntsKEResult.Success,          Is.True, ntsKEResult.ErrorMessage);
            Assert.That(ntsKEResult.ErrorCategory,    Is.EqualTo(NTSKEErrorCategory.None));
            Assert.That(ntsKEResponse,                   Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey,            Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.S2CKey,            Is.Not.Null);
            Assert.That(ntsKEResponse.S2CKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.Cookies.Count(),   Is.GreaterThan(0));


            var ntsResult      = await ntsClient.QueryTime(NTSKEResponse: ntsKEResponse);
            var ntsResponse    = ntsResult.Response;
            Assert.That(ntsResponse,    Is.Not.Null);

            if (ntsResponse is not null)
            {

                var request = ntsResponse.Request;
                Assert.That(request,  Is.Not.Null,  ntsResponse.ErrorMessage);
                if (request is not null)
                {

                    var fakeNTSResponseBytes = ntsResponse.ResponseBytes?.ToHexString().FromHEX() ?? [];

                    Assert.That(fakeNTSResponseBytes,                                             Is.Not.Empty);
                    Assert.That(FlipAuthenticatorAndEncryptedCiphertextBit(fakeNTSResponseBytes),  Is.True);

                    if (!NTPResponse.TryParse(fakeNTSResponseBytes, out _, out var error, NTSKey: ntsKEResponse.S2CKey))
                        Assert.That(error, Does.Contain("SIV"));
                    else
                        Assert.Fail("Parsing the fake NTS response should have failed!");

                }

            }

        }

        #endregion

        #region TestNTS_CustomTLSCertificateValidation()

        /// <summary>
        /// Test the NTS client against the public NTS server,
        /// but use a custom TLS certificate validation handler.
        /// </summary>
        [Test]
        public async Task TestNTS_CustomTLSCertificateValidation()
        {

            var ntsClient                  = new NTSClient(
                                                 ServerName,
                                                 RemoteCertificateValidator: (sender,
                                                                              serverCertificate,
                                                                              certificateChain,
                                                                              ntsKETLSClient,
                                                                              sslPolicyErrors) => {

                                                                                  var sans = serverCertificate is not null
                                                                                                 ? serverCertificate.DecodeSubjectAlternativeNames()
                                                                                                 : [];

                                                                                  if (serverCertificate?.Subject.Contains(ServerName.Trimmed) == true &&
                                                                                      sans.Any(san => san.EndsWith(ServerName.Trimmed, StringComparison.Ordinal)))
                                                                                  {
                                                                                      return TLSValidationResult.Success();
                                                                                  }

                                                                                  return TLSValidationResult.Failed("Wrong server certificate!");

                                                                              },

                                                 Timeout:    Timeout,
                                                 DNSClient:  new DNSClient(SearchForIPv6DNSServers: false)

                                             );

            var ntsKEResult                = await ntsClient.GetNTSKERecords();
            var ntsKEResponse              = ntsKEResult.Response!;

            Assert.That(ntsKEResult.Success,              Is.True, ntsKEResult.ErrorMessage);
            Assert.That(ntsKEResult.ErrorCategory,        Is.EqualTo(NTSKEErrorCategory.None));
            Assert.That(ntsKEResponse,                   Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey,            Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.S2CKey,            Is.Not.Null);
            Assert.That(ntsKEResponse.S2CKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.Cookies.Count(),   Is.GreaterThan(0));


            var ntsResult                  = await ntsClient.QueryTime(NTSKEResponse: ntsKEResponse);
            var ntsResponse                = ntsResult.Response;
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

        #region TestNTS_CustomTLSCertificateValidation_Failed()

        /// <summary>
        /// Test the NTS client against the public NTS server,
        /// but use a custom TLS certificate validation handler.
        /// </summary>
        [Test]
        public async Task TestNTS_CustomTLSCertificateValidation_Failed()
        {

            var ntsClient                  = new NTSClient(
                                                 ServerName,
                                                 RemoteCertificateValidator: (sender,
                                                                              serverCertificate,
                                                                              certificateChain,
                                                                              ntsKETLSClient,
                                                                              sslPolicyErrors) => {
                                                                                  return TLSValidationResult.Failed("Wrong server certificate!");
                                                                              },

                                                 Timeout:    Timeout,
                                                 DNSClient:  new DNSClient(SearchForIPv6DNSServers: false)

                                             );

            var ntsKEResult                = await ntsClient.GetNTSKERecords();
            var ntsKEResponse              = ntsKEResult.Response!;

            Assert.That(ntsKEResult.Success,        Is.False);
            Assert.That(ntsKEResult.ErrorCategory,  Is.EqualTo(NTSKEErrorCategory.TLSCertificate));
            Assert.That(ntsKEResponse.ErrorMessage,   Is.EqualTo("certificate_unknown(46)"));


            var ntsResult                  = await ntsClient.QueryTime(NTSKEResponse: ntsKEResponse);
            var ntsResponse                = ntsResult.Response;

            Assert.That(ntsResponse,                  Is.Not.Null);
            Assert.That(ntsResult.ErrorMessage,       Is.EqualTo("certificate_unknown(46)"));

        }

        #endregion


        #region TestNTS_RequestSignedResponse()

        /// <summary>
        /// Test the NTS client against the public NTS server
        /// using the NTSRequestSignedResponse extension, which should be ignored.
        /// </summary>
        [Test]
        public async Task TestNTS_RequestSignedResponse()
        {

            var ntsClient                  = new NTSClient(
                                                 ServerName,
                                                 Timeout:    Timeout,
                                                 DNSClient:  new DNSClient(SearchForIPv6DNSServers: false)
                                             );

            var ntsKEResult                = await ntsClient.GetNTSKERecords();
            var ntsKEResponse              = ntsKEResult.Response!;

            Assert.That(ntsKEResult.Success,              Is.True, ntsKEResult.ErrorMessage);
            Assert.That(ntsKEResult.ErrorCategory,        Is.EqualTo(NTSKEErrorCategory.None));
            Assert.That(ntsKEResponse,                   Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey,            Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.S2CKey,            Is.Not.Null);
            Assert.That(ntsKEResponse.S2CKey.Length,     Is.GreaterThan(0));
            Assert.That(ntsKEResponse.Cookies.Count(),   Is.GreaterThan(0));


            var ntsResult                  = await ntsClient.QueryTime(
                                                       NTSKEResponse:       ntsKEResponse,
                                                       SignedResponseMode:  SignedResponseMode.Scheduled
                                                   );
            var ntsResponse                = ntsResult.Response;

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


        private static Boolean FlipAuthenticatorAndEncryptedCiphertextBit(Byte[] Packet)
        {

            var offset = 48;

            while (offset + 4 <= Packet.Length)
            {

                var type   = (ExtensionTypes) ((Packet[offset]     << 8) | Packet[offset + 1]);
                var length = (UInt16)         ((Packet[offset + 2] << 8) | Packet[offset + 3]);

                if (length < 4 || offset + length > Packet.Length)
                    return false;

                if (type == ExtensionTypes.AuthenticatorAndEncrypted)
                {

                    var valueOffset       = offset + 4;

                    if (valueOffset + 4 > Packet.Length)
                        return false;

                    var nonceLength       = (UInt16) ((Packet[valueOffset]     << 8) | Packet[valueOffset + 1]);
                    var ciphertextLength  = (UInt16) ((Packet[valueOffset + 2] << 8) | Packet[valueOffset + 3]);
                    var paddedNonceLength = (nonceLength + 3) & ~3;
                    var ciphertextOffset  = valueOffset + 4 + paddedNonceLength;

                    if (ciphertextLength == 0 ||
                        ciphertextOffset + ciphertextLength > Packet.Length)
                    {
                        return false;
                    }

                    Packet[ciphertextOffset + ciphertextLength - 1] ^= 0x01;
                    return true;

                }

                offset += length;

            }

            return false;

        }


    }

}
