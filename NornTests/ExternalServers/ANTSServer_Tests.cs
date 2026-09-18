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
using org.GraphDefined.Vanaheimr.Norn.NTS.NTSKERecords;

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

        #region TestNTS_TwoKeyExchangesOnOneClient()

        /// <summary>
        /// Two key exchanges on one client, each followed by a request: what a
        /// "synchronise now" button does when somebody presses it twice.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The second one is the whole test. A cookie is not a bearer token
        /// that stands on its own - the server decrypts it to recover the C2S
        /// and S2C keys of the exchange that issued it, and checks the request
        /// against those. The cookies left over from the first exchange are
        /// therefore not spare credentials once a second exchange has run, they
        /// are credentials for keys the server has replaced.
        /// </para>
        /// <para>
        /// This is not a hypothetical: against ptbtime1.ptb.de the first sync
        /// succeeded and every one after it came back with a Kiss-o-Death
        /// NTSN. The pool was a FIFO that accepted both generations, so the
        /// request after the second exchange was sealed under the second
        /// exchange key while handing the server a cookie from the first - the
        /// same thing a replay looks like from the server side, and answered
        /// the same way.
        /// </para>
        /// </remarks>
        [Test]
        public async Task TestNTS_TwoKeyExchangesOnOneClient()
        {

            var ntsClient = new NTSClient(
                                ServerName,
                                Timeout:    Timeout,
                                DNSClient:  new DNSClient(SearchForIPv6DNSServers: false)
                            );

            for (var attempt = 1; attempt <= 2; attempt++)
            {

                var keyExchange = await ntsClient.GetNTSKERecords();
                Assert.That(keyExchange.Success,             Is.True,  $"Key exchange {attempt}: {keyExchange.ErrorMessage}");

                var response    = keyExchange.Response!;
                Assert.That(response,                        Is.Not.Null,  $"Key exchange {attempt}: no response!");

                ntsClient.SeedCookies(response);

                // Whatever the exchange before left behind, the pool holds this
                // one and nothing else - which is the property that makes the
                // request below answerable at all.
                Assert.That(ntsClient.AvailableCookieCount,  Is.EqualTo(response.Cookies.Count()),
                            $"Key exchange {attempt}: the pool is holding cookies from more than one exchange.");

                var query       = await ntsClient.QueryTime(NTSKEResponse: response);

                Assert.That(query.Success,                   Is.True,  $"Request {attempt}: {query.ErrorMessage}");
                Assert.That(query.KissOfDeath,               Is.Null,  $"Request {attempt} was answered with a Kiss-o-Death.");

            }

        }

        #endregion

        #region TestNTS_NAKRetiresTheCookiePool()

        /// <summary>
        /// A cookie the server cannot unwrap earns an NTS NAK, and the client
        /// then throws away every cookie it holds rather than only the one it
        /// spent.
        /// </summary>
        /// <remarks>
        /// <para>
        /// RFC 8915 section 5.7 - "the client SHOULD discard all cookies and
        /// AEAD keys associated with the server and initiate a fresh NTS-KE
        /// handshake" - and the only thing that lets a long-lived client
        /// recover. A key exchange is run when the pool runs dry, so a pool
        /// kept full of cookies the server has stopped accepting, which is what
        /// a rotated server key leaves behind, is a client that never runs
        /// another one and never works again.
        /// </para>
        /// <para>
        /// Three cookies, so the assertion is about the pool and not about the
        /// one cookie the request spent: dequeuing one leaves two, and nought
        /// is reachable only by retiring them.
        /// </para>
        /// <para>
        /// A server is within its rights to say nothing at all instead - our
        /// own <c>NTSServer</c> fails closed and drops the datagram, since an
        /// authenticator it cannot verify is one it cannot answer either - so a
        /// server that stays silent is ignored rather than failed. It is the
        /// servers that do NAK, and ptbtime1.ptb.de is one, that this is about.
        /// </para>
        /// </remarks>
        [Test]
        public async Task TestNTS_NAKRetiresTheCookiePool()
        {

            var ntsClient = new NTSClient(
                                ServerName,
                                Timeout:    Timeout,
                                DNSClient:  new DNSClient(SearchForIPv6DNSServers: false)
                            );

            // Nothing this server ever issued: the keys are the right length
            // for AES-SIV-CMAC-256 so the request is well formed, and the
            // cookies are the right sort of size for it to try to unwrap them.
            var stranger  = new NTSKE_Response(
                                Enumerable.Range(1, 3).
                                    Select(number => new NewCookieForNTPv4(
                                                         false,
                                                         Enumerable.Repeat((Byte) number, 104).ToArray()
                                                     ) as NTSKE_Record).
                                    ToArray(),
                                C2SKey:  Enumerable.Repeat((Byte) 0xC2, 32).ToArray(),
                                S2CKey:  Enumerable.Repeat((Byte) 0x52, 32).ToArray()
                            );

            ntsClient.SeedCookies(stranger);
            Assert.That(ntsClient.AvailableCookieCount,  Is.EqualTo(3));

            var query     = await ntsClient.QueryTime(NTSKEResponse: stranger);

            Assert.That(query.Success,                   Is.False, "The server accepted a cookie it never issued!");

            if (query.ErrorCategory == NTSQueryErrorCategory.NTPTimeout)
                Assert.Ignore($"{ServerName} answers a cookie it cannot unwrap with silence rather than a NAK.");

            Assert.That(query.KissOfDeath?.Code,         Is.EqualTo("NTSN"));
            Assert.That(query.KissOfDeath?.Action,       Is.EqualTo(NTPKissAction.RenegotiateNTS));

            // The point of the whole test: two cookies were never sent and are
            // gone all the same, because they could only have earned the same
            // answer.
            Assert.That(ntsClient.AvailableCookieCount,  Is.EqualTo(0), "The client kept cookies the server has refused.");

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
                                                                                                 ? Illias.CertificateExtensions.DecodeSubjectAlternativeNames(serverCertificate)
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
