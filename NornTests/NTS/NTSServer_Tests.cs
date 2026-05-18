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

using System.Net;
using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// NTS server tests.
    /// </summary>
    [TestFixture]
    [Category("LocalIntegration")]
    public class NTSServer_Tests
    {

        #region Data

        private static readonly IPPort testNTSKEPort = FindFreeTCPPort();
        private static readonly IPPort testNTPPort   = FindFreeUDPPort();

        private readonly NTSServer ntsServer;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new NTS server.
        /// </summary>
        public NTSServer_Tests()
        {

            ntsServer = new NTSServer(
                            NTSKEPort: testNTSKEPort,
                            NTSPort:   testNTPPort,
                            MasterKeysFilePath: null,
                            KeyPair:   new KeyPair(
                                           Id:                   1,
                                           PrivateKey:          "ANm7PAbjqlK+SPW/JLFXVt8U7vCpg69Xxy77rA8SN+Ce".FromBASE64(),
                                           PublicKey:           "BNJ9BLZTcAeuPMHDDDXA0RiVNse8WH4b+/r/bA9HhDsDtTSBsrvmjbnA3w3JlC7ipvhHEkdGbFEIH+ZT0ZEekTA=".FromBASE64(),
                                           Description:          I18NString.Create(Languages.en, "Test public key"),
                                           EllipticCurve:       "secp256r1",
                                           SignatureAlgorithm:  "SHA256withECDSA",
                                           NotBefore:            Timestamp.Now,
                                           NotAfter:             Timestamp.Now.AddMonths(1)
                                       )
                        );

        }

        #endregion


        #region StartNTSServer()

        /// <summary>
        /// Start the NTS server.
        /// </summary>
        [OneTimeSetUp]
        public async Task StartNTSServer()
        {
            await ntsServer.Start();
        }

        #endregion

        #region ShutdownNTSServer()

        /// <summary>
        /// Stop the NTS server.
        /// </summary>
        [OneTimeTearDown]
        public void ShutdownNTSServer()
        {
            ntsServer.Shutdown();
        }

        #endregion


        #region TestServer1()

        /// <summary>
        /// Test the NTS server.
        /// </summary>
        [Test]
        public async Task TestServer1()
        {

            var ntsClient                  = new NTSClient(
                                                 Hermod.DNS.DomainName.Localhost,
                                                 NTSKE_Port: testNTSKEPort,
                                                 NTP_Port:   testNTPPort,
                                                 IPVersionPreference: IPVersionPreference.IPv4Only,
                                                 RemoteCertificateValidator: (sender,
                                                                              serverCertificate,
                                                                              certificateChain,
                                                                              ntsKETLSClient,
                                                                              sslPolicyErrors) => {

                                                                                  var sans = serverCertificate is not null
                                                                                                 ? serverCertificate.DecodeSubjectAlternativeNames()
                                                                                                 : [];

                                                                                  if (serverCertificate?.Subject.Contains("ntpKE.example.org") == true &&
                                                                                      sans.Contains("DNS-Name=ntpKE1.example.org") &&
                                                                                      sans.Contains("DNS-Name=ntpKE2.example.org"))
                                                                                  {
                                                                                      return TLSValidationResult.Success();
                                                                                  }

                                                                                  return TLSValidationResult.Failed("Wrong server certificate!");

                                                                              }
                                              );

            var ntsKEResult                = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: false);
            var ntsKEResponse              = ntsKEResult.Response!;

            Assert.That(ntsKEResult.Success,                    Is.True, ntsKEResult.ErrorMessage);
            Assert.That(ntsKEResult.ErrorCategory,              Is.EqualTo(NTSKEErrorCategory.None));
            Assert.That(ntsKEResponse,                      Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey,               Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey.Length,        Is.GreaterThan(0));
            Assert.That(ntsKEResponse.S2CKey,               Is.Not.Null);
            Assert.That(ntsKEResponse.S2CKey.Length,        Is.GreaterThan(0));
            Assert.That(ntsKEResponse.Cookies.   Count(),   Is.GreaterThan(0));
            Assert.That(ntsKEResponse.TimingInfo,                             Is.Not.Null);
            Assert.That(ntsKEResponse.TimingInfo?.DNSLookupDuration,          Is.Not.Null);
            Assert.That(ntsKEResponse.TimingInfo?.TCPConnectDuration,         Is.Not.Null);
            Assert.That(ntsKEResponse.TimingInfo?.TLSHandshakeDuration,       Is.Not.Null);
            Assert.That(ntsKEResponse.TimingInfo?.NTSKEProtocolDuration,      Is.Not.Null);
            Assert.That(ntsKEResponse.TimingInfo?.TotalDuration,              Is.Not.Null);
            Assert.That(ntsKEResponse.TimingInfo?.ResolvedIPAddresses.Any(),  Is.True);
            Assert.That(ntsKEResponse.TimingInfo?.ConnectedIPAddress,         Is.Not.Null);
            Assert.That(ntsKEResponse.TLSInfo,                                Is.Not.Null);
            Assert.That(ntsKEResponse.TLSInfo?.ServerCertificate,             Is.Not.Null);
            Assert.That(ntsKEResponse.TLSInfo?.NegotiatedCipherSuite,         Is.Not.Null);
            Assert.That(ntsKEResponse.TLSInfo?.NegotiatedTLSVersion,          Is.EqualTo("TLS 1.3"));

            var ntsQueryResult             = await ntsClient.QueryTime(NTSKEResponse:  ntsKEResponse,
                                                                               Timeout:        TimeSpan.FromSeconds(10));

            Assert.That(ntsQueryResult.Success,                    Is.True, ntsQueryResult.ErrorMessage);
            Assert.That(ntsQueryResult.ErrorCategory,              Is.EqualTo(NTSQueryErrorCategory.None));
            Assert.That(ntsQueryResult.Response,                   Is.Not.Null);
            Assert.That(ntsQueryResult.RemoteDescription,          Is.Not.Empty);
            Assert.That(ntsQueryResult.UsedCookie,                 Is.Not.Null);
            Assert.That(ntsQueryResult.RemainingCookiesAfterQuery, Is.GreaterThanOrEqualTo(0));
            Assert.That(ntsQueryResult.Diagnostics,                Is.Not.Null);
            Assert.That(ntsQueryResult.Diagnostics.RemoteDescription, Is.Not.Empty);

            var ntsResponse                = ntsQueryResult.Response;
            Assert.That(ntsResponse,    Is.Not.Null);

            if (ntsResponse is not null)
            {

                var request = ntsResponse.Request;

                Assert.That(request,  Is.Not.Null,  ntsResponse.ErrorMessage);

                if (request is not null)
                {

                    Assert.That(request.    UniqueIdentifier(),                                          Is.Not.Null);
                    Assert.That(ntsResponse.UniqueIdentifier(),                                          Is.Not.Null);
                    Assert.That(ntsResponse.UniqueIdentifier()?.ToHexString(),                           Is.EqualTo(request.UniqueIdentifier()?.ToHexString()));

                    Assert.That(request.Extensions.Count(),                                              Is.GreaterThanOrEqualTo(3));
                    Assert.That(request.Extensions.ElementAt(0) is UniqueIdentifierExtension,            Is.True);
                    Assert.That(request.Extensions.ElementAt(1) is NTSCookieExtension,                   Is.True);
                    Assert.That(request.Extensions.Last() is AuthenticatorAndEncryptedExtension,         Is.True);

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

            var metrics = ntsServer.Metrics;

            Assert.That(metrics.NTSKEConnectionsAccepted, Is.GreaterThanOrEqualTo(1));
            Assert.That(metrics.NTSKEResponsesSent,       Is.GreaterThanOrEqualTo(1));
            Assert.That(metrics.NTPRequestsReceived,      Is.GreaterThanOrEqualTo(1));
            Assert.That(metrics.NTPResponsesSent,         Is.GreaterThanOrEqualTo(1));

        }

        #endregion

        #region TestNTSKE_Advertises_Explicit_ExternalURLs()

        /// <summary>
        /// Test that explicitly configured NTP URLs are announced via NTS-KE.
        /// </summary>
        [Test]
        public async Task TestNTSKE_Advertises_Explicit_ExternalURLs()
        {

            var ntsKEPort = FindFreeTCPPort();
            var ntpPort   = FindFreeUDPPort();

            var server    = new NTSServer(
                                NTSKEPort:          ntsKEPort,
                                NTSPort:            ntpPort,
                                ExternalURLs:       [ URL.Parse($"udp://localhost:{ntpPort}") ],
                                MasterKeysFilePath: null
                            );

            await server.Start();

            try
            {

                var ntsClient     = new NTSClient(
                                        Hermod.DNS.DomainName.Localhost,
                                        NTSKE_Port: ntsKEPort,
                                        NTP_Port:   ntpPort,
                                        IPVersionPreference: IPVersionPreference.IPv4Only,
                                        RemoteCertificateValidator: (sender,
                                                                     serverCertificate,
                                                                     certificateChain,
                                                                     ntsKETLSClient,
                                                                     sslPolicyErrors) => TLSValidationResult.Success()
                                    );

                var ntsKEResult   = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: false);
                var ntsKEResponse = ntsKEResult.Response!;

                Assert.That(ntsKEResult.Success, Is.True, ntsKEResult.ErrorMessage);
                Assert.That(ntsKEResponse.NTPv4Servers.Select(server => server.ToString().TrimEnd('.')), Does.Contain("localhost"));
                Assert.That(ntsKEResponse.NTPv4Ports, Does.Contain(ntpPort));

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region MasterKey_Rotates_After_Lifetime()

        /// <summary>
        /// Test that expired master keys are not kept as the active key for new cookies.
        /// </summary>
        [Test]
        public async Task MasterKey_Rotates_After_Lifetime()
        {

            var server = new NTSServer(
                             MasterKeysFilePath:           null,
                             MasterKeyLifetime:            TimeSpan.FromMilliseconds(1),
                             MasterKeyRotationGracePeriod: TimeSpan.FromSeconds(10)
                         );

            var firstMasterKeyId = server.CurrentMasterKeyId;

            await Task.Delay(TimeSpan.FromMilliseconds(1200));

            var secondMasterKeyId = server.CurrentMasterKeyId;

            Assert.That(secondMasterKeyId, Is.GreaterThan(firstMasterKeyId));

        }

        #endregion

        #region TestServer_SignedResponses1()

        /// <summary>
        /// Test the NTS server using our "signed responses" vendor extension.
        /// </summary>
        [Test]
        public async Task TestServer_SignedResponses1()
        {

            var ntsClient                  = new NTSClient(
                                                 Hermod.DNS.DomainName.Localhost,
                                                 NTSKE_Port: testNTSKEPort,
                                                 NTP_Port:   testNTPPort,
                                                 IPVersionPreference: IPVersionPreference.IPv4Only,
                                                 RemoteCertificateValidator: (sender,
                                                                              serverCertificate,
                                                                              certificateChain,
                                                                              ntsKETLSClient,
                                                                              sslPolicyErrors) => {

                                                                                  var sans = serverCertificate is not null
                                                                                                 ? serverCertificate.DecodeSubjectAlternativeNames()
                                                                                                 : [];

                                                                                  if (serverCertificate?.Subject.Contains("ntpKE.example.org") == true &&
                                                                                      sans.Contains("DNS-Name=ntpKE1.example.org") &&
                                                                                      sans.Contains("DNS-Name=ntpKE2.example.org"))
                                                                                  {
                                                                                      return TLSValidationResult.Success();
                                                                                  }

                                                                                  return TLSValidationResult.Failed("Wrong server certificate!");

                                                                              }
                                              );

            var ntsKEResult                = await ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);
            var ntsKEResponse              = ntsKEResult.Response!;

            Assert.That(ntsKEResult.Success,                              Is.True, ntsKEResult.ErrorMessage);
            Assert.That(ntsKEResult.ErrorCategory,                        Is.EqualTo(NTSKEErrorCategory.None));
            Assert.That(ntsKEResponse,                                    Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey,                             Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey.Length,                      Is.GreaterThan(0));
            Assert.That(ntsKEResponse.S2CKey,                             Is.Not.Null);
            Assert.That(ntsKEResponse.S2CKey.Length,                      Is.GreaterThan(0));
            Assert.That(ntsKEResponse.Cookies.   Count(),                 Is.GreaterThan(0));
            Assert.That(ntsKEResponse.PublicKeys.Count(),                 Is.GreaterThan(0));
            Assert.That(ntsKEResponse.TimingInfo,                         Is.Not.Null);
            Assert.That(ntsKEResponse.TimingInfo?.TLSHandshakeDuration,   Is.Not.Null);
            Assert.That(ntsKEResponse.TimingInfo?.NTSKEProtocolDuration,  Is.Not.Null);

            var publicKey                  = ntsKEResponse.PublicKeys.First();

            var ntsQueryResult             = await ntsClient.QueryTime(
                                                       NTSKEResponse:       ntsKEResponse,
                                                       SignedResponseMode:  SignedResponseMode.Scheduled,
                                                       Timeout:             TimeSpan.FromSeconds(10)
                                                   );
            var ntsResponse                = ntsQueryResult.Response;

            Assert.That(ntsResponse,    Is.Not.Null);

            if (ntsResponse?.TransmitTimestamp is not null)
                DebugX.Log($"{ntsClient.Hostname} Serverzeit 1 (UTC): " + NTPPacket.NTPTimestampToDateTime(ntsResponse.TransmitTimestamp.Value).ToString("o"));


            if (ntsResponse is not null)
            {

                var request = ntsResponse.Request;

                Assert.That(request,  Is.Not.Null,  ntsResponse.ErrorMessage);

                if (request is not null)
                {

                    Assert.That(request.    UniqueIdentifier(),                                          Is.Not.Null);
                    Assert.That(ntsResponse.UniqueIdentifier(),                                          Is.Not.Null);
                    Assert.That(ntsResponse.UniqueIdentifier()?.ToHexString(),                           Is.EqualTo(request.UniqueIdentifier()?.ToHexString()));

                    Assert.That(request.Extensions.Count(),                                              Is.GreaterThanOrEqualTo(4));
                    Assert.That(request.Extensions.ElementAt(0) is UniqueIdentifierExtension,            Is.True);
                    Assert.That(request.Extensions.ElementAt(1) is NTSCookieExtension,                   Is.True);
                    Assert.That(request.Extensions.Any(extension => extension is NTSRequestSignedResponseExtension), Is.True);
                    Assert.That(request.Extensions.Last() is AuthenticatorAndEncryptedExtension,         Is.True);

                }


                // Initially 3, but +1 decrypted extension and +1 for response signature
                Assert.That(ntsResponse.Extensions.Count(),  Is.EqualTo(5));


                // 1. Check Unique Identifier Extension
                if (ntsResponse.Extensions.ElementAt(0) is UniqueIdentifierExtension uniqueIdentifierExtension)
                {
                    Assert.That(uniqueIdentifierExtension.Authenticated,                          Is.True);
                    Assert.That(uniqueIdentifierExtension.Encrypted,                              Is.False);
                }
                else
                    Assert.Fail("Unique Identifier Extension is invalid!");


                // 2. Check NTS Signed Response Announcement Extension
                if (ntsResponse.Extensions.ElementAt(1) is NTSSignedResponseAnnouncementExtension signedResponseAnnouncementExtension)
                {
                    Assert.That(signedResponseAnnouncementExtension.IsScheduled,                  Is.True);
                }
                else
                    Assert.Fail("NTS Signed Response Announcement Extension is invalid!");


                // 3. Check NTS Authenticator and Encrypted Extension
                if (ntsResponse.Extensions.ElementAt(2) is AuthenticatorAndEncryptedExtension authenticatorAndEncryptedExtension)
                {
                    Assert.That(authenticatorAndEncryptedExtension.Authenticated,                 Is.False);
                    Assert.That(authenticatorAndEncryptedExtension.Encrypted,                     Is.False);
                    Assert.That(authenticatorAndEncryptedExtension.EncryptedExtensions.Count(),   Is.EqualTo(1));
                }
                else
                    Assert.Fail("NTS Authenticator and Encrypted Extension is invalid!");


                // 4. Check NTS Cookie Extension
                if (ntsResponse.Extensions.ElementAt(3) is NTSCookieExtension cookieExtension)
                {
                    Assert.That(cookieExtension.Authenticated,                                    Is.True);
                    Assert.That(cookieExtension.Encrypted,                                        Is.True);
                }
                else
                    Assert.Fail("NTS Cookie Extension is invalid!");


                // 5. Check NTS Signed Response Extension
                if (ntsResponse.Extensions.ElementAt(4) is NTSSignedResponseExtension signedResponseExtension)
                {
                    Assert.That(signedResponseExtension.Authenticated,                            Is.False);
                    Assert.That(signedResponseExtension.Encrypted,                                Is.False);
                    Assert.That(signedResponseExtension.Verify(ntsResponse, publicKey),           Is.True);
                }
                else
                    Assert.Fail("NTS Signed Response Extension is invalid!");

            }

        }

        #endregion

        #region (private static) FindFreeTCPPort()

        private static IPPort FindFreeTCPPort()
        {

            using var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);

            listener.Start();

            return IPPort.Parse(
                       ((IPEndPoint) listener.LocalEndpoint).Port
                   );

        }

        #endregion

        #region (private static) FindFreeUDPPort()

        private static IPPort FindFreeUDPPort()
        {

            using var udpClient = new UdpClient(
                                      new IPEndPoint(
                                          System.Net.IPAddress.Loopback,
                                          0
                                      )
                                  );

            return IPPort.Parse(
                       ((IPEndPoint) udpClient.Client.LocalEndPoint!).Port
                   );

        }

        #endregion


    }

}
