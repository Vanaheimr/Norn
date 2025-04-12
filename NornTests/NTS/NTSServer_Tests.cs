/*
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

using Microsoft.Extensions.Hosting;
using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// Test the NTS server.
    /// </summary>
    [TestFixture]
    public class NTSServer_Tests
    {

        #region TestServer1()

        /// <summary>
        /// Test the NTS server.
        /// </summary>
        [Test]
        public async Task TestServer1()
        {

            var ntsServer                  = new NTSServer(
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
            await ntsServer.Start();

            var ntsClient                  = new NTSClient(
                                                 "127.0.0.1",
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
                                                                                      return (true, []);
                                                                                  }

                                                                                  return (false, ["Wrong server certificate!"]);

                                                                              }
                                             );

            var ntsKEResponse              = ntsClient.GetNTSKERecords(RequestNTSPublicKeys: true);

            Assert.That(ntsKEResponse,                      Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey,               Is.Not.Null);
            Assert.That(ntsKEResponse.C2SKey.Length,        Is.GreaterThan(0));
            Assert.That(ntsKEResponse.S2CKey,               Is.Not.Null);
            Assert.That(ntsKEResponse.S2CKey.Length,        Is.GreaterThan(0));
            Assert.That(ntsKEResponse.Cookies.   Count(),   Is.GreaterThan(0));
            Assert.That(ntsKEResponse.PublicKeys.Count(),   Is.GreaterThan(0));

            var publicKey                  = ntsKEResponse.PublicKeys.First();

            var ntsResponse                = await ntsClient.QueryTime(
                                                       NTSKEResponse:       ntsKEResponse,
                                                       SignedResponseMode:  SignedResponseMode.Scheduled,
                                                       Timeout:             TimeSpan.FromMinutes(1)
                                                   );

            Assert.That(ntsResponse,    Is.Not.Null);

            DebugX.Log($"{ntsClient.Host} Serverzeit 1 (UTC): " + NTPPacket.NTPTimestampToDateTime(ntsResponse.TransmitTimestamp.Value).ToString("o"));


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

    }

}
