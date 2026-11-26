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

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// The certificate NTS-KE over TLS shows, renewed while the server runs - as a certificate
    /// of an ACME CA is renewed every 60 days.
    /// </summary>
    [TestFixture]
    public class NTSServer_TLSIdentity_Tests
    {

        #region ARunningServerShowsTheNewCertificate_AndItsClientsGoOn()

        /// <summary>
        /// A key exchange after the call is made under the new certificate, and a client goes on
        /// with the cookies of its key exchange from before: the server was not made anew.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task ARunningServerShowsTheNewCertificate_AndItsClientsGoOn()
        {

            var first   = Identity("first.test");
            var second  = Identity("second.test");

            var server  = await FreePorts.Start(() => new NTSServer(NTSKEPort:             FreePorts.TCP(),
                                                                    NTSPort:               FreePorts.UDP(),
                                                                    TLSCertificate:        first.Certificate,
                                                                    TLSPrivateKey:         first.PrivateKey,
                                                                    TLSServerSubjectName:  "first.test"));

            try
            {

                Byte[]? shown         = null;
                var     client        = ClientOf(server.TCPPort, server.UDPPort, certificate => shown = certificate);

                var     before        = await client.GetNTSKERecords(RequestNTSPublicKeys: false);

                Assert.That(before.Success, Is.True, before.ErrorMessage);
                Assert.That(shown,          Is.EqualTo(first.Certificate.GetEncoded()), "the first certificate was not shown");

                server.RenewTLSIdentity(second.Certificate, second.PrivateKey, "second.test");

                Assert.That(server.TLSCertificate,        Is.SameAs(second.Certificate));
                Assert.That(server.TLSServerSubjectName,  Is.EqualTo("second.test"));

                var     after         = await client.GetNTSKERecords(RequestNTSPublicKeys: false);

                Assert.That(after.Success,  Is.True, after.ErrorMessage);
                Assert.That(shown,          Is.EqualTo(second.Certificate.GetEncoded()), "the second certificate was not shown");

                var     withOldCookie = await client.QueryTime(NTSKEResponse:  before.Response,
                                                               Timeout:        TimeSpan.FromSeconds(10));

                Assert.That(withOldCookie.Success, Is.True, withOldCookie.ErrorMessage);

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region AKeyThatIsNotTheCertificatesIsRefused()

        /// <summary>
        /// A certificate with a key that is not its own, or one without the other, could make
        /// no handshake: it is refused, by the constructor and by RenewTLSIdentity, and the
        /// identity before stays.
        /// </summary>
        [Test]
        public void AKeyThatIsNotTheCertificatesIsRefused()
        {

            var first   = Identity("first.test");
            var second  = Identity("second.test");

            Assert.Throws<ArgumentException>(() => new NTSServer(TLSCertificate:   first.Certificate,
                                                                 TLSPrivateKey:    second.PrivateKey,
                                                                 ClockResolution:  TimeSpan.FromMilliseconds(1)));

            var server  = new NTSServer(TLSCertificate:   first.Certificate,
                                        TLSPrivateKey:    first.PrivateKey,
                                        ClockResolution:  TimeSpan.FromMilliseconds(1));

            Assert.Throws<ArgumentException>(() => server.RenewTLSIdentity(second.Certificate, first.PrivateKey));
            Assert.Throws<ArgumentException>(() => server.RenewTLSIdentity(second.Certificate, null));
            Assert.Throws<ArgumentException>(() => server.RenewTLSIdentity(null,               second.PrivateKey));

            Assert.That(server.TLSCertificate, Is.SameAs(first.Certificate));

            server.RenewTLSIdentity(null, null);

            Assert.That(server.TLSCertificate, Is.Null, "a self-signed certificate the server made itself");

        }

        #endregion


        #region (private static) Identity(Name)

        private static (X509Certificate Certificate, ECPrivateKeyParameters PrivateKey) Identity(String Name)

            => NTSKE_TLSService.GenerateSelfSignedServerCertificate($"CN={Name}", [ Name ]);

        #endregion

        #region (private static) ClientOf(NTSKEPort, NTPPort, Shown)

        private static NTSClient ClientOf(IPPort          NTSKEPort,
                                          IPPort          NTPPort,
                                          Action<Byte[]>  Shown)

            => new (Hermod.DNS.DomainName.Localhost,
                    NTSKE_Port:                  NTSKEPort,
                    NTP_Port:                    NTPPort,
                    IPVersionPreference:         IPVersionPreference.IPv4Only,
                    RemoteCertificateValidator:  (sender, serverCertificate, certificateChain, ntsKETLSClient, sslPolicyErrors) => {
                                                     if (serverCertificate is not null)
                                                         Shown(serverCertificate.RawData);
                                                     return TLSValidationResult.Success();
                                                 });

        #endregion

    }

}
