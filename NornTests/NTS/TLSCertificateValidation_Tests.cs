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
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// TLS certificate validation tests.
    /// </summary>
    [TestFixture]
    public class TLSCertificateValidation_Tests
    {

        #region HostnameMatches_UsesSubjectAlternativeNames()

        [Test]
        public void HostnameMatches_UsesSubjectAlternativeNames()
        {

            using var rsa = RSA.Create(2048);
            var request   = new CertificateRequest(
                                "CN=wrong.example.org",
                                rsa,
                                HashAlgorithmName.SHA256,
                                RSASignaturePadding.Pkcs1
                            );

            var subjectAlternativeNames = new SubjectAlternativeNameBuilder();
            subjectAlternativeNames.AddDnsName("time.example.org");
            request.CertificateExtensions.Add(subjectAlternativeNames.Build());

            using var certificate = request.CreateSelfSigned(
                                        DateTimeOffset.UtcNow.AddMinutes(-1),
                                        DateTimeOffset.UtcNow.AddHours(1)
                                    );

            Assert.That(HostnameMatches(certificate, "time.example.org"),  Is.True);
            Assert.That(HostnameMatches(certificate, "other.example.org"), Is.False);

        }

        #endregion


        #region AValidatorOfOnesOwnIsLeftToAskAboutRevocation()

        /// <summary>
        /// Where a validator of one's own judges the certificate, the chain it is handed asked
        /// nothing about revocation: that is the validator's to ask.
        /// </summary>
        [Test]
        public void AValidatorOfOnesOwnIsLeftToAskAboutRevocation()
        {

            var policy = ValidatingTlsAuthentication.ChainPolicyFor(AskHere: false);

            Assert.That(policy.RevocationMode, Is.EqualTo(X509RevocationMode.NoCheck));

        }

        #endregion

        #region WithoutAValidatorTheKeyExchangeAsksOnlineAndNoLongerThanTheWait()

        /// <summary>
        /// Without a validator, the key exchange asks of the whole chain, online, for no longer
        /// than its time limit, and forgives a status that could not be had wherever it is.
        /// </summary>
        [Test]
        public void WithoutAValidatorTheKeyExchangeAsksOnlineAndNoLongerThanTheWait()
        {

            var policy = ValidatingTlsAuthentication.ChainPolicyFor(AskHere: true);

            Assert.Multiple(() => {
                Assert.That(policy.RevocationMode,          Is.EqualTo(X509RevocationMode.Online));
                Assert.That(policy.RevocationFlag,          Is.EqualTo(X509RevocationFlag.EntireChain));
                Assert.That(policy.UrlRetrievalTimeout,     Is.EqualTo(NTSKE_TLSClient.RevocationWait));
                Assert.That(NTSKE_TLSClient.RevocationWait, Is.EqualTo(TimeSpan.FromSeconds(3)));
                Assert.That(policy.VerificationFlags,       Is.EqualTo(X509VerificationFlags.IgnoreEndRevocationUnknown                  |
                                                                       X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown |
                                                                       X509VerificationFlags.IgnoreRootRevocationUnknown));
            });

        }

        #endregion

        #region ARevocationStatusThatCouldNotBeHadIsNoChainError()

        /// <summary>
        /// A list or a responder out of reach is not held against the certificate, wherever in
        /// the chain it is, and however the platform reports it.
        /// </summary>
        [Test]
        public void ARevocationStatusThatCouldNotBeHadIsNoChainError()
        {

            Assert.Multiple(() => {
                Assert.That(ValidatingTlsAuthentication.ChainErrorsOf(false, [ X509ChainStatusFlags.RevocationStatusUnknown ]),                                       Is.False);
                Assert.That(ValidatingTlsAuthentication.ChainErrorsOf(false, [ X509ChainStatusFlags.OfflineRevocation ]),                                             Is.False);
                Assert.That(ValidatingTlsAuthentication.ChainErrorsOf(false, [ X509ChainStatusFlags.RevocationStatusUnknown, X509ChainStatusFlags.OfflineRevocation ]), Is.False);
                Assert.That(ValidatingTlsAuthentication.ChainErrorsOf(true,  [ X509ChainStatusFlags.RevocationStatusUnknown ]),                                       Is.False);
                Assert.That(ValidatingTlsAuthentication.ChainErrorsOf(true,  []),                                                                                     Is.False);
            });

        }

        #endregion

        #region ARevokedCertificateAndEverythingElseIsAChainError()

        /// <summary>
        /// A certificate known to be revoked is a chain error, as is everything else that keeps a
        /// chain from being built - also beside a status that could not be had - and a chain not
        /// built that says nothing of why.
        /// </summary>
        [Test]
        public void ARevokedCertificateAndEverythingElseIsAChainError()
        {

            Assert.Multiple(() => {
                Assert.That(ValidatingTlsAuthentication.ChainErrorsOf(false, [ X509ChainStatusFlags.Revoked ]),                                                       Is.True);
                Assert.That(ValidatingTlsAuthentication.ChainErrorsOf(false, [ X509ChainStatusFlags.Revoked, X509ChainStatusFlags.RevocationStatusUnknown ]),          Is.True);
                Assert.That(ValidatingTlsAuthentication.ChainErrorsOf(false, [ X509ChainStatusFlags.UntrustedRoot, X509ChainStatusFlags.RevocationStatusUnknown ]),    Is.True);
                Assert.That(ValidatingTlsAuthentication.ChainErrorsOf(false, [ X509ChainStatusFlags.NotTimeValid ]),                                                  Is.True);
                Assert.That(ValidatingTlsAuthentication.ChainErrorsOf(false, []),                                                                                     Is.True);
            });

        }

        #endregion


        private static Boolean HostnameMatches(X509Certificate2 Certificate,
                                               String           Hostname)
        {

            var methodInfo = typeof(ValidatingTlsAuthentication).GetMethod(
                                 "HostnameMatches",
                                 BindingFlags.NonPublic | BindingFlags.Static
                             );

            Assert.That(methodInfo, Is.Not.Null);

            return (Boolean) methodInfo!.Invoke(null, [ Certificate, Hostname ])!;

        }

    }

}
