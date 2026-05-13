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
