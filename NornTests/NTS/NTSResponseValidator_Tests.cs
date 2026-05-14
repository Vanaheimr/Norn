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

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    [TestFixture]
    public class NTSResponseValidator_Tests
    {

        #region Validate_AcceptsAuthenticatedNTSResponse()

        [Test]
        public void Validate_AcceptsAuthenticatedNTSResponse()
        {

            var key       = Enumerable.Range(0, 32).Select(value => (Byte) value).ToArray();
            var uniqueId  = Enumerable.Range(1, 32).Select(value => (Byte) value).ToArray();
            var request   = CreateRequest(uniqueId);
            var response  = CreateResponse(
                                request,
                                [
                                    new UniqueIdentifierExtension(uniqueId, Authenticated: true),
                                    new AuthenticatorAndEncryptedExtension(new Byte[16], new Byte[16]),
                                    new NTSCookieExtension(new Byte[100], Authenticated: true, Encrypted: true)
                                ]
                            );

            var result = NTSResponseValidator.Validate(response, request, uniqueId, key);

            Assert.That(result.IsValid,       Is.True, result.ErrorMessage);
            Assert.That(result.ErrorCategory, Is.EqualTo(NTSQueryErrorCategory.None));
            Assert.That(result.Response,      Is.SameAs(response));

        }

        #endregion

        #region Validate_RejectsMissingAuthenticator_ButKeepsResponse()

        [Test]
        public void Validate_RejectsMissingAuthenticator_ButKeepsResponse()
        {

            var key       = Enumerable.Range(0, 32).Select(value => (Byte) value).ToArray();
            var uniqueId  = Enumerable.Range(1, 32).Select(value => (Byte) value).ToArray();
            var request   = CreateRequest(uniqueId);
            var response  = CreateResponse(
                                request,
                                [
                                    new UniqueIdentifierExtension(uniqueId, Authenticated: false),
                                    new NTSCookieExtension(new Byte[100], Authenticated: true, Encrypted: true)
                                ]
                            );

            var result = NTSResponseValidator.Validate(response, request, uniqueId, key);

            Assert.That(result.IsValid,       Is.False);
            Assert.That(result.ErrorCategory, Is.EqualTo(NTSQueryErrorCategory.NTSAuthentication));
            Assert.That(result.Response,      Is.SameAs(response));
            Assert.That(result.ErrorMessage,  Does.Contain("Authenticator"));
            Assert.That(result.ErrorMessage,  Does.Contain("Unique Identifier was not authenticated"));

        }

        #endregion

        #region Validate_RejectsMissingUniqueIdentifier()

        [Test]
        public void Validate_RejectsMissingUniqueIdentifier()
        {

            var key       = Enumerable.Range(0, 32).Select(value => (Byte) value).ToArray();
            var uniqueId  = Enumerable.Range(1, 32).Select(value => (Byte) value).ToArray();
            var request   = CreateRequest(uniqueId);
            var response  = CreateResponse(
                                request,
                                [
                                    new AuthenticatorAndEncryptedExtension(new Byte[16], new Byte[16]),
                                    new NTSCookieExtension(new Byte[100], Authenticated: true, Encrypted: true)
                                ]
                            );

            var result = NTSResponseValidator.Validate(response, request, uniqueId, key);

            Assert.That(result.IsValid,       Is.False);
            Assert.That(result.ErrorCategory, Is.EqualTo(NTSQueryErrorCategory.NTSAuthentication));
            Assert.That(result.Response,      Is.SameAs(response));
            Assert.That(result.ErrorMessage,  Does.Contain("Unique Identifier"));

        }

        #endregion

        #region Validate_RejectsOriginateTimestampMismatch()

        [Test]
        public void Validate_RejectsOriginateTimestampMismatch()
        {

            var key       = Enumerable.Range(0, 32).Select(value => (Byte) value).ToArray();
            var uniqueId  = Enumerable.Range(1, 32).Select(value => (Byte) value).ToArray();
            var request   = CreateRequest(uniqueId);
            var response  = CreateResponse(
                                request,
                                [
                                    new UniqueIdentifierExtension(uniqueId, Authenticated: true),
                                    new AuthenticatorAndEncryptedExtension(new Byte[16], new Byte[16]),
                                    new NTSCookieExtension(new Byte[100], Authenticated: true, Encrypted: true)
                                ],
                                OriginateTimestamp: request.TransmitTimestamp!.Value + 1
                            );

            var result = NTSResponseValidator.Validate(response, request, uniqueId, key);

            Assert.That(result.IsValid,       Is.False);
            Assert.That(result.ErrorCategory, Is.EqualTo(NTSQueryErrorCategory.Protocol));
            Assert.That(result.Response,      Is.SameAs(response));
            Assert.That(result.ErrorMessage,  Does.Contain("originate timestamp"));

        }

        #endregion

        #region Validate_RejectsKissOfDeath_ButKeepsResponse()

        [Test]
        public void Validate_RejectsKissOfDeath_ButKeepsResponse()
        {

            var uniqueId  = Enumerable.Range(1, 32).Select(value => (Byte) value).ToArray();
            var request   = CreateRequest(uniqueId);
            var response  = CreateResponse(
                                request,
                                [],
                                Stratum: 0
                            );

            var result = NTSResponseValidator.Validate(response, request, RequireNTS: false);

            Assert.That(result.IsValid,       Is.False);
            Assert.That(result.ErrorCategory, Is.EqualTo(NTSQueryErrorCategory.KissOfDeath));
            Assert.That(result.Response,      Is.SameAs(response));

        }

        #endregion

        #region Validate_RejectsReplay()

        [Test]
        public void Validate_RejectsReplay()
        {

            var key       = Enumerable.Range(0, 32).Select(value => (Byte) value).ToArray();
            var uniqueId  = Enumerable.Range(1, 32).Select(value => (Byte) value).ToArray();
            var request   = CreateRequest(uniqueId);
            var response  = CreateResponse(
                                request,
                                [
                                    new UniqueIdentifierExtension(uniqueId, Authenticated: true),
                                    new AuthenticatorAndEncryptedExtension(new Byte[16], new Byte[16]),
                                    new NTSCookieExtension(new Byte[100], Authenticated: true, Encrypted: true)
                                ]
                            );

            var result = NTSResponseValidator.Validate(response, request, uniqueId, key, IsReplay: true);

            Assert.That(result.IsValid,       Is.False);
            Assert.That(result.ErrorCategory, Is.EqualTo(NTSQueryErrorCategory.Protocol));
            Assert.That(result.ErrorMessage,  Does.Contain("duplicate/replay"));

        }

        #endregion

        #region Validate_RejectsHugeRootDistanceFields()

        [Test]
        public void Validate_RejectsHugeRootDistanceFields()
        {

            var key       = Enumerable.Range(0, 32).Select(value => (Byte) value).ToArray();
            var uniqueId  = Enumerable.Range(1, 32).Select(value => (Byte) value).ToArray();
            var request   = CreateRequest(uniqueId);
            var response  = CreateResponse(
                                request,
                                [
                                    new UniqueIdentifierExtension(uniqueId, Authenticated: true),
                                    new AuthenticatorAndEncryptedExtension(new Byte[16], new Byte[16]),
                                    new NTSCookieExtension(new Byte[100], Authenticated: true, Encrypted: true)
                                ],
                                RootDelay:       20u * 65536u,
                                RootDispersion:  21u * 65536u
                            );

            var result = NTSResponseValidator.Validate(response, request, uniqueId, key);

            Assert.That(result.IsValid,       Is.False);
            Assert.That(result.ErrorCategory, Is.EqualTo(NTSQueryErrorCategory.Protocol));
            Assert.That(result.ErrorMessage,  Does.Contain("root delay"));
            Assert.That(result.ErrorMessage,  Does.Contain("root dispersion"));

        }

        #endregion


        private static NTPRequest CreateRequest(Byte[] UniqueId)
        {

            return new NTPRequest(
                       TransmitTimestamp:  NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 00, DateTimeKind.Utc)),
                       Extensions:         [ new UniqueIdentifierExtension(UniqueId) ]
                   );

        }

        private static NTPResponse CreateResponse(NTPRequest                Request,
                                                  IEnumerable<NTPExtension> Extensions,
                                                  UInt64?                   OriginateTimestamp = null,
                                                  Byte?                     Stratum            = null,
                                                  UInt32?                   RootDelay          = null,
                                                  UInt32?                   RootDispersion     = null)
        {

            var transmitTimestamp = NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 02, DateTimeKind.Utc));

            return new NTPResponse(
                       Mode:                 4,
                       Stratum:              Stratum ?? 2,
                       RootDelay:            RootDelay      ?? 0,
                       RootDispersion:       RootDispersion ?? 0,
                       ReferenceTimestamp:   transmitTimestamp,
                       OriginateTimestamp:   OriginateTimestamp ?? Request.TransmitTimestamp!.Value,
                       ReceiveTimestamp:     NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 01, 01, 00, 00, 01, DateTimeKind.Utc)),
                       TransmitTimestamp:    transmitTimestamp,
                       Extensions:           Extensions,
                       Request:              Request
                   );

        }

    }

}
