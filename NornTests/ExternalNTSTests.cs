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

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Norn.NTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    [TestFixture]
    public class ExternalNTSTests
    {

        #region TestPTBTime1()

        [Test]
        public async Task TestPTBTime1()
        {

            var ntsClient                  = new NTSClient("ptbtime1.ptb.de");
            var ntsKEResponse              = ntsClient.GetNTSKERecords();
            var ntsResponse                = await ntsClient.QueryTime(NTSKEResponse: ntsKEResponse);

            Assert.That(ntsResponse,  Is.Not.Null);

            if (ntsResponse is not null)
            {

                var request                             = ntsResponse.Request;

                Assert.That(request, Is.Not.Null);

                if (request is not null)
                {

                    Assert.That(request.    UniqueIdentifier,                  Is.Not.Null);
                    Assert.That(ntsResponse.UniqueIdentifier,                  Is.Not.Null);

                    Assert.That(ntsResponse.UniqueIdentifier?.ToHexString(),   Is.EqualTo(request.UniqueIdentifier?.ToHexString()));


                    Assert.That(request.Extensions.Count(),                    Is.EqualTo(3));

                }




                // Initially 2, but one additional decrypted extension
                Assert.That(ntsResponse.Extensions.Count(),  Is.EqualTo(3));


                // Check Unique Identifier Extension
                if (ntsResponse.Extensions.ElementAt(0) is UniqueIdentifierExtension uniqueIdentifierExtension)
                {
                    Assert.That(uniqueIdentifierExtension.Authenticated,                          Is.False);
                    Assert.That(uniqueIdentifierExtension.Encrypted,                              Is.False);
                }
                else
                    Assert.Fail("Unique Identifier Extension is invalid!");


                // Check NTS Authenticator and Encrypted Extension
                if (ntsResponse.Extensions.ElementAt(1) is AuthenticatorAndEncryptedExtension authenticatorAndEncryptedExtension)
                {
                    Assert.That(authenticatorAndEncryptedExtension.Authenticated,                 Is.False);
                    Assert.That(authenticatorAndEncryptedExtension.Encrypted,                     Is.False);
                    Assert.That(authenticatorAndEncryptedExtension.EncryptedExtensions.Count(),   Is.EqualTo(1));
                }
                else
                    Assert.Fail("NTS Authenticator and Encrypted Extension is invalid!");


                // Check NTS Cookie Extension
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
