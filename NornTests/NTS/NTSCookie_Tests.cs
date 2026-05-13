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

using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// NTS cookie tests.
    /// </summary>
    [TestFixture]
    public class NTSCookie_Tests
    {

        #region ToByteArray_UsesStoredNonce()

        [Test]
        public void ToByteArray_UsesStoredNonce()
        {

            var cookie = CreateCookie(1);

            var bytes1 = cookie.ToByteArray();
            var bytes2 = cookie.ToByteArray();

            Assert.That(bytes2, Is.EqualTo(bytes1));
            Assert.That(NTSCookie.TryParse(bytes1, out var parsedCookie, out var errorResponse), Is.True, errorResponse);
            Assert.That(parsedCookie, Is.EqualTo(cookie));
            Assert.That(parsedCookie!.GetHashCode(), Is.EqualTo(cookie.GetHashCode()));

        }

        #endregion

        #region Equals_IncludesMasterKeyId()

        [Test]
        public void Equals_IncludesMasterKeyId()
        {

            var originalBytes = CreateCookie(1).ToByteArray();
            var bytes         = originalBytes.ToArray();

            for (var i = 0; i < 8; i++)
                bytes[8 + i] = (Byte) (2UL >> (56 - 8 * i));

            Assert.That(NTSCookie.TryParse(originalBytes, out var cookie1, out var errorResponse1), Is.True, errorResponse1);
            Assert.That(NTSCookie.TryParse(bytes,         out var cookie2, out var errorResponse2), Is.True, errorResponse2);

            Assert.That(cookie2, Is.Not.EqualTo(cookie1));

        }

        #endregion

        #region TryParse_RejectsShortBinaryCookie()

        [Test]
        public void TryParse_RejectsShortBinaryCookie()
        {

            Assert.That(NTSCookie.TryParse([ 0x01, 0x02 ], out _, out var errorResponse), Is.False);
            Assert.That(errorResponse, Does.Contain("too short"));
            Assert.That(errorResponse, Does.Contain("binary representation"));

        }

        #endregion


        private static NTSCookie CreateCookie(UInt64 MasterKeyId)
        {

            var masterKey = new MasterKey(
                                MasterKeyId,
                                RandomNumberGenerator.GetBytes(32),
                                DateTimeOffset.UtcNow.AddMinutes(-1),
                                DateTimeOffset.UtcNow.AddHours(1)
                            );

            return NTSCookie.Create(
                       masterKey,
                       RandomNumberGenerator.GetBytes(32),
                       RandomNumberGenerator.GetBytes(32)
                   );

        }

    }

}
