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
    ///
    /// Cookies are sealed with an AEAD under the server's master key (RFC 8915 § 6), so
    /// they can only be read back through the master key that issued them. There is
    /// deliberately no keyless parse: the cookie body carries both session keys.
    /// </summary>
    [TestFixture]
    public class NTSCookie_Tests
    {

        #region SealedCookie_RoundTripsUnderItsMasterKey()

        [Test]
        public void SealedCookie_RoundTripsUnderItsMasterKey()
        {

            var masterKey = CreateMasterKey(1);
            var cookie    = CreateCookie(masterKey);

            var sealed1   = cookie.Encrypt(masterKey);
            var sealed2   = cookie.Encrypt(masterKey);

            // AES-SIV is deterministic, and the cookie keeps its nonce, so sealing twice
            // yields the same bytes.
            Assert.That(sealed2, Is.EqualTo(sealed1));

            Assert.That(NTSCookie.TryParse(sealed1, masterKey, out var parsedCookie, out var errorResponse), Is.True, errorResponse);
            Assert.That(parsedCookie,                Is.EqualTo(cookie));
            Assert.That(parsedCookie!.GetHashCode(), Is.EqualTo(cookie.GetHashCode()));

        }

        #endregion

        #region SealedCookie_IsOpaque()

        [Test]
        public void SealedCookie_IsOpaque()
        {

            var masterKey = CreateMasterKey(1);
            var c2sKey    = RandomNumberGenerator.GetBytes(32);
            var s2cKey    = RandomNumberGenerator.GetBytes(32);

            var sealedCookie = NTSCookie.Create(masterKey, c2sKey, s2cKey).Encrypt(masterKey);

            Assert.That(IndexOf(sealedCookie, c2sKey), Is.LessThan(0), "the C2S key must not appear in the sealed cookie");
            Assert.That(IndexOf(sealedCookie, s2cKey), Is.LessThan(0), "the S2C key must not appear in the sealed cookie");

        }

        #endregion

        #region TryParse_RejectsForeignMasterKey()

        [Test]
        public void TryParse_RejectsForeignMasterKey()
        {

            var ourKey       = CreateMasterKey(1);

            // Same id, different secret — the case a forged cookie would present.
            var foreignKey   = CreateMasterKey(1);

            var sealedCookie = CreateCookie(ourKey).Encrypt(ourKey);

            Assert.That(NTSCookie.TryParse(sealedCookie, foreignKey, out _, out var errorResponse), Is.False);
            Assert.That(errorResponse, Does.Contain("authenticity"));

        }

        #endregion

        #region TryParse_RejectsTamperedCookie()

        [Test]
        public void TryParse_RejectsTamperedCookie()
        {

            var masterKey    = CreateMasterKey(1);
            var sealedCookie = CreateCookie(masterKey).Encrypt(masterKey);

            for (var offset = 0; offset < sealedCookie.Length; offset += 13)
            {

                var tampered = sealedCookie.ToArray();
                tampered[offset] ^= 0x01;

                Assert.That(NTSCookie.TryParse(tampered, masterKey, out _, out _),
                            Is.False,
                            $"a cookie with octet {offset} flipped must be rejected");

            }

        }

        #endregion

        #region Equals_IncludesMasterKeyId()

        [Test]
        public void Equals_IncludesMasterKeyId()
        {

            var c2sKey  = RandomNumberGenerator.GetBytes(32);
            var s2cKey  = RandomNumberGenerator.GetBytes(32);

            var key1    = CreateMasterKey(1);
            var key2    = CreateMasterKey(2);

            var cookie1 = NTSCookie.Create(key1, c2sKey, s2cKey);
            var cookie2 = NTSCookie.Create(key2, c2sKey, s2cKey);

            Assert.That(cookie2, Is.Not.EqualTo(cookie1));

        }

        #endregion

        #region TryParse_RejectsShortBinaryCookie()

        [Test]
        public void TryParse_RejectsShortBinaryCookie()
        {

            Assert.That(NTSCookie.TryParse([ 0x01, 0x02 ], CreateMasterKey(1), out _, out var errorResponse), Is.False);
            Assert.That(errorResponse, Does.Contain("too short"));
            Assert.That(errorResponse, Does.Contain("binary representation"));

        }

        #endregion

        #region TryParse_RejectsUnknownMasterKeyId()

        [Test]
        public void TryParse_RejectsUnknownMasterKeyId()
        {

            var knownKey     = CreateMasterKey(1);
            var strangerKey  = CreateMasterKey(99);

            var sealedCookie = CreateCookie(strangerKey).Encrypt(strangerKey);

            var masterKeys   = new Dictionary<UInt64, MasterKey> { [knownKey.Id] = knownKey };

            Assert.That(NTSCookie.TryParse(sealedCookie, masterKeys, out _, out var errorResponse), Is.False);
            Assert.That(errorResponse, Does.Contain("Unknown"));

        }

        #endregion

        #region TryParse_RejectsCookieOutsideKeyValidity()

        [Test]
        public void TryParse_RejectsCookieOutsideKeyValidity()
        {

            // A key whose validity window closed before the cookie was minted.
            var expiredKey   = new MasterKey(
                                   1,
                                   RandomNumberGenerator.GetBytes(32),
                                   DateTimeOffset.UtcNow.AddDays(-3),
                                   DateTimeOffset.UtcNow.AddDays(-2)
                               );

            var sealedCookie = NTSCookie.Create(expiredKey,
                                                RandomNumberGenerator.GetBytes(32),
                                                RandomNumberGenerator.GetBytes(32)).
                                   Encrypt(expiredKey);

            var masterKeys   = new Dictionary<UInt64, MasterKey> { [expiredKey.Id] = expiredKey };

            Assert.That(NTSCookie.TryParse(sealedCookie, masterKeys, out _, out var errorResponse), Is.False);
            Assert.That(errorResponse, Does.Contain("validity window"));

        }

        #endregion


        #region (private) Helpers

        private static MasterKey CreateMasterKey(UInt64 MasterKeyId)

            => new (
                   MasterKeyId,
                   RandomNumberGenerator.GetBytes(32),
                   DateTimeOffset.UtcNow.AddMinutes(-1),
                   DateTimeOffset.UtcNow.AddHours(1)
               );


        private static NTSCookie CreateCookie(MasterKey MasterKey)

            => NTSCookie.Create(
                   MasterKey,
                   RandomNumberGenerator.GetBytes(32),
                   RandomNumberGenerator.GetBytes(32)
               );


        private static Int32 IndexOf(Byte[] Haystack, Byte[] Needle)
            => ((ReadOnlySpan<Byte>) Haystack).IndexOf((ReadOnlySpan<Byte>) Needle);

        #endregion

    }

}
