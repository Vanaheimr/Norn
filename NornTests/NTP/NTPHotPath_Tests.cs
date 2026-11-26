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

using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTP
{

    /// <summary>
    /// Regression and zero-allocation tests for the NTP/NTS packet parse, validate,
    /// AEAD, cookie, and serialization hot paths.
    /// </summary>
    [TestFixture]
    public class NTPHotPath_Tests
    {

        #region Helpers

        private static MasterKey CreateTestMasterKey(UInt64 Id = 42)
        {
            var keyBytes = new Byte[32];
            for (var i = 0; i < keyBytes.Length; i++)
                keyBytes[i] = (Byte) (0xA0 + i);

            var now = DateTimeOffset.UtcNow;
            return new MasterKey(Id, keyBytes, now.AddHours(-1), now.AddHours(1));
        }

        private static Byte[] BuildSampleNtsRequestWire(MasterKey      MasterKey,
                                                        AEADAlgorithms Algorithm,
                                                        out Byte[]     C2SKey,
                                                        out Byte[]     S2CKey,
                                                        out Byte[]     UniqueId)
        {

            var keyLength = NTSAEAD.KeyLength(Algorithm)!.Value;
            C2SKey        = RandomNumberGenerator.GetBytes(keyLength);
            S2CKey        = RandomNumberGenerator.GetBytes(keyLength);
            UniqueId      = RandomNumberGenerator.GetBytes(32);

            var sealedCookie = NTSCookie.Create(MasterKey, C2SKey, S2CKey, Algorithm).Encrypt(MasterKey);
            var header       = new NTPRequest(
                                   TransmitTimestamp: NTPPacket.GetCurrentNTPTimestamp(new DateTime(2026, 05, 01, 12, 00, 00, DateTimeKind.Utc))
                               );

            var extensions   = new List<NTPExtension> {
                                   new UniqueIdentifierExtension(UniqueId),
                                   new NTSCookieExtension(sealedCookie),
                                   new NTSCookiePlaceholderExtension((UInt16) sealedCookie.Length)
                               };

            var adBuffer     = new Byte[48 + extensions.Sum(e => e.Length)];
            header.WriteHeaderTo(adBuffer);

            var offset = 48;
            foreach (var ext in extensions)
            {
                ext.WriteTo(adBuffer.AsSpan(offset, ext.Length));
                offset += ext.Length;
            }

            extensions.Add(
                AuthenticatorAndEncryptedExtension.Create(
                    NTSKey:         C2SKey,
                    AssociatedData: adBuffer.AsSpan(),
                    Plaintext:      ReadOnlySpan<Byte>.Empty,
                    AEADAlgorithm:  Algorithm
                )
            );

            return new NTPRequest(header, extensions).ToByteArray();

        }

        #endregion

        #region NTPExtensionFieldValidator_TryValidate_AllocatesZeroBytes_ForValidPlainAndNtsPackets()

        [Test]
        public void NTPExtensionFieldValidator_TryValidate_AllocatesZeroBytes_ForValidPlainAndNtsPackets()
        {

            var masterKey  = CreateTestMasterKey();
            var plainWire  = new NTPRequest(TransmitTimestamp: 0x0102030405060708UL).ToByteArray();
            var ntsWire    = BuildSampleNtsRequestWire(masterKey, AEADAlgorithms.AES_SIV_CMAC_256, out _, out _, out _);

            // Warm up JIT before measuring allocations.
            Assert.That(NTPExtensionFieldValidator.TryValidate(plainWire.AsSpan(), out _), Is.True);
            Assert.That(NTPExtensionFieldValidator.TryValidate(ntsWire.AsSpan(),   out _), Is.True);

            var beforePlain = GC.GetAllocatedBytesForCurrentThread();
            var plainOk     = NTPExtensionFieldValidator.TryValidate(plainWire.AsSpan(), out var plainErr);
            var afterPlain  = GC.GetAllocatedBytesForCurrentThread();

            var beforeNts   = GC.GetAllocatedBytesForCurrentThread();
            var ntsOk       = NTPExtensionFieldValidator.TryValidate(ntsWire.AsSpan(), out var ntsErr);
            var afterNts    = GC.GetAllocatedBytesForCurrentThread();

            Assert.Multiple(() => {
                Assert.That(plainOk,                 Is.True, plainErr);
                Assert.That(afterPlain - beforePlain, Is.EqualTo(0), "Plain NTP validation must allocate 0 bytes");
                Assert.That(ntsOk,                   Is.True, ntsErr);
                Assert.That(afterNts - beforeNts,    Is.EqualTo(0), "NTS extension chain validation must allocate 0 bytes");
            });

        }

        #endregion

        #region NTPExtensionFieldValidator_PreservesErrorPrecedence_DuplicateBeforeShortField()

        [Test]
        public void NTPExtensionFieldValidator_PreservesErrorPrecedence_DuplicateBeforeShortField()
        {

            // Build a packet with 2 UniqueIdentifier fields (36 bytes each) followed by a short last field (16 bytes < 28).
            var packet = new Byte[48 + 36 + 36 + 16];

            // First UniqueIdentifier (36 bytes)
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(48, 2), (UInt16) ExtensionTypes.UniqueIdentifier);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(50, 2), 36);

            // Second UniqueIdentifier (36 bytes)
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(84, 2), (UInt16) ExtensionTypes.UniqueIdentifier);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(86, 2), 36);

            // Short last unknown extension field (16 bytes < 28 minimum)
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(120, 2), 0x0999);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(122, 2), 16);

            var ok = NTPExtensionFieldValidator.TryValidate(packet.AsSpan(), out var error);

            Assert.Multiple(() => {
                Assert.That(ok,    Is.False);
                Assert.That(error, Does.Contain(nameof(ExtensionTypes.UniqueIdentifier)));
            });

        }

        #endregion

        #region NTPExtension_WriteTo_ZeroPadsTrailingBytesInDirtyBuffer()

        [Test]
        public void NTPExtension_WriteTo_ZeroPadsTrailingBytesInDirtyBuffer()
        {

            // 13-byte value => 4 + 13 = 17, padded to 20 bytes (3 zero padding octets).
            var value = new Byte[13];
            for (var i = 0; i < value.Length; i++)
                value[i] = (Byte) (i + 1);

            var ext         = new NTPExtension((ExtensionTypes) 0x0999, value);
            var expected    = ext.ToByteArray();

            var dirtyBuffer = new Byte[ext.Length];
            Array.Fill(dirtyBuffer, (Byte) 0xFF);

            ext.WriteTo(dirtyBuffer);

            Assert.That(dirtyBuffer, Is.EqualTo(expected).AsCollection);
            Assert.That(dirtyBuffer[17], Is.EqualTo(0));
            Assert.That(dirtyBuffer[18], Is.EqualTo(0));
            Assert.That(dirtyBuffer[19], Is.EqualTo(0));

        }

        #endregion

        #region AES_SIV_And_AES_GCM_SIV_SpanOverloads_MatchByteArrayOverloads()

        [TestCase(0)]
        [TestCase(1)]
        [TestCase(16)]
        [TestCase(74)]
        public void AES_SIV_SpanOverloads_MatchByteArrayOverloads(Int32 PlaintextLength)
        {

            var key       = RandomNumberGenerator.GetBytes(32);
            var ad        = RandomNumberGenerator.GetBytes(84);
            var nonce     = RandomNumberGenerator.GetBytes(16);
            var plaintext = PlaintextLength == 0 ? [] : RandomNumberGenerator.GetBytes(PlaintextLength);

            var siv       = new AES_SIV(key);
            var ctArray   = siv.Encrypt([ ad ], nonce, plaintext);
            var ctSpan    = siv.Encrypt(ad.AsSpan(), nonce.AsSpan(), plaintext.AsSpan());
            var ctDirect  = new Byte[16 + PlaintextLength];
            siv.Encrypt(ad.AsSpan(), nonce.AsSpan(), plaintext.AsSpan(), ctDirect);

            Assert.That(ctSpan,   Is.EqualTo(ctArray).AsCollection);
            Assert.That(ctDirect, Is.EqualTo(ctArray).AsCollection);

            var ptSpan    = siv.Decrypt(ad.AsSpan(), nonce.AsSpan(), ctDirect.AsSpan());
            var ptDirect  = new Byte[PlaintextLength];
            siv.Decrypt(ad.AsSpan(), nonce.AsSpan(), ctDirect.AsSpan(), ptDirect);

            Assert.That(ptSpan,   Is.EqualTo(plaintext).AsCollection);
            Assert.That(ptDirect, Is.EqualTo(plaintext).AsCollection);

            // Tampering with SIV must throw CryptographicException and zero the destination buffer.
            ctDirect[0] ^= 0x01;
            Array.Fill(ptDirect, (Byte) 0xCC);
            Assert.Throws<CryptographicException>(() => siv.Decrypt(ad.AsSpan(), nonce.AsSpan(), ctDirect.AsSpan(), ptDirect));
            Assert.That(ptDirect, Is.All.EqualTo((Byte) 0));

        }

        [TestCase(AEADAlgorithms.AES_128_GCM_SIV, 0)]
        [TestCase(AEADAlgorithms.AES_128_GCM_SIV, 64)]
        [TestCase(AEADAlgorithms.AES_256_GCM_SIV, 0)]
        [TestCase(AEADAlgorithms.AES_256_GCM_SIV, 64)]
        public void AES_GCM_SIV_SpanOverloads_MatchByteArrayOverloads(AEADAlgorithms Algorithm,
                                                                      Int32          PlaintextLength)
        {

            var keyLength = NTSAEAD.KeyLength(Algorithm)!.Value;
            var key       = RandomNumberGenerator.GetBytes(keyLength);
            var ad        = RandomNumberGenerator.GetBytes(84);
            var nonce     = RandomNumberGenerator.GetBytes(AES_GCM_SIV.NonceLength);
            var plaintext = PlaintextLength == 0 ? [] : RandomNumberGenerator.GetBytes(PlaintextLength);

            var gcmSiv    = new AES_GCM_SIV(key);
            var ctArray   = gcmSiv.Encrypt(ad, nonce, plaintext);
            var ctSpan    = gcmSiv.Encrypt(ad.AsSpan(), nonce.AsSpan(), plaintext.AsSpan());

            Assert.That(ctSpan, Is.EqualTo(ctArray).AsCollection);

            var ptArray   = gcmSiv.Decrypt(ad, nonce, ctArray);
            var ptSpan    = gcmSiv.Decrypt(ad.AsSpan(), nonce.AsSpan(), ctSpan.AsSpan());

            Assert.That(ptSpan, Is.EqualTo(ptArray).AsCollection);
            Assert.That(ptSpan, Is.EqualTo(plaintext).AsCollection);

        }

        #endregion

        #region NTSCookie_SpanTryParse_RoundTrips_AndRejectsTamperedCookie()

        [TestCase(AEADAlgorithms.AES_SIV_CMAC_256)]
        [TestCase(AEADAlgorithms.AES_128_GCM_SIV)]
        public void NTSCookie_SpanTryParse_RoundTrips_AndRejectsTamperedCookie(AEADAlgorithms Algorithm)
        {

            var masterKey = CreateTestMasterKey(99);
            var keyLen    = NTSAEAD.KeyLength(Algorithm)!.Value;
            var c2s       = RandomNumberGenerator.GetBytes(keyLen);
            var s2c       = RandomNumberGenerator.GetBytes(keyLen);

            var original  = NTSCookie.Create(masterKey, c2s, s2c, Algorithm);
            var sealedBin = original.Encrypt(masterKey);

            var ok = NTSCookie.TryParse(sealedBin.AsSpan(), masterKey, out var parsed, out var err);

            Assert.Multiple(() => {
                Assert.That(ok,                    Is.True, err);
                Assert.That(parsed,                Is.Not.Null);
                Assert.That(parsed!.MasterKeyId,   Is.EqualTo(masterKey.Id));
                Assert.That(parsed.AEADAlgorithm,  Is.EqualTo(Algorithm));
                Assert.That(parsed.C2SKey,         Is.EqualTo(c2s).AsCollection);
                Assert.That(parsed.S2CKey,         Is.EqualTo(s2c).AsCollection);
            });

            // Tampering with ciphertext must fail cleanly.
            sealedBin[^1] ^= 0x80;
            Assert.That(NTSCookie.TryParse(sealedBin.AsSpan(), masterKey, out _, out _), Is.False);

        }

        #endregion

        #region NTSRequestAndResponse_SpanHotPath_RoundTrip()

        [TestCase(AEADAlgorithms.AES_SIV_CMAC_256)]
        [TestCase(AEADAlgorithms.AES_128_GCM_SIV)]
        public void NTSRequestAndResponse_SpanHotPath_RoundTrip(AEADAlgorithms Algorithm)
        {

            var masterKey  = CreateTestMasterKey(7);
            var masterKeys = new ConcurrentDictionary<UInt64, MasterKey>();
            masterKeys[masterKey.Id] = masterKey;

            var reqWire = BuildSampleNtsRequestWire(masterKey, Algorithm, out var c2s, out var s2c, out var uniqueId);

            Assert.That(
                NTPRequest.TryParse(reqWire, out var parsedReq, out var reqErr, MasterKeys: masterKeys),
                Is.True,
                reqErr
            );

            var reqExts = parsedReq!.Extensions.ToList();

            Assert.Multiple(() => {
                Assert.That(reqExts.OfType<UniqueIdentifierExtension>().Single().Authenticated,          Is.True);
                Assert.That(reqExts.OfType<NTSCookieExtension>().Single().Authenticated,                 Is.True);
                Assert.That(reqExts.OfType<NTSCookieExtension>().Single().Cookie,                        Is.Not.Null);
                Assert.That(reqExts.OfType<NTSCookiePlaceholderExtension>().Single().Authenticated,      Is.True);
                Assert.That(reqExts.OfType<AuthenticatorAndEncryptedExtension>().Single().Authenticated, Is.False);
            });

            // Build a matching NTS response carrying two encrypted cookies.
            var respHeader = new NTPResponse(
                                 Mode:              4,
                                 Stratum:           2,
                                 OriginateTimestamp: parsedReq.TransmitTimestamp,
                                 ReceiveTimestamp:   parsedReq.TransmitTimestamp,
                                 TransmitTimestamp:  parsedReq.TransmitTimestamp
                             );

            var respExts   = new List<NTPExtension> {
                                 new UniqueIdentifierExtension(uniqueId)
                             };

            var innerCookies = masterKey.GenerateNTSCookieExtensions(2, c2s, s2c, Algorithm).ToList();
            var ptBuffer     = new Byte[innerCookies.Sum(c => c.Length)];
            var ptOffset     = 0;
            foreach (var c in innerCookies)
            {
                c.WriteTo(ptBuffer.AsSpan(ptOffset, c.Length));
                ptOffset += c.Length;
            }

            var adBuffer = new Byte[48 + respExts[0].Length];
            respHeader.WriteHeaderTo(adBuffer);
            respExts[0].WriteTo(adBuffer.AsSpan(48, respExts[0].Length));

            respExts.Add(
                AuthenticatorAndEncryptedExtension.Create(
                    NTSKey:         s2c,
                    AssociatedData: adBuffer.AsSpan(),
                    Plaintext:      ptBuffer.AsSpan(),
                    AEADAlgorithm:  Algorithm
                )
            );

            var respWire = new NTPResponse(respHeader, respExts).ToByteArray();

            Assert.That(
                NTPResponse.TryParse(respWire,
                                     out var parsedResp,
                                     out var respErr,
                                     NTSKey:           s2c,
                                     ExpectedUniqueId: uniqueId,
                                     AEADAlgorithm:    Algorithm),
                Is.True,
                respErr
            );

            var parsedCookies = parsedResp!.Extensions.OfType<NTSCookieExtension>().ToList();

            Assert.Multiple(() => {
                Assert.That(parsedCookies,                                                 Has.Count.EqualTo(2));
                Assert.That(parsedCookies.All(c => c.Authenticated && c.Encrypted),        Is.True);
                Assert.That(parsedResp.Extensions.OfType<UniqueIdentifierExtension>().Single().Authenticated, Is.True);
            });

        }

        #endregion

    }

}
