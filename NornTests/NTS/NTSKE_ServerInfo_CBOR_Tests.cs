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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// An NTS-KE server info written as CBOR and read back from its bytes is
    /// the same - its keys, cookies and public keys bytes, not BASE64 texts.
    /// </summary>
    [TestFixture]
    public class NTSKE_ServerInfo_CBOR_Tests
    {

        private static NTSKE_ServerInfo Sample()

            => new (
                   [ 1, 2, 3 ],
                   [ 4, 5, 6 ],
                   [ new Byte[] { 7, 8, 9 }, new Byte[] { 10, 11 } ],
                   [ URL.Parse("https://time.example"), URL.Parse("https://time2.example") ],
                   [ new Byte[] { 12, 13 } ],
                   AEADAlgorithms.AES_128_GCM,
                   [ Warning.Create("a warning") ],
                   [ "an error" ]
               );

        [Test]
        public void WrittenAndReadAsCBOR()
        {

            var serverInfo = Sample();
            var cbor       = CBORValue.Parse(serverInfo.ToCBOR().ToByteArray());

            Assert.That(NTSKE_ServerInfo.TryParseCBOR(cbor, out var fromCBOR, out var errorResponse), Is.True, errorResponse);

            Assert.That(JToken.DeepEquals(fromCBOR!.ToJSON(), serverInfo.ToJSON()), Is.True,
                        $"Read from CBOR: {fromCBOR.ToJSON().ToString(Newtonsoft.Json.Formatting.None)}{Environment.NewLine}" +
                        $"Written:        {serverInfo.ToJSON().ToString(Newtonsoft.Json.Formatting.None)}");

            // The keys of its JSON object, the keys and cookies bytes.
            Assert.That(cbor.AsMap().Select(entry => entry.Key.AsText()).OrderBy(key => key, StringComparer.Ordinal),
                        Is.EqualTo(serverInfo.ToJSON().Properties().Select(property => property.Name).OrderBy(key => key, StringComparer.Ordinal)));

            Assert.That(cbor.TryGetValue(CBORValue.FromText("c2sKey"), out var c2sKey), Is.True);
            Assert.That(c2sKey.Kind,      Is.EqualTo(CBORValueKind.ByteString));
            Assert.That(c2sKey.AsBytes(), Is.EqualTo(new Byte[] { 1, 2, 3 }));

        }

        [Test]
        public void WithoutItsOptionalValues()
        {

            var serverInfo = new NTSKE_ServerInfo(
                                 [ 1, 2, 3 ],
                                 [ 4, 5, 6 ],
                                 [ new Byte[] { 7, 8, 9 } ],
                                 [ URL.Parse("https://time.example") ]
                             );

            Assert.That(NTSKE_ServerInfo.TryParseCBOR(CBORValue.Parse(serverInfo.ToCBOR().ToByteArray()), out var fromCBOR, out var errorResponse), Is.True, errorResponse);
            Assert.That(JToken.DeepEquals(fromCBOR!.ToJSON(), serverInfo.ToJSON()), Is.True);

        }

        [TestCase("cookies")]
        [TestCase("urls")]
        [TestCase("publicKeys")]
        [TestCase("warnings")]
        [TestCase("errors")]
        public void AListNotValidIsRefused(String Key)
        {

            var entries = Sample().ToCBOR().AsMap().Where(entry => entry.Key.AsText() != Key).ToList();
            entries.Add(new (CBORValue.FromText(Key), CBORValue.FromText("not a list")));

            Assert.That(NTSKE_ServerInfo.TryParseCBOR(CBORValue.FromMap(entries), out _, out var errorResponse), Is.False);
            Assert.That(errorResponse, Does.Contain(Key));

        }

        [Test]
        public void AKeyAsTextIsRefused()
        {

            var entries = Sample().ToCBOR().AsMap().Where(entry => entry.Key.AsText() != "c2sKey").ToList();
            entries.Add(new (CBORValue.FromText("c2sKey"), CBORValue.FromText("AQID")));

            Assert.That(NTSKE_ServerInfo.TryParseCBOR(CBORValue.FromMap(entries), out _, out _), Is.False);

        }

    }

}
