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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// The public keys, warnings and errors of an NTS-KE server info, which
    /// are optional, are refused while they are there but not valid, and are
    /// no reason to refuse while they are not there.
    /// </summary>
    /// <remarks>
    /// NTSKE_ServerInfo asked for them with a negation, if
    /// (!JSON.ParseOptionalHashSet(...)), and looked for an error only while
    /// it returned false: a list not valid, for which it returned true, was
    /// passed over, and the rest read as if it were not there.
    /// </remarks>
    [TestFixture]
    public class NTSKE_ServerInfo_OptionalValues_Tests
    {

        [TestCase("publicKeys")]
        [TestCase("warnings")]
        [TestCase("errors")]
        public void AListNotValidIsRefused(String PropertyName)
        {

            var json = new NTSKE_ServerInfo(
                           [ 1, 2, 3 ],
                           [ 4, 5, 6 ],
                           [ new Byte[] { 7, 8, 9 } ],
                           [ URL.Parse("https://time.example") ]
                       ).ToJSON();

            json.Remove(PropertyName);

            Assert.That(NTSKE_ServerInfo.TryParse(json, out _, out var error), Is.True, $"Without '{PropertyName}' it is not read: {error}");

            json[PropertyName] = "not a list";

            var parsed = NTSKE_ServerInfo.TryParse(json, out _, out error);

            Assert.Multiple(() => {
                Assert.That(parsed, Is.False,    $"With '{PropertyName}' not valid it is read.");
                Assert.That(error,  Is.Not.Null, $"With '{PropertyName}' not valid it is refused without a reason.");
            });

        }

    }

}
