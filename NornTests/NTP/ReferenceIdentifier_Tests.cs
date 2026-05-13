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

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTP
{

    /// <summary>
    /// NTP reference identifier tests.
    /// </summary>
    [TestFixture]
    public class ReferenceIdentifier_Tests
    {

        #region Stratum1_ASCII_Allows_ZeroPadding()

        [Test]
        public void Stratum1_ASCII_Allows_ZeroPadding()
        {

            var referenceIdentifier = ReferenceIdentifier.From([ 0x50, 0x54, 0x42, 0x00 ]);

            Assert.That(referenceIdentifier.IsASCII,            Is.True);
            Assert.That(referenceIdentifier.AsASCII,            Is.EqualTo("PTB"));
            Assert.That(referenceIdentifier.ToString(1),        Does.Contain("PTB"));

        }

        #endregion

        #region Stratum2_Uses_IPv4OrHash_Rendering()

        [Test]
        public void Stratum2_Uses_IPv4OrHash_Rendering()
        {

            var referenceIdentifier = ReferenceIdentifier.From([ 0x0A, 0xA5, 0x08, 0x04 ]);

            Assert.That(referenceIdentifier.NetworkInteger, Is.EqualTo(0x0AA50804));
            Assert.That(referenceIdentifier.ToString(2),    Is.EqualTo("IPv4/Hash: 10.165.8.4 (0x0AA50804)"));

        }

        #endregion

        #region Integer_Is_NetworkByteOrder()

        [Test]
        public void Integer_Is_NetworkByteOrder()
        {

            var referenceIdentifier = ReferenceIdentifier.From([ 0x50, 0x54, 0x42, 0x00 ]);

            Assert.That(referenceIdentifier.Integer, Is.EqualTo(0x50544200));

        }

        #endregion

    }

}
