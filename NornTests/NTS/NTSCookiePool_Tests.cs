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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTS.NTSKERecords;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// What the cookie pool may and may not hold at the same time.
    /// </summary>
    /// <remarks>
    /// A cookie is not a bearer token that stands on its own: the server
    /// decrypts it to recover the C2S and S2C keys of the exchange that issued
    /// it, and then checks the request against those. So a cookie and the keys
    /// it was issued with are one thing, and a pool holding two generations at
    /// once is a pool that will sooner or later seal a request under one
    /// exchange's key while handing the server another's - which is NAKed, and
    /// looks to the server exactly like somebody replaying cookies.
    /// </remarks>
    [TestFixture]
    public class NTSCookiePool_Tests
    {

        #region (private) Exchange(NumberOfCookies)

        /// <summary>
        /// A key exchange response carrying this many distinguishable cookies.
        /// </summary>
        /// <remarks>
        /// The count is what tells the generations apart below: no accessor
        /// hands out the queued cookies, but a pool of five where five were
        /// offered second and three first cannot be holding the first.
        /// </remarks>
        private static NTSKE_Response Exchange(Byte NumberOfCookies)

            => new (Enumerable.Range(1, NumberOfCookies).
                        Select(number => new NewCookieForNTPv4(
                                             false,
                                             [ NumberOfCookies, (Byte) number ]
                                         ) as NTSKE_Record).
                        ToArray(),
                    C2SKey: [ NumberOfCookies ],
                    S2CKey: [ NumberOfCookies ]);

        #endregion

        #region (private) Client()

        private static NTSClient Client()

            => new (DomainName.Parse("time.example.org"),
                    DNSClient: new DNSClient(SearchForIPv6DNSServers: false));

        #endregion


        #region Seeding_One_Exchange_Fills_The_Pool()

        [Test]
        public void Seeding_One_Exchange_Fills_The_Pool()
        {

            var client = Client();

            client.SeedCookies(Exchange(3));

            Assert.That(client.AvailableCookieCount, Is.EqualTo(3));

        }

        #endregion

        #region Seeding_The_Same_Exchange_Twice_Does_Not_Double_The_Pool()

        /// <summary>
        /// Cookies are single use, so a response that has already been spent
        /// from must not be able to put its cookies back.
        /// </summary>
        [Test]
        public void Seeding_The_Same_Exchange_Twice_Does_Not_Double_The_Pool()
        {

            var client    = Client();
            var exchange  = Exchange(3);

            client.SeedCookies(exchange);
            client.SeedCookies(exchange);

            Assert.That(client.AvailableCookieCount, Is.EqualTo(3));

        }

        #endregion

        #region A_New_Exchange_Retires_The_Previous_Cookies()

        /// <summary>
        /// The one this fixture exists for: a second key exchange replaces the
        /// pool rather than adding to it.
        /// </summary>
        /// <remarks>
        /// Five offered second against three offered first, because the pool
        /// has no accessor for what is in it and the arity is therefore the
        /// evidence: eight would mean both generations are queued, three would
        /// mean the new cookies were dropped instead of the old ones, and five
        /// is the only answer that is the second exchange alone.
        ///
        /// Queued first-generation cookies are not merely surplus - they are
        /// unusable, because the keys they were issued with have been replaced.
        /// Keeping them is how a client comes to spend one under the wrong key
        /// and earn a Kiss-o'-Death 'NTSN'.
        /// </remarks>
        [Test]
        public void A_New_Exchange_Retires_The_Previous_Cookies()
        {

            var client = Client();

            client.SeedCookies(Exchange(3));
            client.SeedCookies(Exchange(5));

            Assert.That(client.AvailableCookieCount, Is.EqualTo(5));

        }

        #endregion

        #region Retired_Cookies_Are_Counted_As_Dropped()

        /// <summary>
        /// Cookies that go this way are gone without ever being spent, so they
        /// belong in the diagnostics: a pool that keeps retiring cookies is a
        /// caller running a key exchange per request.
        /// </summary>
        [Test]
        public void Retired_Cookies_Are_Counted_As_Dropped()
        {

            var client = Client();

            client.SeedCookies(Exchange(3));
            client.SeedCookies(Exchange(5));

            Assert.That(client.CookiePoolDiagnostics.DroppedCookieCount, Is.EqualTo(3));

        }

        #endregion

    }

}
