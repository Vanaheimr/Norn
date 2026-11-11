/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Norn <https://www.github.com/Vanaheimr/Norn>
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

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTP
{

    /// <summary>
    /// What a Kiss-o'-Death may cost a client, by how far it can be believed.
    /// </summary>
    [TestFixture]
    public class NTPServerAccessState_Tests
    {

        private static readonly DateTimeOffset now = new (2026, 11, 11, 12, 0, 0, TimeSpan.Zero);


        #region RATE_CostsOneStepWhateverThePollValue()

        /// <summary>
        /// RFC 8633 § 5.4: "it MUST NOT simply accept any value". A kiss asking for the
        /// longest interval there is still slows the client by a factor of two.
        /// </summary>
        [Test]
        public void RATE_CostsOneStepWhateverThePollValue()
        {

            var access = new NTPServerAccessState(InitialPollExponent: 6);

            access.Apply(new NTPKissOfDeath("RATE", 255), now);

            Assert.That(access.PollExponent,           Is.EqualTo(7));
            Assert.That(access.NextQueryNotBefore,     Is.EqualTo(now.AddSeconds(128)));
            Assert.That(access.MayQuery(now.AddSeconds(127)),  Is.False);
            Assert.That(access.MayQuery(now.AddSeconds(128)),  Is.True);

            // § 7.4 b: "continue to reduce it each time it receives a RATE kiss code".
            access.Apply(new NTPKissOfDeath("RATE", 0), now);

            Assert.That(access.PollExponent,           Is.EqualTo(8));

        }

        #endregion

        #region RATE_NeverPassesTheCeiling()

        [Test]
        public void RATE_NeverPassesTheCeiling()
        {

            var access = new NTPServerAccessState();

            for (var i = 0; i < 40; i++)
                access.Apply(new NTPKissOfDeath("RATE", 17), now);

            Assert.That(access.PollExponent,           Is.EqualTo(NTPServerAccessState.DefaultMaximumPollExponent));
            Assert.That(access.Demobilized,            Is.False);

        }

        #endregion

        #region RATE_LastsUntilItIsEarnedBack()

        /// <summary>
        /// RFC 5905 § 7.4 b asks for a reduced polling interval, not for one pause:
        /// every query is followed by a wait, until answers have brought the rate back.
        /// </summary>
        [Test]
        public void RATE_LastsUntilItIsEarnedBack()
        {

            var access = new NTPServerAccessState(InitialPollExponent: 6);

            // Nothing to wait for while the server has not complained.
            access.RecordQuery(now);
            Assert.That(access.MayQuery(now),                   Is.True);

            access.Apply(new NTPKissOfDeath("RATE", 6), now);
            access.Apply(new NTPKissOfDeath("RATE", 6), now);

            Assert.That(access.PollExponent,                    Is.EqualTo(8));
            Assert.That(access.IsRateLimited,                   Is.True);

            // The pause is over, the next query goes out, and is answered.
            var later = now.AddSeconds(256);

            Assert.That(access.MayQuery(later),                 Is.True);

            access.RecordQuery(later);

            Assert.That(access.MayQuery(later.AddSeconds(255)), Is.False, "The slower rate must hold after the first pause.");
            Assert.That(access.MayQuery(later.AddSeconds(256)), Is.True);

            access.RecordAnswer();
            Assert.That(access.PollExponent,                    Is.EqualTo(7));

            access.RecordAnswer();
            Assert.That(access.PollExponent,                    Is.EqualTo(6));
            Assert.That(access.IsRateLimited,                   Is.False);

            // And not below where it started.
            access.RecordAnswer();
            Assert.That(access.PollExponent,                    Is.EqualTo(6));

        }

        #endregion


        #region DENY_EndsAPlainAssociation()

        /// <summary>
        /// RFC 5905 § 7.4 a, for an association that has nothing better to go by.
        /// </summary>
        [TestCase("DENY")]
        [TestCase("RSTR")]
        public void DENY_EndsAPlainAssociation(String Code)
        {

            var access = new NTPServerAccessState();

            access.Apply(new NTPKissOfDeath(Code, 4), now);

            Assert.That(access.Demobilized,                     Is.True);
            Assert.That(access.MayQuery(now.AddYears(1)),       Is.False);

        }

        #endregion

        #region DENY_EndsAnNTSAssociationWhenTheServerSealedIt()

        [Test]
        public void DENY_EndsAnNTSAssociationWhenTheServerSealedIt()
        {

            var access = new NTPServerAccessState();

            access.Apply(new NTPKissOfDeath("DENY", 4), now, NTPKissTrust.Authenticated);

            Assert.That(access.Demobilized,                     Is.True);
            Assert.That(access.MayQuery(now.AddYears(1)),       Is.False);

        }

        #endregion

        #region DENY_WithoutAuthenticationCostsAnNTSAssociationOnePause()

        /// <summary>
        /// Anyone who saw the request can write this kiss.
        /// It must not be the end of a time source.
        /// </summary>
        [TestCase("DENY")]
        [TestCase("RSTR")]
        public void DENY_WithoutAuthenticationCostsAnNTSAssociationOnePause(String Code)
        {

            var access = new NTPServerAccessState(InitialPollExponent: 6);

            access.Apply(new NTPKissOfDeath(Code, 4), now, NTPKissTrust.Unauthenticated);

            Assert.That(access.Demobilized,                              Is.False);
            Assert.That(access.MayQuery(now.AddSeconds(8191)),           Is.False);
            Assert.That(access.MayQuery(now.AddSeconds(8192)),           Is.True);

            // The polling rate is as it was: after the pause, nothing is left of the kiss.
            Assert.That(access.PollExponent,                             Is.EqualTo(6));
            Assert.That(access.IsRateLimited,                            Is.False);

            access.RecordQuery(now.AddSeconds(8192));

            Assert.That(access.MayQuery(now.AddSeconds(8193)),           Is.True);

        }

        #endregion


        #region Reset_ReturnsToTheStartingRate()

        [Test]
        public void Reset_ReturnsToTheStartingRate()
        {

            var access = new NTPServerAccessState(InitialPollExponent: 6);

            access.Apply(new NTPKissOfDeath("RATE", 9), now);
            access.Apply(new NTPKissOfDeath("DENY", 4), now);

            access.Reset();

            Assert.That(access.Demobilized,                     Is.False);
            Assert.That(access.PollExponent,                    Is.EqualTo(6));
            Assert.That(access.MayQuery(now),                   Is.True);

        }

        #endregion

    }

}
