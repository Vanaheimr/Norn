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

        #region DENY_WithoutAuthentication_DemobilizesUntilANewKeyExchange(Code)

        /// <summary>
        /// Anyone who saw the request can write this kiss, and it ends the association all the
        /// same, as RFC 8915 § 5.7 has the client comply with it. It is not the end of the time
        /// source: a new key exchange may make a new association, after a backoff.
        /// </summary>
        [TestCase("DENY")]
        [TestCase("RSTR")]
        public void DENY_WithoutAuthentication_DemobilizesUntilANewKeyExchange(String Code)
        {

            var access = new NTPServerAccessState(InitialPollExponent: 6);

            access.Apply(new NTPKissOfDeath(Code, 4), now, NTPKissTrust.Unauthenticated);

            Assert.That(access.Demobilized,                              Is.True);
            Assert.That(access.MayQuery(now.AddDays(365)),               Is.False, "no packet to the old association, ever");
            Assert.That(access.KeyExchangeNotBefore,                     Is.EqualTo(now.AddSeconds(8192)));
            Assert.That(access.MayRerunKeyExchange(now.AddSeconds(8191)), Is.False);
            Assert.That(access.MayRerunKeyExchange(now.AddSeconds(8192)), Is.True);

            // A key exchange that was not begun as a rerun lifts nothing.
            Assert.That(access.RecordKeyExchange(now.AddSeconds(8192)),  Is.False);
            Assert.That(access.Demobilized,                              Is.True);

            Assert.That(access.TryBeginKeyExchangeRerun(now.AddSeconds(8192)), Is.True);
            Assert.That(access.MayQuery(now.AddSeconds(8192)),           Is.False, "not before the key exchange has succeeded");
            Assert.That(access.RecordKeyExchange(now.AddSeconds(8193)),  Is.True);

            Assert.That(access.Demobilized,                              Is.False);
            Assert.That(access.MayQuery(now.AddSeconds(8193)),           Is.True);
            Assert.That(access.KeyExchangeNotBefore,                     Is.Null);

            // The polling rate is as it was.
            Assert.That(access.PollExponent,                             Is.EqualTo(6));
            Assert.That(access.IsRateLimited,                            Is.False);

        }

        #endregion


        #region DENY_WithoutAuthentication_BacksOffAsRFC8915Section4_2Says()

        /// <summary>
        /// RFC 8915 § 4.2: exponential backoff with a base of 1.5, at least ten seconds and at
        /// most five days, and not reset before a key exchange has been followed by a
        /// successful use of what it agreed to. Two hours is where this client starts, and
        /// whoever runs it may weigh that otherwise within those bounds.
        /// </summary>
        [Test]
        public void DENY_WithoutAuthentication_BacksOffAsRFC8915Section4_2Says()
        {

            Assert.That(new NTPServerAccessState().UnauthenticatedDenyPause,                            Is.EqualTo(TimeSpan.FromSeconds(8192)));
            Assert.That(new NTPServerAccessState(MaximumPollExponent: 10).UnauthenticatedDenyPause,     Is.EqualTo(TimeSpan.FromSeconds(1024)));
            Assert.That(new NTPServerAccessState(UnauthenticatedDenyPause: TimeSpan.Zero).UnauthenticatedDenyPause,
                        Is.EqualTo(TimeSpan.FromSeconds(10)), "zero no longer ignores the kiss: ten seconds at the least");
            Assert.That(new NTPServerAccessState(UnauthenticatedDenyPause: TimeSpan.FromDays(9)).UnauthenticatedDenyPause,
                        Is.EqualTo(TimeSpan.FromDays(5)));

            var access = new NTPServerAccessState(UnauthenticatedDenyPause: TimeSpan.FromMinutes(10));
            var t      = now;

            // DENY, rerun, answered by nobody but the next DENY: 600 s, 900 s, 1350 s.
            foreach (var wait in new[] { 600, 900, 1350 })
            {

                access.Apply(new NTPKissOfDeath("DENY", 4), t, NTPKissTrust.Unauthenticated);

                Assert.That(access.KeyExchangeNotBefore, Is.EqualTo(t.AddSeconds(wait)), $"the wait of {wait} s");

                t = t.AddSeconds(wait);

                Assert.That(access.TryBeginKeyExchangeRerun(t), Is.True);
                Assert.That(access.RecordKeyExchange(t),        Is.True);

            }

            Assert.That(access.KeyExchangeReruns, Is.EqualTo(3));

            // A rerun that fails is a retry like any other: the next one waits longer.
            access.Apply(new NTPKissOfDeath("DENY", 4), t, NTPKissTrust.Unauthenticated);
            t = t.AddSeconds(2025);
            Assert.That(access.TryBeginKeyExchangeRerun(t),            Is.True);
            Assert.That(access.KeyExchangeNotBefore,                   Is.EqualTo(t.AddSeconds(3037.5)));
            Assert.That(access.TryBeginKeyExchangeRerun(t.AddSeconds(3037)), Is.False);

            t = t.AddSeconds(3037.5);
            Assert.That(access.TryBeginKeyExchangeRerun(t), Is.True);
            Assert.That(access.RecordKeyExchange(t),        Is.True);

            // An answer under the new association is the successful use: back to the start.
            access.RecordAnswer();
            Assert.That(access.KeyExchangeReruns, Is.Zero);

            access.Apply(new NTPKissOfDeath("DENY", 4), t, NTPKissTrust.Unauthenticated);
            Assert.That(access.KeyExchangeNotBefore, Is.EqualTo(t.AddSeconds(600)));

            // Never more than five days.
            Assert.That(access.KeyExchangeRetryInterval(1000), Is.EqualTo(TimeSpan.FromDays(5)));

            Assert.That(() => new NTPServerAccessState(UnauthenticatedDenyPause: TimeSpan.FromSeconds(-1)),
                        Throws.InstanceOf<ArgumentOutOfRangeException>());

        }

        #endregion


        #region DENY_Authenticated_IsForGood()

        /// <summary>
        /// A kiss sealed under the S2C key is the server's own word: no new key exchange follows
        /// it, and a later one without authentication does not soften it.
        /// </summary>
        [Test]
        public void DENY_Authenticated_IsForGood()
        {

            var access = new NTPServerAccessState(UnauthenticatedDenyPause: TimeSpan.FromMinutes(10));

            access.Apply(new NTPKissOfDeath("DENY", 4), now, NTPKissTrust.Authenticated);
            access.Apply(new NTPKissOfDeath("DENY", 4), now, NTPKissTrust.Unauthenticated);

            Assert.That(access.Demobilized,                               Is.True);
            Assert.That(access.KeyExchangeNotBefore,                      Is.Null);
            Assert.That(access.MayRerunKeyExchange(now.AddDays(3650)),    Is.False);
            Assert.That(access.TryBeginKeyExchangeRerun(now.AddDays(3650)), Is.False);
            Assert.That(access.RecordKeyExchange(now.AddDays(3650)),      Is.False);

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

        #region ExtremeMaximumPollExponent_IsClampedWithoutOverflow()

        [Test]
        public void ExtremeMaximumPollExponent_IsClampedWithoutOverflow()
        {

            var access = new NTPServerAccessState(MaximumPollExponent: 255);

            Assert.Multiple(() => {
                Assert.That(access.MaximumPollExponent, Is.EqualTo(NTPServerAccessState.AbsoluteMaximumPollExponent));
                Assert.That(() => access.PollInterval, Throws.Nothing);
                Assert.That(access.UnauthenticatedDenyPause, Is.GreaterThan(TimeSpan.Zero));
            });

        }

        #endregion

    }

}
