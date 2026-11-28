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

using System.Net;
using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests
{

    /// <summary>
    /// The ports the other tests start their servers on: a port taken between finding it free
    /// and binding it is passed over, and nothing else is.
    /// </summary>
    [TestFixture]
    [Category("LocalIntegration")]
    public class FreePorts_Tests
    {

        #region APortTakenInBetweenIsPassedOver()

        /// <summary>
        /// Somebody else holds the UDP port the first server was to bind: a second one is made
        /// on a port found free anew, and that one starts.
        /// </summary>
        [Test]
        public async Task APortTakenInBetweenIsPassedOver()
        {

            using var somebodyElse  = new UdpClient(new IPEndPoint(System.Net.IPAddress.Any, 0));
            var       taken         = IPPort.Parse(((IPEndPoint) somebodyElse.Client.LocalEndPoint!).Port);
            var       attempts      = 0;

            var server = await FreePorts.Start(() => new NTSServer(
                                                         NTSKEPort:           FreePorts.TCP(),
                                                         NTSPort:             ++attempts == 1 ? taken : FreePorts.UDP(),
                                                         MasterKeysFilePath:  null
                                                     ));

            try
            {
                Assert.That(attempts,        Is.EqualTo(2));
                Assert.That(server.UDPPort,  Is.Not.EqualTo(taken));
            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region APortTakenEveryTimeIsTheTestsFailure()

        /// <summary>
        /// A port that is taken however often the server is made again is not waited out for
        /// ever: after the last attempt, the test learns why.
        /// </summary>
        [Test]
        public async Task APortTakenEveryTimeIsTheTestsFailure()
        {

            using var somebodyElse  = new UdpClient(new IPEndPoint(System.Net.IPAddress.Any, 0));
            var       taken         = IPPort.Parse(((IPEndPoint) somebodyElse.Client.LocalEndPoint!).Port);
            var       attempts      = 0;

            var thrown = await Assert.CatchAsync(async () => await FreePorts.Start(() => {
                                                                        attempts++;
                                                                        return new NTSServer(
                                                                                   NTSKEPort:           FreePorts.TCP(),
                                                                                   NTSPort:             taken,
                                                                                   MasterKeysFilePath:  null
                                                                               );
                                                                    },
                                                                    Attempts: 3));

            Assert.That(attempts,                         Is.EqualTo(3));
            Assert.That(FreePorts.IsAPortTaken(thrown),   Is.True, thrown?.ToString());

        }

        #endregion

        #region APortRefusedWithAccessDeniedIsTakenToo()

        /// <summary>
        /// What Windows says of a port held for exclusive use by somebody else - AccessDenied,
        /// not AddressAlreadyInUse - is a port taken as well, wrapped as deep as it may be;
        /// another socket error is not.
        /// </summary>
        [Test]
        public void APortRefusedWithAccessDeniedIsTakenToo()
        {

            var accessDenied = new SocketException((Int32) SocketError.AccessDenied);

            Assert.Multiple(() => {
                Assert.That(FreePorts.IsAPortTaken(accessDenied),                                                     Is.True);
                Assert.That(FreePorts.IsAPortTaken(new AggregateException(new InvalidOperationException("start", accessDenied))), Is.True);
                Assert.That(FreePorts.IsAPortTaken(new SocketException((Int32) SocketError.ConnectionRefused)),       Is.False);
            });

        }

        #endregion

        #region AnythingElseIsNotTriedAgain()

        /// <summary>
        /// Anything else than a port taken - here a server that cannot even be made - is the
        /// test's failure at once, not tried again.
        /// </summary>
        [Test]
        public async Task AnythingElseIsNotTriedAgain()
        {

            var attempts = 0;

            await Assert.CatchAsync(async () => await FreePorts.Start(() => {
                                                           attempts++;
                                                           throw new InvalidOperationException("not a port");
                                                       }));

            Assert.That(attempts, Is.EqualTo(1));

        }

        #endregion

    }

}
