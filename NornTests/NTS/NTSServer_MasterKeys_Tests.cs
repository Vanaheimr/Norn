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
using System.Security.Cryptography;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// The master keys of an NTS server in their file: what a server takes up again of what an
    /// earlier one wrote, what it forgets, and that a cookie outlives a restart because of it.
    /// </summary>
    [TestFixture]
    public class NTSServer_MasterKeys_Tests
    {

        #region Data

        private static readonly DateTimeOffset  T = new (2026, 11, 9, 12, 0, 0, TimeSpan.Zero);

        private String directory = "";

        private String KeyFile
            => Path.Combine(directory, "masterKeys.json");

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public void MakeADirectory()
        {
            directory = Path.Combine(Path.GetTempPath(), "NornMasterKeys-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public void RemoveTheDirectory()
        {
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch
            { }
        }

        #endregion


        #region AMasterKeyIsReadBackAsItWasWritten()

        /// <summary>
        /// What a master key says of itself in JSON is what it is read back as.
        /// </summary>
        [Test]
        public void AMasterKeyIsReadBackAsItWasWritten()
        {

            var written = new MasterKey(
                              Id:         5,
                              Value:      RandomNumberGenerator.GetBytes(32),
                              NotBefore:  T,
                              NotAfter:   T.AddDays(1)
                          );

            var text    = written.ToJSON().ToString(Newtonsoft.Json.Formatting.None);

            Assert.That(MasterKey.TryParse(text, out var read, out var errorResponse), Is.True, errorResponse);
            Assert.That(read.Id,         Is.EqualTo(written.Id));
            Assert.That(read.Value,      Is.EqualTo(written.Value));
            Assert.That(read.NotBefore,  Is.EqualTo(written.NotBefore));
            Assert.That(read.NotAfter,   Is.EqualTo(written.NotAfter));

        }

        #endregion

        #region TheNextServerTakesUpTheCurrentMasterKey()

        /// <summary>
        /// A server made on the key file of an earlier one seals its cookies under the key the
        /// earlier one sealed them under - it makes no key of its own, and the file is left as it
        /// was. The directory of the file is made where it is missing.
        /// </summary>
        [Test]
        public void TheNextServerTakesUpTheCurrentMasterKey()
        {

            var clock   = new SetClock(T);
            var keyFile = Path.Combine(directory, "not", "yet", "there", "masterKeys.json");

            var first   = ServerOn(keyFile, clock);
            var id      = first.CurrentMasterKeyId;
            var written = File.ReadAllText(keyFile);

            clock.Now   = T.AddHours(6);

            var second  = ServerOn(keyFile, clock);

            Assert.That(second.CurrentMasterKeyId,  Is.EqualTo(id));
            Assert.That(File.ReadAllText(keyFile),  Is.EqualTo(written));
            Assert.That(IdsIn(keyFile),             Is.EqualTo(new UInt64[] { id }));

        }

        #endregion

        #region AKeyLongPastItsGracePeriodIsForgotten_AndItsIdIsNotGivenAgain()

        /// <summary>
        /// A key whose end lies further back than the grace period is not taken up, and goes from
        /// the file with the next key written - but its id is never given to another key: a
        /// cookie names its key by nothing else.
        /// </summary>
        [Test]
        public void AKeyLongPastItsGracePeriodIsForgotten_AndItsIdIsNotGivenAgain()
        {

            WriteKeys(Key(7, T.AddDays(-30), T.AddDays(-29)));

            var server = ServerOn(KeyFile, new SetClock(T));

            Assert.That(server.CurrentMasterKeyId,  Is.EqualTo(8));
            Assert.That(IdsIn(KeyFile),             Is.EqualTo(new UInt64[] { 8 }));

        }

        #endregion

        #region AKeyWithinItsGracePeriodIsKept_ButSealsNoNewCookies()

        /// <summary>
        /// A key that ended within the grace period is taken up, so that the cookies sealed under
        /// it are still accepted, but new ones are sealed under a new key.
        /// </summary>
        [Test]
        public void AKeyWithinItsGracePeriodIsKept_ButSealsNoNewCookies()
        {

            WriteKeys(Key(3, T.AddDays(-2), T.AddDays(-1)));

            var server = ServerOn(KeyFile, new SetClock(T));

            Assert.That(server.CurrentMasterKeyId,  Is.EqualTo(4));
            Assert.That(IdsIn(KeyFile),             Is.EqualTo(new UInt64[] { 3, 4 }));

        }

        #endregion

        #region OfTwoKeysWithTheSameId_TheLaterLineIsKept()

        /// <summary>
        /// A file written while no key was ever taken up again holds the same ids more than once,
        /// every run having begun anew with 1. Of two keys with the same id the later line - the
        /// newer key - is the one kept, and the next key is numbered above every id of the file.
        /// </summary>
        [Test]
        public void OfTwoKeysWithTheSameId_TheLaterLineIsKept()
        {

            var newer = Key(1, T.AddHours(-1), T.AddHours(23));

            WriteKeys(Key(1, T.AddDays(-20), T.AddDays(-19)),
                      Key(2, T.AddDays(-19), T.AddDays(-18)),
                      newer);

            var clock  = new SetClock(T);
            var server = ServerOn(KeyFile, clock);

            Assert.That(server.CurrentMasterKeyId, Is.EqualTo(1));

            clock.Now  = T.AddDays(1);

            Assert.That(server.CurrentMasterKeyId, Is.EqualTo(3));
            Assert.That(IdsIn(KeyFile),            Is.EqualTo(new UInt64[] { 1, 3 }));

            var kept   = File.ReadAllLines(KeyFile).Select(JObject.Parse).First(json => json["id"]?.Value<UInt64>() == 1);

            Assert.That(kept["masterKey"]?.Value<String>(), Is.EqualTo(newer.Value.ToBase64()));

        }

        #endregion

        #region TheKeyFileIsTheOwnersOnly()

        /// <summary>
        /// Whoever reads the master keys can open every cookie, and with it the keys its client
        /// authenticates time with: the file is the owner's alone.
        /// </summary>
        [Test]
        [Platform(Exclude = "Win")]
        public void TheKeyFileIsTheOwnersOnly()
        {

            _ = ServerOn(KeyFile, new SetClock(T)).CurrentMasterKeyId;

            Assert.That(File.GetUnixFileMode(KeyFile), Is.EqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite));

        }

        #endregion

        #region ACookieOutlivesARestart()

        /// <summary>
        /// A cookie handed out before a restart is accepted after it, by a server made on the same
        /// key file - and, as the counterpart, not by one without it.
        /// </summary>
        [Test]
        [Category("LocalIntegration")]
        public async Task ACookieOutlivesARestart()
        {

            var ntpPort        = FindFreeUDPPort();

            var first          = new NTSServer(NTSKEPort:           FindFreeTCPPort(),
                                               NTSPort:             ntpPort,
                                               MasterKeysFilePath:  KeyFile);

            var ntsKEPort      = first.TCPPort;

            await first.Start();

            NTSKE_Response ntsKEResponse;

            try
            {

                var ntsKEResult = await ClientOf(ntsKEPort, ntpPort).GetNTSKERecords(RequestNTSPublicKeys: false);

                Assert.That(ntsKEResult.Success, Is.True, ntsKEResult.ErrorMessage);

                ntsKEResponse   = ntsKEResult.Response!;

            }
            finally
            {
                await first.ShutdownAsync();
            }


            var stranger       = new NTSServer(NTSKEPort:           FindFreeTCPPort(),
                                               NTSPort:             ntpPort,
                                               MasterKeysFilePath:  Path.Combine(directory, "otherKeys.json"));

            await stranger.Start();

            try
            {

                var refused = await ClientOf(ntsKEPort, ntpPort).QueryTime(NTSKEResponse:  ntsKEResponse,
                                                                           Timeout:        TimeSpan.FromSeconds(3));

                Assert.That(refused.Success, Is.False, "a server without the key file accepted the cookie");

            }
            finally
            {
                await stranger.ShutdownAsync();
            }


            var second         = new NTSServer(NTSKEPort:           FindFreeTCPPort(),
                                               NTSPort:             ntpPort,
                                               MasterKeysFilePath:  KeyFile);

            await second.Start();

            try
            {

                var answered = await ClientOf(ntsKEPort, ntpPort).QueryTime(NTSKEResponse:  ntsKEResponse,
                                                                            Timeout:        TimeSpan.FromSeconds(10));

                Assert.That(answered.Success,        Is.True, answered.ErrorMessage);
                Assert.That(answered.ErrorCategory,  Is.EqualTo(NTSQueryErrorCategory.None));

            }
            finally
            {
                await second.ShutdownAsync();
            }

        }

        #endregion


        #region (private) ServerOn(KeyFile, Clock)

        private static NTSServer ServerOn(String        KeyFile,
                                          TimeProvider  Clock)

            => new (MasterKeysFilePath:  KeyFile,
                    TimeProvider:        Clock,
                    // Given, as a clock that stands still cannot be measured.
                    ClockResolution:     TimeSpan.FromMilliseconds(1));

        #endregion

        #region (private) Key(Id, NotBefore, NotAfter)

        private static MasterKey Key(UInt64          Id,
                                     DateTimeOffset  NotBefore,
                                     DateTimeOffset  NotAfter)

            => new (Id, RandomNumberGenerator.GetBytes(32), NotBefore, NotAfter);

        #endregion

        #region (private) WriteKeys(params Keys)

        private void WriteKeys(params MasterKey[] Keys)

            => File.WriteAllLines(KeyFile,
                                  Keys.Select(key => key.ToJSON().ToString(Newtonsoft.Json.Formatting.None)));

        #endregion

        #region (private static) IdsIn(KeyFile)

        private static UInt64[] IdsIn(String KeyFile)

            => File.ReadAllLines(KeyFile).
                    Where (line => !String.IsNullOrWhiteSpace(line)).
                    Select(line => JObject.Parse(line)["id"]!.Value<UInt64>()).
                    Order ().
                    ToArray();

        #endregion

        #region (private static) ClientOf(NTSKEPort, NTPPort)

        private static NTSClient ClientOf(IPPort  NTSKEPort,
                                          IPPort  NTPPort)

            => new (Hermod.DNS.DomainName.Localhost,
                    NTSKE_Port:                  NTSKEPort,
                    NTP_Port:                    NTPPort,
                    IPVersionPreference:         IPVersionPreference.IPv4Only,
                    RemoteCertificateValidator:  (sender, serverCertificate, certificateChain, ntsKETLSClient, sslPolicyErrors) => TLSValidationResult.Success());

        #endregion

        #region (private static) FindFreeTCPPort() / FindFreeUDPPort()

        private static IPPort FindFreeTCPPort()
        {

            using var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);

            listener.Start();

            return IPPort.Parse(((IPEndPoint) listener.LocalEndpoint).Port);

        }

        private static IPPort FindFreeUDPPort()
        {

            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            return IPPort.Parse(((IPEndPoint) udpClient.Client.LocalEndPoint!).Port);

        }

        #endregion

        #region (private) SetClock

        /// <summary>
        /// A clock that shows what it is set to, and nothing else.
        /// </summary>
        private sealed class SetClock(DateTimeOffset Now) : TimeProvider
        {

            public DateTimeOffset Now { get; set; } = Now;

            public override DateTimeOffset GetUtcNow()
                => Now;

        }

        #endregion

    }

}
