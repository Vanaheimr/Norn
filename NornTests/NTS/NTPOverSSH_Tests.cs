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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// The framing of NTP over SSH, section 10.3 of the white paper "NTS Key Establishment over
    /// SSH": a two-octet length in network byte order, and the message.
    /// </summary>
    [TestFixture]
    public class NTPOverSSH_Framing_Tests
    {

        private static async Task<(NTPOverSSHReadStatus Status, Byte[]? Message)> Read(Byte[] Stream, Int32 MaxLength = 4096)
            => await NTPOverSSH.ReadMessageAsync(new MemoryStream(Stream), MaxLength, CancellationToken.None);


        [Test]
        public void Frame_PutsTheLengthInFront_BigEndian()
        {

            var message = Enumerable.Range(0, 300).Select(i => (Byte) i).ToArray();
            var framed  = NTPOverSSH.Frame(message);

            Assert.That(framed[0..2], Is.EqualTo(new Byte[] { 0x01, 0x2C }));
            Assert.That(framed[2..],  Is.EqualTo(message));

        }

        [TestCase(0)]
        [TestCase(47)]
        [TestCase(65536)]
        public void Frame_RefusesWhatNoLengthCanSay(Int32 Length)

            => Assert.That(() => NTPOverSSH.Frame(new Byte[Length]), Throws.ArgumentException);


        [Test]
        public async Task Read_TakesOneMessage_AndLeavesTheNext()
        {

            var first   = Enumerable.Repeat((Byte) 1, 48).ToArray();
            var second  = Enumerable.Repeat((Byte) 2, 60).ToArray();
            var stream  = new MemoryStream([ .. NTPOverSSH.Frame(first), .. NTPOverSSH.Frame(second) ]);

            var (status1, message1) = await NTPOverSSH.ReadMessageAsync(stream, 4096, CancellationToken.None);
            var (status2, message2) = await NTPOverSSH.ReadMessageAsync(stream, 4096, CancellationToken.None);
            var (status3, _)        = await NTPOverSSH.ReadMessageAsync(stream, 4096, CancellationToken.None);

            Assert.Multiple(() => {
                Assert.That(status1,  Is.EqualTo(NTPOverSSHReadStatus.Message));
                Assert.That(message1, Is.EqualTo(first));
                Assert.That(status2,  Is.EqualTo(NTPOverSSHReadStatus.Message));
                Assert.That(message2, Is.EqualTo(second));
                Assert.That(status3,  Is.EqualTo(NTPOverSSHReadStatus.EndOfStream));
            });

        }

        [Test]
        public async Task Read_OfNothing_IsTheEndOfTheStream()
            => Assert.That((await Read([])).Status, Is.EqualTo(NTPOverSSHReadStatus.EndOfStream));

        [Test]
        public async Task Read_OfHalfALength_IsTruncated()
            => Assert.That((await Read([ 0x00 ])).Status, Is.EqualTo(NTPOverSSHReadStatus.Truncated));

        [Test]
        public async Task Read_OfLessThanTheLengthSays_IsTruncated()
            => Assert.That((await Read([ 0x00, 0x40, .. new Byte[63] ])).Status, Is.EqualTo(NTPOverSSHReadStatus.Truncated));

        [TestCase(0)]
        [TestCase(1)]
        [TestCase(47)]
        public async Task Read_OfALengthBelow48_IsTooShort(Int32 Length)
            => Assert.That((await Read([ 0x00, (Byte) Length, .. new Byte[Length] ])).Status, Is.EqualTo(NTPOverSSHReadStatus.TooShort));

        [Test]
        public async Task Read_OfALengthAboveTheMaximum_IsTooLong_WithoutReadingIt()
        {

            var stream = new MemoryStream([ 0x10, 0x01, .. new Byte[4097] ]);

            var (status, _) = await NTPOverSSH.ReadMessageAsync(stream, 4096, CancellationToken.None);

            Assert.That(status,          Is.EqualTo(NTPOverSSHReadStatus.TooLong));
            Assert.That(stream.Position, Is.EqualTo(2), "the reader read the length alone");

        }

        [Test]
        public async Task Read_OfExactlyTheMaximum_IsAMessage()
            => Assert.That((await Read([ 0x05, 0x00, .. new Byte[1280] ], 1280)).Status, Is.EqualTo(NTPOverSSHReadStatus.Message));

    }


    /// <summary>
    /// Norn's client against Norn's server, NTP over SSH on the server's own SSH listener.
    /// </summary>
    [TestFixture]
    public class NTPOverSSH_Tests
    {

        #region Data

        private static readonly ISshHostKey  clientKey  = SshHostKey.GenerateEd25519();

        private NTSServer? ntsServer;
        private NTSServer? withoutNTPOverSSH;

        #endregion

        #region Start/stop the NTS servers

        [OneTimeSetUp]
        public async Task StartNTSServers()
        {

            // A server of NTS alone on UDP: over SSH it answers plain requests all the same.
            ntsServer          = await FreePorts.Start(() => new NTSServer(
                                                                 NTSKEPort:           FreePorts.TCP(),
                                                                 NTSPort:             FreePorts.UDP(),
                                                                 MasterKeysFilePath:  null,
                                                                 SSHPort:             FreePorts.TCP(),
                                                                 SSHAuthenticator:    SshUserAuthenticator.ForAuthorizedKeys(clientKey.PublicKeyBlob),
                                                                 PlainNTP:            false,
                                                                 NTPv5:               NTPv5Support.Draft,
                                                                 NTPOverSSH:          true
                                                             ));

            withoutNTPOverSSH  = await FreePorts.Start(() => new NTSServer(
                                                                 NTSKEPort:           FreePorts.TCP(),
                                                                 NTSPort:             FreePorts.UDP(),
                                                                 MasterKeysFilePath:  null,
                                                                 SSHPort:             FreePorts.TCP(),
                                                                 SSHAuthenticator:    SshUserAuthenticator.ForAuthorizedKeys(clientKey.PublicKeyBlob)
                                                             ));

        }

        [OneTimeTearDown]
        public async Task StopNTSServers()
        {

            if (ntsServer is not null)
                await ntsServer.ShutdownAsync();

            if (withoutNTPOverSSH is not null)
                await withoutNTPOverSSH.ShutdownAsync();

        }

        #endregion

        #region (private) helpers

        private static Task<SSHClient> ConnectAsync(NTSServer Server)
        {

            var hostKey = Server.SSHHostKeys[0].PublicKeyBlob;

            return SSHClient.Connect(
                       "127.0.0.1",
                       Server.SSHPort!.Value,
                       new SSHClientOptions {
                           Username       = User_Id.Parse("ntp"),
                           Credentials    = [ clientKey ],
                           VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(hostKey)
                       }
                   ).AsTask();

        }

        private static NTSClient Client()

            => new (DomainName.Localhost,
                    IPVersionPreference:  IPVersionPreference.IPv4Only,
                    Timeout:              TimeSpan.FromSeconds(5));

        #endregion


        [Test]
        public void TheServer_SaysItOffersNTPOverSSH()
        {
            Assert.That(ntsServer!.NTPOverSSHEnabled,             Is.True);
            Assert.That(withoutNTPOverSSH!.NTPOverSSHEnabled,     Is.False);
            Assert.That(ntsServer.NTPOverSSHIdleTimeout,          Is.GreaterThanOrEqualTo(NTPOverSSH.MinIdleTimeout));
        }

        [Test]
        public async Task NTPv4_OverSSH_IsAnswered_ByAServerOfNTSAlone()
        {

            await using var connection  = await ConnectAsync(ntsServer!);
            await using var channel     = await NTPOverSSHChannel.OpenAsync(connection);

            var before = ntsServer!.Metrics;
            var result = await Client().QueryTimeOverSSH(channel);
            var after  = ntsServer.Metrics;

            Assert.That(result.Success, Is.True, result.ErrorMessage);
            Assert.That(result.Response?.ClockOffset?.Duration(), Is.LessThan(TimeSpan.FromMilliseconds(50)), "one clock on both ends");
            Assert.That(after.NTPOverSSHRequestsReceived - before.NTPOverSSHRequestsReceived, Is.EqualTo(1), after.ToString());

        }

        [Test]
        public async Task NTPv5_OverSSH_IsAnswered()
        {

            await using var connection  = await ConnectAsync(ntsServer!);
            await using var channel     = await NTPOverSSHChannel.OpenAsync(connection);

            var result = await Client().QueryNTPv5OverSSH(channel);

            Assert.That(result.Success,                         Is.True, result.ErrorMessage);
            Assert.That(result.Measurement?.BestOffset.Duration(), Is.LessThan(TimeSpan.FromMilliseconds(50)), "one clock on both ends");

        }

        [Test]
        public async Task Negotiated_OverSSH_ChangesToNTPv5()
        {

            await using var connection  = await ConnectAsync(ntsServer!);
            await using var channel     = await NTPOverSSHChannel.OpenAsync(connection);

            var client       = Client();
            var negotiation  = new NTPv5VersionNegotiation();

            var first        = await client.QueryNegotiatedOverSSH(channel, negotiation);
            var second       = await client.QueryNegotiatedOverSSH(channel, negotiation);

            Assert.That(first.NTPv4?.Success,  Is.True, first.NTPv4?.ErrorMessage);
            Assert.That(first.NextVersion,     Is.EqualTo(NTPv5NegotiatedVersion.NTPv5), "the server echoed the offer, though it answers plain requests on UDP not at all");
            Assert.That(second.NTPv5?.Success, Is.True, second.NTPv5?.ErrorMessage);

        }

        [Test]
        public async Task ManyQueries_OnOneChannel()
        {

            await using var connection  = await ConnectAsync(ntsServer!);
            await using var channel     = await NTPOverSSHChannel.OpenAsync(connection);

            var client = Client();

            for (var i = 0; i < 10; i++)
                Assert.That((await client.QueryTimeOverSSH(channel)).Success, Is.True, $"query {i + 1}");

            Assert.That(channel.IsOpen, Is.True);

        }

        [Test]
        public async Task WhereItIsNotOffered_TheSubsystemIsRefused()
        {

            await using var connection = await ConnectAsync(withoutNTPOverSSH!);

            Assert.That(async () => await NTPOverSSHChannel.OpenAsync(connection), Throws.InstanceOf<SshSubsystemRefusedException>());

        }

        [Test]
        public async Task TheServerStopping_EndsTheChannel_AndTheQueryFails()
        {

            var server = await FreePorts.Start(() => new NTSServer(
                                                         NTSKEPort:           FreePorts.TCP(),
                                                         NTSPort:             FreePorts.UDP(),
                                                         MasterKeysFilePath:  null,
                                                         SSHPort:             FreePorts.TCP(),
                                                         SSHAuthenticator:    SshUserAuthenticator.ForAuthorizedKeys(clientKey.PublicKeyBlob),
                                                         NTPOverSSH:          true
                                                     ));

            await using var connection  = await ConnectAsync(server);
            await using var channel     = await NTPOverSSHChannel.OpenAsync(connection);

            Assert.That((await Client().QueryTimeOverSSH(channel)).Success, Is.True, "before the server stops");

            await server.ShutdownAsync();

            var result = await Client().QueryTimeOverSSH(channel);

            Assert.That(result.Success,       Is.False);
            Assert.That(result.ErrorCategory, Is.Not.EqualTo(NTSQueryErrorCategory.NTPTimeout), result.ErrorMessage);

        }

    }

}
