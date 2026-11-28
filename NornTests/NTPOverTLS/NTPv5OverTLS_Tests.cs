/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Norn <https://www.github.com/Vanaheimr/Norn>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;
using org.GraphDefined.Vanaheimr.Norn.NTPOverTLS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTPOverTLS
{

    /// <summary>
    /// NTPv5 over TLS after section 6.1 of the white paper "Secure Time Synchronization":
    /// the framing, and Norn's client against Norn's server.
    /// </summary>
    [TestFixture]
    public class NTPv5OverTLS_Tests
    {

        #region Data

        private static readonly RemoteTLSServerCertificateValidationHandler<NTPOverTLS_TLSClient> AcceptAnyServer
            = (sender, certificate, chain, client, policyErrors) => TLSValidationResult.Success();

        #endregion


        #region (private) StartServer(NTPv5, PlainNTP)

        private static Task<NTSServer> StartServer(NTPv5Support  NTPv5     = NTPv5Support.Draft,
                                                   Boolean       PlainNTP  = false)

            => FreePorts.Start(() => new NTSServer(NTSKEPort:           FreePorts.TCP(),
                                                   NTSPort:             FreePorts.UDP(),
                                                   MasterKeysFilePath:  null,
                                                   PlainNTP:            PlainNTP,
                                                   NTPv5:               NTPv5,
                                                   NTPOverTLSPort:      FreePorts.TCP()));

        private static NTPOverTLSClient ClientOf(NTSServer Server)

            => new ("127.0.0.1",
                    Server.NTPOverTLSPort,
                    AcceptAnyServer,
                    Timeout: TimeSpan.FromSeconds(10));

        #endregion


        #region Framing

        [Test]
        public void TheLengthOctet_HasTheBitsVNZero()
        {

            for (var length = NTPOverTLSProtocol.MinFramedLength; length <= NTPOverTLSProtocol.MaxFramedLength; length++)
                Assert.That(NTPOverTLSProtocol.IsLengthOctet((Byte) (length >> 8)), Is.True, $"length {length}");

            // The first octet of every NTP client request of versions 1 to 5, whatever its leap indicator.
            for (var version = 1; version <= 5; version++)
                for (var leap = 0; leap <= 3; leap++)
                    Assert.That(NTPOverTLSProtocol.IsLengthOctet((Byte) ((leap << 6) | (version << 3) | 3)), Is.False, $"LI {leap}, VN {version}");

        }

        [Test]
        public void AFramedMessage_IsReadBack()
        {

            var message = Enumerable.Range(0, 76).Select(i => (Byte) (0x2B + i)).ToArray();
            message[0]  = (5 << 3) | 3;

            var framed  = NTPOverTLSProtocol.Frame(message);

            Assert.That(framed[0], Is.EqualTo(0));
            Assert.That(framed[1], Is.EqualTo(76));

            using var stream = new MemoryStream([.. framed, .. new Byte[48].Select((_, i) => i == 0 ? (Byte) 0x23 : (Byte) 0)]);

            var (status1, read1, framed1) = NTPOverTLSProtocol.ReadMessage(stream);
            var (status2, read2, framed2) = NTPOverTLSProtocol.ReadMessage(stream);
            var (status3, _,     _)       = NTPOverTLSProtocol.ReadMessage(stream);

            Assert.That(status1, Is.EqualTo(NTPOverTLSReadStatus.Message));
            Assert.That(framed1, Is.True);
            Assert.That(read1,   Is.EqualTo(message));

            Assert.That(status2, Is.EqualTo(NTPOverTLSReadStatus.Message));
            Assert.That(framed2, Is.False, "a bare NTPv4 header follows on the same stream");
            Assert.That(read2,   Has.Length.EqualTo(48));
            Assert.That(read2![0], Is.EqualTo(0x23));

            Assert.That(status3, Is.EqualTo(NTPOverTLSReadStatus.EndOfStream));

        }

        [TestCase(new Byte[] { 0x00, 0x2F },       NTPOverTLSReadStatus.BadLength, TestName = "A length of 47")]
        [TestCase(new Byte[] { 0x40, 0x00 },       NTPOverTLSReadStatus.BadLength, TestName = "A length of 16384")]
        [TestCase(new Byte[] { 0x00 },             NTPOverTLSReadStatus.Truncated, TestName = "Half a length")]
        [TestCase(new Byte[] { 0x00, 0x30, 0x2B }, NTPOverTLSReadStatus.Truncated, TestName = "A message cut short")]
        [TestCase(new Byte[] { 0x23, 0x00 },       NTPOverTLSReadStatus.Truncated, TestName = "A bare header cut short")]
        public void WhatIsNoWholeMessage_IsTold(Byte[] Bytes, NTPOverTLSReadStatus Expected)
        {

            using var stream = new MemoryStream(Bytes);

            Assert.That(NTPOverTLSProtocol.ReadMessage(stream).Status, Is.EqualTo(Expected));

        }

        [Test]
        public void TooLongOrShortAMessage_IsNotFramed()
        {
            Assert.That(() => NTPOverTLSProtocol.Frame(new Byte[47]),   Throws.ArgumentException);
            Assert.That(() => NTPOverTLSProtocol.Frame(new Byte[2048]), Throws.ArgumentException);
        }

        #endregion


        #region NTPv5_IsAnsweredOverTLS()

        [Test]
        public async Task NTPv5_IsAnsweredOverTLS()
        {

            // A server of NTS alone, which answers plain NTPv5 over TLS all the same.
            var server = await StartServer();

            try
            {

                var result  = await ClientOf(server).QueryNTPv5();

                var metrics = await Settled.Until(() => server.Metrics, m => m.NTPOverTLSResponsesSent >= 1);

                Assert.That(result.Success,                        Is.True, result.ToString());
                Assert.That(result.Version,                        Is.EqualTo(5));
                Assert.That(result.NTPv5Response,                  Is.Not.Null);
                Assert.That(result.TLSVersion,                     Is.EqualTo("TLS 1.3"));
                Assert.That(result.RequestBytes!.Length,           Is.GreaterThan(48), "the Draft Identification makes it longer than the header");
                Assert.That(result.ResponseBytes!.Length,          Is.EqualTo(result.RequestBytes.Length));
                Assert.That(result.ClockOffset!.Value.Duration(),  Is.LessThan(TimeSpan.FromSeconds(1)));
                Assert.That(result.MaximumError,                   Is.Not.Null);
                Assert.That(metrics.NTPOverTLSResponsesSent,       Is.EqualTo(1), metrics.ToString());

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region NTPv5_IsNotAnswered_WhereTheServerHasNone()

        [Test]
        public async Task NTPv5_IsNotAnswered_WhereTheServerHasNone()
        {

            var server = await StartServer(NTPv5: NTPv5Support.Disabled);

            try
            {

                var result  = await ClientOf(server).QueryNTPv5();

                var metrics = await Settled.Until(() => server.Metrics, m => m.NTPOverTLSRequestsInvalid >= 1);

                Assert.That(result.Success,                     Is.False);
                Assert.That(result.Version,                     Is.EqualTo(5));
                Assert.That(result.ErrorMessage,                Does.Contain("without a response"));
                Assert.That(metrics.NTPOverTLSResponsesSent,    Is.Zero);
                Assert.That(metrics.NTPOverTLSRequestsInvalid,  Is.EqualTo(1));

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region TheOffer_IsEchoed_WhereTheServerSpeaksNTPv5([Values] NTPv5)

        [Test]
        public async Task TheOffer_IsEchoed_WhereTheServerSpeaksNTPv5([Values] Boolean NTPv5)
        {

            var server = await StartServer(NTPv5: NTPv5 ? NTPv5Support.Draft : NTPv5Support.Disabled);

            try
            {

                var result = await ClientOf(server).QueryTime(AdvertiseNTPv5: true);

                Assert.That(result.Success,       Is.True, result.ToString());
                Assert.That(result.Version,       Is.EqualTo(4));
                Assert.That(result.NTPv5Offered,  Is.True);
                Assert.That(result.NTPv5Echoed,   Is.EqualTo(NTPv5));
                Assert.That(BitConverter.ToUInt64(result.RequestBytes!.AsSpan(16, 8).ToArray().Reverse().ToArray()),
                            Is.EqualTo(NTPv5Draft.NegotiationMagic),
                            "the minimized request carries the magic in its reference timestamp");

                var plain  = await ClientOf(server).QueryTime();

                Assert.That(plain.Success,        Is.True, plain.ToString());
                Assert.That(plain.NTPv5Offered,   Is.False);
                Assert.That(plain.NTPv5Echoed,    Is.False);
                Assert.That(plain.RequestBytes!.AsSpan(16, 8).ToArray(), Is.All.Zero);

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region TheNegotiation_ChangesToNTPv5_AfterTheEcho()

        [Test]
        public async Task TheNegotiation_ChangesToNTPv5_AfterTheEcho()
        {

            var server = await StartServer();

            try
            {

                var client      = ClientOf(server);
                var negotiation = new NTPv5VersionNegotiation();

                var first       = await client.QueryNegotiated(negotiation);

                Assert.That(first.Success,       Is.True, first.ToString());
                Assert.That(first.Version,       Is.EqualTo(4));
                Assert.That(first.NTPv5Echoed,   Is.True);
                Assert.That(negotiation.Version, Is.EqualTo(NTPv5NegotiatedVersion.NTPv5));

                var second      = await client.QueryNegotiated(negotiation);

                Assert.That(second.Success,      Is.True, second.ToString());
                Assert.That(second.Version,      Is.EqualTo(5));
                Assert.That(negotiation.Version, Is.EqualTo(NTPv5NegotiatedVersion.NTPv5));

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region TheNegotiation_StaysWithNTPv4_WithoutAnEcho()

        [Test]
        public async Task TheNegotiation_StaysWithNTPv4_WithoutAnEcho()
        {

            var server = await StartServer(NTPv5: NTPv5Support.Disabled);

            try
            {

                var client      = ClientOf(server);
                var negotiation = new NTPv5VersionNegotiation();

                for (var i = 0; i < 3; i++)
                {

                    var result = await client.QueryNegotiated(negotiation);

                    Assert.That(result.Success,       Is.True, result.ToString());
                    Assert.That(result.Version,       Is.EqualTo(4));
                    Assert.That(result.NTPv5Offered,  Is.True);
                    Assert.That(result.NTPv5Echoed,   Is.False);

                }

                Assert.That(negotiation.Version, Is.EqualTo(NTPv5NegotiatedVersion.NTPv4Advertising));

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

        #region TheNegotiation_FallsBack_WhenNTPv5GoesUnanswered()

        [Test]
        public async Task TheNegotiation_FallsBack_WhenNTPv5GoesUnanswered()
        {

            // A server that echoed once and then lost NTPv5 is what a negotiation already in
            // NTPv5 meets at a server without it.
            var server = await StartServer(NTPv5: NTPv5Support.Disabled);

            try
            {

                var client      = ClientOf(server);
                var negotiation = new NTPv5VersionNegotiation(MaxFailures: 2, BackoffRequests: 3);

                negotiation.RecordNTPv4Response(NTPv5Draft.NegotiationMagic);

                Assert.That(negotiation.Version, Is.EqualTo(NTPv5NegotiatedVersion.NTPv5));

                var first   = await client.QueryNegotiated(negotiation);
                var second  = await client.QueryNegotiated(negotiation);
                var third   = await client.QueryNegotiated(negotiation);

                Assert.That(first.Success,        Is.False);
                Assert.That(first.Version,        Is.EqualTo(5));
                Assert.That(second.Success,       Is.False);
                Assert.That(third.Success,        Is.True, third.ToString());
                Assert.That(third.Version,        Is.EqualTo(4));
                Assert.That(third.NTPv5Offered,   Is.False, "while it backs off, the request offers nothing");

            }
            finally
            {
                await server.ShutdownAsync();
            }

        }

        #endregion

    }

}
