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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// Lifetime and ownership tests for <see cref="IDisposable"/> / <see cref="IAsyncDisposable"/>
    /// across <see cref="NTSServer"/>, <see cref="NTSClient"/>, <see cref="NTSKE_TLSInfo"/>,
    /// <see cref="NTSKE_Response"/>, <see cref="NTSKEResult"/>, and <see cref="MeasurementEngine"/>.
    /// </summary>
    [TestFixture]
    public class NTSLifetime_Tests
    {

        #region Helpers

        private sealed class TrackingDNSClient() : DNSClient(SearchForIPv4DNSServers: false,
                                                             SearchForIPv6DNSServers: false)
        {

            private Int32 disposeCount;

            public Int32 DisposeCount
                => Volatile.Read(ref disposeCount);

            protected override void Dispose(Boolean Disposing)
            {
                if (Disposing)
                    Interlocked.Increment(ref disposeCount);

                base.Dispose(Disposing);
            }

        }

        private static NTSServer CreateLoopbackServer(out IPPort   TCPPort,
                                                      out IPPort   UDPPort,
                                                      DNSClient?   DNSClient = null)
        {

            TCPPort = FreePorts.TCP();
            UDPPort = FreePorts.UDP();

            return new NTSServer(
                       NTSKEPort:          TCPPort,
                       NTSPort:            UDPPort,
                       ListenIPAddress:    IPv4Address.Localhost,
                       MasterKeysFilePath: null,
                       DNSClient:          DNSClient
                   );

        }

        private static Boolean IsCertificateDisposed(X509Certificate2 Certificate)
        {

            try
            {
                _ = Certificate.Subject;
                return false;
            }
            catch (CryptographicException)
            {
                return true;
            }
            catch (ObjectDisposedException)
            {
                return true;
            }

        }

        #endregion

        #region NTSServer_DisposeAsync_StopsServer_IsIdempotent_AndPreventsRestart()

        [Test]
        public async Task NTSServer_DisposeAsync_StopsServer_IsIdempotent_AndPreventsRestart()
        {

            var server = CreateLoopbackServer(out var tcpPort, out var udpPort);
            await server.Start();

            using (var client = new NTSClient(
                                    IPv4Address.Localhost,
                                    NTSKE_Port:                 tcpPort,
                                    NTP_Port:                   udpPort,
                                    RemoteCertificateValidator: (_, _, _, _, _) => TLSValidationResult.Success(),
                                    Timeout:                    TimeSpan.FromSeconds(5)
                                ))
            {
                using var ke = await client.GetNTSKERecords();
                Assert.That(ke.Success, Is.True, ke.ErrorMessage);
            }

            await server.DisposeAsync();

            // Subsequent DisposeAsync / Dispose calls must be safe no-ops.
            await server.DisposeAsync();
            server.Dispose();

            // Starting a disposed server must throw ObjectDisposedException.
            Assert.That(async () => await server.Start(), Throws.TypeOf<ObjectDisposedException>());

        }

        #endregion

        #region NTSServer_RespectsDNSClientOwnership()

        [Test]
        public async Task NTSServer_RespectsDNSClientOwnership()
        {

            using var sharedDns = new TrackingDNSClient();

            await using (var server = CreateLoopbackServer(out _, out _, DNSClient: sharedDns))
            {
                await server.Start();
            }

            Assert.That(sharedDns.DisposeCount, Is.EqualTo(0),
                        "NTSServer must not dispose a caller-supplied DNSClient.");

        }

        #endregion

        #region NTSClient_RespectsDNSClientOwnership_AndThrowsAfterDispose()

        [Test]
        public async Task NTSClient_RespectsDNSClientOwnership_AndThrowsAfterDispose()
        {

            using var sharedDns = new TrackingDNSClient();

            var client = new NTSClient(
                             IPv4Address.Localhost,
                             DNSClient: sharedDns
                         );

            await client.DisposeAsync();
            await client.DisposeAsync();
            client.Dispose();

            Assert.Multiple(() => {
                Assert.That(sharedDns.DisposeCount, Is.EqualTo(0),
                            "NTSClient must not dispose a caller-supplied DNSClient.");
                Assert.That(async () => await client.GetNTSKERecords(), Throws.TypeOf<ObjectDisposedException>());
                Assert.That(async () => await client.QueryTime(),       Throws.TypeOf<ObjectDisposedException>());
            });

        }

        #endregion

        #region NTSKEResult_Dispose_ReleasesCertificates_DeduplicatesLeaf_AndIsIdempotent()

        [Test]
        public async Task NTSKEResult_Dispose_ReleasesCertificates_DeduplicatesLeaf_AndIsIdempotent()
        {

            await using var server = CreateLoopbackServer(out var tcpPort, out var udpPort);
            await server.Start();

            await using var client = new NTSClient(
                                         IPv4Address.Localhost,
                                         NTSKE_Port:                 tcpPort,
                                         NTP_Port:                   udpPort,
                                         RemoteCertificateValidator: (_, _, _, _, _) => TLSValidationResult.Success(),
                                         Timeout:                    TimeSpan.FromSeconds(5)
                                     );

            var result = await client.GetNTSKERecords();

            Assert.That(result.Success, Is.True, result.ErrorMessage);
            Assert.That(result.TLSInfo, Is.Not.Null);
            Assert.That(result.TLSInfo!.ServerCertificate, Is.Not.Null);
            Assert.That(result.TLSInfo.CertificateChain, Has.Count.GreaterThanOrEqualTo(1));

            // Leaf certificate must be reused rather than loaded twice as two separate native handles.
            Assert.That(
                ReferenceEquals(result.TLSInfo.ServerCertificate, result.TLSInfo.CertificateChain[0]),
                Is.True,
                "ServerCertificate and CertificateChain[0] should share the same X509Certificate2 instance."
            );

            var leafCert = result.TLSInfo.ServerCertificate!;
            Assert.That(IsCertificateDisposed(leafCert), Is.False, "Certificate must be live before Dispose.");

            result.Dispose();

            // Repeated disposal across result / response / TLSInfo must be idempotent.
            result.Dispose();
            result.Response?.Dispose();
            result.TLSInfo.Dispose();

            Assert.That(IsCertificateDisposed(leafCert), Is.True, "Certificate must be disposed after NTSKEResult.Dispose().");

        }

        #endregion

        #region MeasurementEngine_DisposeAsync_ClearsCache_DisposesCerts_AndKeepsCallerDNSClient()

        [Test]
        public async Task MeasurementEngine_DisposeAsync_ClearsCache_DisposesCerts_AndKeepsCallerDNSClient()
        {

            await using var server    = CreateLoopbackServer(out var tcpPort, out var udpPort);
            await server.Start();

            using var sharedDns       = new TrackingDNSClient();

            var endpoint              = new NTSServerEndpoint(
                                            DomainName.Parse("127.0.0.1"),
                                            NTSKEPort:                  tcpPort,
                                            NTPPort:                    udpPort,
                                            RemoteCertificateValidator: (_, _, _, _, _) => TLSValidationResult.Success()
                                        );

            var config                = new MonitoringConfig {
                                            DroneId       = "lifetime-tests",
                                            NTSKETimeout  = TimeSpan.FromSeconds(5),
                                            NTPTimeout    = TimeSpan.FromSeconds(5)
                                        };

            var engine                = new MeasurementEngine(config);

            var result                = await engine.MeasureSingleServer(endpoint, Guid.NewGuid(), sharedDns);
            Assert.That(result.Success, Is.True, result.ErrorMessage?.ToString());

            Assert.That(engine.KeyExchanges.TryGetValue(endpoint.Hostname, out var cached), Is.True);
            var cachedCert = cached!.NTSKEResponse?.TLSInfo?.ServerCertificate;
            Assert.That(cachedCert, Is.Not.Null);
            Assert.That(IsCertificateDisposed(cachedCert!), Is.False);

            await engine.DisposeAsync();
            await engine.DisposeAsync();
            engine.Dispose();

            Assert.Multiple(() => {
                Assert.That(engine.KeyExchanges,              Is.Empty);
                Assert.That(IsCertificateDisposed(cachedCert!), Is.True);
                Assert.That(sharedDns.DisposeCount,           Is.EqualTo(0),
                            "MeasurementEngine must not dispose the caller-supplied DNSClient.");
            });

        }

        #endregion

    }

}
