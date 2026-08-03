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

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Security;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// The Network Time Security Key Establishment (NTS-KE) TLS client.
    /// </summary>
    public class NTSKE_TLSClient(RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient>?  RemoteCertificateValidator    = null,
                                 DomainName?                                                    ExpectedHostname              = null)

        : DefaultTlsClient(
              new BcTlsCrypto(
                  new SecureRandom()
              )
          )

    {

        #region Data

        private readonly RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient>? remoteCertificateValidator = RemoteCertificateValidator;

        #endregion

        #region Properties

        public TlsContext?  NTSKEContext    { get; private set; }

        public DomainName?  ExpectedHostname { get; } = ExpectedHostname;

        /// <summary>
        /// TLS certificate and handshake information captured during NTS-KE.
        /// </summary>
        public NTSKE_TLSInfo?  TLSInfo       { get; private set; }

        /// <summary>
        /// The leaf server certificate captured during NTS-KE.
        /// </summary>
        public X509Certificate2?  ServerCertificate
            => TLSInfo?.ServerCertificate;

        /// <summary>
        /// The negotiated TLS cipher suite.
        /// </summary>
        public String?  NegotiatedCipherSuite
            => TLSInfo?.NegotiatedCipherSuite;

        /// <summary>
        /// The negotiated TLS protocol version.
        /// </summary>
        public String?  NegotiatedTLSVersion
            => TLSInfo?.NegotiatedTLSVersion;

        /// <summary>
        /// The NTP-KE Client-2-Server Key
        /// </summary>
        public Byte[]?      NTS_C2S_Key     { get; private set; }

        /// <summary>
        /// The NTP-KE Server-2-Client Key
        /// </summary>
        public Byte[]?      NTS_S2C_Key     { get; private set; }

        #endregion


        #region NotifyHandshakeComplete()

        public override void NotifyHandshakeComplete()
        {

            base.NotifyHandshakeComplete();

            NTSKEContext = base.m_context;

            var securityParameters = NTSKEContext.SecurityParameters;
            var cipherSuiteId      = securityParameters.CipherSuite;

            TLSInfo = (TLSInfo ?? new NTSKE_TLSInfo()).WithHandshakeInfo(
                          GetCipherSuiteName(cipherSuiteId),
                          cipherSuiteId,
                          securityParameters.NegotiatedVersion?.Name,
                          securityParameters.ApplicationProtocol?.GetUtf8Decoding(),
                          securityParameters.KeyExchangeAlgorithm
                      );

            var algorithmBytes = AEADAlgorithms.AES_SIV_CMAC_256.GetBytes();

            // Export 32 bytes for AES-SIV-CMAC-256:
            NTS_C2S_Key = NTSKEContext.ExportKeyingMaterial(
                "EXPORTER-network-time-security",
                [0x00, 0x00, algorithmBytes[0], algorithmBytes[1], 0x00],
                32
            );

            NTS_S2C_Key = NTSKEContext.ExportKeyingMaterial(
                "EXPORTER-network-time-security",
                [0x00, 0x00, algorithmBytes[0], algorithmBytes[1], 0x01],
                32
            );

        }

        #endregion

        #region SetCertificateInfo(ServerCertificate, CertificateChain, CertificatePolicyErrors)

        internal void SetCertificateInfo(X509Certificate2               ServerCertificate,
                                         IEnumerable<X509Certificate2>  CertificateChain,
                                         SslPolicyErrors                CertificatePolicyErrors)
        {

            TLSInfo = new NTSKE_TLSInfo(
                          ServerCertificate,
                          CertificateChain,
                          CertificatePolicyErrors,
                          TLSInfo?.NegotiatedCipherSuite,
                          TLSInfo?.NegotiatedCipherSuiteId,
                          TLSInfo?.NegotiatedTLSVersion,
                          TLSInfo?.NegotiatedApplicationProtocol,
                          TLSInfo?.KeyExchangeAlgorithm
                      );

        }

        #endregion

        #region (private) GetCipherSuiteName(CipherSuiteId)

        private static String GetCipherSuiteName(Int32 CipherSuiteId)

            => CipherSuiteId switch {
                   0x1301  => "TLS_AES_128_GCM_SHA256",
                   0x1302  => "TLS_AES_256_GCM_SHA384",
                   0x1303  => "TLS_CHACHA20_POLY1305_SHA256",
                   0x1304  => "TLS_AES_128_CCM_SHA256",
                   0x1305  => "TLS_AES_128_CCM_8_SHA256",
                   _       => $"0x{CipherSuiteId:X4}"
               };

        #endregion

        #region (override) GetProtocolVersions()

        public override ProtocolVersion[] GetProtocolVersions()

            => [ProtocolVersion.TLSv13];

        #endregion

        // Restrict to a subset of TLS 1.3 cipher suites
        //public override int[] GetCipherSuites()
        //
        //    => new int[] {
        //           CipherSuite.TLS_AES_256_GCM_SHA384,
        //           CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        //           CipherSuite.TLS_AES_128_GCM_SHA256,
        //       };

        #region (override) GetClientExtensions()

        public override IDictionary<Int32, Byte[]> GetClientExtensions()
        {

            var clientExtensions = base.GetClientExtensions();

            clientExtensions ??= new Dictionary<Int32, Byte[]>();

            TlsExtensionsUtilities.AddAlpnExtensionClient(
                clientExtensions,
                [ProtocolName.Ntske_1]
            );

            return clientExtensions;

        }

        #endregion

        #region (override) GetAuthentication()

        public override TlsAuthentication GetAuthentication()
        {
            return new ValidatingTlsAuthentication(
                       this,
                       remoteCertificateValidator
                   );
        }

        #endregion

    }


    public class ValidatingTlsAuthentication(NTSKE_TLSClient                                                NTSKETLSClient,
                                             RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient>?  RemoteCertificateValidator   = null)

        : TlsAuthentication

    {

        #region Data

        private readonly RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient>? remoteCertificateValidator = RemoteCertificateValidator;

        #endregion


        public TlsCredentials GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest CertificateRequest)
        {
            // We don't do client-certificate-based auth here:
            return null!;
        }

        public void NotifyServerCertificate(TlsServerCertificate ServerCertificate)
        {

            var certList = ServerCertificate.Certificate.GetCertificateList();
            if (certList is null || certList.Length == 0)
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);

            var remoteCertificate = X509CertificateLoader.LoadCertificate(certList[0].GetEncoded());
            var certificateChain  = certList.
                                        Select(certificate => X509CertificateLoader.LoadCertificate(certificate.GetEncoded())).
                                        ToArray();

            // Validate the chain with .NET’s X509Chain
            using var chain = new X509Chain {
                                  ChainPolicy = {
                                      RevocationMode    = X509RevocationMode.   Online,
                                      RevocationFlag    = X509RevocationFlag.   EntireChain,
                                      VerificationFlags = X509VerificationFlags.NoFlag
                                  }
                              };


            foreach (var cert in certificateChain.Skip(1))
                chain.ChainPolicy.ExtraStore.Add(cert);


            var policyErrors = SslPolicyErrors.None;

            // Validate the chain via the leafCertificate
            if (!chain.Build(remoteCertificate))
                policyErrors |= SslPolicyErrors.RemoteCertificateChainErrors;

            if (NTSKETLSClient.ExpectedHostname is not null &&
                !HostnameMatches(remoteCertificate, NTSKETLSClient.ExpectedHostname.ToString()))
            {
                policyErrors |= SslPolicyErrors.RemoteCertificateNameMismatch;
            }

            NTSKETLSClient.SetCertificateInfo(
                remoteCertificate,
                certificateChain,
                policyErrors
            );

            if (remoteCertificateValidator is not null)
            {

                var tlsValidationResult = remoteCertificateValidator(
                                               this,
                                               remoteCertificate,
                                               chain,
                                               NTSKETLSClient,
                                               policyErrors
                                           );

                if (!tlsValidationResult.IsValid)
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);

                return;

            }

            if (policyErrors != SslPolicyErrors.None)
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);

        }

        /// <summary>
        /// Whether the server's certificate was issued for the host this client dialled —
        /// RFC 9525 § 6.3, matching the reference identifier against the presented ones.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The matching itself is <see cref="DNSNamePattern"/>'s. It used to be a dozen lines
        /// here, and it was the wrong dozen lines to own: comparing a wildcard against a host
        /// name is a rule with exactly one correct reading and several plausible wrong ones,
        /// every wrong one accepts a certificate issued for somebody else, and none of them
        /// looks wrong on the page. It belongs somewhere it can be tested once.
        /// </para>
        /// <para>
        /// The subject alternative names are the only names consulted. The Common Name fallback
        /// through GetNameInfo is gone: RFC 9525 § 6.1 dropped it, browsers stopped honouring it
        /// years before that, and a client that keeps it accepts certificates that no
        /// certificate authority may issue any more. It was also worse than it looked here —
        /// GetNameInfo reports one name, so a certificate valid for several was judged on
        /// whichever the platform picked.
        /// </para>
        /// </remarks>
        private static Boolean HostnameMatches(X509Certificate2  Certificate,
                                               String            Hostname)

            => DomainName.TryParse(Hostname, out var hostName, out _) &&
               Certificate.MatchesHostName(hostName);

    }

}
