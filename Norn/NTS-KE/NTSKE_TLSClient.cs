/*
 * Copyright (c) 2010-2025 GraphDefined GmbH <achim.friedland@graphdefined.com>
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

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTP
{

    /// <summary>
    /// The Network Time Security Key Establishment (NTS-KE) TLS client.
    /// </summary>
    public class NTSKE_TLSClient(RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient>? RemoteCertificateValidator = null)

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

            // Export 32 bytes for AES-SIV-CMAC-256:
            NTS_C2S_Key = NTSKEContext.ExportKeyingMaterial(
                "EXPORTER-network-time-security",
                [0x00, 0x00, 0x00, NTSKE_Record.AES_SIV_CMAC_256, 0x00],
                32
            );

            NTS_S2C_Key = NTSKEContext.ExportKeyingMaterial(
                "EXPORTER-network-time-security",
                [0x00, 0x00, 0x00, NTSKE_Record.AES_SIV_CMAC_256, 0x01],
                32
            );

        }

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
            return new ValidatingTlsAuthentication(this, remoteCertificateValidator);
        }

        #endregion

    }


    public class ValidatingTlsAuthentication(NTSKE_TLSClient                                                NTSKETLSClient,
                                             RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient>?  RemoteCertificateValidator   = null) : TlsAuthentication
    {

        #region Data

        private readonly RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient>? remoteCertificateValidator = RemoteCertificateValidator;

        #endregion


        public TlsCredentials GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest certificateRequest)
        {
            // We don't do client-certificate-based auth here:
            return null!;
        }

        public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
        {

            var certList = serverCertificate.Certificate.GetCertificateList();
            if (certList is null || certList.Length == 0)
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);

            var remoteCertificate = X509CertificateLoader.LoadCertificate(certList[0].GetEncoded());

            // Validate the chain with .NET’s X509Chain
            using var chain = new X509Chain {
                                  ChainPolicy = {
                                      RevocationMode    = X509RevocationMode.   Online,
                                      RevocationFlag    = X509RevocationFlag.   EntireChain,
                                      VerificationFlags = X509VerificationFlags.NoFlag
                                  }
                              };


            foreach (var cert in certList.Skip(1))
                chain.ChainPolicy.ExtraStore.Add(X509CertificateLoader.LoadCertificate(cert.GetEncoded()));


            // Use the given custom remoteCertificateValidator
            if (remoteCertificateValidator is not null)
            {

                var x509Certificates = certList.Select(cert => X509CertificateLoader.LoadCertificate(cert.GetEncoded())).ToArray();

                // Validate the certificate using the provided delegate
                var (isValid, errors) = remoteCertificateValidator(
                                            this,
                                            remoteCertificate,
                                            chain,
                                            NTSKETLSClient,
                                            SslPolicyErrors.None
                                        );

                if (!isValid)
                {
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);
                }

                return;

            }

            // Validate the chain via the leafCertificate
            if (!chain.Build(remoteCertificate))
            {
                // Inspect chain.ChainStatus for details if needed
                throw new TlsFatalAlert(AlertDescription.certificate_unknown);
            }

            // Additional checks, e.g. hostname matching
            // if (!HostnameMatches(chain, "expected.host.com"))
            // {
            //     throw new TlsFatalAlert(AlertDescription.certificate_unknown);
            // }

        }

    }

}
