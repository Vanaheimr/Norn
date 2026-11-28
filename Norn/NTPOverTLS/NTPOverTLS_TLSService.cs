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
using Org.BouncyCastle.Crypto;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using BCX509Certificate     = Org.BouncyCastle.X509.X509Certificate;
using CertificateRequest    = Org.BouncyCastle.Tls.CertificateRequest;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTPOverTLS
{

    /// <summary>
    /// Judges the certificate an NTP-over-TLS client showed: the leaf, the chain built from it
    /// with what the client sent along, and what building that chain found.
    /// </summary>
    internal delegate TLSValidationResult NTPOverTLSClientCertificateJudge(X509Certificate2  Certificate,
                                                                           X509Chain         Chain,
                                                                           SslPolicyErrors   PolicyErrors);


    /// <summary>
    /// The TLS server side of one NTP-over-TLS connection (BSI TR-03109-5 § 6 and § 7).
    /// </summary>
    /// <remarks>
    /// TLS 1.3 and 1.2, no ALPN - the guideline names no protocol identifier, and a client that
    /// offers some is answered without one, as RFC 7301 § 3.2 allows - and, where a judge is
    /// given, a client certificate that is required and judged by it.
    /// </remarks>
    internal sealed class NTPOverTLS_TLSService : DefaultTlsServer
    {

        #region Data

        private readonly BCX509Certificate                   certificate;
        private readonly AsymmetricKeyParameter              privateKey;
        private readonly IReadOnlyList<Byte[]>               encodedChain;
        private readonly NTPOverTLSClientCertificateJudge?   clientCertificateJudge;

        #endregion

        #region Properties

        /// <summary>
        /// The certificate the client showed, where one was asked for and given.
        /// </summary>
        public X509Certificate2?  ClientCertificate      { get; private set; }

        /// <summary>
        /// The TLS version that was negotiated, once the handshake is complete.
        /// </summary>
        public ProtocolVersion?   NegotiatedVersion      { get; private set; }

        /// <summary>
        /// The cipher suite that was negotiated, once the handshake is complete.
        /// </summary>
        public Int32?             NegotiatedCipherSuite  { get; private set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The TLS server of one connection.
        /// </summary>
        /// <param name="Certificate">The server's certificate.</param>
        /// <param name="PrivateKey">Its private key.</param>
        /// <param name="CertificateChain">The intermediates shown after it.</param>
        /// <param name="ClientCertificateJudge">Where given, a client has to show a certificate, and this decides whether it may go on.</param>
        public NTPOverTLS_TLSService(BCX509Certificate                   Certificate,
                                     AsymmetricKeyParameter              PrivateKey,
                                     IEnumerable<BCX509Certificate>?     CertificateChain,
                                     NTPOverTLSClientCertificateJudge?   ClientCertificateJudge)

            : base(new BcTlsCrypto(new SecureRandom()))

        {

            this.certificate             = Certificate;
            this.privateKey              = PrivateKey;
            this.encodedChain            = NTPOverTLSProtocol.EncodedChain(Certificate, CertificateChain);
            this.clientCertificateJudge  = ClientCertificateJudge;

        }

        #endregion


        #region Versions and cipher suites

        /// <summary>
        /// TLS 1.3 and 1.2: REQ.TA.TLS.Handshake.10 makes 1.2 a MUST, .180 the fallback from 1.3.
        /// </summary>
        protected override ProtocolVersion[] GetSupportedVersions()
            => NTPOverTLSProtocol.SupportedVersions;

        protected override Int32[] GetSupportedCipherSuites()
            => TlsUtilities.GetSupportedCipherSuites(Crypto, NTPOverTLSProtocol.CipherSuitesFor(privateKey));

        #endregion

        #region Credentials

        public override TlsCredentials GetCredentials()
            => Signer();

        protected override TlsCredentialedSigner GetECDsaSignerCredentials()
            => Signer();

        protected override TlsCredentialedSigner GetRsaSignerCredentials()
            => Signer();

        private TlsCredentialedSigner Signer()

            => NTPOverTLSProtocol.SignerCredentials(m_context,
                                            (BcTlsCrypto) Crypto,
                                            privateKey,
                                            certificate,
                                            encodedChain,
                                            TlsUtilities.EmptyBytes,
                                            m_context.SecurityParameters.ClientSigAlgs);

        #endregion

        #region Client certificate

        /// <summary>
        /// Ask for a client certificate where one is required, and only there.
        /// </summary>
        public override CertificateRequest? GetCertificateRequest()
        {

            if (clientCertificateJudge is null)
                return null;

            var signatureAlgorithms = TlsUtilities.GetDefaultSupportedSignatureAlgorithms(m_context);

            return TlsUtilities.IsTlsV13(m_context)
                       ? new CertificateRequest(TlsUtilities.EmptyBytes, signatureAlgorithms, null, null)
                       : new CertificateRequest([ ClientCertificateType.ecdsa_sign, ClientCertificateType.rsa_sign ],
                                                signatureAlgorithms,
                                                null);

        }

        /// <summary>
        /// A client that shows no certificate where one is required is refused - in TLS 1.3 with
        /// certificate_required, which RFC 8446 § 4.4.2.4 has for it - and one that shows a
        /// certificate the judge refuses with bad_certificate. REQ.TA.TLS.Handshake.130 has the
        /// handshake end with a fatal alert after an authentication error.
        /// </summary>
        public override void NotifyClientCertificate(Certificate ClientCertificate)
        {

            if (clientCertificateJudge is null)
                return;

            if (ClientCertificate is null || ClientCertificate.IsEmpty)
                throw new TlsFatalAlert(TlsUtilities.IsTlsV13(m_context)
                                            ? AlertDescription.certificate_required
                                            : AlertDescription.handshake_failure);

            var certificates  = ClientCertificate.GetCertificateList().
                                    Select(entry => X509CertificateLoader.LoadCertificate(entry.GetEncoded())).
                                    ToArray();

            var leaf          = certificates[0];

            using var chain   = new X509Chain {
                                    ChainPolicy = ValidatingTlsAuthentication.ChainPolicyFor(AskHere: false)
                                };

            foreach (var intermediate in certificates.Skip(1))
                chain.ChainPolicy.ExtraStore.Add(intermediate);

            var policyErrors  = SslPolicyErrors.None;
            Boolean built;

            try
            {
                built = chain.Build(leaf);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                built = false;
            }

            if (ValidatingTlsAuthentication.ChainErrorsOf(built, chain.ChainStatus.Select(status => status.Status)))
                policyErrors |= SslPolicyErrors.RemoteCertificateChainErrors;

            if (!clientCertificateJudge(leaf, chain, policyErrors).IsValid)
                throw new TlsFatalAlert(AlertDescription.bad_certificate);

            this.ClientCertificate = leaf;

        }

        #endregion

        #region NotifyHandshakeComplete()

        public override void NotifyHandshakeComplete()
        {

            base.NotifyHandshakeComplete();

            NegotiatedVersion      = m_context.SecurityParameters.NegotiatedVersion;
            NegotiatedCipherSuite  = m_context.SecurityParameters.CipherSuite;

        }

        #endregion

    }

}
