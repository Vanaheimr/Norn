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
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using BCX509Certificate     = Org.BouncyCastle.X509.X509Certificate;
using CertificateRequest    = Org.BouncyCastle.Tls.CertificateRequest;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTPOverTLS
{

    /// <summary>
    /// The TLS client side of one NTP-over-TLS connection (BSI TR-03109-5 § 6 and § 7).
    /// </summary>
    /// <remarks>
    /// TLS 1.3 offered first and 1.2 below it (REQ.TA.TLS.Handshake.190), the server named by SNI
    /// when it is known by a name (REQ.TA.TLS.OpenHanSessionAsClient.30), no ALPN, and a client
    /// certificate of one's own where one is given and the server asks for it. The server's
    /// certificate is judged as in NTS-KE: by the validator given, or else by the chain the
    /// platform builds and the name the client connected to.
    /// </remarks>
    public class NTPOverTLS_TLSClient : DefaultTlsClient
    {

        #region Data

        private readonly RemoteTLSServerCertificateValidationHandler<NTPOverTLS_TLSClient>?  remoteCertificateValidator;
        private readonly BCX509Certificate?                                                  clientCertificate;
        private readonly AsymmetricKeyParameter?                                             clientPrivateKey;
        private readonly IReadOnlyList<Byte[]>                                               clientEncodedChain = [];

        #endregion

        #region Properties

        /// <summary>
        /// The name the server's certificate has to be issued for, and the one sent as SNI.
        /// </summary>
        public DomainName?               ExpectedHostname          { get; }

        /// <summary>
        /// The address the server's certificate has to name instead, where the client connected
        /// to a literal address: there is no SNI then, since RFC 6066 § 3 has none for addresses.
        /// </summary>
        public System.Net.IPAddress?     ExpectedIPAddress         { get; }

        /// <summary>
        /// The certificate the server showed.
        /// </summary>
        public X509Certificate2?         ServerCertificate         { get; private set; }

        /// <summary>
        /// The chain the server sent, leaf first.
        /// </summary>
        public IReadOnlyList<X509Certificate2>  ServerCertificateChain  { get; private set; } = [];

        /// <summary>
        /// What judging the server's certificate found.
        /// </summary>
        public SslPolicyErrors?          CertificatePolicyErrors   { get; private set; }

        /// <summary>
        /// Whether the server asked for a client certificate.
        /// </summary>
        public Boolean                   ClientCertificateRequested { get; private set; }

        /// <summary>
        /// Whether one was sent in answer.
        /// </summary>
        public Boolean                   ClientCertificateSent     { get; private set; }

        /// <summary>
        /// The TLS version that was negotiated, e.g. "TLS 1.3".
        /// </summary>
        public String?                   NegotiatedTLSVersion      { get; private set; }

        /// <summary>
        /// The cipher suite that was negotiated.
        /// </summary>
        public String?                   NegotiatedCipherSuite     { get; private set; }

        /// <summary>
        /// The application protocol the server selected - none, unless it took one the client did
        /// not offer.
        /// </summary>
        public String?                   NegotiatedApplicationProtocol { get; private set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The TLS client of one NTP-over-TLS connection.
        /// </summary>
        /// <param name="RemoteCertificateValidator">Judges the server's certificate; by default the platform's chain and the name or address connected to.</param>
        /// <param name="ExpectedHostname">The name of the server.</param>
        /// <param name="ExpectedIPAddress">Or its address, where it was connected to by one.</param>
        /// <param name="ClientCertificate">A certificate to show where the server asks for one.</param>
        /// <param name="ClientPrivateKey">Its private key.</param>
        /// <param name="ClientCertificateChain">Intermediates to show after it.</param>
        public NTPOverTLS_TLSClient(RemoteTLSServerCertificateValidationHandler<NTPOverTLS_TLSClient>?  RemoteCertificateValidator  = null,
                                    DomainName?                                                         ExpectedHostname            = null,
                                    System.Net.IPAddress?                                               ExpectedIPAddress           = null,
                                    BCX509Certificate?                                                  ClientCertificate           = null,
                                    AsymmetricKeyParameter?                                             ClientPrivateKey            = null,
                                    IEnumerable<BCX509Certificate>?                                     ClientCertificateChain      = null)

            : base(new BcTlsCrypto(new SecureRandom()))

        {

            if ((ClientCertificate is null) != (ClientPrivateKey is null))
                throw new ArgumentException("A client certificate and its private key are given together, or neither of them.");

            if (ClientPrivateKey is not null)
                NTSKE_TLSService.ValidatePrivateKey(ClientPrivateKey);

            this.remoteCertificateValidator  = RemoteCertificateValidator;
            this.ExpectedHostname            = ExpectedHostname;
            this.ExpectedIPAddress           = ExpectedIPAddress;
            this.clientCertificate           = ClientCertificate;
            this.clientPrivateKey            = ClientPrivateKey;

            if (ClientCertificate is not null)
                this.clientEncodedChain      = NTPOverTLSProtocol.EncodedChain(ClientCertificate, ClientCertificateChain);

        }

        #endregion


        #region Versions, cipher suites, SNI

        public override ProtocolVersion[] GetProtocolVersions()
            => NTPOverTLSProtocol.SupportedVersions;

        protected override Int32[] GetSupportedCipherSuites()
            => TlsUtilities.GetSupportedCipherSuites(Crypto, NTPOverTLSProtocol.CipherSuitesFor(null));

        /// <summary>
        /// REQ.TA.TLS.OpenHanSessionAsClient.30: a server_name of type host_name, in the DNS
        /// format of RFC 1035 - without the trailing dot, and not for a literal address.
        /// </summary>
        protected override IList<ServerName>? GetSniServerNames()
        {

            if (ExpectedIPAddress is not null)
                return null;

            var host = ExpectedHostname?.ToString().TrimEnd('.').Trim('[', ']');

            if (String.IsNullOrWhiteSpace(host) ||
                System.Net.IPAddress.TryParse(host, out _))
            {
                return null;
            }

            return [ new ServerName(NameType.host_name, System.Text.Encoding.ASCII.GetBytes(host)) ];

        }

        #endregion

        #region NotifyHandshakeComplete()

        public override void NotifyHandshakeComplete()
        {

            base.NotifyHandshakeComplete();

            var securityParameters        = m_context.SecurityParameters;

            NegotiatedTLSVersion          = securityParameters.NegotiatedVersion?.Name;
            NegotiatedCipherSuite         = NTPOverTLSProtocol.DescribeCipherSuite(securityParameters.CipherSuite);
            NegotiatedApplicationProtocol = securityParameters.ApplicationProtocol?.GetUtf8Decoding();

        }

        #endregion

        #region GetAuthentication()

        public override TlsAuthentication GetAuthentication()
            => new Authentication(this);

        #endregion


        #region (private) Authentication

        private sealed class Authentication(NTPOverTLS_TLSClient Client) : TlsAuthentication
        {

            public TlsCredentials? GetClientCredentials(CertificateRequest CertificateRequest)
            {

                Client.ClientCertificateRequested = true;

                if (Client.clientCertificate is null ||
                    Client.clientPrivateKey  is null)
                {
                    return null;
                }

                var credentials = NTPOverTLSProtocol.SignerCredentials(Client.m_context,
                                                               (BcTlsCrypto) Client.Crypto,
                                                               Client.clientPrivateKey,
                                                               Client.clientCertificate,
                                                               Client.clientEncodedChain,
                                                               CertificateRequest.GetCertificateRequestContext() ?? TlsUtilities.EmptyBytes,
                                                               CertificateRequest.SupportedSignatureAlgorithms);

                Client.ClientCertificateSent = true;

                return credentials;

            }

            public void NotifyServerCertificate(TlsServerCertificate ServerCertificate)
            {

                var list = ServerCertificate.Certificate.GetCertificateList();

                if (list is null || list.Length == 0)
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);

                var certificates  = list.Select(certificate => X509CertificateLoader.LoadCertificate(certificate.GetEncoded())).ToArray();
                var leaf          = certificates[0];

                Client.ServerCertificate       = leaf;
                Client.ServerCertificateChain  = certificates;

                using var chain   = new X509Chain {
                                        ChainPolicy = ValidatingTlsAuthentication.ChainPolicyFor(AskHere: Client.remoteCertificateValidator is null)
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

                if (Client.ExpectedIPAddress is not null)
                {
                    if (!leaf.MatchesIPAddress(Client.ExpectedIPAddress))
                        policyErrors |= SslPolicyErrors.RemoteCertificateNameMismatch;
                }
                else if (Client.ExpectedHostname is not null &&
                         !HostnameMatches(leaf, Client.ExpectedHostname))
                {
                    policyErrors |= SslPolicyErrors.RemoteCertificateNameMismatch;
                }

                Client.CertificatePolicyErrors = policyErrors;

                // REQ.TA.TLS.Handshake.130: a certificate that does not validate ends the
                // handshake with a fatal alert.
                var valid = Client.remoteCertificateValidator is not null
                                ? Client.remoteCertificateValidator(this, leaf, chain, Client, policyErrors).IsValid
                                : policyErrors == SslPolicyErrors.None;

                if (!valid)
                    throw new TlsFatalAlert(AlertDescription.certificate_unknown);

            }

            private static Boolean HostnameMatches(X509Certificate2  Certificate,
                                                   DomainName        Hostname)
            {

                var trimmed = Hostname.ToString().TrimEnd('.').Trim('[', ']');

                return System.Net.IPAddress.TryParse(trimmed, out var address)
                           ? Certificate.MatchesIPAddress(address)
                           : Certificate.MatchesHostName(Hostname);

            }

        }

        #endregion

    }

}
