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

using org.GraphDefined.Vanaheimr.Hermod.DNS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// TLS information captured during a Network Time Security Key Establishment exchange.
    /// </summary>
    /// <remarks>
    /// What the validation of the server's certificate found is kept whichever way it went,
    /// and before anything is decided on it: an exchange refused over its certificate is the
    /// one somebody most needs to be told the certificate of.
    /// </remarks>
    public class NTSKE_TLSInfo(X509Certificate2?                  ServerCertificate             = null,
                               IEnumerable<X509Certificate2>?     CertificateChain              = null,
                               SslPolicyErrors?                   CertificatePolicyErrors       = null,
                               String?                            NegotiatedCipherSuite         = null,
                               Int32?                             NegotiatedCipherSuiteId       = null,
                               String?                            NegotiatedTLSVersion          = null,
                               String?                            NegotiatedApplicationProtocol = null,
                               Int32?                             KeyExchangeAlgorithm          = null,
                               IEnumerable<X509Certificate2>?     ValidatedChain                = null,
                               IEnumerable<X509ChainStatusFlags>? ChainStatus                   = null,
                               DomainName?                        CheckedHostname               = null,
                               X509RevocationMode?                RevocationMode                = null)
    {

        #region Properties

        /// <summary>
        /// The leaf server certificate.
        /// </summary>
        public X509Certificate2?             ServerCertificate             { get; } = ServerCertificate;

        /// <summary>
        /// The certificate chain sent by the server.
        /// </summary>
        public IReadOnlyList<X509Certificate2> CertificateChain            { get; } = [.. CertificateChain ?? []];

        /// <summary>
        /// Certificate policy errors observed during default validation.
        /// </summary>
        public SslPolicyErrors?              CertificatePolicyErrors       { get; } = CertificatePolicyErrors;

        /// <summary>
        /// The negotiated TLS cipher suite name.
        /// </summary>
        public String?                       NegotiatedCipherSuite         { get; } = NegotiatedCipherSuite;

        /// <summary>
        /// The negotiated TLS cipher suite numeric identifier.
        /// </summary>
        public Int32?                        NegotiatedCipherSuiteId       { get; } = NegotiatedCipherSuiteId;

        /// <summary>
        /// The negotiated TLS protocol version.
        /// </summary>
        public String?                       NegotiatedTLSVersion          { get; } = NegotiatedTLSVersion;

        /// <summary>
        /// The negotiated ALPN application protocol.
        /// </summary>
        public String?                       NegotiatedApplicationProtocol { get; } = NegotiatedApplicationProtocol;

        /// <summary>
        /// The negotiated TLS key exchange algorithm identifier.
        /// </summary>
        public Int32?                        KeyExchangeAlgorithm          { get; } = KeyExchangeAlgorithm;

        /// <summary>
        /// The chain as this client built it from the server's certificate: the server's own
        /// first, and last the certificate it ended at - a root this machine trusts when the
        /// validation went well.
        /// </summary>
        /// <remarks>
        /// Not what the server sent, which is <see cref="CertificateChain"/>: a server usually
        /// leaves its root out, and may send a cross-signed one that is not where the chain
        /// ends here. The root this ends at is the one a pinned root is compared with, and its
        /// validity counts as much as the server certificate's.
        /// </remarks>
        public IReadOnlyList<X509Certificate2> ValidatedChain              { get; } = [.. ValidatedChain ?? []];

        /// <summary>
        /// What building that chain found wrong with it - an untrusted root, a certificate out
        /// of its validity, a revocation that could not be checked - and nothing when nothing
        /// was.
        /// </summary>
        public IReadOnlyList<X509ChainStatusFlags> ChainStatus             { get; } = [.. ChainStatus ?? []];

        /// <summary>
        /// The name the certificate was checked against, or null when it was checked against
        /// none.
        /// </summary>
        public DomainName?                   CheckedHostname               { get; } = CheckedHostname;

        /// <summary>
        /// How revocation was checked while the chain was built.
        /// </summary>
        public X509RevocationMode?           RevocationMode                { get; } = RevocationMode;

        #endregion

        #region WithHandshakeInfo(...)

        internal NTSKE_TLSInfo WithHandshakeInfo(String?  NegotiatedCipherSuite,
                                                 Int32?   NegotiatedCipherSuiteId,
                                                 String?  NegotiatedTLSVersion,
                                                 String?  NegotiatedApplicationProtocol,
                                                 Int32?   KeyExchangeAlgorithm)

            => new (
                   ServerCertificate,
                   CertificateChain,
                   CertificatePolicyErrors,
                   NegotiatedCipherSuite,
                   NegotiatedCipherSuiteId,
                   NegotiatedTLSVersion,
                   NegotiatedApplicationProtocol,
                   KeyExchangeAlgorithm,
                   ValidatedChain,
                   ChainStatus,
                   CheckedHostname,
                   RevocationMode
               );

        #endregion

    }

}
