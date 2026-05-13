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

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// TLS information captured during a Network Time Security Key Establishment exchange.
    /// </summary>
    public class NTSKE_TLSInfo(X509Certificate2?             ServerCertificate            = null,
                               IEnumerable<X509Certificate2>? CertificateChain             = null,
                               SslPolicyErrors?              CertificatePolicyErrors      = null,
                               String?                       NegotiatedCipherSuite        = null,
                               Int32?                        NegotiatedCipherSuiteId      = null,
                               String?                       NegotiatedTLSVersion         = null,
                               String?                       NegotiatedApplicationProtocol = null,
                               Int32?                        KeyExchangeAlgorithm         = null)
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
                   KeyExchangeAlgorithm
               );

        #endregion

    }

}
