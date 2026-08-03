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

using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;

using org.GraphDefined.Vanaheimr.Illias;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// A Network Time Secure Key Establishment (NTS-KE) TLS service.
    /// </summary>
    internal class NTSKE_TLSService : DefaultTlsServer
    {

        #region Data

        // Just for TLS optimization!
        private readonly Byte[] encodedCertificate;

        #endregion

        #region Properties

        /// <summary>
        /// The used TLS certificate.
        /// </summary>
        public X509Certificate         Certificate    { get; }

        /// <summary>
        /// The used TLS private key.
        /// </summary>
        public ECPrivateKeyParameters  PrivateKey     { get; }

        /// <summary>
        /// The optional X.509 subject name to use for new certificates.
        /// </summary>
        public String?                 SubjectName    { get; }


        /// <summary>
        /// The NTP-KE Client-2-Server Key
        /// </summary>
        public Byte[]?                 NTS_C2S_Key    { get; private set; }

        /// <summary>
        /// The NTP-KE Server-2-Client Key
        /// </summary>
        public Byte[]?                 NTS_S2C_Key    { get; private set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new NTS-KE TLS service.
        /// </summary>
        /// <param name="Certificate">The TLS certificate to use.</param>
        /// <param name="PrivateKey">The private key to use.</param>
        /// <param name="SubjectName">The optional X.509 subject name to use for new certificates.</param>
        /// <param name="TimeProvider">The optional clock deciding a generated certificate's validity period.</param>
        public NTSKE_TLSService(X509Certificate?         Certificate    = null,
                                ECPrivateKeyParameters?  PrivateKey     = null,
                                String?                  SubjectName    = null,
                                TimeProvider?            TimeProvider   = null)

            : base(
                  new BcTlsCrypto(
                      new SecureRandom()
                  )
              )

        {

            if ((Certificate is null) != (PrivateKey is null))
                throw new ArgumentException("TLS certificate and private key must be provided together.");

            if (Certificate is not null &&
                PrivateKey  is not null)
            {

                this.Certificate  = Certificate;
                this.PrivateKey   = PrivateKey;
                this.SubjectName  = SubjectName;

            }
            else
            {

                (this.Certificate, this.PrivateKey)  = GenerateSelfSignedServerCertificate(
                                                           SubjectName.IsNotNullOrEmpty()
                                                               ? $"CN={SubjectName}"
                                                               : "CN=ntpKE.example.org",
                                                           [ "ntpKE1.example.org", "ntpKE2.example.org" ],
                                                           TimeProvider
                                                       );

                this.SubjectName = SubjectName;

            }

            this.encodedCertificate              = this.Certificate.GetEncoded();

        }

        #endregion


        #region (protected override) GetProtocolNames()

        /// <summary>
        /// Offer the "ntske/1" application protocol, so it is selected and echoed back in the
        /// ServerHello.
        ///
        /// RFC 8915 § 4 requires NTS-KE to run under this ALPN identifier. Without it the
        /// server completes the TLS handshake but never tells the client which protocol was
        /// chosen, and a client that checks — chrony's does — has to treat the connection as
        /// something other than NTS-KE and give up. Returning the name here also makes
        /// BouncyCastle fail the handshake when a client offers ALPN with no overlap, rather
        /// than proceeding on an unstated protocol.
        /// </summary>
        protected override IList<ProtocolName> GetProtocolNames()
            => [ ProtocolName.Ntske_1 ];

        #endregion

        #region (public    override) ProcessClientExtensions(ClientExtensions)

        /// <summary>
        /// Refuse a client that offered no ALPN extension at all.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <see cref="GetProtocolNames"/> already makes BouncyCastle fail the handshake when a
        /// client offers ALPN and none of it is <c>ntske/1</c>. It does nothing about a client
        /// that offers no ALPN extension at all: RFC 7301 lets a server stay silent about a
        /// negotiation it was never asked for, so the handshake completed and this server went on
        /// to hand out cookies to a peer that never said it was doing NTS.
        /// </para>
        /// <para>
        /// Those two cases deserve the same answer. RFC 8915 § 4 describes the exchange as one
        /// "with the client offering (via an ALPN extension), and the server accepting, an
        /// application-layer protocol of ntske/1", and § 3 makes support for the extension
        /// "REQUIRED for interoperability" — a client that does not offer it is not an NTS-KE
        /// client, whether it offered the wrong thing or nothing.
        /// </para>
        /// <para>
        /// chrony does the same and checks it on both sides of the connection: its
        /// <c>check_alpn</c> compares the selected protocol by name after every handshake, client
        /// and server alike, and drops the session when it does not match. This refuses earlier
        /// than that — during the ClientHello, before a certificate is signed or a key derived —
        /// and with the alert RFC 7301 § 3.2 defines for having no protocol in common, which is
        /// the one BouncyCastle already sends for the neighbouring case.
        /// </para>
        /// </remarks>
        public override void ProcessClientExtensions(IDictionary<Int32, Byte[]> ClientExtensions)
        {

            base.ProcessClientExtensions(ClientExtensions);

            if (ClientExtensions is null ||
                TlsExtensionsUtilities.GetAlpnExtensionClient(ClientExtensions) is null)
            {
                throw new TlsFatalAlert(AlertDescription.no_application_protocol);
            }

        }

        #endregion

        #region (public    override) NotifyHandshakeComplete()

        public override void NotifyHandshakeComplete()
        {

            base.NotifyHandshakeComplete();

            ExportAllKeys();

        }

        #endregion

        #region ExportAllKeys() / KeysFor(AEADAlgorithm, CompliantExporterContext = true)

        /// <summary>
        /// Every key pair this key exchange could still turn out to need, derived from inside the
        /// handshake-complete callback because that is the only place BouncyCastle allows it.
        /// </summary>
        private NTSKE_ExportedKeys? exportedKeys;


        private void ExportAllKeys()
        {

            exportedKeys = NTSKE_ExportedKeys.ExportAll(m_context);

            // The mandatory algorithm's keys are what these properties held before an AEAD could
            // be negotiated at all, and callers that never negotiate still read them.
            (NTS_C2S_Key, NTS_S2C_Key) = exportedKeys.For(NTSAEAD.Default);

        }

        /// <summary>
        /// The keys for the agreed algorithm.
        /// </summary>
        /// <param name="AEADAlgorithm">The AEAD algorithm the key exchange settled on.</param>
        /// <param name="CompliantExporterContext">
        /// Whether the client asked for RFC 8915 § 5.1's context by sending the Compliant
        /// AES-128-GCM-SIV Exporter Context record. Ignored for every other algorithm.
        /// </param>
        /// <exception cref="NotSupportedException">
        /// No keys were derived for it, which means it is not one this implementation supports —
        /// and so not one it should have agreed to.
        /// </exception>
        public (Byte[] C2SKey, Byte[] S2CKey) KeysFor(AEADAlgorithms  AEADAlgorithm,
                                                      Boolean         CompliantExporterContext   = true)
        {

            if (exportedKeys is null)
                throw new NotSupportedException("The TLS handshake has not completed, so no NTS keys have been derived yet.");

            var keys = exportedKeys.For(AEADAlgorithm, CompliantExporterContext);

            NTS_C2S_Key = keys.C2SKey;
            NTS_S2C_Key = keys.S2CKey;

            return keys;

        }

        #endregion

        #region (public    override) GetCredentials()

        public override TlsCredentials GetCredentials()
        {

            //int keyExchangeAlgorithm = m_context.SecurityParameters.KeyExchangeAlgorithm;

            //switch (keyExchangeAlgorithm)
            //{
            //    case KeyExchangeAlgorithm.DHE_DSS:
            //        return GetDsaSignerCredentials();

            //    case KeyExchangeAlgorithm.ECDHE_ECDSA:
                    return GetECDsaSignerCredentials();

            //    case KeyExchangeAlgorithm.DHE_RSA:
            //    case KeyExchangeAlgorithm.ECDHE_RSA:
            //        return GetRsaSignerCredentials();

            //    case KeyExchangeAlgorithm.RSA:
            //        return GetRsaEncryptionCredentials();

            //    default:
            //        // Note: internal error here; selected a key exchange we don't implement!
            //        throw new TlsFatalAlert(AlertDescription.internal_error);
            //}

        }

        #endregion

        #region (protected override) GetECDsaSignerCredentials()

        protected override TlsCredentialedSigner GetECDsaSignerCredentials()
        {

            var certificateEntry    = new CertificateEntry(new BcTlsCertificate((BcTlsCrypto) Crypto, encodedCertificate), null);
            var certificateChain    = new Org.BouncyCastle.Tls.Certificate(TlsUtilities.EmptyBytes, [ certificateEntry ]);

            var signatureAlgorithm  = new SignatureAndHashAlgorithm(
                                          HashAlgorithm.sha256,
                                          SignatureAlgorithm.ecdsa
                                      );

            return new DefaultTlsCredentialedSigner(
                       new TlsCryptoParameters(m_context),
                       new BcTlsECDsaSigner((BcTlsCrypto) Crypto, PrivateKey),
                       certificateChain,
                       signatureAlgorithm
                   );

        }

        #endregion


        #region GenerateSelfSignedServerCertificate(SubjectName)

        /// <summary>
        /// Generates a TLS server certificate and ECC private key.
        /// </summary>
        /// <param name="SubjectName">The X.509 subject name to use for the new certificate.</param>
        /// <param name="SubjectAlternativeNames">Optional enumeration of subject alternative DNS names.</param>
        /// <param name="TimeProvider">The optional clock the validity period is measured from.</param>
        public static (X509Certificate         Certificate,
                       ECPrivateKeyParameters  PrivateKey)
            GenerateSelfSignedServerCertificate(String                SubjectName,
                                                IEnumerable<String>?  SubjectAlternativeNames   = null,
                                                TimeProvider?         TimeProvider              = null)

        {

            var randomGenerator     = new CryptoApiRandomGenerator();
            var random              = new SecureRandom(randomGenerator);
            var ecKeyPairGenerator  = new ECKeyPairGenerator("ECDSA");

            // Seeded from the curve's OID, not from an ECDomainParameters assembled out of the
            // curve's components. The latter makes BouncyCastle encode the full curve
            // specification into the certificate's SubjectPublicKeyInfo as explicit EC
            // parameters — 335 octets rather than 91 — and Windows' SChannel/CNG only accepts
            // named curves. A certificate carrying explicit parameters is rejected outright
            // with CRYPT_E_ASN1_BADTAG, so no .NET SslStream client can complete the
            // handshake, even though BouncyCastle and GnuTLS both accept it.
            ecKeyPairGenerator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, random));

            var keyPair             = ecKeyPairGenerator.GenerateKeyPair();

            var certGenerator       = new X509V3CertificateGenerator();

            certGenerator.SetSerialNumber(new BigInteger(128, random));

            certGenerator.SetSubjectDN   (new X509Name(SubjectName));
            certGenerator.SetIssuerDN    (new X509Name(SubjectName));  // self-signed!

            // One clock read for both bounds, so a certificate cannot be issued with a validity
            // period that straddles two different readings.
            var now = TimeProvider?.GetUtcNow() ?? Timestamp.Now;

            certGenerator.SetNotBefore   (now.AddDays(-1).UtcDateTime);
            certGenerator.SetNotAfter    (now.AddDays(30).UtcDateTime);

            certGenerator.SetPublicKey   (keyPair.Public);

            certGenerator.AddExtension(
                X509Extensions.BasicConstraints,
                true,
                new BasicConstraints(false)
            );

            certGenerator.AddExtension(
                X509Extensions.KeyUsage,
                true,
                new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyAgreement)
            );

            certGenerator.AddExtension(
                X509Extensions.ExtendedKeyUsage,
                false,
                new ExtendedKeyUsage([ KeyPurposeID.id_kp_serverAuth ])
            );

            if (SubjectAlternativeNames?.Any() == true)
            {

                var generalNames = new List<Asn1Encodable>();
                foreach (var name in SubjectAlternativeNames)
                {
                    generalNames.Add(new GeneralName(GeneralName.DnsName, name));
                }

                certGenerator.AddExtension(
                    X509Extensions.SubjectAlternativeName,
                    false,
                    new DerSequence(generalNames.ToArray())
                );

            }

            var signedCertificate = certGenerator.Generate(
                                        new Asn1SignatureFactory(
                                            "SHA256WithECDSA",
                                            keyPair.Private,
                                            random
                                        )
                                    );

            return (
                signedCertificate,
                (ECPrivateKeyParameters) keyPair.Private
            );

        }

        #endregion


    }

}
