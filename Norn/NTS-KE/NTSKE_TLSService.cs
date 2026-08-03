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

        #region (public    override) NotifyHandshakeComplete()

        public override void NotifyHandshakeComplete()
        {

            base.NotifyHandshakeComplete();

            ExportAllKeys();

        }

        #endregion

        #region ExportKeys(AEADAlgorithm)

        /// <summary>
        /// Derive the C2S and S2C keys for the agreed algorithm, per RFC 8915 § 5.1.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Called once the AEAD has been negotiated, which is necessarily after the handshake:
        /// the algorithm id goes into the exporter context and its key length decides how many
        /// octets are asked for, so the keys cannot be derived before both are known. This used
        /// to happen the moment the handshake completed, with AES-SIV-CMAC-256 written in — which
        /// worked precisely as long as that was the only algorithm on offer.
        /// </para>
        /// <para>
        /// § 5.1 fixes the context as the protocol id (0 for NTPv4), the algorithm id, and a
        /// final octet that is 0 for the client-to-server key and 1 for the other direction.
        /// Those five octets are the only thing separating two keys derived from the same
        /// session.
        /// </para>
        /// </remarks>
        private readonly Dictionary<AEADAlgorithms, (Byte[] C2SKey, Byte[] S2CKey)> exportedKeys = [];


        /// <summary>
        /// Derive the C2S and S2C keys of RFC 8915 section 5.1 for every algorithm this
        /// implementation supports, so that whichever one the records go on to agree is already
        /// available.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Every algorithm, because the exporter can only be used from here. BouncyCastle
        /// discards the exporter secret the moment this callback returns — "Export of key
        /// material only available from NotifyHandshakeComplete()" — and the AEAD is not agreed
        /// until the records have been exchanged, which is necessarily later. Deriving on demand
        /// is the natural design and it is not available.
        /// </para>
        /// <para>
        /// The cost is small and worth stating: three key pairs of at most thirty-two octets
        /// each, of which two are discarded unused. They live as long as this object does, which
        /// is one key exchange.
        /// </para>
        /// <para>
        /// Section 5.1 fixes the context as the protocol id (0 for NTPv4), the algorithm id, and
        /// a final octet that is 0 for the client-to-server key and 1 for the other direction.
        /// Those five octets are the only thing separating the two keys of a session — and the
        /// algorithm id among them is why each algorithm needs its own derivation rather than
        /// one output truncated to different lengths.
        /// </para>
        /// </remarks>
        private void ExportAllKeys()
        {

            // Implemented rather than Supported: the narrower list is what this peer offers,
            // but the other side may name anything from the wider one and be agreed with — and
            // the exporter is unavailable by the time that is known.
            foreach (var algorithm in NTSAEAD.Implemented)
            {

                var keyLength       = NTSAEAD.KeyLength(algorithm)!.Value;
                var algorithmBytes  = algorithm.GetBytes();

                exportedKeys[algorithm] = (
                    m_context.ExportKeyingMaterial(
                        "EXPORTER-network-time-security",
                        [0x00, 0x00, algorithmBytes[0], algorithmBytes[1], 0x00],
                        keyLength
                    ),
                    m_context.ExportKeyingMaterial(
                        "EXPORTER-network-time-security",
                        [0x00, 0x00, algorithmBytes[0], algorithmBytes[1], 0x01],
                        keyLength
                    )
                );

            }

            // The mandatory algorithm's keys are what these properties held before an AEAD could
            // be negotiated at all, and callers that never negotiate still read them.
            (NTS_C2S_Key, NTS_S2C_Key) = exportedKeys[NTSAEAD.Default];

        }

        /// <summary>
        /// The keys for the agreed algorithm.
        /// </summary>
        /// <exception cref="NotSupportedException">
        /// No keys were derived for it, which means it is not one this implementation supports —
        /// and so not one it should have agreed to.
        /// </exception>
        public (Byte[] C2SKey, Byte[] S2CKey) KeysFor(AEADAlgorithms AEADAlgorithm)
        {

            if (!exportedKeys.TryGetValue(AEADAlgorithm, out var keys))
                throw new NotSupportedException(
                          $"No NTS keys were derived for AEAD algorithm {AEADAlgorithm.AsText()} " +
                          $"({(UInt16) AEADAlgorithm}), so it is not one this implementation can use.");

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
