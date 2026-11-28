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
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.X509;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTPOverTLS
{

    /// <summary>
    /// NTP over TLS after chapter 7 of BSI TR-03109-5 (version 1.0, 2023-11-24): an NTPv4
    /// client/server exchange of RFC 5905, carried in a TLS connection instead of UDP datagrams.
    /// </summary>
    /// <remarks>
    /// <para>
    /// § 7.1.1 lists what differs from RFC 5905: no NTP authentication, since TLS authenticates
    /// both ends by their certificates; no extension fields; no UDP header; a transport port of
    /// its own; a connection-oriented transport; the client/server mode alone; and no obligation
    /// to process kiss codes. What is left on the wire is the bare 48-octet NTP header of RFC 5905
    /// Figure 8, once from the client and once in answer - REQ.TA.NTP.BuildRequest.30: "Der
    /// NTP-Request hat eine Länge von 48 Bytes". There is no length prefix: both ends know it.
    /// </para>
    /// <para>
    /// How the connection itself is to be set up and secured is not part of chapter 7. It is
    /// chapter 6's: TLS 1.2 is a MUST (REQ.TA.TLS.Handshake.10), TLS 1.3 a SHOULD
    /// (REQ.TA.TLS.OpenHanSessionAsClient.10) with fallback to 1.2 on both sides
    /// (REQ.TA.TLS.Handshake.180/190), and the client names the server by SNI
    /// (REQ.TA.TLS.OpenHanSessionAsClient.30). Neither chapter says how many requests one
    /// connection may carry; Norn's server answers as many as come until the client closes or
    /// falls silent, and Norn's client sends one per connection.
    /// </para>
    /// <para>
    /// There is no NTPv5 over TLS. The guideline knows NTPv4 alone, and REQ.TA.NTP.BuildRequest.10
    /// has the request be "NTPMessage der Version 4".
    /// </para>
    /// </remarks>
    public static class NTPOverTLSProtocol
    {

        /// <summary>
        /// The length of every message in either direction: the NTP header of RFC 5905 Figure 8,
        /// with neither extension fields nor a MAC.
        /// </summary>
        public const Int32 PacketLength = 48;

        /// <summary>
        /// The port a client connects to unless told otherwise. TR-03109-5 fixes none; the
        /// smart meter gateways it was written for listen on 443.
        /// </summary>
        public static IPPort DefaultPort { get; } = IPPort.Parse(443);

        /// <summary>
        /// The TLS 1.3 cipher suites, the AES-GCM ones of TR-03116-4.
        /// </summary>
        internal static readonly Int32[] TLS13CipherSuites = [
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_AES_128_GCM_SHA256
        ];

        /// <summary>
        /// The TLS 1.2 cipher suites for a server key of ECDSA or EdDSA: ECDHE, with AES in GCM
        /// and, for the backward compatibility § 6.3.1.5 note 3 asks for, in CBC with
        /// encrypt_then_mac.
        /// </summary>
        internal static readonly Int32[] TLS12ECDSACipherSuites = [
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        ];

        /// <summary>
        /// The same four for a server key of RSA.
        /// </summary>
        internal static readonly Int32[] TLS12RSACipherSuites = [
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        ];

        /// <summary>
        /// The cipher suites that can be negotiated with the given server key - or, for a client,
        /// which does not know the server's key yet, all of them.
        /// </summary>
        /// <remarks>
        /// A TLS 1.2 suite names the kind of key the server signs its key exchange with, and
        /// BouncyCastle picks one the client offered without asking what key there is: a server
        /// of an ECDSA key that offered ECDHE_RSA would select it for a client that prefers it,
        /// and fail the handshake a moment later.
        /// </remarks>
        internal static Int32[] CipherSuitesFor(AsymmetricKeyParameter? ServerKey)

            => ServerKey switch {
                   null                    => [ .. TLS13CipherSuites, .. TLS12ECDSACipherSuites, .. TLS12RSACipherSuites ],
                   RsaKeyParameters        => [ .. TLS13CipherSuites, .. TLS12RSACipherSuites ],
                   _                       => [ .. TLS13CipherSuites, .. TLS12ECDSACipherSuites ]
               };

        /// <summary>
        /// TLS 1.3, and TLS 1.2 below it.
        /// </summary>
        internal static ProtocolVersion[] SupportedVersions
            => ProtocolVersion.TLSv13.DownTo(ProtocolVersion.TLSv12);


        #region (internal) SignerCredentials(Context, Crypto, PrivateKey, Leaf, EncodedChain, CertificateRequestContext, PeerSignatureAlgorithms)

        /// <summary>
        /// What one end of the connection signs its part of the handshake with: its certificate
        /// chain and its private key, for the TLS version that was negotiated.
        /// </summary>
        /// <param name="Context">The TLS context, which knows the version.</param>
        /// <param name="Crypto">The crypto provider of the peer.</param>
        /// <param name="PrivateKey">The private key (ECDSA P-256/P-384/P-521, RSA, Ed25519 or Ed448).</param>
        /// <param name="Leaf">The certificate of that key.</param>
        /// <param name="EncodedChain">The leaf first, then any intermediates, DER-encoded.</param>
        /// <param name="CertificateRequestContext">For a TLS 1.3 client certificate, the context of the server's request, which the Certificate message has to echo; empty otherwise.</param>
        /// <param name="PeerSignatureAlgorithms">The signature algorithms the other end said it accepts.</param>
        internal static TlsCredentialedSigner SignerCredentials(TlsContext                         Context,
                                                                BcTlsCrypto                        Crypto,
                                                                AsymmetricKeyParameter             PrivateKey,
                                                                X509Certificate                    Leaf,
                                                                IReadOnlyList<Byte[]>              EncodedChain,
                                                                Byte[]                             CertificateRequestContext,
                                                                IList<SignatureAndHashAlgorithm>?  PeerSignatureAlgorithms)
        {

            var tls13         = TlsUtilities.IsTlsV13(Context);
            var cryptoParams  = new TlsCryptoParameters(Context);

            var certificate   = tls13
                                    ? new Certificate(CertificateRequestContext,
                                                      [.. EncodedChain.Select(encoded => new CertificateEntry(new BcTlsCertificate(Crypto, encoded), null))])
                                    : new Certificate([.. EncodedChain.Select(encoded => (TlsCertificate) new BcTlsCertificate(Crypto, encoded))]);

            switch (PrivateKey)
            {

                case ECPrivateKeyParameters ecKey:
                {

                    var scheme = NTSKE_TLSService.ResolveECDsaSignatureScheme(ecKey);
                    NTSKE_TLSService.EnsureClientSupportsSignatureScheme(PeerSignatureAlgorithms, scheme);

                    // In TLS 1.3 the scheme ties the hash to the curve. TLS 1.2 says ecdsa with
                    // some hash, and the hash of the curve's own strength is the one offered.
                    return tls13
                               ? new DefaultTlsCredentialedSigner(cryptoParams,
                                                                  new BcTlsECDsa13Signer(Crypto, ecKey, scheme),
                                                                  certificate,
                                                                  SignatureScheme.GetSignatureAndHashAlgorithm(scheme))
                               : new DefaultTlsCredentialedSigner(cryptoParams,
                                                                  new BcTlsECDsaSigner(Crypto, ecKey),
                                                                  certificate,
                                                                  SignatureScheme.GetSignatureAndHashAlgorithm(scheme));

                }

                case RsaKeyParameters rsaKey:
                {

                    // RSA-PSS wherever the other end takes it, as TLS 1.3 requires. A TLS 1.2
                    // peer that offers no PSS scheme gets PKCS #1 v1.5 with SHA-256, which is
                    // what RFC 5246 has; a certificate of an id-RSASSA-PSS key allows PSS alone.
                    var isPssCertificate  = PkcsObjectIdentifiers.IdRsassaPss.Equals(Leaf.CertificateStructure.SubjectPublicKeyInfo.Algorithm.Algorithm);
                    var offersPss         = PeerSignatureAlgorithms is null ||
                                            PeerSignatureAlgorithms.Count == 0 ||
                                            PeerSignatureAlgorithms.Any(algorithm => SignatureScheme.IsRsaPss(SignatureScheme.From(algorithm)));

                    if (tls13 || offersPss || isPssCertificate)
                    {

                        var scheme = NTSKE_TLSService.SelectRsaPssSignatureScheme(Leaf, PeerSignatureAlgorithms);

                        return new DefaultTlsCredentialedSigner(cryptoParams,
                                                                new BcTlsRsaPssSigner(Crypto, rsaKey, scheme),
                                                                certificate,
                                                                SignatureScheme.GetSignatureAndHashAlgorithm(scheme));

                    }

                    var pkcs1 = new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.rsa);

                    if (PeerSignatureAlgorithms is not null &&
                        PeerSignatureAlgorithms.Count > 0 &&
                        !PeerSignatureAlgorithms.Contains(pkcs1))
                    {
                        throw new TlsFatalAlert(AlertDescription.handshake_failure);
                    }

                    return new DefaultTlsCredentialedSigner(cryptoParams,
                                                            new BcTlsRsaSigner(Crypto, rsaKey),
                                                            certificate,
                                                            pkcs1);

                }

                case Ed25519PrivateKeyParameters ed25519Key:
                    NTSKE_TLSService.EnsureClientSupportsSignatureScheme(PeerSignatureAlgorithms, SignatureScheme.ed25519);
                    return new DefaultTlsCredentialedSigner(cryptoParams,
                                                            new BcTlsEd25519Signer(Crypto, ed25519Key),
                                                            certificate,
                                                            SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.ed25519));

                case Ed448PrivateKeyParameters ed448Key:
                    NTSKE_TLSService.EnsureClientSupportsSignatureScheme(PeerSignatureAlgorithms, SignatureScheme.ed448);
                    return new DefaultTlsCredentialedSigner(cryptoParams,
                                                            new BcTlsEd448Signer(Crypto, ed448Key),
                                                            certificate,
                                                            SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.ed448));

                default:
                    throw new TlsFatalAlert(AlertDescription.internal_error);

            }

        }

        #endregion

        #region (internal) EncodedChain(Leaf, Intermediates)

        /// <summary>
        /// The leaf and the intermediates, DER-encoded, leaf first and none twice: a chain
        /// given as [leaf, intermediate, ...] is taken as well as one of the intermediates alone.
        /// </summary>
        internal static IReadOnlyList<Byte[]> EncodedChain(X509Certificate                Leaf,
                                                           IEnumerable<X509Certificate>?  Intermediates)
        {

            var leafEncoded = Leaf.GetEncoded();
            var encoded     = new List<Byte[]> { leafEncoded };

            foreach (var intermediate in Intermediates ?? [])
            {

                var bytes = intermediate.GetEncoded();

                if (!bytes.AsSpan().SequenceEqual(leafEncoded))
                    encoded.Add(bytes);

            }

            return encoded;

        }

        #endregion

        #region (internal) Describe(CipherSuite)

        /// <summary>
        /// The name of one of the cipher suites this transport negotiates.
        /// </summary>
        internal static String DescribeCipherSuite(Int32 CipherSuiteId)

            => CipherSuiteId switch {
                   CipherSuite.TLS_AES_256_GCM_SHA384                   => "TLS_AES_256_GCM_SHA384",
                   CipherSuite.TLS_AES_128_GCM_SHA256                   => "TLS_AES_128_GCM_SHA256",
                   CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                   CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                   CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384  => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                   CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256  => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384    => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384    => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256    => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                   _                                                    => $"0x{CipherSuiteId:X4}"
               };

        #endregion

    }

}
