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

using System.Diagnostics.CodeAnalysis;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTP
{

    public class NTSSignedResponseExtension : NTPExtension
    {

        #region Properties

        /// <summary>
        /// The algorithm used to sign the response.
        /// </summary>
        public UInt16  KeyId        { get; }

        /// <summary>
        /// The signature of the response.
        /// </summary>
        public Byte[]  Signature    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new Authenticator and Encrypted extension.
        /// </summary>
        /// <param name="KeyId">The key used to sign the response.</param>
        /// <param name="Signature">The signature of the response.</param>
        /// <param name="Authenticated">Whether the extension is/was authenticated.</param>
        /// <param name="Encrypted">Whether the extension is/was encrypted.</param>
        public NTSSignedResponseExtension(UInt16   KeyId,
                                          Byte[]   Signature,
                                          Boolean  Authenticated   = false,
                                          Boolean  Encrypted       = false)

            : base(ExtensionTypes.NTSSignedResponse,
                   new Byte[4 + ((Signature.Length + 3) & ~3)],
                   Authenticated,
                   Encrypted)

        {

            this.KeyId           = KeyId;
            this.Signature       = Signature;

            var signatureLength  = Signature.Length;

            Value[0] = (Byte) ((KeyId           >> 8) & 0xff);
            Value[1] = (Byte)  (KeyId                 & 0xff);

            Value[2] = (Byte) ((signatureLength >> 8) & 0xff);
            Value[3] = (Byte)  (signatureLength       & 0xff);

            Buffer.BlockCopy(Signature, 0, Value, 4, signatureLength);

        }

        #endregion


        public static Boolean TryParse(Byte[]                                                Data,
                                       [NotNullWhen(true)]  out NTSSignedResponseExtension?  NTSSignedResponseExtension,
                                       [NotNullWhen(false)] out String?                      ErrorResponse,
                                       Boolean                                               Authenticated   = false,
                                       Boolean                                               Encrypted       = false)
        {

            try
            {

                ErrorResponse               = null;
                NTSSignedResponseExtension  = null;

                if (Data is null || Data.Length < 4)
                {
                    ErrorResponse = "NTS Signed Response extension value is null or too short!";
                    return false;
                }

                var keyId                   = (UInt16) ((Data[0] << 8) | Data[1]);
                var signatureLength         = (UInt16) ((Data[2] << 8) | Data[3]);

                var signature               = new Byte[signatureLength];
                if (signatureLength > 0)
                    Buffer.BlockCopy(Data, 4, signature, 0, signatureLength);

                NTSSignedResponseExtension  = new NTSSignedResponseExtension(
                                                  keyId,
                                                  signature
                                              );

                return true;

            }
            catch (Exception e)
            {
                ErrorResponse               = e.Message;
                NTSSignedResponseExtension  = null;
                return false;
            }

        }


        public Boolean Verify(NTPPacket NTPResponse, UInt16 KeyId)
        {

            var data            = new NTPPacket(
                                      NTPResponse,
                                      NTPResponse.Extensions.Where(e => e is not NTSCookieExtension && e is not NTSSignedResponseExtension)
                                  ).ToByteArray();

            var ellipticCurve   = SecNamedCurves.GetByName("secp256r1");

            var domainParams    = new ECDomainParameters(
                                        ellipticCurve.Curve,
                                        ellipticCurve.G,
                                        ellipticCurve.N,
                                        ellipticCurve.H
                                    );

            var publicKey       = ParsePublicKeyBase64(domainParams, "BNJ9BLZTcAeuPMHDDDXA0RiVNse8WH4b+/r/bA9HhDsDtTSBsrvmjbnA3w3JlC7ipvhHEkdGbFEIH+ZT0ZEekTA=");

            var verifier = SignerUtilities.GetSigner("SHA-256withECDSA");
            verifier.Init(false, publicKey);
            verifier.BlockUpdate(data);
            return verifier.VerifySignature(Signature);

        }



        #region Sign(KeyId, Data, PrivateKey = null)

        /// <summary>
        /// Create a "NTS Signed Response Extension Fields" extension (type=0x0404)
        /// </summary>
        /// <param name="Data">An array of bytes to be signed.</param>
        /// <param name="PrivateKey">The private key to sign the response.</param>
        public static NTSSignedResponseExtension

            Sign(UInt16                   KeyId,
                 Byte[]                   Data,
                 ECPrivateKeyParameters?  PrivateKey   = null)

        {

            var ellipticCurve   = SecNamedCurves.GetByName("secp256r1");

            var domainParams    = new ECDomainParameters(
                                      ellipticCurve.Curve,
                                      ellipticCurve.G,
                                      ellipticCurve.N,
                                      ellipticCurve.H
                                  );

            //var keyPair         = GenerateECKeys(domainParams);
            var privateKey      = ParsePrivateKeyBase64(domainParams, "ANm7PAbjqlK+SPW/JLFXVt8U7vCpg69Xxy77rA8SN+Ce");//SerializePrivateKey(PrivateKey ?? keyPair.Item1).ToBase64();
            //var publicKey       = SerializePublicKey (keyPair.Item2              ).ToBase64();

            var signer = SignerUtilities.GetSigner("SHA-256withECDSA");
            signer.Init(true, PrivateKey ?? privateKey);
            signer.BlockUpdate(Data, 0, Data.Length);

            return new NTSSignedResponseExtension(
                       KeyId,
                       signer.GenerateSignature()
                   );

        }

        #endregion


        #region (static) GenerateECKeys        (ECCurve)

        public static (ECPrivateKeyParameters, ECPublicKeyParameters) GenerateECKeys(ECDomainParameters ECCurve)
        {

            var keyPairGenerator  = new ECKeyPairGenerator();
            var keyGenParams      = new ECKeyGenerationParameters(ECCurve, new SecureRandom());

            keyPairGenerator.Init(keyGenParams);
            var keyPair = keyPairGenerator.GenerateKeyPair();

            return ((ECPrivateKeyParameters) keyPair.Private,
                    (ECPublicKeyParameters)  keyPair.Public);

        }

        #endregion

        #region (static) SerializePrivateKey   (PrivateKey)

        public static Byte[] SerializePrivateKey(ECPrivateKeyParameters PrivateKey)
            => PrivateKey.D.ToByteArray();

        #endregion

        #region (static) SerializePublicKey    (PublicKey)

        public static Byte[] SerializePublicKey(ECPublicKeyParameters PublicKey)

            => PublicKey.Q.GetEncoded();

        #endregion

        #region (static) ParsePrivateKeyBase64 (EllipticCurveSpec, PrivateKeyBase64)

        public static ECPrivateKeyParameters ParsePrivateKeyBase64(ECDomainParameters  EllipticCurveSpec,
                                                                   String              PrivateKeyBase64)

            => new (new BigInteger(PrivateKeyBase64.FromBASE64()),
                    EllipticCurveSpec);

        #endregion

        #region (static) ParsePublicKeyBase64 (EllipticCurveSpec, PublicKeyBase64)

        public static ECPublicKeyParameters ParsePublicKeyBase64(ECDomainParameters  EllipticCurveSpec,
                                                                 String              PublicKeyBase64)

            => new ("ECDSA",
                    EllipticCurveSpec.Curve.DecodePoint(PublicKeyBase64.FromBASE64()),
                    EllipticCurveSpec);

        #endregion


    }

}
