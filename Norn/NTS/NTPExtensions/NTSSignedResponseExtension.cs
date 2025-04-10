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

using System.Security.Cryptography;
using System.Diagnostics.CodeAnalysis;

using org.GraphDefined.Vanaheimr.Illias;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Asn1.X9;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTP
{

    public class NTSSignedResponseExtension : NTPExtension
    {

        #region Properties

        /// <summary>
        /// The algorithm used to sign the response.
        /// </summary>
        public Byte[]  Algorithm    { get; }

        /// <summary>
        /// The signature of the response.
        /// </summary>
        public Byte[]  Signature    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new Authenticator and Encrypted extension.
        /// </summary>
        /// <param name="Algorithm">The algorithm used to sign the response.</param>
        /// <param name="Signature">The signature of the response.</param>
        /// <param name="Authenticated">Whether the extension is/was authenticated.</param>
        /// <param name="Encrypted">Whether the extension is/was encrypted.</param>
        public NTSSignedResponseExtension(Byte[]   Algorithm,
                                          Byte[]   Signature,
                                          Boolean  Authenticated   = false,
                                          Boolean  Encrypted       = false)

            : base(ExtensionTypes.NTSSignedResponse,
                   new Byte[4 + ((Signature.Length + 3) & ~3)],
                   Authenticated,
                   Encrypted)

        {

            this.Algorithm = Algorithm;
            this.Signature = Signature;

            var signatureLength  = Signature.Length;

            //var paddedNonceLength       = (nonceLength      + 3) & ~3;
            //var paddedSignatureLength  = (ciphertextLength + 3) & ~3;

            Value[0] = Algorithm[0];
            Value[1] = Algorithm[1];

            Value[2] = (Byte) ((signatureLength >> 8) & 0xff);
            Value[3] = (Byte)  (signatureLength       & 0xff);

            Buffer.BlockCopy(Signature, 0, Value, 4, signatureLength);

        }

        #endregion


        public static Boolean TryParse(Byte[]                                                ReceivedValue,
                                       IEnumerable<Byte[]>                                   AssociatedData,
                                       ref List<NTPExtension>                                AuthenticatedExtensions,
                                       Byte[]                                                Key, // S2C or C2S key!
                                       [NotNullWhen(true)]  out NTSSignedResponseExtension?  NTSSignedResponseExtension,
                                       [NotNullWhen(false)] out String?                      ErrorResponse)
        {

            try
            {

                ErrorResponse              = null;
                NTSSignedResponseExtension = null;

                if (ReceivedValue is null || ReceivedValue.Length < 4)
                {
                    ErrorResponse = "NTS Signed Response extension value is null or too short!";
                    return false;
                }

                var signatureLength             = (UInt16) ((ReceivedValue[2] << 8) | ReceivedValue[3]);

                //var paddedNonceLength            = (nonceLength      + 3) & ~3;
                //var paddedCiphertextLength       = (ciphertextLength + 3) & ~3;

                //var expectedTotalLength          = 4 + paddedNonceLength + paddedCiphertextLength;
                //if (ReceivedValue.Length < expectedTotalLength)
                //{
                //    ErrorResponse = "NTS Authenticator and Encrypted extension value has unexpected length!";
                //    return false;
                //}

                var receivedAlgorithm         = new Byte[2];
                Buffer.BlockCopy(ReceivedValue, 0, receivedAlgorithm, 0, 2);

                var receivedSignature         = new Byte[signatureLength];
                if (signatureLength > 0)
                    Buffer.BlockCopy(ReceivedValue, 4, receivedSignature, 0, signatureLength);

                NTSSignedResponseExtension = new NTSSignedResponseExtension(
                                                 receivedAlgorithm,
                                                 receivedSignature
                                             );

                return true;

            }
            catch (Exception e)
            {
                ErrorResponse              = e.Message;
                NTSSignedResponseExtension = null;
                return false;
            }

        }


        #region Create(AssociatedData, PrivateKey = null)

        /// <summary>
        /// Create a "NTS Signed Response Extension Fields" extension (type=0x0404)
        /// </summary>
        /// <param name="AssociatedData">An array of byte arrays to be signed.</param>
        /// <param name="PrivateKey">The private key to sign the response.</param>
        public static NTSSignedResponseExtension

            Create(IEnumerable<Byte[]>      AssociatedData,
                   ECPrivateKeyParameters?  PrivateKey   = null)

        {

            var ellipticCurve = SecNamedCurves.GetByName("secp256r1");

            var domainParams = new ECDomainParameters(
                                      ellipticCurve.Curve,
                                      ellipticCurve.G,
                                      ellipticCurve.N,
                                      ellipticCurve.H
                                  );

            var keyPair         = GenerateECKeys(domainParams);
            var dataToBeSigned  = AssociatedData.Aggregate();

            var signer = SignerUtilities.GetSigner("SHA-256withECDSA");
            signer.Init(true, PrivateKey ?? keyPair.Item1);
            signer.BlockUpdate(dataToBeSigned, 0, dataToBeSigned.Length);

            return new NTSSignedResponseExtension(
                       new Byte[2],
                       signer.GenerateSignature()
                   );

        }

        #endregion


        #region (private) GenerateECKeys(ECCurve)

        private static (ECPrivateKeyParameters, ECPublicKeyParameters) GenerateECKeys(ECDomainParameters ECCurve)
        {

            var keyPairGenerator  = new ECKeyPairGenerator();
            var keyGenParams      = new ECKeyGenerationParameters(ECCurve, new SecureRandom());

            keyPairGenerator.Init(keyGenParams);
            var keyPair = keyPairGenerator.GenerateKeyPair();

            return ((ECPrivateKeyParameters) keyPair.Private,
                    (ECPublicKeyParameters)  keyPair.Public);

        }

        #endregion


    }

}
