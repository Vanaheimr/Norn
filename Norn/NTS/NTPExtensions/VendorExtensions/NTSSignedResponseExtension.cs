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

using System.Diagnostics.CodeAnalysis;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;

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

                var paddedSignatureLength   = (signatureLength + 3) & ~3;

                if (4 + signatureLength > Data.Length ||
                    4 + paddedSignatureLength > Data.Length)
                {
                    ErrorResponse = $"NTS Signed Response extension declares {signatureLength} signature bytes, exceeding the {Data.Length - 4}-byte payload!";
                    return false;
                }

                for (var i = 4 + signatureLength; i < Data.Length; i++)
                {
                    if (Data[i] != 0)
                    {
                        ErrorResponse = "NTS Signed Response extension contains non-zero trailing padding!";
                        return false;
                    }
                }

                var signature               = new Byte[signatureLength];
                if (signatureLength > 0)
                    Buffer.BlockCopy(Data, 4, signature, 0, signatureLength);

                NTSSignedResponseExtension  = new NTSSignedResponseExtension(
                                                  keyId,
                                                  signature,
                                                  Authenticated,
                                                  Encrypted
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


        #region Sign(KeyPair, Data, PrivateKey = null)

        /// <summary>
        /// Sign 
        /// </summary>
        /// <param name="KeyPair">The key pair to be used to sign the response.</param>
        /// <param name="Data">An array of bytes to be signed.</param>
        public static NTSSignedResponseExtension Sign(KeyPair  KeyPair,
                                                      Byte[]   Data)
        {

            var ellipticCurve  = SecNamedCurves.GetByName(KeyPair.EllipticCurve)
                                     ?? throw new ArgumentException($"Unknown elliptic curve '{KeyPair.EllipticCurve}'!",
                                                                    nameof(KeyPair));

            var domainParams   = new ECDomainParameters(
                                     ellipticCurve.Curve,
                                     ellipticCurve.G,
                                     ellipticCurve.N,
                                     ellipticCurve.H
                                 );

            var privateKey     = KeyPair.ParsePrivateKey(domainParams, KeyPair.PrivateKey);

            var signer         = SignerUtilities.GetSigner(KeyPair.SignatureAlgorithm);
            signer.Init(true, privateKey);
            signer.BlockUpdate(Data, 0, Data.Length);

            return new NTSSignedResponseExtension(
                       KeyPair.Id,
                       signer.GenerateSignature()
                   );

        }

        #endregion

        #region Verify(NTPResponse, PublicKey)

        /// <summary>
        /// Verify the signature of the NTP response.
        /// </summary>
        /// <param name="NTPResponse">A NTP response.</param>
        /// <param name="PublicKey">The public key to verify the response.</param>
        public Boolean Verify(NTPPacket  NTPResponse,
                              PublicKey  PublicKey)
        {

            // The signature names the key it was made with. Checked against any other,
            // it could only ever fail, and saying so is clearer than letting it.
            if (KeyId != PublicKey.Id)
                return false;

            try
            {

                var data            = ExtractSignedPrefix(NTPResponse)
                                          ?? new NTPPacket(
                                                 NTPResponse,
                                                 NTPResponse.Extensions.Where(e => !e.Encrypted && e is not NTSSignedResponseExtension)
                                             ).ToByteArray();

                var ellipticCurve   = SecNamedCurves.GetByName(PublicKey.EllipticCurve);

                if (ellipticCurve is null)
                    return false;

                var domainParams    = new ECDomainParameters(
                                          ellipticCurve.Curve,
                                          ellipticCurve.G,
                                          ellipticCurve.N,
                                          ellipticCurve.H
                                      );

                var publicKey       = KeyPair.ParsePublicKey(domainParams, PublicKey.Value);

                var verifier        = SignerUtilities.GetSigner(PublicKey.SignatureAlgorithm);
                verifier.Init(false, publicKey);
                verifier.BlockUpdate(data);

                return verifier.VerifySignature(Signature);

            }
            catch (Exception)
            {
                // The key and the signature both come from the server: a point that is not
                // on the curve, a signature that is not one, an algorithm nobody knows.
                // Whatever is wrong with them, the answer to "is this signed?" is no,
                // and not an exception in the caller.
                return false;
            }

        }

        private static Byte[]? ExtractSignedPrefix(NTPPacket Packet)
        {

            var raw = Packet.ResponseBytes;

            if (raw is null || raw.Length < 48)
                return null;

            var offset = 48;

            while (offset + 4 <= raw.Length)
            {

                var type   = (ExtensionTypes) ((raw[offset]     << 8) | raw[offset + 1]);
                var length = (UInt16)         ((raw[offset + 2] << 8) | raw[offset + 3]);

                if (length < 4 || offset + length > raw.Length)
                    return null;

                if (type == ExtensionTypes.NTSSignedResponse)
                {
                    // Must be the final extension on the wire so no unsigned trailing extensions
                    // can be appended after the signature.
                    if (offset + length != raw.Length)
                        return null;

                    var prefix = new Byte[offset];
                    Buffer.BlockCopy(raw, 0, prefix, 0, offset);
                    return prefix;
                }

                offset += length;

            }

            return null;

        }

        #endregion


    }

}
