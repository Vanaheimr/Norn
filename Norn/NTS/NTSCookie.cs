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

using System.Security.Cryptography;
using System.Diagnostics.CodeAnalysis;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// A NTS cookie as used by the NTS server.
    /// </summary>
    public class NTSCookie : IEquatable<NTSCookie>,
                             IComparable<NTSCookie>
    {

        #region Data

        /// <summary>
        /// The JSON-LD context of this object.
        /// </summary>
        public readonly static JSONLDContext DefaultJSONLDContext = JSONLDContext.Parse("https://graphdefined.org/context/vanaheimr/norn/nts/cookie");


        private const Byte    NonceLength         = 32;

        // Layout of the decrypted cookie body (see ToByteArray()).
        private const UInt16  OffsetTimestamp     =                     0;
        private const UInt16  OffsetMasterKeyId   = OffsetTimestamp   + 8;
        private const UInt16  OffsetNonce         = OffsetMasterKeyId + 8;
        private const UInt16  OffsetAlgorithmId   = OffsetNonce       + NonceLength;
        private const UInt16  OffsetC2SKey        = OffsetAlgorithmId + 2;
        // OffsetS2CKey variable!

        // Layout of the sealed cookie that actually goes on the wire (see Encrypt()):
        //
        //     MasterKeyId (8) | AEADLength (2) | Nonce (32) | AES-SIV-CMAC-256(body)
        //
        // The master key id and nonce stay in the clear because the server needs them to
        // select the key and run the AEAD before it can trust anything else. Both, and the
        // length, are covered as associated data, so none of them can be altered.
        //
        // The explicit length matters: a cookie rides inside an NTP extension field, and
        // RFC 7822 pads those to a four-octet boundary. Without a length the server would
        // feed that padding to the AEAD and every cookie whose size is not a multiple of
        // four would fail to authenticate.
        private const UInt16  SealedOffsetMasterKeyId  =                            0;
        private const UInt16  SealedOffsetAEADLength   = SealedOffsetMasterKeyId  + 8;
        private const UInt16  SealedOffsetNonce        = SealedOffsetAEADLength   + 2;
        private const UInt16  SealedOffsetAEAD         = SealedOffsetNonce        + NonceLength;

        /// <summary>The synthetic IV AES-SIV prepends to its ciphertext (RFC 5297 §2.6).</summary>
        private const UInt16  SyntheticIVLength        = 16;

        #endregion

        #region Properties

        public UInt64          MasterKeyId      { get; } = 0;
        public Byte[]          C2SKey           { get; } = [];
        public Byte[]          S2CKey           { get; } = [];
        public AEADAlgorithms  AEADAlgorithm    { get; } = AEADAlgorithms.AES_SIV_CMAC_256;
        public DateTimeOffset  Timestamp        { get; } = Illias.Timestamp.Now;
        public Byte[]          Nonce            { get; } = [];

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a new NTS cookie.
        /// </summary>
        private NTSCookie(UInt64           MasterKeyId,
                          Byte[]           C2SKey,
                          Byte[]           S2CKey,
                          DateTimeOffset?  Timestamp       = null,
                          AEADAlgorithms?  AEADAlgorithm   = null,
                          Byte[]?          Nonce           = null)
        {

            #region Initial checks

            if (C2SKey.Length == 0)
                throw new ArgumentException("The C2SKey must not be empty!", nameof(C2SKey));

            if (S2CKey.Length == 0)
                throw new ArgumentException("The S2CKey must not be empty!", nameof(S2CKey));

            if (C2SKey.Length != S2CKey.Length)
                throw new ArgumentException("The C2SKey and S2CKey must be of the same length!");

            if (Nonce is not null && Nonce.Length != NonceLength)
                throw new ArgumentException($"The nonce must be {NonceLength} bytes long!", nameof(Nonce));

            #endregion

            this.C2SKey         = C2SKey;
            this.S2CKey         = S2CKey;
            this.MasterKeyId    = MasterKeyId;
            this.AEADAlgorithm  = AEADAlgorithm ?? AEADAlgorithms.AES_SIV_CMAC_256;
            this.Timestamp      = Timestamp     ?? Illias.Timestamp.Now;
            this.Nonce          = Nonce         ?? RandomNumberGenerator.GetBytes(32);

            unchecked
            {

                var hash = new HashCode();

                hash.AddBytes(this.C2SKey);
                hash.AddBytes(this.S2CKey);
                hash.Add     (this.MasterKeyId);
                hash.Add     (this.AEADAlgorithm);
                hash.Add     (this.Timestamp.ToUnixTimestamp());
                hash.AddBytes(this.Nonce);

                hashCode = hash.ToHashCode();

            }

        }

        #endregion


        /// <summary>
        /// Create a new NTS cookie for the given session keys.
        /// </summary>
        /// <param name="TimeProvider">
        /// The optional clock to timestamp the cookie with. It must be the same clock the server
        /// rotates its master keys on, because TryParse checks this timestamp against that key's
        /// validity window — two clocks that disagree would make a freshly minted cookie
        /// unusable. Without one the ambient <see cref="Illias.Timestamp.Now"/> is read, as before.
        /// </param>
        public static NTSCookie Create(MasterKey        MasterKey,
                                       Byte[]           C2SKey,
                                       Byte[]           S2CKey,
                                       AEADAlgorithms?  AEADAlgorithm   = null,
                                       TimeProvider?    TimeProvider    = null)
        {

            return new (
                       C2SKey:          C2SKey,
                       S2CKey:          S2CKey,
                       MasterKeyId:     MasterKey.Id,
                       AEADAlgorithm:   AEADAlgorithm,
                       Timestamp:       TimeProvider?.GetUtcNow() ?? Illias.Timestamp.Now,
                       Nonce:           RandomNumberGenerator.GetBytes(32)
                   );

        }


        #region (static) Parse    (JSON,  ...)

        /// <summary>
        /// Parse the given JSON representation of a NTS cookie.
        /// </summary>
        /// <param name="CustomNTSCookieParser">A delegate to parse custom NTSCookie JSON objects.</param>
        public static NTSCookie Parse(JObject                                  JSON,
                                      CustomJObjectParserDelegate<NTSCookie>?  CustomNTSCookieParser   = null)
        {

            if (TryParse(JSON,
                         out var ntsCookie,
                         out var errorResponse,
                         CustomNTSCookieParser))
            {
                return ntsCookie;
            }

            throw new ArgumentException("The given JSON representation of a NTS cookie is invalid: " + errorResponse,
                                        nameof(JSON));

        }

        #endregion

        #region (static) Parse    (SealedCookie, MasterKey, ...)

        /// <summary>
        /// Unseal the given binary representation of a NTS cookie using the master key that
        /// issued it, throwing when it cannot be authenticated.
        /// </summary>
        public static NTSCookie Parse(Byte[]     SealedCookie,
                                      MasterKey  MasterKey)
        {

            if (TryParse(SealedCookie,
                         MasterKey,
                         out var ntsCookie,
                         out var errorResponse))
            {
                return ntsCookie;
            }

            throw new ArgumentException("The given binary representation of a NTS cookie is invalid: " + errorResponse,
                                        nameof(SealedCookie));

        }

        #endregion

        #region (static) TryParse (JSON,  out NTSCookie, out ErrorResponse, ...)

        // Note: The following is needed to satisfy pattern matching delegates! Do not refactor it!

        /// <summary>
        /// Try to parse the given JSON representation of a NTS cookie.
        /// </summary>
        /// <param name="JSON">The JSON to be parsed.</param>
        /// <param name="NTSCookie">The parsed NTS cookie.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        public static Boolean TryParse(JObject                              JSON,
                                       [NotNullWhen(true)]  out NTSCookie?  NTSCookie,
                                       [NotNullWhen(false)] out String?     ErrorResponse)

            => TryParse(JSON,
                        out NTSCookie,
                        out ErrorResponse,
                        null);


        /// <summary>
        /// Try to parse the given JSON representation of a NTS cookie.
        /// </summary>
        /// <param name="JSON">The JSON to be parsed.</param>
        /// <param name="NTSCookie">The parsed NTS cookie.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        /// <param name="CustomNTSCookieParser">A delegate to parse custom NTSCookie JSON objects.</param>
        public static Boolean TryParse(JObject                                  JSON,
                                       [NotNullWhen(true)]  out NTSCookie?      NTSCookie,
                                       [NotNullWhen(false)] out String?         ErrorResponse,
                                       CustomJObjectParserDelegate<NTSCookie>?  CustomNTSCookieParser)
        {
            try
            {

                NTSCookie = null;

                #region MasterKeyId      [mandatory]

                if (!JSON.ParseMandatory("masterKeyId",
                                         "master key identification",
                                         out UInt64 masterKeyId,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region C2SKey           [mandatory]

                if (!JSON.ParseMandatoryText("c2sKey",
                                             "C2S key",
                                             out String? c2sKeyBASE64,
                                             out ErrorResponse))
                {
                    return false;
                }

                var c2sKey = c2sKeyBASE64.FromBASE64();

                #endregion

                #region S2CKey           [mandatory]

                if (!JSON.ParseMandatoryText("s2cKey",
                                             "S2C key",
                                             out String? s2cKeyBASE64,
                                             out ErrorResponse))
                {
                    return false;
                }

                var s2cKey = s2cKeyBASE64.FromBASE64();

                #endregion

                #region Timestamp        [mandatory]

                if (!JSON.ParseMandatory("timestamp",
                                         "NTS cookie timestamp",
                                         out DateTimeOffset timestamp,
                                         out ErrorResponse))
                {
                    return false;
                }

                #endregion

                #region AEADAlgorithm    [optional]

                if (JSON.ParseOptional("aeadAlgorithm",
                                       "AEAD algorithm",
                                       AEADAlgorithmsExtensions.TryParse,
                                       out AEADAlgorithms? aeadAlgorithm,
                                       out ErrorResponse))
                {
                    if (ErrorResponse is not null)
                        return false;
                }

                #endregion

                #region Nonce            [mandatory]

                if (!JSON.ParseMandatoryText("nonce",
                                             "cryptographic nonce",
                                             out String? nonceBASE64,
                                             out ErrorResponse))
                {
                    return false;
                }

                var nonce = nonceBASE64.FromBASE64();

                #endregion


                NTSCookie = new NTSCookie(
                                masterKeyId,
                                c2sKey,
                                s2cKey,
                                timestamp,
                                aeadAlgorithm,
                                nonce
                            );

                if (CustomNTSCookieParser is not null)
                    NTSCookie = CustomNTSCookieParser(JSON,
                                                      NTSCookie);

                return true;

            }
            catch (Exception e)
            {
                NTSCookie      = default;
                ErrorResponse  = "The given JSON representation of a NTS cookie is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region (private, static) TryParseBody (Bytes, out NTSCookie, out ErrorResponse)

        /// <summary>
        /// Parse the <em>decrypted</em> cookie body.
        ///
        /// Private by design: these bytes carry both session keys, so the only way to reach
        /// them is through <see cref="TryParse(Byte[], MasterKey, out NTSCookie?, out String?)"/>,
        /// which first verifies the AEAD. There is deliberately no public keyless parse.
        /// </summary>
        /// <param name="Bytes">The decrypted cookie body.</param>
        /// <param name="NTSCookie">The parsed NTS cookie.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        private static Boolean TryParseBody(Byte[]                               Bytes,
                                            [NotNullWhen(true)]  out NTSCookie?  NTSCookie,
                                            [NotNullWhen(false)] out String?     ErrorResponse)
        {
            try
            {

                NTSCookie      = null;
                ErrorResponse  = null;


                if (Bytes.Length < OffsetC2SKey)
                {
                    ErrorResponse = $"The given binary representation of a NTS cookie is too short: {Bytes.Length} bytes!";
                    return false;
                }

                UInt64 timestampUInt64 = 0;
                for (var j = 0; j < 8; j++)
                    timestampUInt64 |= (UInt64) Bytes[OffsetTimestamp + j] << (56 - 8 * j);

                if (timestampUInt64 > Int64.MaxValue)
                {
                    ErrorResponse = "The timestamp within the given binary representation of a NTS cookie is too large!";
                    return false;
                }

                UInt64 masterKeyIdUInt64 = 0;
                for (var j = 0; j < 8; j++)
                    masterKeyIdUInt64 |= (UInt64) Bytes[OffsetMasterKeyId + j] << (56 - 8 * j);


                // The following should be **encrypted**!!!

                var nonce = new Byte[32];
                Array.Copy(Bytes, OffsetNonce, nonce, 0, nonce.Length);

                // AlgorithmId (Big-Endian)
                UInt16 algorithmIdUInt16 = 0;
                algorithmIdUInt16 |= (UInt16) (Bytes[OffsetAlgorithmId + 0] << 8);
                algorithmIdUInt16 |= (UInt16) (Bytes[OffsetAlgorithmId + 1] & 0xFF);
                var algorithmId = (AEADAlgorithms) algorithmIdUInt16;

                // Key length
                // From the one place that knows, so that an algorithm added there cannot be
                // accepted into a cookie here without its key length being known.
                var keyLength = NTSAEAD.KeyLength(algorithmId) ?? 0;

                if (keyLength == 0)
                {
                    ErrorResponse = $"Unsupported AEAD algorithm id '{algorithmIdUInt16}' within the given binary representation of a NTS cookie!";
                    return false;
                }

                var expectedLength = OffsetC2SKey + 2 * keyLength;

                if (Bytes.Length < expectedLength)
                {
                    ErrorResponse = $"The given binary representation of a NTS cookie is too short for {algorithmId}: {Bytes.Length} < {expectedLength} bytes!";
                    return false;
                }

                // C2S key
                var c2sKey = new Byte[keyLength];
                Array.Copy(Bytes, OffsetC2SKey,           c2sKey, 0, c2sKey.Length);

                // S2C key
                var s2cKey = new Byte[keyLength];
                Array.Copy(Bytes, OffsetC2SKey+keyLength, s2cKey, 0, s2cKey.Length);


                NTSCookie = new NTSCookie(
                                masterKeyIdUInt64,
                                c2sKey,
                                s2cKey,
                                DateTimeOffsetExtensions.FromUnixTimestamp((Int64) timestampUInt64),
                                algorithmId,
                                nonce
                            );

                return true;

            }
            catch (Exception e)
            {
                NTSCookie      = default;
                ErrorResponse  = "The given binary representation of a NTS cookie is invalid: " + e.Message;
                return false;
            }

        }

        #endregion

        #region ToJSON      (IncludeJSONLDContext = false, CustomNTSCookieSerializer = null)

        /// <summary>
        /// Return a JSON representation of this NTS cookie.
        /// </summary>
        /// <param name="IncludeJSONLDContext">Whether to include the JSON-LD context or not.</param>
        /// <param name="CustomNTSCookieSerializer">A delegate to serialize custom NTSCookie objects.</param>
        public JObject ToJSON(Boolean                                      IncludeJSONLDContext        = false,
                              CustomJObjectSerializerDelegate<NTSCookie>?  CustomNTSCookieSerializer   = null)
        {

            var json = JSONObject.Create(

                           IncludeJSONLDContext
                               ? new JProperty("@context",        DefaultJSONLDContext.ToString())
                               : null,

                                 new JProperty("masterKeyId",     MasterKeyId),
                                 new JProperty("c2sKey",          C2SKey.              ToBase64()),
                                 new JProperty("s2cKey",          S2CKey.              ToBase64()),
                                 new JProperty("timestamp",       Timestamp.           ToISO8601()),

                           AEADAlgorithm != AEADAlgorithms.AES_SIV_CMAC_256
                               ? new JProperty("aeadAlgorithm",   AEADAlgorithm.       ToString())
                               : null,

                                 new JProperty("nonce",           Nonce.               ToBase64())

                       );

            return CustomNTSCookieSerializer is not null
                       ? CustomNTSCookieSerializer(this, json)
                       : json;

        }

        #endregion

        #region ToByteArray ()

        /// <summary>
        /// Return the decrypted cookie body.
        ///
        /// This is the AEAD plaintext, not the wire format: it contains both session keys in
        /// the clear. Use <see cref="Encrypt(MasterKey)"/> for anything that leaves the server.
        /// </summary>
        public Byte[] ToByteArray()
        {

            #region Data

            var OffsetS2CKey   = (UInt16) (OffsetC2SKey + C2SKey.Length);
            var totalLength    = OffsetS2CKey + S2CKey.Length;

            var unixTimestamp  = (UInt64) Timestamp.ToUnixTimestamp();

            #endregion

            // NOTE: This is a vendor specific implementation of the NTS cookie format!
            // rfc8915 Section 6 https://datatracker.ietf.org/doc/html/rfc8915#name-suggested-format-for-nts-co
            // gives just some general hints about the cookie format!

            var cookie = new Byte[totalLength];

            // Timestamp (Big-Endian)
            for (var i = 0; i < 8; i++)
                cookie[OffsetTimestamp + i] = (Byte) (unixTimestamp >> (56 - 8 * i));

            // MasterKeyId (Big-Endian)
            //if (MasterKeyId.HasValue)
                for (var i = 0; i < 8; i++)
                    cookie[OffsetMasterKeyId + i] = (Byte) (MasterKeyId >> (56 - 8 * i));


            // The following should be **encrypted**!!!
            // ToDo: AEAD-Encrypt `cookie` with master key

            // Nonce (32 bytes)
            Buffer.BlockCopy(Nonce, 0, cookie, OffsetNonce, Nonce.Length);

            // AlgorithmId (Big-Endian)
            var algorithmBytes = AEADAlgorithm.GetBytes();
            cookie[OffsetAlgorithmId]     = algorithmBytes[0];
            cookie[OffsetAlgorithmId + 1] = algorithmBytes[1];

            // C2S/S2C keys
            Buffer.BlockCopy(C2SKey, 0, cookie, OffsetC2SKey,                 C2SKey.Length);
            Buffer.BlockCopy(S2CKey, 0, cookie, OffsetC2SKey + C2SKey.Length, S2CKey.Length);

            return cookie;

        }

        #endregion

        #region Clone()

        /// <summary>
        /// Clone this NTS cookie.
        /// </summary>
        public NTSCookie Clone()

            => new (
                   MasterKeyId,
                   C2SKey.ToHexString().FromHEX(),
                   S2CKey.ToHexString().FromHEX(),
                   Timestamp,
                   AEADAlgorithm,
                   Nonce. ToHexString().FromHEX()
               );

        #endregion


        #region Encrypt(MasterKey)

        /// <summary>
        /// Seal this cookie for the wire, as RFC 8915 §6 requires: the body is encrypted
        /// and authenticated with an AEAD under the server's secret master key, so the
        /// client — and anyone observing the network — sees only opaque bytes.
        ///
        /// The cookie travels in the clear inside every NTS request and carries both
        /// session keys, so this encryption is the only thing keeping them secret.
        /// </summary>
        /// <param name="MasterKey">The server's current master key.</param>
        public Byte[] Encrypt(MasterKey MasterKey)
        {

            if (MasterKey.Value is null || MasterKey.Value.Length != 32)
                throw new ArgumentException($"The master key value must be 32 bytes long for {AEADAlgorithms.AES_SIV_CMAC_256}!",
                                            nameof(MasterKey));

            // Re-stamp the cookie when it is sealed under a newer master key than it was created with.
            var ntsCookie      = MasterKey.Id != this.MasterKeyId

                                     ? new NTSCookie(
                                           MasterKey.Id,
                                           C2SKey,
                                           S2CKey,
                                           Timestamp,
                                           AEADAlgorithm,
                                           Nonce
                                       )

                                     : this;

            var body           = ntsCookie.ToByteArray();
            var aeadLength     = SyntheticIVLength + body.Length;

            // The header that frames the ciphertext is authenticated but not encrypted, so
            // neither the key id nor the length can be swapped without failing the AEAD.
            var header         = new Byte[SealedOffsetNonce];
            Buffer.BlockCopy(ToNetworkByteOrder(MasterKey.Id), 0, header, SealedOffsetMasterKeyId, 8);
            header[SealedOffsetAEADLength]     = (Byte) (aeadLength >> 8);
            header[SealedOffsetAEADLength + 1] = (Byte)  aeadLength;

            var aeadOutput     = new AES_SIV(MasterKey.Value).
                                     Encrypt(
                                         [ header ],
                                         ntsCookie.Nonce,
                                         body
                                     );

            var sealedCookie   = new Byte[SealedOffsetAEAD + aeadOutput.Length];

            Buffer.BlockCopy(header,           0, sealedCookie, 0,                 header.Length);
            Buffer.BlockCopy(ntsCookie.Nonce,  0, sealedCookie, SealedOffsetNonce, NonceLength);
            Buffer.BlockCopy(aeadOutput,       0, sealedCookie, SealedOffsetAEAD,  aeadOutput.Length);

            return sealedCookie;

        }

        #endregion

        #region (static) TryReadMasterKeyId (SealedCookie, out MasterKeyId, out ErrorResponse)

        /// <summary>
        /// Read just the master key id from a sealed cookie, so a server can pick the right
        /// key before it is able to decrypt anything. The value is unauthenticated at this
        /// point — it is only a lookup hint, and the AEAD in
        /// <see cref="TryParse(Byte[], MasterKey, out NTSCookie?, out String?)"/> is what
        /// actually verifies it.
        /// </summary>
        public static Boolean TryReadMasterKeyId(Byte[]                            SealedCookie,
                                                 out UInt64                        MasterKeyId,
                                                 [NotNullWhen(false)] out String?  ErrorResponse)
        {

            MasterKeyId    = 0;
            ErrorResponse  = null;

            if (SealedCookie.Length < SealedOffsetAEAD + SyntheticIVLength)
            {
                ErrorResponse = $"The given binary representation of a NTS cookie is too short: {SealedCookie.Length} bytes!";
                return false;
            }

            for (var i = 0; i < 8; i++)
                MasterKeyId |= (UInt64) SealedCookie[SealedOffsetMasterKeyId + i] << (56 - 8 * i);

            return true;

        }

        #endregion

        #region (static) TryParse (SealedCookie, MasterKey(s), out NTSCookie, out ErrorResponse)

        /// <summary>
        /// Unseal a cookie using the master key that issued it. Fails closed: a cookie that
        /// was tampered with, or that this server never issued, yields no cookie at all.
        /// </summary>
        public static Boolean TryParse(Byte[]                                SealedCookie,
                                       MasterKey                             MasterKey,
                                       [NotNullWhen(true)]  out NTSCookie?   NTSCookie,
                                       [NotNullWhen(false)] out String?      ErrorResponse)
        {

            NTSCookie      = null;
            ErrorResponse  = null;

            if (!TryReadMasterKeyId(SealedCookie, out var masterKeyId, out ErrorResponse))
                return false;

            if (masterKeyId != MasterKey.Id)
            {
                ErrorResponse = $"The NTS cookie was issued under master key {masterKeyId}, not {MasterKey.Id}!";
                return false;
            }

            if (MasterKey.Value is null || MasterKey.Value.Length != 32)
            {
                ErrorResponse = "The master key value must be 32 bytes long!";
                return false;
            }

            try
            {

                var aeadLength  = (SealedCookie[SealedOffsetAEADLength] << 8) | SealedCookie[SealedOffsetAEADLength + 1];

                if (aeadLength < SyntheticIVLength ||
                    SealedOffsetAEAD + aeadLength > SealedCookie.Length)
                {
                    ErrorResponse = $"The NTS cookie declares {aeadLength} bytes of ciphertext, which does not fit " +
                                    $"its {SealedCookie.Length} bytes!";
                    return false;
                }

                // Sliced to the declared length, so any RFC 7822 padding the extension field
                // added around the cookie is left out of the AEAD.
                var header      = new Byte[SealedOffsetNonce];
                Buffer.BlockCopy(SealedCookie, 0, header, 0, header.Length);

                var nonce       = new Byte[NonceLength];
                Buffer.BlockCopy(SealedCookie, SealedOffsetNonce, nonce, 0, NonceLength);

                var aeadOutput  = new Byte[aeadLength];
                Buffer.BlockCopy(SealedCookie, SealedOffsetAEAD, aeadOutput, 0, aeadLength);

                var body        = new AES_SIV(MasterKey.Value).
                                      Decrypt(
                                          [ header ],
                                          nonce,
                                          aeadOutput
                                      );

                return TryParseBody(body, out NTSCookie, out ErrorResponse);

            }
            catch (Exception e)
            {
                // A synthetic-IV mismatch means the cookie was forged or altered.
                ErrorResponse = $"The NTS cookie failed its authenticity check: {e.Message}";
                return false;
            }

        }


        /// <summary>
        /// Unseal a cookie by looking its master key up among the server's current and
        /// still-accepted keys, then checking the cookie falls inside that key's validity
        /// window.
        /// </summary>
        public static Boolean TryParse(Byte[]                                                   SealedCookie,
                                       IReadOnlyDictionary<UInt64, MasterKey>?                  MasterKeys,
                                       [NotNullWhen(true)]  out NTSCookie?                      NTSCookie,
                                       [NotNullWhen(false)] out String?                         ErrorResponse)
        {

            NTSCookie      = null;
            ErrorResponse  = null;

            if (MasterKeys is null)
            {
                ErrorResponse = "No master keys available to validate the NTS cookie!";
                return false;
            }

            if (!TryReadMasterKeyId(SealedCookie, out var masterKeyId, out ErrorResponse))
                return false;

            if (!MasterKeys.TryGetValue(masterKeyId, out var masterKey))
            {
                ErrorResponse = $"Unknown NTS cookie master key {masterKeyId}!";
                return false;
            }

            if (!TryParse(SealedCookie, masterKey, out NTSCookie, out ErrorResponse))
                return false;

            if (NTSCookie.Timestamp.ToUnixTimestamp() <  masterKey.NotBefore.ToUnixTimestamp() ||
                NTSCookie.Timestamp.ToUnixTimestamp() >= masterKey.NotAfter. ToUnixTimestamp())
            {
                ErrorResponse = $"The NTS cookie timestamp {NTSCookie.Timestamp:O} is outside the validity " +
                                $"window of master key {masterKeyId}!";
                NTSCookie     = null;
                return false;
            }

            return true;

        }

        #endregion

        #region (private, static) ToNetworkByteOrder(Value)

        private static Byte[] ToNetworkByteOrder(UInt64 Value)
        {

            var bytes = new Byte[8];

            for (var i = 0; i < 8; i++)
                bytes[i] = (Byte) (Value >> (56 - 8 * i));

            return bytes;

        }

        #endregion


        #region Operator overloading

        #region Operator == (NTSCookie1, NTSCookie2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="NTSCookie1">A NTS cookie.</param>
        /// <param name="NTSCookie2">Another NTS cookie.</param>
        /// <returns>true|false</returns>
        public static Boolean operator == (NTSCookie NTSCookie1,
                                           NTSCookie NTSCookie2)

            => NTSCookie1.Equals(NTSCookie2);

        #endregion

        #region Operator != (NTSCookie1, NTSCookie2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="NTSCookie1">A NTS cookie.</param>
        /// <param name="NTSCookie2">Another NTS cookie.</param>
        /// <returns>true|false</returns>
        public static Boolean operator != (NTSCookie NTSCookie1,
                                           NTSCookie NTSCookie2)

            => !NTSCookie1.Equals(NTSCookie2);

        #endregion

        #region Operator <  (NTSCookie1, NTSCookie2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="NTSCookie1">A NTS cookie.</param>
        /// <param name="NTSCookie2">Another NTS cookie.</param>
        /// <returns>true|false</returns>
        public static Boolean operator < (NTSCookie NTSCookie1,
                                          NTSCookie NTSCookie2)

            => NTSCookie1.CompareTo(NTSCookie2) < 0;

        #endregion

        #region Operator <= (NTSCookie1, NTSCookie2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="NTSCookie1">A NTS cookie.</param>
        /// <param name="NTSCookie2">Another NTS cookie.</param>
        /// <returns>true|false</returns>
        public static Boolean operator <= (NTSCookie NTSCookie1,
                                           NTSCookie NTSCookie2)

            => NTSCookie1.CompareTo(NTSCookie2) <= 0;

        #endregion

        #region Operator >  (NTSCookie1, NTSCookie2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="NTSCookie1">A NTS cookie.</param>
        /// <param name="NTSCookie2">Another NTS cookie.</param>
        /// <returns>true|false</returns>
        public static Boolean operator > (NTSCookie NTSCookie1,
                                          NTSCookie NTSCookie2)

            => NTSCookie1.CompareTo(NTSCookie2) > 0;

        #endregion

        #region Operator >= (NTSCookie1, NTSCookie2)

        /// <summary>
        /// Compares two instances of this object.
        /// </summary>
        /// <param name="NTSCookie1">A NTS cookie.</param>
        /// <param name="NTSCookie2">Another NTS cookie.</param>
        /// <returns>true|false</returns>
        public static Boolean operator >= (NTSCookie NTSCookie1,
                                           NTSCookie NTSCookie2)

            => NTSCookie1.CompareTo(NTSCookie2) >= 0;

        #endregion

        #endregion

        #region IComparable<NTSCookie> Members

        #region CompareTo(Object)

        /// <summary>
        /// Compares two NTS cookies.
        /// </summary>
        /// <param name="Object">A NTS cookie to compare with.</param>
        public Int32 CompareTo(Object? Object)

            => Object is NTSCookie ntsCookie
                   ? CompareTo(ntsCookie)
                   : throw new ArgumentException("The given object is not a NTS cookie!",
                                                 nameof(Object));

        #endregion

        #region CompareTo(NTSCookie)

        /// <summary>
        /// Compares two NTS cookies.
        /// </summary>
        /// <param name="NTSCookie">A NTS cookie to compare with.</param>
        public Int32 CompareTo(NTSCookie? NTSCookie)
        {

            if (NTSCookie is null)
                throw new ArgumentNullException(nameof(NTSCookie), "The given NTS cookie must not be null!");

            var c = C2SKey.    ToHexString().CompareTo(NTSCookie.C2SKey.    ToHexString());

            if (c == 0)
                c = S2CKey.    ToHexString().CompareTo(NTSCookie.S2CKey.    ToHexString());

            // MasterKeyId

            if (c == 0)
                c = AEADAlgorithm.  CompareTo(NTSCookie.AEADAlgorithm);

            if (c == 0)
                c = Timestamp. ToISO8601().  CompareTo(NTSCookie.Timestamp. ToISO8601());

            if (c == 0)
                c = Nonce.     ToHexString().CompareTo(NTSCookie.Nonce.     ToHexString());

            return c;

        }

        #endregion

        #endregion

        #region IEquatable<NTSCookie> Members

        #region Equals(Object)

        /// <summary>
        /// Compares two NTS cookies for equality.
        /// </summary>
        /// <param name="Object">A NTS cookie to compare with.</param>
        public override Boolean Equals(Object? Object)

            => Object is NTSCookie ntsCookie &&
                   Equals(ntsCookie);

        #endregion

        #region Equals(NTSCookie)

        /// <summary>
        /// Compares two NTS cookies for equality.
        /// </summary>
        /// <param name="NTSCookie">A NTS cookie to compare with.</param>
        public Boolean Equals(NTSCookie? NTSCookie)

            => NTSCookie is not null &&
               C2SKey.               SequenceEqual(NTSCookie.C2SKey)                 &&
               S2CKey.               SequenceEqual(NTSCookie.S2CKey)                 &&
               MasterKeyId.          Equals       (NTSCookie.MasterKeyId)            &&
               AEADAlgorithm.        Equals       (NTSCookie.AEADAlgorithm)          &&
               Timestamp.ToUnixTimestamp().Equals (NTSCookie.Timestamp.ToUnixTimestamp()) &&
               Nonce.                SequenceEqual(NTSCookie.Nonce);

        #endregion

        #endregion

        #region (override) GetHashCode()

        private readonly Int32 hashCode;

        /// <summary>
        /// Return the hash code of this object.
        /// </summary>
        public override Int32 GetHashCode()
            => hashCode;

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"{AEADAlgorithm} / '{Nonce.ToBase64()[12..]}' @ {Timestamp}";

        #endregion


    }

}
