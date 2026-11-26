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

using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
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

        // Layout of the decrypted cookie body (see ToByteArray()):
        //
        //     Timestamp (8) | AlgorithmId (2) | C2SKey | S2CKey
        //
        // The master key id and the nonce are not repeated in here. Both stand in front of
        // the sealed body, where the AEAD covers them just the same: the id as associated
        // data, the nonce as the nonce. A second copy inside bought nothing, and cost 40
        // octets in every cookie of every request and response.
        private const UInt16  OffsetTimestamp     =                     0;
        private const UInt16  OffsetAlgorithmId   = OffsetTimestamp   + 8;
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

        /// <summary>
        /// The synthetic IV AES-SIV prepends to its ciphertext (RFC 5297 §2.6).
        /// </summary>
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
        /// <param name="MasterKeyId">The master key id from in front of the sealed body, which the AEAD has verified.</param>
        /// <param name="Nonce">The nonce from in front of the sealed body, which the AEAD has verified.</param>
        /// <param name="NTSCookie">The parsed NTS cookie.</param>
        /// <param name="ErrorResponse">An optional error response.</param>
        private static Boolean TryParseBody(ReadOnlySpan<Byte>                   Bytes,
                                            UInt64                               MasterKeyId,
                                            Byte[]                               Nonce,
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

                var timestampUInt64 = BinaryPrimitives.ReadUInt64BigEndian(Bytes.Slice(OffsetTimestamp, 8));

                if (timestampUInt64 > Int64.MaxValue)
                {
                    ErrorResponse = "The timestamp within the given binary representation of a NTS cookie is too large!";
                    return false;
                }

                // AlgorithmId (Big-Endian)
                var algorithmIdUInt16 = BinaryPrimitives.ReadUInt16BigEndian(Bytes.Slice(OffsetAlgorithmId, 2));
                var algorithmId       = (AEADAlgorithms) algorithmIdUInt16;

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
                var c2sKey = Bytes.Slice(OffsetC2SKey,             keyLength).ToArray();

                // S2C key
                var s2cKey = Bytes.Slice(OffsetC2SKey + keyLength, keyLength).ToArray();


                NTSCookie = new NTSCookie(
                                MasterKeyId,
                                c2sKey,
                                s2cKey,
                                DateTimeOffsetExtensions.FromUnixTimestamp((Int64) timestampUInt64),
                                algorithmId,
                                Nonce
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

        private void WriteBodyTo(Span<Byte> Destination)
        {

            // NOTE: This is a vendor specific implementation of the NTS cookie format!
            // rfc8915 Section 6 https://datatracker.ietf.org/doc/html/rfc8915#name-suggested-format-for-nts-co
            // gives just some general hints about the cookie format!
            BinaryPrimitives.WriteUInt64BigEndian(Destination.Slice(OffsetTimestamp,   8), (UInt64) Timestamp.ToUnixTimestamp());
            BinaryPrimitives.WriteUInt16BigEndian(Destination.Slice(OffsetAlgorithmId, 2), (UInt16) AEADAlgorithm);

            C2SKey.AsSpan().CopyTo(Destination.Slice(OffsetC2SKey,                 C2SKey.Length));
            S2CKey.AsSpan().CopyTo(Destination.Slice(OffsetC2SKey + C2SKey.Length, S2CKey.Length));

        }

        /// <summary>
        /// Return the decrypted cookie body.
        ///
        /// This is the AEAD plaintext, not the wire format: it contains both session keys in
        /// the clear. Use <see cref="Encrypt(MasterKey)"/> for anything that leaves the server.
        /// </summary>
        public Byte[] ToByteArray()
        {

            var cookie = new Byte[OffsetC2SKey + C2SKey.Length + S2CKey.Length];
            WriteBodyTo(cookie);
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
                   (Byte[]) C2SKey.Clone(),
                   (Byte[]) S2CKey.Clone(),
                   Timestamp,
                   AEADAlgorithm,
                   (Byte[]) Nonce. Clone()
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
            // Keep the timestamp inside the new master key's validity window and mint a fresh nonce
            // so the re-sealed cookie passes validation under the rotated key without nonce reuse.
            NTSCookie ntsCookie;
            if (MasterKey.Id != this.MasterKeyId)
            {
                var reStampedTimestamp = Timestamp.ToUnixTimestamp() <  MasterKey.NotBefore.ToUnixTimestamp() ||
                                         Timestamp.ToUnixTimestamp() >= MasterKey.NotAfter. ToUnixTimestamp()
                                             ? MasterKey.NotBefore
                                             : Timestamp;

                ntsCookie = new NTSCookie(
                                MasterKey.Id,
                                C2SKey,
                                S2CKey,
                                reStampedTimestamp,
                                AEADAlgorithm,
                                RandomNumberGenerator.GetBytes(NonceLength)
                            );
            }
            else
                ntsCookie = this;

            var bodyLength     = OffsetC2SKey + ntsCookie.C2SKey.Length + ntsCookie.S2CKey.Length;
            var aeadLength     = SyntheticIVLength + bodyLength;
            var sealedCookie   = new Byte[SealedOffsetAEAD + aeadLength];

            // The header that frames the ciphertext is authenticated but not encrypted, so
            // neither the key id nor the length can be swapped without failing the AEAD.
            var headerSpan     = sealedCookie.AsSpan(0, SealedOffsetNonce);
            BinaryPrimitives.WriteUInt64BigEndian(headerSpan.Slice(SealedOffsetMasterKeyId, 8), MasterKey.Id);
            BinaryPrimitives.WriteUInt16BigEndian(headerSpan.Slice(SealedOffsetAEADLength,  2), (UInt16) aeadLength);

            ntsCookie.Nonce.AsSpan().CopyTo(sealedCookie.AsSpan(SealedOffsetNonce, NonceLength));

            Byte[]? rentedBody = null;
            Span<Byte> body    = bodyLength <= 256
                                     ? stackalloc Byte[bodyLength]
                                     : (rentedBody = ArrayPool<Byte>.Shared.Rent(bodyLength)).AsSpan(0, bodyLength);

            try
            {
                ntsCookie.WriteBodyTo(body);

                (MasterKey.Cipher ?? new AES_SIV(MasterKey.Value)).
                    Encrypt(
                        headerSpan,
                        ntsCookie.Nonce,
                        body,
                        sealedCookie.AsSpan(SealedOffsetAEAD, aeadLength)
                    );
            }
            finally
            {
                CryptographicOperations.ZeroMemory(body);
                if (rentedBody is not null)
                    ArrayPool<Byte>.Shared.Return(rentedBody);
            }

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

            => TryReadMasterKeyId(SealedCookie.AsSpan(), out MasterKeyId, out ErrorResponse);

        /// <summary>
        /// Read just the master key id from a sealed cookie span.
        /// </summary>
        [OverloadResolutionPriority(-1)]
        public static Boolean TryReadMasterKeyId(ReadOnlySpan<Byte>                SealedCookie,
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

            MasterKeyId = BinaryPrimitives.ReadUInt64BigEndian(SealedCookie.Slice(SealedOffsetMasterKeyId, 8));

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

            => TryParse(SealedCookie.AsSpan(), MasterKey, out NTSCookie, out ErrorResponse);

        /// <summary>
        /// Unseal a cookie from a read-only span using the master key that issued it.
        /// </summary>
        [OverloadResolutionPriority(-1)]
        public static Boolean TryParse(ReadOnlySpan<Byte>                    SealedCookie,
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

                var aeadLength   = (Int32) BinaryPrimitives.ReadUInt16BigEndian(SealedCookie.Slice(SealedOffsetAEADLength, 2));
                var sealedEnd    = SealedOffsetAEAD + aeadLength;
                var paddingBytes = SealedCookie.Length - sealedEnd;

                if (aeadLength < SyntheticIVLength ||
                    paddingBytes < 0 ||
                    paddingBytes > 3)
                {
                    ErrorResponse = $"The NTS cookie declares {aeadLength} bytes of ciphertext, which does not fit " +
                                    $"its {SealedCookie.Length} bytes!";
                    return false;
                }

                for (var i = sealedEnd; i < SealedCookie.Length; i++)
                {
                    if (SealedCookie[i] != 0)
                    {
                        ErrorResponse = "The NTS cookie contains non-zero trailing padding bytes!";
                        return false;
                    }
                }

                // Sliced to the declared length, so any RFC 7822 padding the extension field
                // added around the cookie is left out of the AEAD.
                var headerSpan     = SealedCookie.Slice(0, SealedOffsetNonce);
                var nonceSpan      = SealedCookie.Slice(SealedOffsetNonce, NonceLength);
                var aeadInputSpan  = SealedCookie.Slice(SealedOffsetAEAD,  aeadLength);
                var bodyLength     = aeadLength - SyntheticIVLength;

                Byte[]? rentedBody = null;
                Span<Byte> body    = bodyLength <= 256
                                         ? stackalloc Byte[bodyLength]
                                         : (rentedBody = ArrayPool<Byte>.Shared.Rent(bodyLength)).AsSpan(0, bodyLength);

                try
                {
                    (MasterKey.Cipher ?? new AES_SIV(MasterKey.Value)).
                        Decrypt(
                            headerSpan,
                            nonceSpan,
                            aeadInputSpan,
                            body
                        );

                    return TryParseBody(body, masterKeyId, nonceSpan.ToArray(), out NTSCookie, out ErrorResponse);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(body);
                    if (rentedBody is not null)
                        ArrayPool<Byte>.Shared.Return(rentedBody);
                }

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

            => TryParse(SealedCookie.AsSpan(), MasterKeys, out NTSCookie, out ErrorResponse);

        /// <summary>
        /// Unseal a cookie span by looking its master key up among the server's current and
        /// still-accepted keys, then checking the cookie falls inside that key's validity
        /// window.
        /// </summary>
        [OverloadResolutionPriority(-1)]
        public static Boolean TryParse(ReadOnlySpan<Byte>                                       SealedCookie,
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
