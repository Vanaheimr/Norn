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

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// One of the AEAD algorithms an NTS session can be built on, with the two facts about it
    /// that reach the wire.
    /// </summary>
    /// <remarks>
    /// The key length decides how much the RFC 8915 § 5.1 exporter is asked for and how large a
    /// cookie has to be; the nonce length decides the shape of the Authenticator extension field
    /// of § 5.6. Everything else about an AEAD is interchangeable from NTS's point of view,
    /// which is why the protocol can negotiate one at all.
    /// </remarks>
    public interface INTSAEAD
    {

        /// <summary>Which registered algorithm this is.</summary>
        AEADAlgorithms  Algorithm    { get; }

        /// <summary>The key length in octets.</summary>
        Int32           KeyLength    { get; }

        /// <summary>The nonce length in octets that this implementation generates.</summary>
        Int32           NonceLength  { get; }

        /// <summary>Seal, returning ciphertext with the tag appended.</summary>
        Byte[] Encrypt(Byte[] AssociatedData, Byte[] Nonce, Byte[] Plaintext);

        /// <summary>Open, or throw if the tag does not verify.</summary>
        Byte[] Decrypt(Byte[] AssociatedData, Byte[] Nonce, Byte[] Ciphertext);

    }


    /// <summary>
    /// The AEAD algorithms this implementation can actually use, and how to build one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="AEADAlgorithms"/> enumerates the whole IANA registry so that any of it can be
    /// named in a negotiation and refused precisely. This is the much shorter list of what is
    /// implemented, and the two must not be confused: offering an algorithm that cannot be
    /// performed produces a key exchange that succeeds and a time query that never validates.
    /// </para>
    /// <para>
    /// Two lists, and the gap between them is the interesting part: <see cref="Implemented"/> is
    /// what the code can do, <see cref="Supported"/> is what it will agree to. Offering an
    /// algorithm that cannot be performed produces a key exchange that succeeds and a time query
    /// that never validates — and so does offering one that can be performed but does not
    /// interoperate, which is why the two lists currently differ.
    /// </para>
    /// <para>
    /// Where several are on offer, § 4.1.5 has the server choose from the client's list in the
    /// client's order.
    /// </para>
    /// </remarks>
    public static class NTSAEAD
    {

        #region Data

        /// <summary>
        /// The algorithms this implementation can perform.
        /// </summary>
        /// <remarks>
        /// Everything <see cref="Create"/> can build. Not the same as <see cref="Supported"/>,
        /// and the difference is deliberate — see there.
        /// </remarks>
        public static readonly AEADAlgorithms[] Implemented = [
                                                     AEADAlgorithms.AES_SIV_CMAC_256,
                                                     AEADAlgorithms.AES_128_GCM_SIV,
                                                     AEADAlgorithms.AES_256_GCM_SIV
                                                 ];

        /// <summary>
        /// The algorithms this implementation offers and accepts in a key exchange, in
        /// descending order of preference.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Shorter than <see cref="Implemented"/> on purpose, and the reason is worth recording
        /// rather than smoothing over. AES-GCM-SIV is implemented here and matches all
        /// twenty-four of RFC 8452's published vectors, and a Norn client and a Norn server
        /// complete a session on it — but against chronyd, which prefers it, every NTP packet
        /// fails in both directions while AES-SIV-CMAC-256 continues to work. The cause has not
        /// been found. The suspicion is the TLS exporter rather than the AEAD, since the two
        /// sides differ only in asking for a sixteen-octet key instead of a thirty-two-octet
        /// one, but that is a suspicion and not a finding.
        /// </para>
        /// <para>
        /// So it is not offered. An algorithm that two implementations agree on and then cannot
        /// use is worse than one that is never agreed: the key exchange succeeds, the time
        /// queries fail, and nothing in either says why. A caller who wants it anyway can pass
        /// it explicitly through the client's offered list.
        /// </para>
        /// </remarks>
        public static readonly AEADAlgorithms[] Supported = [
                                                     AEADAlgorithms.AES_SIV_CMAC_256
                                                 ];

        /// <summary>
        /// The algorithm assumed where none was negotiated.
        /// </summary>
        /// <remarks>
        /// RFC 8915 § 5.1 makes AEAD_AES_SIV_CMAC_256 the one a conformant implementation must
        /// have, so it is the only safe thing to fall back to — and the only one whose absence
        /// would be a defect rather than a choice.
        /// </remarks>
        public const AEADAlgorithms Default = AEADAlgorithms.AES_SIV_CMAC_256;

        #endregion


        #region IsSupported(Algorithm)

        /// <summary>
        /// Whether this implementation can perform the given algorithm.
        /// </summary>
        /// <remarks>
        /// Against <see cref="Implemented"/> rather than <see cref="Supported"/>: this answers
        /// "could this be done", which is the question a validator and a cookie reader ask. What
        /// gets offered in a key exchange is the narrower list, and that decision belongs to the
        /// negotiation rather than here.
        /// </remarks>
        public static Boolean IsSupported(AEADAlgorithms Algorithm)

            => Implemented.Contains(Algorithm);

        #endregion

        #region KeyLength(Algorithm)

        /// <summary>
        /// The key length in octets, or null for an algorithm this implementation cannot perform.
        /// </summary>
        /// <remarks>
        /// This is what the § 5.1 exporter is asked for, so getting it wrong produces two peers
        /// with keys of different lengths and no indication of why nothing validates.
        /// </remarks>
        public static Int32? KeyLength(AEADAlgorithms Algorithm)

            => Algorithm switch {
                   AEADAlgorithms.AES_SIV_CMAC_256  => 32,
                   AEADAlgorithms.AES_128_GCM_SIV   => 16,
                   AEADAlgorithms.AES_256_GCM_SIV   => 32,
                   _                                => null
               };

        #endregion

        #region NonceLength(Algorithm)

        /// <summary>
        /// The nonce length in octets, or null for an algorithm this implementation cannot
        /// perform.
        /// </summary>
        /// <remarks>
        /// AES-SIV takes a nonce of any length — it is simply one more associated-data component
        /// — and sixteen octets is what this implementation has always sent. AES-GCM-SIV takes
        /// exactly twelve, and RFC 8452 § 6 admits no other length.
        /// </remarks>
        public static Int32? NonceLength(AEADAlgorithms Algorithm)

            => Algorithm switch {
                   AEADAlgorithms.AES_SIV_CMAC_256  => 16,
                   AEADAlgorithms.AES_128_GCM_SIV   => AES_GCM_SIV.NonceLength,
                   AEADAlgorithms.AES_256_GCM_SIV   => AES_GCM_SIV.NonceLength,
                   _                                => null
               };

        #endregion

        #region Create(Algorithm, Key)

        /// <summary>
        /// Build an AEAD context for the given algorithm and key.
        /// </summary>
        /// <exception cref="NotSupportedException">The algorithm is not implemented here.</exception>
        /// <exception cref="ArgumentException">The key is the wrong length for it.</exception>
        public static INTSAEAD Create(AEADAlgorithms  Algorithm,
                                      Byte[]          Key)
        {

            var keyLength = KeyLength(Algorithm)
                                ?? throw new NotSupportedException(
                                       $"AEAD algorithm {Algorithm.AsText()} ({(UInt16) Algorithm}) is registered with " +
                                       $"IANA but not implemented here.");

            if (Key is null || Key.Length != keyLength)
                throw new ArgumentException($"{Algorithm.AsText()} needs a {keyLength}-byte key, but got " +
                                            $"{Key?.Length.ToString() ?? "none"}.",
                                            nameof(Key));

            return Algorithm switch {
                       AEADAlgorithms.AES_SIV_CMAC_256  => new AesSivAEAD    (Key),
                       _                                => new AesGcmSivAEAD (Algorithm, Key)
                   };

        }

        #endregion

    }


    /// <summary>AEAD_AES_SIV_CMAC_256, the algorithm RFC 8915 § 5.1 requires.</summary>
    internal sealed class AesSivAEAD(Byte[] Key) : INTSAEAD
    {

        private readonly AES_SIV aesSiv = new (Key);

        public AEADAlgorithms  Algorithm    => AEADAlgorithms.AES_SIV_CMAC_256;
        public Int32           KeyLength    => 32;
        public Int32           NonceLength  => 16;

        // AES-SIV takes a vector of associated-data components rather than one string; NTS uses
        // exactly one, so the vector always has a single element.
        public Byte[] Encrypt(Byte[] AssociatedData, Byte[] Nonce, Byte[] Plaintext)
            => aesSiv.Encrypt([ AssociatedData ], Nonce, Plaintext);

        public Byte[] Decrypt(Byte[] AssociatedData, Byte[] Nonce, Byte[] Ciphertext)
            => aesSiv.Decrypt([ AssociatedData ], Nonce, Ciphertext);

    }


    /// <summary>AEAD_AES_128_GCM_SIV and AEAD_AES_256_GCM_SIV (RFC 8452).</summary>
    internal sealed class AesGcmSivAEAD(AEADAlgorithms Algorithm, Byte[] Key) : INTSAEAD
    {

        private readonly AES_GCM_SIV aesGcmSiv = new (Key);

        public AEADAlgorithms  Algorithm    { get; } = Algorithm;
        public Int32           KeyLength    => Key.Length;
        public Int32           NonceLength  => AES_GCM_SIV.NonceLength;

        public Byte[] Encrypt(Byte[] AssociatedData, Byte[] Nonce, Byte[] Plaintext)
            => aesGcmSiv.Encrypt(AssociatedData, Nonce, Plaintext);

        public Byte[] Decrypt(Byte[] AssociatedData, Byte[] Nonce, Byte[] Ciphertext)
            => aesGcmSiv.Decrypt(AssociatedData, Nonce, Ciphertext);

    }

}
