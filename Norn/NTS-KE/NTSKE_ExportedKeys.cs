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

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// The client-to-server and server-to-client keys of RFC 8915 § 5.1, derived from a finished
    /// NTS-KE handshake for every algorithm that could still be agreed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every algorithm, because the TLS exporter can only be used from the handshake-complete
    /// callback. BouncyCastle discards the exporter secret the moment it returns — "Export of key
    /// material only available from NotifyHandshakeComplete()" — while the AEAD is not agreed
    /// until the records have been exchanged, which is necessarily later. Deriving on demand is
    /// the natural design and it is not available, so the derivation happens eagerly and the
    /// selection happens afterwards.
    /// </para>
    /// <para>
    /// The cost is small and worth stating: four key pairs of at most thirty-two octets each, of
    /// which three are discarded unused. They live as long as the TLS peer object does, which is
    /// one key exchange.
    /// </para>
    /// <para>
    /// This lives here rather than in the TLS client and the TLS service, which is where it used
    /// to live twice. Two copies of a key derivation are two chances for one side to drift, and
    /// the failure mode is silent: a client and a server that derive different keys complete the
    /// key exchange perfectly and then reject every packet.
    /// </para>
    /// </remarks>
    public sealed class NTSKE_ExportedKeys
    {

        #region Data

        /// <summary>
        /// The exporter label of RFC 8915 § 5.1, which is the same for both keys and every
        /// algorithm.
        /// </summary>
        public const String ExporterLabel = "EXPORTER-network-time-security";

        /// <summary>
        /// Keyed by the algorithm the session will use <em>and</em> the algorithm id written into
        /// the exporter context, because for AES-128-GCM-SIV those two are not always the same —
        /// see <see cref="ExporterAlgorithmFor"/>.
        /// </summary>
        private readonly Dictionary<(AEADAlgorithms Algorithm, AEADAlgorithms ExporterAlgorithm),
                                    (Byte[] C2SKey, Byte[] S2CKey)> keys = [];

        #endregion

        #region Constructor(s)

        private NTSKE_ExportedKeys()
        { }

        #endregion


        #region ExporterAlgorithmFor(Algorithm, CompliantExporterContext)

        /// <summary>
        /// The algorithm id that goes into the § 5.1 exporter context, which is the negotiated
        /// algorithm except where a peer has asked for chrony's non-compliant derivation.
        /// </summary>
        /// <param name="Algorithm">The algorithm the session will actually be encrypted with.</param>
        /// <param name="CompliantExporterContext">
        /// Whether both peers confirmed the compliant context by exchanging the NTS-KE record
        /// <see cref="NTSKE_RecordTypes.CompliantAES128GCMSIVExporterContext"/>.
        /// </param>
        /// <remarks>
        /// <para>
        /// RFC 8915 § 5.1 puts the negotiated algorithm's id in the context, and for every
        /// algorithm but one that is the end of it. chrony writes 15 (AES-SIV-CMAC-256) there
        /// when the session runs on 30 (AES-128-GCM-SIV) — the key length is taken from the real
        /// algorithm, only the two context octets are wrong — and it has done so since it first
        /// shipped algorithm 30. Correcting it outright would have broken every deployed pair, so
        /// chrony instead negotiates its way out: record type 1024, registered with IANA as
        /// "Compliant AES-128-GCM-SIV Exporter Context", sent by a client that can do it and
        /// echoed by a server that agrees. Only when both have said so does the compliant context
        /// get used.
        /// </para>
        /// <para>
        /// So Norn honours the quirk exactly where it must and nowhere else. Two peers deriving
        /// the same wrong key agree with each other perfectly, which is why this was invisible
        /// until an independent implementation was on the other end: Norn spoke § 5.1 correctly,
        /// chronyd spoke chrony, the key exchange succeeded, and every NTP packet after it failed
        /// in both directions with nothing to say why.
        /// </para>
        /// </remarks>
        public static AEADAlgorithms ExporterAlgorithmFor(AEADAlgorithms  Algorithm,
                                                          Boolean         CompliantExporterContext)

            => CompliantExporterContext || Algorithm != AEADAlgorithms.AES_128_GCM_SIV
                   ? Algorithm
                   : AEADAlgorithms.AES_SIV_CMAC_256;

        #endregion

        #region Context(ExporterAlgorithm, ServerToClient)

        /// <summary>
        /// The five-octet per-association context of RFC 8915 § 5.1: the protocol id (0 for
        /// NTPv4), the algorithm id in network byte order, and a final octet that is 0 for the
        /// client-to-server key and 1 for the other direction.
        /// </summary>
        /// <remarks>
        /// Those five octets are the only thing separating the two keys of a session, and the
        /// algorithm id among them is why each algorithm needs its own derivation rather than one
        /// output truncated to different lengths — the length is part of what HKDF expands.
        /// </remarks>
        public static Byte[] Context(AEADAlgorithms  ExporterAlgorithm,
                                     Boolean         ServerToClient)
        {

            var algorithmBytes = ExporterAlgorithm.GetBytes();

            return [
                       0x00,
                       0x00,
                       algorithmBytes[0],
                       algorithmBytes[1],
                       ServerToClient ? (Byte) 0x01 : (Byte) 0x00
                   ];

        }

        #endregion

        #region (static) ExportAll(TLSContext)

        /// <summary>
        /// Derive every key pair that this key exchange could still turn out to need.
        /// </summary>
        /// <param name="TLSContext">A TLS context inside its handshake-complete callback.</param>
        public static NTSKE_ExportedKeys ExportAll(TlsContext TLSContext)
        {

            var exportedKeys = new NTSKE_ExportedKeys();

            // Implemented rather than Supported: the narrower list is what this peer offers, but
            // the other side may name anything from the wider one and be agreed with — and the
            // exporter is unavailable by the time that is known.
            foreach (var algorithm in NTSAEAD.Implemented)
            {

                exportedKeys.Export(TLSContext, algorithm, CompliantExporterContext: true);

                // And the same algorithm again under chrony's context, for a peer that turns out
                // not to have asked for the compliant one.
                if (ExporterAlgorithmFor(algorithm, CompliantExporterContext: false) != algorithm)
                    exportedKeys.Export(TLSContext, algorithm, CompliantExporterContext: false);

            }

            return exportedKeys;

        }

        #endregion

        #region (private) Export(TLSContext, Algorithm, CompliantExporterContext)

        private void Export(TlsContext      TLSContext,
                            AEADAlgorithms  Algorithm,
                            Boolean         CompliantExporterContext)
        {

            // The length comes from the algorithm the session will use, the context from the one
            // the peers agreed to name. For everything but chrony's AES-128-GCM-SIV they are the
            // same algorithm.
            var keyLength          = NTSAEAD.KeyLength(Algorithm)!.Value;
            var exporterAlgorithm  = ExporterAlgorithmFor(Algorithm, CompliantExporterContext);

            keys[(Algorithm, exporterAlgorithm)] = (
                TLSContext.ExportKeyingMaterial(
                    ExporterLabel,
                    Context(exporterAlgorithm, ServerToClient: false),
                    keyLength
                ),
                TLSContext.ExportKeyingMaterial(
                    ExporterLabel,
                    Context(exporterAlgorithm, ServerToClient: true),
                    keyLength
                )
            );

        }

        #endregion

        #region For(Algorithm, CompliantExporterContext = true)

        /// <summary>
        /// The keys for the agreed algorithm.
        /// </summary>
        /// <param name="Algorithm">The AEAD algorithm the key exchange settled on.</param>
        /// <param name="CompliantExporterContext">
        /// Whether both peers confirmed RFC 8915 § 5.1's context for AES-128-GCM-SIV. Ignored for
        /// every other algorithm, which has only one context.
        /// </param>
        /// <exception cref="NotSupportedException">
        /// No keys were derived for it, which means it is not one this implementation supports —
        /// and so not one it should have agreed to.
        /// </exception>
        public (Byte[] C2SKey, Byte[] S2CKey) For(AEADAlgorithms  Algorithm,
                                                  Boolean         CompliantExporterContext   = true)
        {

            var exporterAlgorithm = ExporterAlgorithmFor(Algorithm, CompliantExporterContext);

            if (!keys.TryGetValue((Algorithm, exporterAlgorithm), out var keyPair))
                throw new NotSupportedException(
                          $"No NTS keys were derived for AEAD algorithm {Algorithm.AsText()} " +
                          $"({(UInt16) Algorithm}), so it is not one this implementation can use.");

            return keyPair;

        }

        #endregion

    }

}
