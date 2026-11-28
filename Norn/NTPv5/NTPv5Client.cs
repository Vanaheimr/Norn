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
using System.Security.Cryptography;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTPv5
{

    #region NTPv5ClientNTS

    /// <summary>
    /// What a client needs of an NTS key exchange that negotiated NTPv5 (0x8001) to send one
    /// request under it: the keys, the algorithm, the cookie it spends, and how many
    /// placeholders to add for as many more cookies in the response.
    /// </summary>
    public sealed record NTPv5ClientNTS(Byte[]          C2SKey,
                                        Byte[]          S2CKey,
                                        AEADAlgorithms  AEADAlgorithm,
                                        Byte[]          Cookie,
                                        Int32           Placeholders = 0);

    #endregion

    #region NTPv5ClientRequest

    /// <summary>
    /// An NTPv5 request as a client sent it, and what it has to remember to judge the answer:
    /// the client cookie and flags of § 9.4, the timescale of § 9.5, the Unique Identifier of
    /// an NTS request, and which extension fields it asked to have answered.
    /// </summary>
    /// <param name="Packet">The request as sent, NTS fields included.</param>
    /// <param name="Datagram">The octets as sent.</param>
    /// <param name="UniqueIdentifier">The Unique Identifier of an NTS request; null for a plain one.</param>
    /// <param name="NTS">The NTS parameters it was sealed with; null for a plain one.</param>
    public sealed record NTPv5ClientRequest(NTPv5Packet      Packet,
                                            Byte[]           Datagram,
                                            Byte[]?          UniqueIdentifier,
                                            NTPv5ClientNTS?  NTS)
    {

        /// <summary>
        /// The client cookie the response must carry.
        /// </summary>
        public UInt64          ClientCookie
            => Packet.ClientCookie;

        /// <summary>
        /// The flags of the request, the only ones a valid response may set.
        /// </summary>
        public NTPv5Flags      Flags
            => Packet.Flags;

        /// <summary>
        /// The timescale asked for.
        /// </summary>
        public NTPv5Timescale  Timescale
            => Packet.Timescale;

        /// <summary>
        /// Whether the request is an NTS one.
        /// </summary>
        public Boolean         IsNTS
            => NTS is not null;

        /// <summary>
        /// Whether the request carries a Correction, which alone makes one in the response
        /// something to read: § 7.7 has a client "ignore an unexpected Correction Extension
        /// Field in the response".
        /// </summary>
        public Boolean         CorrectionRequested
            => Packet.Find(NTPv5ExtensionTypes.Correction) is not null;

        /// <summary>
        /// Whether the request asks for the server's reference IDs.
        /// </summary>
        public Boolean         ReferenceIdsRequested
            => Packet.Find(NTPv5ExtensionTypes.ReferenceIDsRequest) is not null;

    }

    #endregion

    #region NTPv5ResponseStatus

    /// <summary>
    /// What came of checking a datagram against a request, as § 9.4 has a client do.
    /// </summary>
    public enum NTPv5ResponseStatus
    {

        /// <summary>
        /// A valid response to the request.
        /// </summary>
        Valid,

        /// <summary>
        /// Not an NTPv5 message: too short, not a whole number of 4 octets, not version 5, or
        /// with an extension field running past its end.
        /// </summary>
        Malformed,

        /// <summary>
        /// An NTPv5 message, but not in mode 4.
        /// </summary>
        NotAResponse,

        /// <summary>
        /// The client cookie is not the request's: an answer to some other request, or a
        /// forgery. Also what an NTPv4 server's answer to an NTPv5 request looks like (§ 12).
        /// </summary>
        WrongClientCookie,

        /// <summary>
        /// A flag this client does not know.
        /// </summary>
        UnknownFlags,

        /// <summary>
        /// A flag the request did not set.
        /// </summary>
        UnrequestedFlags,

        /// <summary>
        /// The Draft Identification of the response names another draft than the request did.
        /// </summary>
        OtherDraft,

        /// <summary>
        /// The response to an NTS request does not authenticate.
        /// </summary>
        NotAuthenticated,

        /// <summary>
        /// An Authentication NAK (flag 0x4) to an NTS request that asked for one: the server
        /// could not authenticate the request. Not valid as time, and unauthenticated itself,
        /// so it is a reason to renegotiate only when no valid response followed it.
        /// </summary>
        AuthenticationNAK

    }

    #endregion

    #region NTPv5ResponseValidation

    /// <summary>
    /// The result of checking a datagram against a request (§ 9.4).
    /// </summary>
    /// <param name="Status">What came of it.</param>
    /// <param name="Packet">The message, where it parsed.</param>
    /// <param name="ErrorMessage">Why it is not valid, when it is not.</param>
    /// <param name="Cookies">The new cookies an authenticated response delivered.</param>
    public sealed record NTPv5ResponseValidation(NTPv5ResponseStatus    Status,
                                                 NTPv5Packet?           Packet,
                                                 String?                ErrorMessage,
                                                 IReadOnlyList<Byte[]>  Cookies)
    {

        /// <summary>
        /// Whether the response is valid.
        /// </summary>
        [MemberNotNullWhen(true, nameof(Packet))]
        public Boolean IsValid
            => Status == NTPv5ResponseStatus.Valid;

    }

    #endregion

    #region NTPv5Unusable

    /// <summary>
    /// Why a valid response is not usable for synchronization (§ 9.5), or None where it is.
    /// </summary>
    public enum NTPv5Unusable
    {

        /// <summary>
        /// The response is usable.
        /// </summary>
        None,

        /// <summary>
        /// The Unsynchronized flag is set.
        /// </summary>
        Unsynchronized,

        /// <summary>
        /// The stratum is 0 or above the maximum.
        /// </summary>
        Stratum,

        /// <summary>
        /// The root delay is above the maximum, or infinite.
        /// </summary>
        RootDelay,

        /// <summary>
        /// The root dispersion is above the maximum, or infinite.
        /// </summary>
        RootDispersion,

        /// <summary>
        /// The timescale is not the one asked for.
        /// </summary>
        Timescale,

        /// <summary>
        /// The receive or the transmit timestamp is 0.
        /// </summary>
        MissingTimestamps,

        /// <summary>
        /// The era places the timestamps outside the range of a date.
        /// </summary>
        Era

    }

    #endregion

    #region NTPv5UsabilityLimits

    /// <summary>
    /// The configured maximums of § 9.5.
    /// </summary>
    /// <param name="MaximumStratum">The largest stratum to accept, by default 15.</param>
    /// <param name="MaximumRootDelay">The largest root delay to accept, by default 4 seconds.</param>
    /// <param name="MaximumRootDispersion">The largest root dispersion to accept, by default 4 seconds.</param>
    public sealed record NTPv5UsabilityLimits(Byte      MaximumStratum         = 15,
                                              TimeSpan? MaximumRootDelay       = null,
                                              TimeSpan? MaximumRootDispersion  = null)
    {

        /// <summary>
        /// The example of § 9.5 for both root delay and root dispersion.
        /// </summary>
        public static readonly TimeSpan DefaultMaximumRoot = TimeSpan.FromSeconds(4);

        /// <summary>
        /// The limits § 9.5 gives as examples.
        /// </summary>
        public static NTPv5UsabilityLimits Default { get; } = new ();

        /// <summary>
        /// The largest root delay to accept.
        /// </summary>
        public TimeSpan RootDelayLimit
            => MaximumRootDelay      ?? DefaultMaximumRoot;

        /// <summary>
        /// The largest root dispersion to accept.
        /// </summary>
        public TimeSpan RootDispersionLimit
            => MaximumRootDispersion ?? DefaultMaximumRoot;

    }

    #endregion

    #region NTPv5CorrectionParameters

    /// <summary>
    /// What § 8 needs besides the corrections themselves: the maximum frequency error of the
    /// devices that made them, and the times the frames took to receive and to transmit.
    /// </summary>
    /// <param name="FrequencyError">FC, the maximum expected frequency error (e.g. 100 ppm).</param>
    /// <param name="ReceiveFrameTime">Drx, the time it took to receive the frame of the response.</param>
    /// <param name="TransmitFrameTime">Dtx, the time it took to transmit the frame of the request; null for "unknown", which § 8 sets to Drx.</param>
    public sealed record NTPv5CorrectionParameters(Double     FrequencyError     = 100e-6,
                                                   TimeSpan   ReceiveFrameTime   = default,
                                                   TimeSpan?  TransmitFrameTime  = null)
    {

        /// <summary>
        /// 100 ppm, no frame times: as much as a client in user space can know.
        /// </summary>
        public static NTPv5CorrectionParameters Default { get; } = new ();

    }

    #endregion

    #region NTPv5Measurement

    /// <summary>
    /// One measurement of § 8: the four timestamps, the offset and delay of § 4.1, and the
    /// corrected pair where the network delivered corrections that pass their checks.
    /// </summary>
    /// <param name="T1">The client's transmit time of the request.</param>
    /// <param name="T2">The server's receive time of the request, its era expanded.</param>
    /// <param name="T3">The server's transmit time of the response.</param>
    /// <param name="T4">The client's receive time of the response.</param>
    /// <param name="Interleaved">Whether T3 came in the interleaved mode, one response late.</param>
    /// <param name="Correction">The Correction of the response that T3 and T4 belong to, where the request asked for one.</param>
    /// <param name="CorrectedOffset">offset_c of § 8, where the corrections are acceptable.</param>
    /// <param name="CorrectedDelay">delay_c of § 8, where the corrections are acceptable.</param>
    public sealed record NTPv5Measurement(DateTime          T1,
                                          DateTime          T2,
                                          DateTime          T3,
                                          DateTime          T4,
                                          Boolean           Interleaved,
                                          NTPv5Correction?  Correction,
                                          TimeSpan?         CorrectedOffset,
                                          TimeSpan?         CorrectedDelay)
    {

        /// <summary>
        /// Eq. (1) of § 4.1: ((T2 + T3) - (T4 + T1)) / 2.
        /// </summary>
        public TimeSpan Offset
            => TimeSpan.FromTicks(((T2 - T1).Ticks + (T3 - T4).Ticks) / 2);

        /// <summary>
        /// Eq. (2) of § 4.1: |(T4 - T1) - (T3 - T2)|. The uncorrected delay, which § 8 has the
        /// root delay always computed from.
        /// </summary>
        public TimeSpan Delay
            => ((T4 - T1) - (T3 - T2)).Duration();

        /// <summary>
        /// The offset to synchronize to: the corrected one where there is one, as § 8 has a
        /// client prefer.
        /// </summary>
        public TimeSpan BestOffset
            => CorrectedOffset ?? Offset;

        /// <summary>
        /// The delay to weigh the measurement by: the corrected one where there is one.
        /// </summary>
        public TimeSpan BestDelay
            => CorrectedDelay ?? Delay;

    }

    #endregion


    /// <summary>
    /// The client side of NTPv5 after draft-ietf-ntp-ntpv5-10 § 9, free of I/O and of any
    /// clock: building a request, checking a response for validity (§ 9.4) and usability
    /// (§ 9.5), expanding its era, and computing the measurement of § 8.
    /// </summary>
    public static class NTPv5Client
    {

        #region Data

        /// <summary>
        /// The flags this client knows (§ 6). A response with any other is invalid, § 9.4:
        /// "Flags are all known".
        /// </summary>
        public const NTPv5Flags KnownFlags = NTPv5Flags.Unsynchronized |
                                             NTPv5Flags.InterleavedMode |
                                             NTPv5Flags.AuthenticationNAK;

        /// <summary>
        /// A Delay Correction "too big to be represented" (§ 7.7): every bit set but the most
        /// significant, as in the PTP correctionField.
        /// </summary>
        public const Int64 CorrectionOverflow = Int64.MaxValue;

        /// <summary>
        /// The Delay Correction counts nanoseconds in 48.16 fixed point: 2^16 units to one.
        /// </summary>
        public const Int64 CorrectionUnitsPerNanosecond = 1L << 16;

        #endregion


        #region BuildRequest(Timescale, Flags, ServerCookie, RequestCorrection, RequestReferenceIds, ExtensionFields, NTS, UniqueIdentifier, ClientCookie)

        /// <summary>
        /// A request of § 9 step 2: a new random client cookie, the timescale and flags asked
        /// for, the server cookie in the interleaved mode, the Draft Identification, and
        /// whatever else the client wants answered. Under NTS it is sealed as § 11 has it and
        /// asks for an Authentication NAK, so that a server which can no longer read the
        /// cookie says so instead of keeping silent.
        /// </summary>
        /// <param name="Timescale">The timescale to operate in.</param>
        /// <param name="Flags">Unsynchronized and interleaved as wanted; Authentication NAK is added under NTS.</param>
        /// <param name="ServerCookie">The server cookie of the last valid response, in the interleaved mode only.</param>
        /// <param name="RequestCorrection">Whether to add a zeroed Correction as the last field (§ 7.7).</param>
        /// <param name="RequestReferenceIds">Whether to ask for all 32 reference IDs (§ 7.4), as a client that serves time "MUST".</param>
        /// <param name="ExtensionFields">Further fields, after the Draft Identification and before NTS.</param>
        /// <param name="NTS">The NTS parameters to seal it with; null for a plain request.</param>
        /// <param name="UniqueIdentifier">The Unique Identifier of an NTS request, by default 32 random octets.</param>
        /// <param name="ClientCookie">The client cookie, by default a new random one, as § 9 step 1 has every poll do.</param>
        public static NTPv5ClientRequest BuildRequest(NTPv5Timescale                     Timescale            = NTPv5Timescale.UTC,
                                                      NTPv5Flags                         Flags                = NTPv5Flags.None,
                                                      UInt64                             ServerCookie         = 0,
                                                      Boolean                            RequestCorrection    = false,
                                                      Boolean                            RequestReferenceIds  = false,
                                                      IEnumerable<NTPv5ExtensionField>?  ExtensionFields      = null,
                                                      NTPv5ClientNTS?                    NTS                  = null,
                                                      Byte[]?                            UniqueIdentifier     = null,
                                                      UInt64?                            ClientCookie         = null)
        {

            // § 9 step 2: the server cookie "is set only in the interleaved mode".
            if (!Flags.HasFlag(NTPv5Flags.InterleavedMode))
                ServerCookie = 0;

            if (NTS is not null)
                Flags |= NTPv5Flags.AuthenticationNAK;
            else
                Flags &= ~NTPv5Flags.AuthenticationNAK;

            var fields = new List<NTPv5ExtensionField>(ExtensionFields ?? []);

            if (RequestReferenceIds)
                fields.Add(NTPv5ReferenceIds.Request());

            // § 7.7: the Correction "MUST be the last extension field in the NTP message" -
            // under NTS after the authenticator, which it is the one exception to.
            var correction = RequestCorrection
                                 ? NTPv5ExtensionField.Correction()
                                 : null;

            if (NTS is null)
            {

                if (correction is not null)
                    fields.Add(correction);

                var plain = NTPv5Packet.Request(ClientCookie:     ClientCookie,
                                                Timescale:        Timescale,
                                                Flags:            Flags,
                                                ServerCookie:     ServerCookie,
                                                ExtensionFields:  fields);

                return new (plain, plain.ToByteArray(), null, null);

            }

            var unsealed   = NTPv5Packet.Request(ClientCookie:     ClientCookie,
                                                 Timescale:        Timescale,
                                                 Flags:            Flags,
                                                 ServerCookie:     ServerCookie,
                                                 ExtensionFields:  fields);

            var uniqueId   = UniqueIdentifier ?? RandomNumberGenerator.GetBytes(NTPv5NTS.MinimumUniqueIdentifierLength);

            var datagram   = NTPv5NTS.BuildRequest(unsealed,
                                                   NTS.C2SKey,
                                                   NTS.AEADAlgorithm,
                                                   NTS.Cookie,
                                                   uniqueId,
                                                   NTS.Placeholders,
                                                   correction is not null ? [correction] : null);

            if (!NTPv5Packet.TryParse(datagram, out var sealedPacket, out var error))
                throw new InvalidOperationException("The NTS request just built does not parse: " + error);

            return new (sealedPacket, datagram, uniqueId, NTS);

        }

        #endregion

        #region Validate(Datagram, Request)

        /// <summary>
        /// § 9.4: whether a datagram is a valid response to the request - version 5, mode 4,
        /// only known flags and none the request did not set, the request's client cookie,
        /// and, under NTS, an authenticator that verifies. An Authentication NAK the request
        /// asked for is told apart, because it is what a client renegotiates on.
        /// </summary>
        /// <remarks>
        /// One check beyond § 9.4: a Draft Identification naming another draft than the
        /// request did makes the response invalid. § 7.1 has a server answer "according to the
        /// same draft specification as given by the client", and one that names another is
        /// speaking a format this client cannot be sure it reads right.
        /// </remarks>
        public static NTPv5ResponseValidation Validate(ReadOnlySpan<Byte>  Datagram,
                                                       NTPv5ClientRequest  Request)
        {

            if (!NTPv5Packet.TryParse(Datagram, out var packet, out var parseError))
                return Invalid(NTPv5ResponseStatus.Malformed, null, parseError);

            if (packet.Mode != NTPv5Packet.ResponseMode)
                return Invalid(NTPv5ResponseStatus.NotAResponse, packet, $"Mode {packet.Mode} is not a response!");

            if (packet.ClientCookie != Request.ClientCookie)
                return Invalid(NTPv5ResponseStatus.WrongClientCookie, packet, "The client cookie is not the request's!");

            if ((packet.Flags & ~KnownFlags) != 0)
                return Invalid(NTPv5ResponseStatus.UnknownFlags, packet, $"Unknown flags 0x{(UInt16) (packet.Flags & ~KnownFlags):x4}!");

            if ((packet.Flags & ~Request.Flags) != 0)
                return Invalid(NTPv5ResponseStatus.UnrequestedFlags, packet, $"Flags 0x{(UInt16) (packet.Flags & ~Request.Flags):x4} were not requested!");

            var requestDraft  = Request.Packet.DraftIdentification;
            var responseDraft = packet.DraftIdentification;

            if (requestDraft  is not null &&
                responseDraft is not null &&
                !requestDraft.AsSpan().SequenceEqual(responseDraft))
                return Invalid(NTPv5ResponseStatus.OtherDraft, packet, "The response names another draft: " + NTPv5Draft.Describe(responseDraft));

            if (Request.NTS is null)
                return new (NTPv5ResponseStatus.Valid, packet, null, []);

            // An Authentication NAK carries no authenticator of its own (§ 11): it is told
            // apart by its flag, which the request set, and by the Unique Identifier it echoes.
            if (packet.Flags.HasFlag(NTPv5Flags.AuthenticationNAK))
            {

                var uniqueId = packet.Find(NTPv5ExtensionTypes.UniqueIdentifier);

                return uniqueId is not null &&
                       Request.UniqueIdentifier is not null &&
                       uniqueId.Value.AsSpan().SequenceEqual(Request.UniqueIdentifier)
                           ? Invalid(NTPv5ResponseStatus.AuthenticationNAK, packet, "The server could not authenticate the request (Authentication NAK).")
                           : Invalid(NTPv5ResponseStatus.NotAuthenticated,  packet, "An Authentication NAK that does not echo the Unique Identifier of the request!");

            }

            if (!NTPv5NTS.TryVerifyResponse(Datagram,
                                            Request.UniqueIdentifier!,
                                            Request.NTS.S2CKey,
                                            Request.NTS.AEADAlgorithm,
                                            out var verified,
                                            out var cookies,
                                            out var ntsError))
                return Invalid(NTPv5ResponseStatus.NotAuthenticated, packet, ntsError);

            return new (NTPv5ResponseStatus.Valid, verified, null, cookies);

        }

        #endregion

        #region CheckUsable(Response, Request, Limits = null)

        /// <summary>
        /// § 9.5: whether a valid response is usable for synchronization - not unsynchronized,
        /// a stratum of 1 to the maximum, root delay and dispersion within their limits, the
        /// timescale asked for, and both timestamps set.
        /// </summary>
        /// <remarks>
        /// A different timescale is reported, not converted: § 9.5 leaves it to the client to
        /// switch, convert or ignore, and the choice belongs to whatever combines servers.
        /// </remarks>
        public static NTPv5Unusable CheckUsable(NTPv5Packet            Response,
                                                NTPv5ClientRequest     Request,
                                                NTPv5UsabilityLimits?  Limits = null)
        {

            Limits ??= NTPv5UsabilityLimits.Default;

            if (Response.Flags.HasFlag(NTPv5Flags.Unsynchronized))
                return NTPv5Unusable.Unsynchronized;

            if (Response.Stratum == 0 || Response.Stratum > Limits.MaximumStratum)
                return NTPv5Unusable.Stratum;

            var rootDelay = Response.RootDelayTime;
            if (rootDelay is null || rootDelay.Value > Limits.RootDelayLimit)
                return NTPv5Unusable.RootDelay;

            var rootDispersion = Response.RootDispersionTime;
            if (rootDispersion is null || rootDispersion.Value > Limits.RootDispersionLimit)
                return NTPv5Unusable.RootDispersion;

            if (Response.Timescale != Request.Timescale)
                return NTPv5Unusable.Timescale;

            if (Response.ReceiveTimestamp == 0 || Response.TransmitTimestamp == 0)
                return NTPv5Unusable.MissingTimestamps;

            if (ReceiveTime(Response) is null)
                return NTPv5Unusable.Era;

            return NTPv5Unusable.None;

        }

        #endregion


        #region ExpandTimestamp(Era, Timestamp)

        /// <summary>
        /// § 9 step 6: a timestamp64 placed in the given era, as a date - or null where that
        /// era lies beyond the range of one. Era 0 starts in 1900, era 1 on 2036-02-07T06:28:16Z.
        /// </summary>
        public static DateTime? ExpandTimestamp(Byte    Era,
                                                UInt64  Timestamp)
        {

            var seconds  = (Int64) Era * NTPPacket.SecondsPerEra + (Int64) (Timestamp >> 32);

            // Compared in seconds first: era 255 in ticks is past the range of an Int64.
            if (seconds >= (DateTime.MaxValue.Ticks - NTPPacket.NTPEpoch.Ticks) / TimeSpan.TicksPerSecond)
                return null;

            return NTPPacket.NTPEpoch.AddTicks(seconds * TimeSpan.TicksPerSecond + FractionTicks(Timestamp));

        }

        #endregion

        #region ExpandNear(Timestamp, Reference)

        /// <summary>
        /// A timestamp64 placed in whichever era puts it nearest a date: for the transmit
        /// timestamp, whose era § 6 does not give - the Era field is the receive timestamp's -
        /// and which lies next to it, across a rollover perhaps.
        /// </summary>
        /// <remarks>
        /// Not <see cref="NTPPacket.NTPTimestampToDateTime(UInt64, DateTime?)"/>, which holds
        /// its reference no earlier than <see cref="NTPPacket.EraFloor"/>: right for a clock
        /// that may not be set yet, wrong for a receive timestamp the server's era placed.
        /// </remarks>
        public static DateTime? ExpandNear(UInt64    Timestamp,
                                           DateTime  Reference)
        {

            var onTheWire   = (Int64) (Timestamp >> 32);
            var reference   = (Reference - NTPPacket.NTPEpoch).Ticks / TimeSpan.TicksPerSecond;

            var era         = (Int64) Math.Round((Double) (reference - onTheWire) / NTPPacket.SecondsPerEra);
            var seconds     = onTheWire + era * NTPPacket.SecondsPerEra;

            if (seconds < 0 || seconds >= (DateTime.MaxValue.Ticks - NTPPacket.NTPEpoch.Ticks) / TimeSpan.TicksPerSecond)
                return null;

            return NTPPacket.NTPEpoch.AddTicks(seconds * TimeSpan.TicksPerSecond + FractionTicks(Timestamp));

        }

        #endregion

        #region ReceiveTime(Response) / TransmitTime(Response)

        /// <summary>
        /// T2: the receive timestamp in the era the response gives for it.
        /// </summary>
        public static DateTime? ReceiveTime(NTPv5Packet Response)

            => Response.ReceiveTimestamp == 0
                   ? null
                   : ExpandTimestamp(Response.Era, Response.ReceiveTimestamp);

        /// <summary>
        /// T3: the transmit timestamp in the era nearest the receive timestamp.
        /// </summary>
        public static DateTime? TransmitTime(NTPv5Packet Response)

            => Response.TransmitTimestamp == 0 || ReceiveTime(Response) is not DateTime t2
                   ? null
                   : ExpandNear(Response.TransmitTimestamp, t2);

        #endregion


        #region CorrectionOf(Response, Request)

        /// <summary>
        /// The Correction of a response, where the request carried one: § 7.7 has a client
        /// "ignore an unexpected Correction Extension Field in the response". Only as the last
        /// field, which § 7.7 requires of it; one anywhere else is ignored as well.
        /// </summary>
        public static NTPv5Correction? CorrectionOf(NTPv5Packet         Response,
                                                    NTPv5ClientRequest  Request)
        {

            if (!Request.CorrectionRequested || Response.ExtensionFields.Count == 0)
                return null;

            var last = Response.ExtensionFields[^1];

            return last.Type == NTPv5ExtensionTypes.Correction &&
                   last.TryReadCorrection(out var correction)
                       ? correction
                       : null;

        }

        #endregion

        #region CorrectionToTimeSpan(Correction)

        /// <summary>
        /// A Delay Correction of § 7.7 - signed nanoseconds in 48.16 fixed point - as a
        /// duration, rounded to the 100 ns of a tick; null where it is "too big to be
        /// represented".
        /// </summary>
        public static TimeSpan? CorrectionToTimeSpan(Int64 Correction)
        {

            if (Correction == CorrectionOverflow || Correction == -CorrectionOverflow)
                return null;

            // 100 ns to a tick, 2^16 units to a nanosecond.
            var ticks = Math.Round(Correction / (Double) (CorrectionUnitsPerNanosecond * 100), MidpointRounding.AwayFromZero);

            return TimeSpan.FromTicks((Int64) ticks);

        }

        #endregion

        #region Correct(Offset, Delay, Correction, Parameters = null)

        /// <summary>
        /// § 8: the corrected offset and delay,
        /// offset_c = offset + (Cd - Co) / 2 and delay_c = delay - (Cd + Co - Drx - Dtx) * (1 - FC),
        /// with Co the Origin Correction and Cd the Delay Correction - or null where any of
        /// delay_c, Co and Cd is negative, which "MUST NOT be accepted", or where a
        /// correction overflowed.
        /// </summary>
        public static (TimeSpan Offset, TimeSpan Delay)? Correct(TimeSpan                    Offset,
                                                                 TimeSpan                    Delay,
                                                                 NTPv5Correction             Correction,
                                                                 NTPv5CorrectionParameters?  Parameters = null)
        {

            Parameters ??= NTPv5CorrectionParameters.Default;

            // On the values as sent, before they are rounded to ticks: a correction of a
            // fraction of a nanosecond below zero is still a negative one.
            if (Correction.OriginCorrection < 0 || Correction.DelayCorrection < 0)
                return null;

            if (CorrectionToTimeSpan(Correction.OriginCorrection) is not TimeSpan co ||
                CorrectionToTimeSpan(Correction.DelayCorrection)  is not TimeSpan cd)
                return null;

            var drx      = Parameters.ReceiveFrameTime;
            var dtx      = Parameters.TransmitFrameTime ?? drx;

            var offset   = Offset + TimeSpan.FromTicks((cd - co).Ticks / 2);
            var delay    = Delay  - TimeSpan.FromTicks((Int64) Math.Round((cd + co - drx - dtx).Ticks * (1 - Parameters.FrequencyError)));

            if (delay < TimeSpan.Zero)
                return null;

            return (offset, delay);

        }

        #endregion

        #region Measure(T1, Response, T4, Request, Parameters = null)

        /// <summary>
        /// The measurement of a basic-mode exchange: T1 and T4 from the client's clock, T2 and
        /// T3 from the response, era-expanded, and the corrections of § 8 where the request
        /// asked for them. Null where the response lacks a timestamp or its era is out of range.
        /// </summary>
        public static NTPv5Measurement? Measure(DateTime                    T1,
                                                NTPv5Packet                 Response,
                                                DateTime                    T4,
                                                NTPv5ClientRequest          Request,
                                                NTPv5CorrectionParameters?  Parameters = null)
        {

            if (ReceiveTime (Response) is not DateTime t2 ||
                TransmitTime(Response) is not DateTime t3)
                return null;

            return Measure(T1, t2, t3, T4, Interleaved: false, CorrectionOf(Response, Request), Parameters);

        }

        /// <summary>
        /// The measurement of the four given timestamps, corrected where a Correction is given.
        /// </summary>
        public static NTPv5Measurement Measure(DateTime                    T1,
                                               DateTime                    T2,
                                               DateTime                    T3,
                                               DateTime                    T4,
                                               Boolean                     Interleaved,
                                               NTPv5Correction?            Correction,
                                               NTPv5CorrectionParameters?  Parameters = null)
        {

            var uncorrected = new NTPv5Measurement(T1, T2, T3, T4, Interleaved, Correction, null, null);

            if (Correction is not NTPv5Correction correction ||
                Correct(uncorrected.Offset, uncorrected.Delay, correction, Parameters) is not { } corrected)
                return uncorrected;

            return uncorrected with { CorrectedOffset = corrected.Offset, CorrectedDelay = corrected.Delay };

        }

        #endregion


        #region ReferenceIdsOf(Response)

        /// <summary>
        /// The reference IDs a response carries, from the index its request asked for - or
        /// null where it carries none that read.
        /// </summary>
        public static IReadOnlyList<NTPv5ReferenceIdEntry>? ReferenceIdsOf(NTPv5Packet Response)

            => Response.Find(NTPv5ExtensionTypes.ReferenceIDsResponse) is NTPv5ExtensionField field &&
               NTPv5ReferenceIds.TryRead(field.Value, out var entries)
                   ? entries
                   : null;

        #endregion

        #region TimeSourcesOf(Response)

        /// <summary>
        /// § 7.5: the time sources a response carries, from the index its request asked for;
        /// empty where the index was none of a source, and null where the response carries no
        /// Time Sources Response that reads - the server does not answer it, or did not here.
        /// </summary>
        public static IReadOnlyList<NTPv5TimeSource>? TimeSourcesOf(NTPv5Packet Response)

            => Response.Find(NTPv5ExtensionTypes.TimeSourcesResponse) is NTPv5ExtensionField field &&
               NTPv5TimeSources.TryRead(field.Value, out var sources)
                   ? sources
                   : null;

        #endregion

        #region SecondaryReceiveTimesOf(Response)

        /// <summary>
        /// § 7.10: the receive timestamps of the request in the other timescales the response
        /// gives, each as a date in its era - or null for a timescale the server supports but
        /// could not convert to (a timestamp of zero). A timescale not in the result is one the
        /// server does not support, or was not asked for.
        /// </summary>
        public static IReadOnlyDictionary<NTPv5Timescale, DateTime?> SecondaryReceiveTimesOf(NTPv5Packet Response)
        {

            var times = new Dictionary<NTPv5Timescale, DateTime?>();

            foreach (var field in Response.ExtensionFields)
                if (field.TryReadSecondaryReceiveTimestamp(out var timescale, out var era, out var timestamp) &&
                    !times.ContainsKey(timescale))
                    times[timescale] = timestamp == 0
                                           ? null
                                           : ExpandTimestamp(era, timestamp);

            return times;

        }

        #endregion

        #region TimescaleOffset(Response, Timescale)

        /// <summary>
        /// § 7.10 and § 9.5: how far the given timescale is ahead of the timescale of the
        /// header, from the same receive timestamp in both - for TAI and a header in UTC, the
        /// 37 s since 2017. Null where the response gives no timestamp in that timescale.
        /// </summary>
        /// <remarks>
        /// Taken from the two timestamps and their eras as they are, in steps of 2^-32 s, so
        /// that a whole number of seconds comes out as one, without the rounding of a date.
        /// </remarks>
        public static TimeSpan? TimescaleOffset(NTPv5Packet     Response,
                                                NTPv5Timescale  Timescale)
        {

            if (Response.ReceiveTimestamp == 0)
                return null;

            foreach (var field in Response.ExtensionFields)
            {

                if (!field.TryReadSecondaryReceiveTimestamp(out var timescale, out var era, out var timestamp) ||
                    timescale != Timescale)
                    continue;

                if (timestamp == 0)
                    return null;

                var difference = (((Int128) era           << 64) | timestamp) -
                                 (((Int128) Response.Era  << 64) | Response.ReceiveTimestamp);

                return TimeSpan.FromTicks((Int64) (difference * TimeSpan.TicksPerSecond / ((Int128) 1 << 32)));

            }

            return null;

        }

        #endregion

        #region IsLoop(Entries, OwnReferenceId, MaximumShare = 0)

        /// <summary>
        /// § 7.4 and § 9: whether a server's reference IDs contain this client's own, so that
        /// selecting it would close a synchronization loop. A share no larger than the given
        /// one may be tolerated, as § 7.4 lets a client configure; the default tolerates none.
        /// </summary>
        /// <param name="Entries">The server's list.</param>
        /// <param name="OwnReferenceId">The client's own reference ID, as it serves it.</param>
        /// <param name="MaximumShare">The share of a loop still acceptable, from 0 to 1.</param>
        public static Boolean IsLoop(IEnumerable<NTPv5ReferenceIdEntry>  Entries,
                                     UInt64                              OwnReferenceId,
                                     Double                              MaximumShare = 0)
        {

            var own = OwnReferenceId & NTPv5ReferenceIds.ReferenceIdMask;

            if (own == 0)
                return false;

            var share = Entries.Where (entry => !entry.IsUnused && entry.ReferenceId == own).
                                Sum   (entry => NTPv5ReferenceIds.DecodeShare(entry.Share));

            return share > 0 && share > MaximumShare;

        }

        #endregion


        #region (private) Invalid(Status, Packet, ErrorMessage)

        private static NTPv5ResponseValidation Invalid(NTPv5ResponseStatus  Status,
                                                       NTPv5Packet?         Packet,
                                                       String?              ErrorMessage)

            => new (Status, Packet, ErrorMessage ?? Status.ToString(), []);

        #endregion

        #region (private) FractionTicks(Timestamp)

        private static Int64 FractionTicks(UInt64 Timestamp)

            => (Int64) ((UInt64) (UInt32) Timestamp * (UInt64) TimeSpan.TicksPerSecond / 0x1_0000_0000UL);

        #endregion

    }

}
