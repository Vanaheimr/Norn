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

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTPv5
{

    /// <summary>
    /// What a server says of its clock in an NTPv5 response.
    /// </summary>
    /// <param name="Stratum">The stratum.</param>
    /// <param name="RootDelay">The root delay.</param>
    /// <param name="RootDispersion">The root dispersion.</param>
    /// <param name="Synchronized">Whether the timestamps are fit to synchronize to; no sets the Unsynchronized flag.</param>
    /// <param name="Precision">The precision of the timestamps, as a power of two in seconds.</param>
    /// <param name="MinimumPoll">The shortest poll interval allowed, as a power of two in seconds.</param>
    public sealed record NTPv5ServerClock(Byte      Stratum,
                                          TimeSpan  RootDelay,
                                          TimeSpan  RootDispersion,
                                          Boolean   Synchronized,
                                          SByte     Precision,
                                          SByte     MinimumPoll)
    {

        /// <summary>
        /// § 7.6: the header flags the server supports, as its Server Information says.
        /// </summary>
        public NTPv5Flags          SupportedFlags      { get; init; } = NTPv5Flags.Unsynchronized;

        /// <summary>
        /// § 7.4: the server's list of reference IDs, or null where it answers no Reference IDs Request.
        /// </summary>
        public NTPv5ReferenceIds?  ReferenceIds        { get; init; }

        /// <summary>
        /// § 7.5: the server's current time sources, or null where it answers no Time Sources
        /// Request - the field is "supported and enabled" only where a list is given.
        /// </summary>
        public IReadOnlyList<NTPv5TimeSource>?  TimeSources  { get; init; }

        /// <summary>
        /// § 7.10: the timescales the server gives a Secondary Receive Timestamp in, each with
        /// its offset from UTC - TAI is UTC and 37 s since 2017 - or null where it supports the
        /// timescale but cannot convert to it now, and then answers with a timestamp of zero.
        /// A timescale not listed is not supported, and its request is ignored. UTC alone by
        /// default: an offset to TAI or UT1 is something the server has to be told.
        /// </summary>
        public IReadOnlyDictionary<NTPv5Timescale, TimeSpan?>  SecondaryTimescales  { get; init; } = UTCOnly;

        /// <summary>
        /// UTC, the timescale of the header, and nothing else.
        /// </summary>
        public static IReadOnlyDictionary<NTPv5Timescale, TimeSpan?> UTCOnly { get; }
            = new Dictionary<NTPv5Timescale, TimeSpan?> { [NTPv5Timescale.UTC] = TimeSpan.Zero };

        /// <summary>
        /// § 7.8: when the clock was last set, or 0 where the server answers no Reference Timestamp.
        /// </summary>
        public UInt64              ReferenceTimestamp  { get; init; }

        /// <summary>
        /// § 7.9: the epoch of the server's monotonic clock, or null where it answers no
        /// Monotonic Receive Timestamp.
        /// </summary>
        public UInt32?             MonotonicEpochId    { get; init; }

        /// <summary>
        /// Whether a request without NTS is answered at all; no for a server of NTS alone.
        /// </summary>
        public Boolean             AnswersPlain        { get; init; } = true;

    }


    /// <summary>
    /// What one exchange decided: the timestamps and cookie of its response.
    /// </summary>
    /// <param name="ReceiveTimestamp">The receive timestamp to report.</param>
    /// <param name="TransmitTimestamp">The transmit timestamp to report: of this response in the basic mode, of the earlier one in the interleaved mode.</param>
    /// <param name="ServerCookie">The server cookie to give the client, 0 for none.</param>
    /// <param name="Interleaved">Whether the transmit timestamp is that of an earlier response.</param>
    /// <param name="MonotonicReceiveTimestamp">The monotonic clock at reception, where it was read.</param>
    public sealed record NTPv5Exchange(UInt64   ReceiveTimestamp,
                                       UInt64   TransmitTimestamp,
                                       UInt64   ServerCookie               = 0,
                                       Boolean  Interleaved                = false,
                                       UInt64?  MonotonicReceiveTimestamp  = null);


    /// <summary>
    /// Why an NTPv5 request was answered, or why not.
    /// </summary>
    public enum NTPv5RequestOutcome
    {

        /// <summary>Answered.</summary>
        Answered,

        /// <summary>Not a well-framed NTPv5 message.</summary>
        Invalid,

        /// <summary>A message, but no request: § 10 answers mode 3 alone.</summary>
        NotARequest,

        /// <summary>No Draft Identification, or one of another draft (§ 7.1, § 11).</summary>
        OtherDraft,

        /// <summary>The clock is not synchronized and the client did not ask to hear anyway (§ 10 step 6).</summary>
        Unsynchronized,

        /// <summary>The response came out longer than the request (§ 10 step 6).</summary>
        TooLong,

        /// <summary>A request without NTS, to a server of NTS alone.</summary>
        PlainNotServed,

        /// <summary>The NTS of the request did not verify, and it did not ask to hear anyway (§ 6, § 7.3).</summary>
        NotAuthenticated,

        /// <summary>
        /// The NTS of the request did not verify, and it asked to hear anyway: answered with the
        /// Authentication NAK flag and stratum 0, and nothing in it to synchronize to.
        /// </summary>
        AuthenticationNAK

    }


    /// <summary>
    /// The server side of NTPv5, draft-ietf-ntp-ntpv5-10 § 10, plain or with NTS (§ 11): from
    /// the datagram of a request to the datagram of its response, or to the reason there is
    /// none.
    /// </summary>
    /// <remarks>
    /// Apart from <see cref="NTS.NTSServer"/>, which owns the sockets and the interleaved
    /// store, so that what § 10 asks of a response can be checked without either.
    /// </remarks>
    public static class NTPv5Responder
    {

        #region Data

        /// <summary>
        /// § 7.6: the versions Norn answers, one bit each from bit 0 for version 1 - 1 to 3 in
        /// the NTPv4 code, which answers them in their own version, 4, and 5.
        /// </summary>
        public const UInt16      SupportedVersions  = 0b1_1111;

        /// <summary>
        /// The header flags this responder can support at all - which of them a server does is
        /// <see cref="NTPv5ServerClock.SupportedFlags"/>.
        /// </summary>
        public const NTPv5Flags  SupportedFlags     = NTPv5Flags.Unsynchronized | NTPv5Flags.InterleavedMode | NTPv5Flags.AuthenticationNAK;

        #endregion


        #region TryRespond(Request, ReceiveTimestamp, ReceiveTime, Clock, TransmitTimestamp, out Response, out ErrorResponse)

        /// <summary>
        /// The response to the given request in the basic mode, following § 10.
        /// </summary>
        /// <param name="Request">The datagram of the request.</param>
        /// <param name="ReceiveTimestamp">When it was received, in the 64-bit NTP format.</param>
        /// <param name="ReceiveTime">The same instant as a date, for the era of § 6.</param>
        /// <param name="Clock">What the server says of its clock.</param>
        /// <param name="TransmitTimestamp">Reads the transmit timestamp, as late as possible.</param>
        /// <param name="Response">The datagram of the response, when there is one.</param>
        /// <param name="ErrorResponse">Why there is none, when there is none.</param>
        public static NTPv5RequestOutcome TryRespond(ReadOnlySpan<Byte>                 Request,
                                                     UInt64                             ReceiveTimestamp,
                                                     DateTime                           ReceiveTime,
                                                     NTPv5ServerClock                   Clock,
                                                     Func<UInt64>                       TransmitTimestamp,
                                                     [NotNullWhen(true)]  out Byte[]?   Response,
                                                     out String?                        ErrorResponse)

            => TryRespond(Request,
                          ReceiveTime,
                          Clock,
                          request => new NTPv5Exchange(ReceiveTimestamp, TransmitTimestamp()),
                          out Response,
                          out ErrorResponse);

        #endregion

        #region TryRespond(Request, ReceiveTime, Clock, Exchange, out Response, out ErrorResponse)

        /// <summary>
        /// The response to the given request, following § 10, in whichever mode the exchange
        /// decides.
        /// </summary>
        /// <param name="Request">The datagram of the request.</param>
        /// <param name="ReceiveTime">When it was received, for the era of § 6.</param>
        /// <param name="Clock">What the server says of its clock.</param>
        /// <param name="Exchange">
        /// Decides the timestamps and cookie of the response, given the request. Called once,
        /// for a request that will be answered unless the response comes out too long, and
        /// not at all for one that will be dropped - so that nothing is remembered of those.
        /// </param>
        /// <param name="Response">The datagram of the response, when there is one.</param>
        /// <param name="ErrorResponse">Why there is none, when there is none.</param>
        public static NTPv5RequestOutcome TryRespond(ReadOnlySpan<Byte>                 Request,
                                                     DateTime                           ReceiveTime,
                                                     NTPv5ServerClock                   Clock,
                                                     Func<NTPv5Packet, NTPv5Exchange>   Exchange,
                                                     [NotNullWhen(true)]  out Byte[]?   Response,
                                                     out String?                        ErrorResponse)

            => TryRespond(Request,
                          ReceiveTime,
                          Clock,
                          null,
                          (request, authenticated) => Exchange(request),
                          out Response,
                          out ErrorResponse);

        #endregion

        #region TryRespond(Request, ReceiveTime, Clock, NTS, Exchange, out Response, out ErrorResponse)

        /// <summary>
        /// The response to the given request, following § 10 and, for a request of NTS, § 11,
        /// in whichever mode the exchange decides.
        /// </summary>
        /// <param name="Request">The datagram of the request.</param>
        /// <param name="ReceiveTime">When it was received, for the era of § 6.</param>
        /// <param name="Clock">What the server says of its clock.</param>
        /// <param name="NTS">The server's NTS, or null for a server that knows none: its fields are then as unknown as any other.</param>
        /// <param name="Exchange">
        /// Decides the timestamps and cookie of the response, given the request and whether it
        /// was authenticated. Called once, for a request that will be answered unless the
        /// response comes out too long, and not at all for one that will be dropped or NAKed -
        /// so that nothing is remembered of those.
        /// </param>
        /// <param name="Response">The datagram of the response, when there is one.</param>
        /// <param name="ErrorResponse">Why there is none, when there is none.</param>
        public static NTPv5RequestOutcome TryRespond(ReadOnlySpan<Byte>                          Request,
                                                     DateTime                                    ReceiveTime,
                                                     NTPv5ServerClock                            Clock,
                                                     NTPv5NTSService?                            NTS,
                                                     Func<NTPv5Packet, Boolean, NTPv5Exchange>   Exchange,
                                                     [NotNullWhen(true)]  out Byte[]?            Response,
                                                     out String?                                 ErrorResponse)
        {

            Response       = null;
            ErrorResponse  = null;

            #region Steps 2 and 3: an NTPv5 request, well framed

            if (!NTPv5Packet.TryParse(Request, out var request, out ErrorResponse))
                return NTPv5RequestOutcome.Invalid;

            if (request.Mode != NTPv5Packet.RequestMode)
            {
                ErrorResponse = $"An NTPv5 message of mode {request.Mode}, which is not a request!";
                return NTPv5RequestOutcome.NotARequest;
            }

            #endregion

            #region § 7.1 and § 11: the same draft, or nothing

            // A draft server "MUST NOT respond to a draft identification it does not recognize",
            // and must not accept NTPv5 at all from a client that names no draft: what that
            // client speaks is a revision this server cannot know it agrees with.
            var draftIdentification = request.DraftIdentification;

            if (draftIdentification is null)
            {
                ErrorResponse = "An NTPv5 request without a Draft Identification!";
                return NTPv5RequestOutcome.OtherDraft;
            }

            if (!NTPv5Draft.IsThisDraft(draftIdentification))
            {
                ErrorResponse = $"An NTPv5 request of '{NTPv5Draft.Describe(draftIdentification)}', not of '{NTPv5Draft.Identification}'!";
                return NTPv5RequestOutcome.OtherDraft;
            }

            #endregion

            #region § 11: NTS, or plain

            // A request that tries NTS is answered with NTS or not as itself at all: answering it
            // in plain would hand an unauthenticated time to a client that asked for the other.
            NTPv5NTSSession? session = null;

            if (NTS is not null && NTPv5NTS.IsNTSRequest(request))
            {

                if (!NTS.TryVerify(Request, request, out session, out var ntsError))
                {

                    ErrorResponse = ntsError;

                    // § 6 and § 7.3: only a client that asked to hear of the failure is told.
                    if (!request.Flags.HasFlag(NTPv5Flags.AuthenticationNAK) ||
                        !Clock.SupportedFlags.HasFlag(NTPv5Flags.AuthenticationNAK))
                        return NTPv5RequestOutcome.NotAuthenticated;

                    Response = AuthenticationNAK(request, ReceiveTime, Clock);

                    return Response is not null
                               ? NTPv5RequestOutcome.AuthenticationNAK
                               : NTPv5RequestOutcome.TooLong;

                }

            }

            else if (!Clock.AnswersPlain)
            {
                ErrorResponse = "A request without NTS, to a server of NTS alone!";
                return NTPv5RequestOutcome.PlainNotServed;
            }

            #endregion

            #region Step 4: the Unsynchronized flag, and step 6

            // Step 6: a response with a flag the request did not set is dropped - so a client
            // that did not ask to hear from an unsynchronized server does not.
            if (!Clock.Synchronized &&
                !request.Flags.HasFlag(NTPv5Flags.Unsynchronized))
            {
                ErrorResponse = "The clock is not synchronized, and the request did not ask to be answered all the same!";
                return NTPv5RequestOutcome.Unsynchronized;
            }

            #endregion

            #region Step 4: the mode, and the timestamps that follow from it

            var exchange     = Exchange(request, session is not null);

            // Whatever the exchange says, a flag the request did not set is not set, and a
            // cookie is given only to a client that asked for the mode it serves (§ 10).
            var askedForIt   = request.Flags.HasFlag(NTPv5Flags.InterleavedMode) &&
                               Clock.SupportedFlags.HasFlag(NTPv5Flags.InterleavedMode);

            var interleaved  = askedForIt && exchange.Interleaved;

            var flags        = (Clock.Synchronized ? NTPv5Flags.None : NTPv5Flags.Unsynchronized) |
                               (interleaved        ? NTPv5Flags.InterleavedMode : NTPv5Flags.None);

            #endregion

            #region § 7: the extension fields of the response

            // Every field of the request that is answered goes back in its place; one that is
            // not is left out, and what that leaves short is padded below. The request's own
            // Padding is not copied but taken into that padding, which comes out the same.
            //
            // Of a request of NTS only what its authenticator covers: a field after it could have
            // been added by anyone on the way. The one exception is the Correction, which is
            // never authenticated and is added to by the devices on the way by design (§ 7.7).
            var responseFields  = new List<NTPv5ExtensionField>();
            var timescales      = new HashSet<NTPv5Timescale>();
            var correction      = (NTPv5ExtensionField?) null;

            for (var index = 0; index < request.ExtensionFields.Count; index++)
            {

                var field          = request.ExtensionFields[index];
                var authenticated  = session is null || index < session.AuthenticatorIndex;

                if (!authenticated && field.Type != NTPv5ExtensionTypes.Correction)
                    continue;

                switch (field.Type)
                {

                    case NTPv5ExtensionTypes.DraftIdentification:
                        responseFields.Add(new NTPv5ExtensionField(NTPv5ExtensionTypes.DraftIdentification,
                                                                   NTPv5Draft.IdentificationBytes.ToArray()));
                        break;

                    // RFC 8915 § 5.7: the Unique Identifier is echoed, where the request is one
                    // of NTS, and the authenticator below covers it.
                    case NTPv5ExtensionTypes.UniqueIdentifier when session is not null:
                        responseFields.Add(new NTPv5ExtensionField(NTPv5ExtensionTypes.UniqueIdentifier,
                                                                   session.UniqueIdentifier));
                        break;

                    // § 7.6 fixes it at 8 octets; one of another length is not this field, and
                    // answering it with 8 would change the length the client meant to send.
                    case NTPv5ExtensionTypes.ServerInformation when field.Length == 8:
                        responseFields.Add(NTPv5ExtensionField.ServerInformation(SupportedVersions,
                                                                                 Clock.SupportedFlags & SupportedFlags));
                        break;

                    // § 7.4: the entries asked for, as many as the request has room for - or
                    // nothing, for a request whose index does not fit its length.
                    case NTPv5ExtensionTypes.ReferenceIDsRequest when Clock.ReferenceIds is not null:
                        if (Clock.ReferenceIds.TryAnswer(field, out var referenceIds))
                            responseFields.Add(referenceIds);
                        break;

                    // § 7.5: the sources from the index on, no longer than the request - and
                    // empty for an index that is none of a source.
                    // § 7.10: the receive timestamp of the header in the timescale asked for -
                    // zero where the server supports it but cannot convert to it now - and a
                    // timescale it does not support is ignored. A request "MUST" ask for each
                    // only once; one that asks again gets it once.
                    case NTPv5ExtensionTypes.SecondaryReceiveTimestamp when field.TryReadSecondaryReceiveTimestamp(out var timescale, out _, out _) &&
                                                                            Clock.SecondaryTimescales.TryGetValue(timescale, out var offset) &&
                                                                            timescales.Add(timescale):
                        responseFields.Add(offset is TimeSpan known &&
                                           NTPv5Packet.TryShift(NTPv5Packet.EraOf(ReceiveTime), exchange.ReceiveTimestamp, known, out var era, out var shifted)
                                               ? NTPv5ExtensionField.SecondaryReceiveTimestamp(timescale, era, shifted)
                                               : NTPv5ExtensionField.SecondaryReceiveTimestamp(timescale));
                        break;

                    case NTPv5ExtensionTypes.TimeSourcesRequest when Clock.TimeSources is not null:
                        if (NTPv5TimeSources.TryAnswer(Clock.TimeSources, field, out var timeSources))
                            responseFields.Add(timeSources);
                        break;

                    // § 7.8.
                    case NTPv5ExtensionTypes.ReferenceTimestamp when field.Length == NTPv5ExtensionField.ReferenceTimestampLength &&
                                                                     Clock.ReferenceTimestamp != 0:
                        responseFields.Add(NTPv5ExtensionField.ReferenceTimestamp(Clock.ReferenceTimestamp));
                        break;

                    // § 7.9: only where the monotonic clock was read at reception.
                    case NTPv5ExtensionTypes.MonotonicReceiveTimestamp when field.Length == NTPv5ExtensionField.MonotonicReceiveTimestampLength &&
                                                                            Clock.MonotonicEpochId is not null &&
                                                                            exchange.MonotonicReceiveTimestamp is not null:
                        responseFields.Add(NTPv5ExtensionField.MonotonicReceiveTimestamp(Clock.MonotonicEpochId.Value,
                                                                                         exchange.MonotonicReceiveTimestamp.Value));
                        break;

                    // § 7.7: the request's Delay Correction and Path ID go back as the Origin
                    // ones, the server's own are zero for the devices on the way back to fill
                    // in, and the field is the last of the response, wherever it was in the
                    // request - after the authenticator, too. Only the first: two would make it
                    // ambiguous which is last.
                    case NTPv5ExtensionTypes.Correction when correction is null &&
                                                             field.TryReadCorrection(out var requestCorrection):
                        correction = NTPv5ExtensionField.Correction(new NTPv5Correction(
                                                                        OriginCorrection:    requestCorrection.DelayCorrection,
                                                                        OriginPathId:        requestCorrection.PathId,
                                                                        DelayCorrection:     0,
                                                                        PathId:              0,
                                                                        ChecksumComplement:  0
                                                                    ));
                        break;

                }

            }

            #endregion

            #region Step 4: the header, and step 5: as long as the request

            NTPv5Packet Build(IEnumerable<NTPv5ExtensionField> Fields)

                => new (Mode:               NTPv5Packet.ResponseMode,
                        Stratum:            Clock.Stratum,
                        Poll:               Clock.MinimumPoll,
                        Precision:          Clock.Precision,
                        RootDelay:          Time32.FromTimeSpan(Clock.RootDelay),
                        RootDispersion:     Time32.FromTimeSpan(Clock.RootDispersion),

                        // Norn's clock is UTC and nothing else, so that is what a client asking
                        // for TAI or UT1 is given too: § 10 answers with "any supported"
                        // timescale, and the client sees from the field that it is not its own.
                        Timescale:          NTPv5Timescale.UTC,
                        Era:                NTPv5Packet.EraOf(ReceiveTime),
                        Flags:              flags,

                        // § 10: set when the mode is asked for and served, "even if this
                        // response cannot be interleaved", so that the next one can be.
                        ServerCookie:       askedForIt ? exchange.ServerCookie : 0,
                        ClientCookie:       request.ClientCookie,
                        ReceiveTimestamp:   exchange.ReceiveTimestamp,
                        TransmitTimestamp:  exchange.TransmitTimestamp,
                        ExtensionFields:    Fields);

            var answeredLength  = NTPv5Packet.HeaderLength +
                                  responseFields.Sum(field => field.PaddedLength) +
                                  (correction?.PaddedLength ?? 0);

            // RFC 8915 § 5.7: as many cookies as the request spent and held places for - and,
            // since an NTPv5 response must not be longer than its request, fewer where the
            // places were too small for them. None at all is still an authenticated response.
            var cookies         = session is not null && NTS is not null
                                      ? NTS.MintCookies(session, Math.Min(1 + session.Placeholders, NTS.MaxCookies))
                                      : [];

            var cookieCount     = cookies.Count;
            var shortBy         = request.Length - answeredLength;

            if (session is not null)
            {

                while (cookieCount > 0 &&
                       request.Length < answeredLength + NTPv5NTS.AuthenticatorLength(session.AEADAlgorithm, cookies.Take(cookieCount).Sum(cookie => cookie.Length)))
                {
                    cookieCount--;
                }

                shortBy = request.Length - answeredLength - NTPv5NTS.AuthenticatorLength(session.AEADAlgorithm, cookies.Take(cookieCount).Sum(cookie => cookie.Length));

            }

            // Step 6. Nothing above makes a plain response longer than its request, but should
            // that ever change, this is the check that keeps the server from being an amplifier.
            if (shortBy < 0)
            {
                ErrorResponse = $"The response would be {-shortBy} octet(s) longer than the request!";
                return NTPv5RequestOutcome.TooLong;
            }

            // Both lengths are whole multiples of 4, so what is short is either nothing or a
            // Padding field of at least its header - before the authenticator, which covers it,
            // and before the Correction, which stays last.
            if (shortBy > 0)
                responseFields.Add(NTPv5ExtensionField.Padding(shortBy));

            if (session is not null)
            {

                var plaintext = new Byte[cookies.Take(cookieCount).Sum(cookie => cookie.Length)];
                var offset    = 0;

                foreach (var cookie in cookies.Take(cookieCount))
                {
                    cookie.CopyTo(plaintext, offset);
                    offset += cookie.Length;
                }

                // Over the header and every field before it, with the server-to-client key.
                responseFields.Add(NTPv5NTS.Seal(Build(responseFields).ToByteArray(),
                                                 session.S2CKey,
                                                 session.AEADAlgorithm,
                                                 plaintext));

            }

            if (correction is not null)
                responseFields.Add(correction);

            Response = Build(responseFields).ToByteArray();

            if (Response.Length != request.Length)
            {
                ErrorResponse = $"The response came out {Response.Length} octets long, not the {request.Length} of the request!";
                Response      = null;
                return NTPv5RequestOutcome.TooLong;
            }

            return NTPv5RequestOutcome.Answered;

            #endregion

        }

        #endregion

        #region (private static) AuthenticationNAK(Request, ReceiveTime, Clock)

        /// <summary>
        /// The answer to a request of NTS that failed and asked to hear of it (§ 6, Authentication
        /// NAK): the flag, stratum 0, the Draft Identification and the Unique Identifier back so
        /// that the client knows what it answers, as long as the request - and nothing else, no
        /// timestamp to synchronize to and no authenticator, since there is no key to make one.
        /// Null where even that would be longer than the request.
        /// </summary>
        private static Byte[]? AuthenticationNAK(NTPv5Packet       Request,
                                                 DateTime          ReceiveTime,
                                                 NTPv5ServerClock  Clock)
        {

            var fields = new List<NTPv5ExtensionField> {
                             new (NTPv5ExtensionTypes.DraftIdentification, NTPv5Draft.IdentificationBytes.ToArray())
                         };

            // Only an identifier of a plausible length: an unauthenticated client must not make
            // the NAK longer than it has to be.
            if (Request.Find(NTPv5ExtensionTypes.UniqueIdentifier) is { Value.Length: >= NTPv5NTS.MinimumUniqueIdentifierLength and <= NTPv5NTS.MaximumEchoedUniqueIdentifierLength } uniqueIdentifier)
                fields.Add(new NTPv5ExtensionField(NTPv5ExtensionTypes.UniqueIdentifier, uniqueIdentifier.Value));

            var shortBy = Request.Length - NTPv5Packet.HeaderLength - fields.Sum(field => field.PaddedLength);

            if (shortBy < 0)
                return null;

            if (shortBy > 0)
                fields.Add(NTPv5ExtensionField.Padding(shortBy));

            return new NTPv5Packet(Mode:             NTPv5Packet.ResponseMode,
                                   Stratum:          0,
                                   Poll:             Clock.MinimumPoll,
                                   Precision:        Clock.Precision,
                                   Timescale:        NTPv5Timescale.UTC,
                                   Era:              NTPv5Packet.EraOf(ReceiveTime),
                                   Flags:            NTPv5Flags.AuthenticationNAK,
                                   ClientCookie:     Request.ClientCookie,
                                   ExtensionFields:  fields).ToByteArray();

        }


        #endregion

    }

}
