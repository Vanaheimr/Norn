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
                                          SByte     MinimumPoll);


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
        TooLong

    }


    /// <summary>
    /// The server side of NTPv5 in the basic mode, draft-ietf-ntp-ntpv5-10 § 10, without
    /// authentication: from the datagram of a request to the datagram of its response, or to
    /// the reason there is none.
    /// </summary>
    /// <remarks>
    /// Apart from <see cref="NTS.NTSServer"/>, which owns the sockets, so that what § 10 asks
    /// of a response can be checked without one.
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
        /// § 7.6: the header flags this responder supports. Only Unsynchronized for now: there is
        /// no interleaved mode and no authentication in NTPv5 yet, so neither of those flags is
        /// ever set in a response.
        /// </summary>
        public const NTPv5Flags  SupportedFlags     = NTPv5Flags.Unsynchronized;

        #endregion


        #region TryRespond(Request, ReceiveTimestamp, ReceiveTime, Clock, TransmitTimestamp, out Response, out ErrorResponse)

        /// <summary>
        /// The response to the given request, following § 10.
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

            #region Step 4: the flags

            // Unknown flags are ignored, and of the known ones only Unsynchronized can be set:
            // the interleaved mode is not served (yet), so a response never claims it, and there
            // is no authentication to fail.
            var flags = Clock.Synchronized
                            ? NTPv5Flags.None
                            : NTPv5Flags.Unsynchronized;

            // Step 6: a response with a flag the request did not set is dropped - so a client
            // that did not ask to hear from an unsynchronized server does not.
            if (!request.Flags.HasFlag(NTPv5Flags.Unsynchronized) &&
                 flags.HasFlag(NTPv5Flags.Unsynchronized))
            {
                ErrorResponse = "The clock is not synchronized, and the request did not ask to be answered all the same!";
                return NTPv5RequestOutcome.Unsynchronized;
            }

            #endregion

            #region § 7: the extension fields of the response

            // Every field of the request that is answered goes back in its place; one that is
            // not is left out, and what that leaves short is padded below. The request's own
            // Padding is not copied but taken into that padding, which comes out the same.
            var responseFields = new List<NTPv5ExtensionField>();

            foreach (var field in request.ExtensionFields)
            {
                switch (field.Type)
                {

                    case NTPv5ExtensionTypes.DraftIdentification:
                        responseFields.Add(new NTPv5ExtensionField(NTPv5ExtensionTypes.DraftIdentification,
                                                                   NTPv5Draft.IdentificationBytes.ToArray()));
                        break;

                    // § 7.6 fixes it at 8 octets; one of another length is not this field, and
                    // answering it with 8 would change the length the client meant to send.
                    case NTPv5ExtensionTypes.ServerInformation when field.Length == 8:
                        responseFields.Add(NTPv5ExtensionField.ServerInformation(SupportedVersions,
                                                                                 SupportedFlags));
                        break;

                }
            }

            #endregion

            #region Step 4: the header, and step 5: as long as the request

            NTPv5Packet Build(UInt64 transmitTimestamp)
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

                        // No interleaved mode, so no cookie of the server's.
                        ServerCookie:       0,
                        ClientCookie:       request.ClientCookie,
                        ReceiveTimestamp:   ReceiveTimestamp,
                        TransmitTimestamp:  transmitTimestamp,
                        ExtensionFields:    responseFields);

            var shortBy = request.Length - Build(0).Length;

            // Step 6. Nothing above makes a response longer than its request, but should that
            // ever change, this is the check that keeps the server from being an amplifier.
            if (shortBy < 0)
            {
                ErrorResponse = $"The response would be {-shortBy} octet(s) longer than the request!";
                return NTPv5RequestOutcome.TooLong;
            }

            // Both lengths are whole multiples of 4, so what is short is either nothing or a
            // Padding field of at least its header.
            if (shortBy > 0)
                responseFields.Add(NTPv5ExtensionField.Padding(shortBy));

            Response = Build(TransmitTimestamp()).ToByteArray();

            return NTPv5RequestOutcome.Answered;

            #endregion

        }

        #endregion

    }

}
