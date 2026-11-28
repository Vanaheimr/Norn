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

using System.Diagnostics;
using System.Net.Sockets;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    #region NTPNegotiatedQueryResult

    /// <summary>
    /// One query of a § 12 negotiation: in NTPv4 or in NTPv5, whichever the negotiation
    /// chose, and where it stands afterwards.
    /// </summary>
    /// <param name="NTPv4">The NTPv4 query, where it was one.</param>
    /// <param name="NTPv5">The NTPv5 query, where it was one.</param>
    /// <param name="NextVersion">The version the next query will go out in.</param>
    public sealed record NTPNegotiatedQueryResult(NTSQueryResult?         NTPv4,
                                                  NTPv5QueryResult?       NTPv5,
                                                  NTPv5NegotiatedVersion  NextVersion)
    {

        /// <summary>
        /// Whether the query, in whichever version, got a valid response.
        /// </summary>
        public Boolean Success
            => NTPv4?.Success ?? NTPv5?.Success ?? false;

    }

    #endregion


    public partial class NTSClient
    {

        #region Properties

        /// <summary>
        /// The NTPv5 interleaved association of this client with its server, where it is to
        /// use the interleaved mode of draft-ietf-ntp-ntpv5-10 § 8; null for the basic mode.
        /// </summary>
        public NTPv5InterleavedAssociation?  NTPv5Interleaved      { get; init; }

        /// <summary>
        /// The reference ID this client serves time under, where it does: then § 9 has every
        /// NTPv5 request ask for the server's reference IDs, and a server that lists this one
        /// is reported as a loop.
        /// </summary>
        public UInt64?                       NTPv5OwnReferenceId   { get; init; }

        #endregion


        #region QueryNTPv5(Timeout = null, NTSKEResponse = null, Timescale = UTC, ...)

        /// <summary>
        /// Sends a single NTPv5 request (draft-ietf-ntp-ntpv5-10 § 9) and returns what came of
        /// it: plain, or under NTS where a key exchange that negotiated NTPv5 is given.
        /// </summary>
        /// <param name="Timeout">How long to wait for a valid response.</param>
        /// <param name="NTSKEResponse">A key exchange that negotiated NTPv5 (0x8001), or null for a plain request.</param>
        /// <param name="Timescale">The timescale to operate in.</param>
        /// <param name="AcceptUnsynchronized">Ask for a response even from an unsynchronized server (flag 0x1).</param>
        /// <param name="RequestCorrection">Add a Correction field for the network to fill in (§ 7.7).</param>
        /// <param name="ExtensionFields">Further fields to send, such as a Server Information request.</param>
        /// <param name="AccessState">The access state of the server, which its poll field is applied to and which may forbid the query.</param>
        /// <param name="Limits">The maximums of § 9.5.</param>
        /// <param name="CorrectionParameters">What § 8 needs besides the corrections.</param>
        /// <param name="NTPServer">Which of the servers the key exchange named to send this request to.</param>
        /// <param name="CancellationToken">A cancellation token.</param>
        /// <remarks>
        /// <para>
        /// What § 9.4 calls invalid is passed over, and the client keeps waiting for the first
        /// valid response within the timeout, as RFC 8915 § 5.7 has an NTS client do: one
        /// forged datagram must not end the query. An Authentication NAK takes effect only
        /// when nothing valid followed it, and then retires the cookies.
        /// </para>
        /// <para>
        /// T1 is read right after the send. Unlike an NTPv4 client, an NTPv5 one does not put
        /// it in the request (§ 4.1), so nothing between reading the clock and sending is
        /// charged to the network.
        /// </para>
        /// </remarks>
        public async Task<NTPv5QueryResult> QueryNTPv5(TimeSpan?                         Timeout                = null,
                                                       NTSKE_Response?                   NTSKEResponse          = null,
                                                       NTPv5Timescale                    Timescale              = NTPv5Timescale.UTC,
                                                       Boolean                           AcceptUnsynchronized   = false,
                                                       Boolean                           RequestCorrection      = false,
                                                       IEnumerable<NTPv5ExtensionField>? ExtensionFields        = null,
                                                       NTPServerAccessState?             AccessState            = null,
                                                       NTPv5UsabilityLimits?             Limits                 = null,
                                                       NTPv5CorrectionParameters?        CorrectionParameters   = null,
                                                       String?                           NTPServer              = null,
                                                       CancellationToken                 CancellationToken      = default)
        {

            ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed) != 0, this);

            var timeout = Timeout ?? this.Timeout ?? DefaultTimeout;

            NTPv5QueryResult Fail(String                        Message,
                                  NTSQueryErrorCategory         Category,
                                  System.Net.IPEndPoint?        EndPoint     = null,
                                  String?                       Description  = null,
                                  NTPv5ClientRequest?           Request      = null,
                                  NTPv5ResponseValidation?      Validation   = null)

                => new (false, Message, Category, EndPoint, Description ?? EndPoint?.ToString() ?? HostText,
                        Request, Validation, RemainingCookies: AvailableCookieCount);

            if (NTSKEResponse?.ErrorMessage is not null)
                return Fail(NTSKEResponse.ErrorMessage, NTSQueryErrorCategory.NTSKE);

            if (NTSKEResponse is not null && NTSKEResponse.NextProtocol != NTPv5Draft.NTSNextProtocolId)
                return Fail($"The key exchange negotiated next protocol {NTSKEResponse.NextProtocol}, not NTPv5 ({NTPv5Draft.NTSNextProtocolId})!",
                            NTSQueryErrorCategory.NTSKE);

            if (AccessState is not null && !AccessState.MayQuery(TimeProvider.GetUtcNow()))
                return Fail(AccessState.Demobilized
                                ? "The server does not want to hear from this client again."
                                : $"The server allows no query before {AccessState.NextQueryNotBefore:o}.",
                            NTSQueryErrorCategory.KissOfDeath);

            #region Take a cookie

            var cookie              = default(Byte[]?);
            var activePoolResponse  = default(NTSKE_Response?);

            if (NTSKEResponse is not null)
            {

                if (TryTakeCookieWithGeneration(NTSKEResponse, out cookie, out activePoolResponse))
                {
                    if (activePoolResponse is not null)
                        NTSKEResponse = activePoolResponse;
                }
                else
                {

                    var renegotiated = await RenegotiateExhaustedPool(NTSKEResponse.PublicKeys.Any(), CancellationToken).ConfigureAwait(false);

                    if (renegotiated is null ||
                        !TryTakeCookieWithGeneration(renegotiated, out cookie, out activePoolResponse))
                        return Fail("No NTS cookie available!", NTSQueryErrorCategory.Cookie);

                    NTSKEResponse = activePoolResponse ?? renegotiated;

                    // A key exchange that fell back to NTPv4 left cookies and keys for NTPv4,
                    // which an NTPv5 request cannot use.
                    if (NTSKEResponse.NextProtocol != NTPv5Draft.NTSNextProtocolId)
                    {
                        ReturnUnusedCookie(activePoolResponse, cookie);
                        return Fail($"The renewed key exchange negotiated next protocol {NTSKEResponse.NextProtocol}, not NTPv5!",
                                    NTSQueryErrorCategory.NTSKE);
                    }

                }

            }

            #endregion

            #region Resolve the server

            var remoteEndPoint     = await NTPRemoteEndPointResolver.ResolveAsync(NTSKEResponse,
                                                                                  HostText,
                                                                                  NTP_Port,
                                                                                  DNSClient,
                                                                                  IPVersionPreference,
                                                                                  timeout,
                                                                                  CancellationToken,
                                                                                  NTPServer).ConfigureAwait(false);

            var remoteDescription  = remoteEndPoint?.ToString()
                                         ?? NTPServer
                                         ?? NTPRemoteEndPointResolver.GetRemoteDescription(NTSKEResponse, HostText, NTP_Port);

            // As for NTPv4: a server the key exchange named is the one that accepts its
            // cookies, and no other is asked in its place.
            if (remoteEndPoint is null && NTSKEResponse?.NTPv4ServerNames.Any() == true)
            {
                ReturnUnusedCookie(activePoolResponse, cookie);
                return Fail($"The NTS-KE server directed this client to {remoteDescription}, which could not be resolved.",
                            NTSQueryErrorCategory.DNS, Description: remoteDescription);
            }

            System.Net.IPEndPoint destination;

            try
            {
                destination = remoteEndPoint ?? await ResolveBySystemAsync(HostText,
                                                                           NTP_Port,
                                                                           IPVersionPreference,
                                                                           CancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                ReturnUnusedCookie(activePoolResponse, cookie);
                return Fail("NTPv5 query operation canceled.", NTSQueryErrorCategory.Canceled, remoteEndPoint, remoteDescription);
            }
            catch (Exception e)
            {
                ReturnUnusedCookie(activePoolResponse, cookie);
                return Fail($"NTPv5 request to {remoteDescription} could not be sent: {e.Message}",
                            NTSQueryErrorCategory.Exception, remoteEndPoint, remoteDescription);
            }

            #endregion

            #region Build the request

            var interleaved  = NTPv5Interleaved;

            var flags        = (AcceptUnsynchronized ? NTPv5Flags.Unsynchronized  : NTPv5Flags.None) |
                               (interleaved is not null ? NTPv5Flags.InterleavedMode : NTPv5Flags.None);

            NTPv5ClientRequest request;

            try
            {
                request = NTPv5Client.BuildRequest(Timescale:            Timescale,
                                                   Flags:                flags,
                                                   ServerCookie:         interleaved?.NextServerCookie ?? 0,
                                                   RequestCorrection:    RequestCorrection,
                                                   RequestReferenceIds:  NTPv5OwnReferenceId is not null,
                                                   ExtensionFields:      ExtensionFields,
                                                   NTS:                  NTSKEResponse is not null && cookie is not null
                                                                             ? new NTPv5ClientNTS(NTSKEResponse.C2SKey,
                                                                                                  NTSKEResponse.S2CKey,
                                                                                                  NTSKEResponse.AEADAlgorithm,
                                                                                                  cookie,
                                                                                                  CalculateCookiePlaceholderCount())
                                                                             : null);
            }
            catch (Exception e)
            {
                ReturnUnusedCookie(activePoolResponse, cookie);
                return Fail($"The NTPv5 request could not be built: {e.Message}", NTSQueryErrorCategory.Exception, remoteEndPoint, remoteDescription);
            }

            #endregion

            var requestSent = false;

            using var receiveBuffer = new ReceiveBuffer();
            using var udpSocket     = new Socket(destination.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

            try
            {

                udpSocket.Bind(udpSocket.AddressFamily == AddressFamily.InterNetworkV6
                                   ? anyIPv6EndPoint
                                   : anyIPv4EndPoint);

                AccessState?.RecordQuery(TimeProvider.GetUtcNow());

                var sendStopwatchTimestamp = Stopwatch.GetTimestamp();

                await udpSocket.SendToAsync(request.Datagram, SocketFlags.None, destination, CancellationToken).ConfigureAwait(false);

                requestSent = true;

                var t1 = TimeProvider.GetUtcNow().UtcDateTime;

                NTPv5ResponseValidation? rejected = null;

                while (true)
                {

                    var remaining = timeout - Stopwatch.GetElapsedTime(sendStopwatchTimestamp);

                    var received  = remaining > TimeSpan.Zero
                                        ? await ReceiveUdpResponseAsync(udpSocket, receiveBuffer.Bytes, remaining, CancellationToken).ConfigureAwait(false)
                                        : (Result: (UdpReceiveResult?) null, TimedOut: true);

                    if (received.TimedOut || received.Result is not UdpReceiveResult datagram)
                    {

                        interleaved?.RecordUnansweredRequest();

                        if (rejected is not null)
                        {

                            // RFC 8915 § 5.7, as for NTPv4: a NAK takes effect when nothing
                            // valid followed it - and a NAK is what retires the cookies.
                            if (rejected.Status == NTPv5ResponseStatus.AuthenticationNAK)
                                lock (cookieLock)
                                    RetirePoolLocked();

                            return Fail(rejected.ErrorMessage ?? rejected.Status.ToString(),
                                        rejected.Status is NTPv5ResponseStatus.NotAuthenticated or NTPv5ResponseStatus.AuthenticationNAK
                                            ? NTSQueryErrorCategory.NTSAuthentication
                                            : NTSQueryErrorCategory.Protocol,
                                        remoteEndPoint, remoteDescription, request, rejected);

                        }

                        return Fail($"No NTPv5 response from {remoteDescription} within {Math.Round(timeout.TotalSeconds, 2)} seconds timeout!",
                                    NTSQueryErrorCategory.NTPTimeout, remoteEndPoint, remoteDescription, request);

                    }

                    if (!EndpointsMatch(datagram.RemoteEndPoint, destination))
                        continue;

                    var t4                       = TimeProvider.GetUtcNow().UtcDateTime;
                    var receiveStopwatchTimestamp = Stopwatch.GetTimestamp();

                    var validation               = NTPv5Client.Validate(datagram.Buffer, request);

                    if (!validation.IsValid)
                    {

                        // § 9.4: "The client MUST ignore all invalid responses". The first is
                        // kept to report, unless a NAK comes later, which says more.
                        if (rejected is null ||
                            (validation.Status == NTPv5ResponseStatus.AuthenticationNAK &&
                             rejected.Status   != NTPv5ResponseStatus.AuthenticationNAK))
                            rejected = validation;

                        continue;

                    }

                    // § 9.4: "accept only the first valid response" - which this is.
                    var response     = validation.Packet;

                    if (validation.Cookies.Count > 0)
                        AddReceivedCookies(validation.Cookies);

                    var measurement  = interleaved is not null
                                           ? interleaved.RecordValidResponse(request, response, t1, t4, CorrectionParameters)
                                           : NTPv5Client.Measure(t1, response, t4, request, CorrectionParameters);

                    var unusable     = NTPv5Client.CheckUsable(response, request, Limits);

                    var referenceIds = request.ReferenceIdsRequested
                                           ? NTPv5Client.ReferenceIdsOf(response)
                                           : null;

                    var isLoop       = referenceIds is not null &&
                                       NTPv5OwnReferenceId is UInt64 own &&
                                       NTPv5Client.IsLoop(referenceIds, own);

                    var mayQuery     = true;

                    if (AccessState is not null)
                    {
                        AccessState.RecordAnswer();
                        mayQuery = AccessState.ApplyNTPv5Poll(response.Poll,
                                                              TimeProvider.GetUtcNow(),
                                                              request.IsNTS ? NTPKissTrust.Authenticated : NTPKissTrust.Unprotected);
                    }

                    return new NTPv5QueryResult(true,
                                                null,
                                                NTSQueryErrorCategory.None,
                                                remoteEndPoint,
                                                remoteDescription,
                                                request,
                                                validation,
                                                unusable,
                                                measurement,
                                                referenceIds,
                                                isLoop,
                                                mayQuery,
                                                validation.Cookies.Count,
                                                AvailableCookieCount,
                                                Stopwatch.GetElapsedTime(sendStopwatchTimestamp, receiveStopwatchTimestamp));

                }

            }
            catch (OperationCanceledException)
            {
                if (!requestSent)
                    ReturnUnusedCookie(activePoolResponse, cookie);

                return Fail("NTPv5 query operation canceled.", NTSQueryErrorCategory.Canceled, remoteEndPoint, remoteDescription, request);
            }
            catch (Exception e)
            {
                if (!requestSent)
                    ReturnUnusedCookie(activePoolResponse, cookie);

                return Fail(requestSent
                                ? $"NTPv5 receive exception from {remoteDescription}: {e.Message}"
                                : $"NTPv5 request to {remoteDescription} could not be sent: {e.Message}",
                            NTSQueryErrorCategory.Exception, remoteEndPoint, remoteDescription, request);
            }

        }

        #endregion

        #region QueryNegotiated(Negotiation, Timeout = null, ...)

        /// <summary>
        /// One unauthenticated query in whichever version the § 12 negotiation chose: NTPv4
        /// advertising NTPv5 in the reference timestamp, NTPv4 alone for a while after NTPv5
        /// failed, or NTPv5 once the server echoed the magic.
        /// </summary>
        /// <param name="Negotiation">The negotiation with this client's server, which this query advances.</param>
        /// <param name="Timeout">How long to wait for a valid response.</param>
        /// <param name="AccessState">The access state of the server.</param>
        /// <param name="CancellationToken">A cancellation token.</param>
        public async Task<NTPNegotiatedQueryResult> QueryNegotiated(NTPv5VersionNegotiation  Negotiation,
                                                                    TimeSpan?                Timeout             = null,
                                                                    NTPServerAccessState?    AccessState         = null,
                                                                    CancellationToken        CancellationToken   = default)
        {

            if (Negotiation.Version == NTPv5NegotiatedVersion.NTPv5)
            {

                var v5 = await QueryNTPv5(Timeout:            Timeout,
                                          AccessState:        AccessState,
                                          CancellationToken:  CancellationToken).ConfigureAwait(false);

                // § 12: what counts is whether a valid response came. A canceled query says
                // nothing about the server either way.
                var next = v5.ErrorCategory == NTSQueryErrorCategory.Canceled
                               ? Negotiation.Version
                               : Negotiation.RecordNTPv5Result(v5.Success);

                return new (null, v5, next);

            }

            var advertise = Negotiation.Version == NTPv5NegotiatedVersion.NTPv4Advertising;

            var v4 = await QueryTime(Timeout:            Timeout,
                                     AdvertiseNTPv5:     advertise,
                                     CancellationToken:  CancellationToken).ConfigureAwait(false);

            // The echo first, while the version is still the one the request went out in.
            if (advertise && v4.Success && v4.Response is not null)
                Negotiation.RecordNTPv4Response(v4.Response.ReferenceTimestamp);

            Negotiation.RecordNTPv4Request();

            return new (v4, null, Negotiation.Version);

        }

        #endregion

    }

}
