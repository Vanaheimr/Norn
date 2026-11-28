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
using System.Net;

using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// The result of one NTPv5 query (draft-ietf-ntp-ntpv5-10 § 9).
    /// </summary>
    /// <remarks>
    /// A query succeeds when a valid response (§ 9.4) arrives; whether its time is usable
    /// (§ 9.5) is <see cref="Unusable"/>, and the measurement is there either way, so that a
    /// monitor can see what an unsynchronized server says. A synchronizing client takes
    /// <see cref="IsUsable"/> and <see cref="IsLoop"/> into account before it believes it.
    /// </remarks>
    /// <param name="Success">Whether a valid response arrived.</param>
    /// <param name="ErrorMessage">Why not, when not.</param>
    /// <param name="ErrorCategory">What kind of failure.</param>
    /// <param name="RemoteEndPoint">Where the request went.</param>
    /// <param name="RemoteDescription">The server, for reports.</param>
    /// <param name="Request">The request as sent, where one was.</param>
    /// <param name="Validation">The validation of the response that decided the query: the valid one, or the first rejected one.</param>
    /// <param name="Unusable">Why the valid response is not usable for synchronization.</param>
    /// <param name="Measurement">The measurement of § 8, where there is one.</param>
    /// <param name="ReferenceIds">The server's reference IDs, where the request asked and the response carried them.</param>
    /// <param name="IsLoop">Whether those contain this client's own reference ID (§ 7.4).</param>
    /// <param name="MayQueryAgain">Whether the server may still be queried, after its poll field.</param>
    /// <param name="NewCookies">How many cookies the response delivered.</param>
    /// <param name="RemainingCookies">How many cookies are left in the pool.</param>
    /// <param name="RoundTripTime">The round trip as the stopwatch measured it.</param>
    public sealed record NTPv5QueryResult(Boolean                                Success,
                                          String?                                ErrorMessage,
                                          NTSQueryErrorCategory                  ErrorCategory,
                                          IPEndPoint?                            RemoteEndPoint,
                                          String                                 RemoteDescription,
                                          NTPv5ClientRequest?                    Request              = null,
                                          NTPv5ResponseValidation?               Validation           = null,
                                          NTPv5Unusable                          Unusable             = NTPv5Unusable.None,
                                          NTPv5Measurement?                      Measurement          = null,
                                          IReadOnlyList<NTPv5ReferenceIdEntry>?  ReferenceIds         = null,
                                          Boolean                                IsLoop               = false,
                                          Boolean                                MayQueryAgain        = true,
                                          Int32                                  NewCookies           = 0,
                                          Int32                                  RemainingCookies     = 0,
                                          TimeSpan?                              RoundTripTime        = null)
    {

        /// <summary>
        /// The response that decided the query.
        /// </summary>
        public NTPv5Packet?  Response
            => Validation?.Packet;

        /// <summary>
        /// Whether the response was authenticated by NTS.
        /// </summary>
        public Boolean       IsAuthenticated
            => Success && Request?.IsNTS == true;

        /// <summary>
        /// Whether the response is valid and usable for synchronization, and not a loop.
        /// </summary>
        [MemberNotNullWhen(true, nameof(Measurement))]
        public Boolean       IsUsable
            => Success && Unusable == NTPv5Unusable.None && Measurement is not null && !IsLoop;

        /// <summary>
        /// Whether the server answered with an Authentication NAK and nothing valid followed.
        /// </summary>
        public Boolean       IsAuthenticationNAK
            => Validation?.Status == NTPv5ResponseStatus.AuthenticationNAK;

        /// <summary>
        /// The poll field of the response: the minimum polling interval the server allows as a
        /// log2 value, or 127 where it wants no more requests.
        /// </summary>
        public SByte?        Poll
            => Success ? Response?.Poll : null;

        /// <summary>
        /// The versions and flags the server announces in a Server Information field.
        /// </summary>
        public (UInt16 SupportedVersions, NTPv5Flags SupportedFlags)? ServerInformation
            => Response?.Find(NTPv5ExtensionTypes.ServerInformation) is NTPv5ExtensionField information &&
               information.TryReadServerInformation(out var versions, out var flags)
                   ? (versions, flags)
                   : null;

        /// <summary>
        /// The server's time sources, where the request asked for them with a Time Sources
        /// Request (draft-ietf-ntp-ntpv5-10 § 7.5) and the response carried them.
        /// </summary>
        public IReadOnlyList<NTPv5TimeSource>? TimeSources
            => Success && Response is not null
                   ? NTPv5Client.TimeSourcesOf(Response)
                   : null;

        /// <summary>
        /// The receive timestamps of the request in the other timescales the response gives
        /// (draft-ietf-ntp-ntpv5-10 § 7.10), where the request asked with a Secondary Receive
        /// Timestamp field for each.
        /// </summary>
        public IReadOnlyDictionary<NTPv5Timescale, DateTime?> SecondaryReceiveTimes
            => Success && Response is not null
                   ? NTPv5Client.SecondaryReceiveTimesOf(Response)
                   : new Dictionary<NTPv5Timescale, DateTime?>();

        /// <summary>
        /// How far the given timescale is ahead of the timescale of the header, from a
        /// Secondary Receive Timestamp of the response (§ 7.10).
        /// </summary>
        public TimeSpan? TimescaleOffset(NTPv5Timescale Timescale)
            => Success && Response is not null
                   ? NTPv5Client.TimescaleOffset(Response, Timescale)
                   : null;

        /// <inheritdoc/>
        public override String ToString()

            => Success
                   ? $"NTPv5 {RemoteDescription}: {(Measurement is null ? "no measurement" : $"offset {Measurement.BestOffset.TotalMilliseconds:0.###} ms, delay {Measurement.BestDelay.TotalMilliseconds:0.###} ms")}{(Unusable != NTPv5Unusable.None ? $", unusable: {Unusable}" : "")}{(IsLoop ? ", loop" : "")}"
                   : $"NTPv5 {RemoteDescription}: {ErrorCategory}: {ErrorMessage}";

    }

}
