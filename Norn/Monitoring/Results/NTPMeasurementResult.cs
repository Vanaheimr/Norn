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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// NTP query measurement with precise timing.
    /// </summary>
    public class NTPMeasurementResult
    {

        #region Properties

        /// <summary>
        /// Whether the NTP query succeeded (response received AND NTS authentication valid).
        /// </summary>
        public Boolean                  Success                       { get; init; }

        /// <summary>
        /// Whether the NTS authentication (Unique ID match + AEAD decrypt) succeeded.
        /// </summary>
        public Boolean                  NTSAuthenticationValid        { get; init; }

        /// <summary>
        /// Whether the Unique Identifier in the response matched the request.
        /// </summary>
        public Boolean                  UniqueIdMatched               { get; init; }


        // ──────────── NTP Timestamps (RFC 5905) ──────────────

        /// <summary>
        /// T1: Time the client sent the request (client clock, high-res Stopwatch).
        /// </summary>
        public DateTimeOffset           T1_ClientSend                 { get; init; }

        /// <summary>
        /// T2: Time the server received the request (server clock from ReceiveTimestamp).
        /// </summary>
        public DateTimeOffset           T2_ServerReceive              { get; init; }

        /// <summary>
        /// T3: Time the server sent the response (server clock from TransmitTimestamp).
        /// </summary>
        public DateTimeOffset           T3_ServerTransmit             { get; init; }

        /// <summary>
        /// T4: Time the client received the response (client clock, high-res Stopwatch).
        /// </summary>
        public DateTimeOffset           T4_ClientReceive              { get; init; }


        // ──────────── Derived Metrics ──────────────

        /// <summary>
        /// Clock offset: θ = ((T2 - T1) + (T3 - T4)) / 2
        /// Positive means local clock is behind the server.
        /// </summary>
        public TimeSpan                 Offset                        { get; init; }

        /// <summary>
        /// Round-trip delay: δ = (T4 - T1) - (T3 - T2)
        /// </summary>
        public TimeSpan                 RoundTripDelay                { get; init; }

        /// <summary>
        /// The measured RTT using high-resolution Stopwatch (not NTP timestamps).
        /// This is more reliable for network quality assessment.
        /// </summary>
        public TimeSpan                 StopwatchRTT                  { get; init; }

        /// <summary>
        /// The hostname selected for the NTP/NTS UDP query.
        /// </summary>
        public DomainName?              RemoteHost                    { get; init; }

        /// <summary>
        /// The concrete remote IP address used for the NTP/NTS UDP query, when known.
        /// </summary>
        public IIPAddress?              RemoteAddress                 { get; init; }

        /// <summary>
        /// The UDP port used for the NTP/NTS query.
        /// </summary>
        public IPPort?                  RemotePort                    { get; init; }


        // ──────────── NTP Header Fields ──────────────

        /// <summary>
        /// Leap Indicator (0 = no warning, 1 = +1s, 2 = -1s, 3 = unsynchronized).
        /// </summary>
        public Byte                     LeapIndicator                 { get; init; }

        /// <summary>
        /// Stratum (1 = primary, 2-15 = secondary).
        /// </summary>
        public Byte                     Stratum                       { get; init; }

        /// <summary>
        /// Poll interval as a log2 value.
        /// </summary>
        public Byte                     Poll                          { get; init; }

        /// <summary>
        /// Precision of the server clock as a log2 value.
        /// </summary>
        public SByte                    Precision                     { get; init; }

        /// <summary>
        /// Root delay as seconds (converted from NTP 16.16 fixed-point).
        /// </summary>
        public Double                   RootDelaySeconds              { get; init; }

        /// <summary>
        /// Root dispersion as seconds (converted from NTP 16.16 fixed-point).
        /// </summary>
        public Double                   RootDispersionSeconds         { get; init; }

        /// <summary>
        /// Reference identifier (e.g., "PTB", "GPS", "PPS").
        /// </summary>
        public String                   ReferenceId                   { get; init; } = "";

        /// <summary>
        /// When the server clock was last set/corrected.
        /// </summary>
        public DateTimeOffset           ReferenceTimestamp            { get; init; }


        // ──────────── NTS Extension Results ──────────────

        /// <summary>
        /// Whether a new cookie was included in the response (cookie rotation health).
        /// </summary>
        public Boolean                  NewCookieReceived             { get; init; }

        /// <summary>
        /// Remaining cached cookies after this query, when tracked by monitoring.
        /// </summary>
        public Byte?                    RemainingCookiesAfterQuery    { get; init; }

        public Int32?                   CookiePoolSize                { get; init; }

        public Int32?                   CookiePoolMaxSize             { get; init; }

        public Int32?                   CookiePoolLowWatermark        { get; init; }

        public Int64?                   SeededCookieCount             { get; init; }

        public Int64?                   CookiesReceived               { get; init; }

        public Int64?                   CookiesConsumed               { get; init; }

        public Int64?                   DroppedCookieCount            { get; init; }

        public Boolean?                 CookiePoolLow                 { get; init; }

        public Boolean?                 CookiePoolEmpty               { get; init; }

        /// <summary>
        /// Whether a Kiss-o'-Death (KoD) packet was received.
        /// </summary>
        public Boolean                  KissOfDeath                   { get; init; }

        /// <summary>
        /// KoD code if received.
        /// </summary>
        public String?                  KissOfDeathCode               { get; init; }


        /// <summary>
        /// Error if NTP query failed.
        /// </summary>
        public Error?                   ErrorMessage                  { get; init; }

        /// <summary>
        /// Structured error category if NTP/NTS failed.
        /// </summary>
        public MonitoringErrorCategory  ErrorCategory                 { get; init; } = MonitoringErrorCategory.None;

        #endregion

        #region Constructor(s)

        //public NTPMeasurementResult(Boolean                  Success,
        //                            Boolean                  NTSAuthenticationValid,
        //                            Boolean                  UniqueIdMatched,
        //                            DateTimeOffset           T1_ClientSend,
        //                            DateTimeOffset           T2_ServerReceive,
        //                            DateTimeOffset           T3_ServerTransmit,
        //                            DateTimeOffset           T4_ClientReceive,
        //                            TimeSpan                 Offset,
        //                            TimeSpan                 RoundTripDelay,
        //                            TimeSpan                 StopwatchRTT,
        //                            Byte                     LeapIndicator,
        //                            Byte                     Stratum,
        //                            Byte                     Poll,
        //                            SByte                    Precision,
        //                            Double                   RootDelaySeconds,
        //                            Double                   RootDispersionSeconds,
        //                            String                   ReferenceId,
        //                            DateTimeOffset           ReferenceTimestamp,
        //                            Boolean                  NewCookieReceived,
        //                            Byte?                    RemainingCookiesAfterQuery,
        //                            Boolean                  KissOfDeath,
        //                            String?                  KissOfDeathCode,
        //                            DomainName?              RemoteHost      = null,
        //                            IIPAddress?              RemoteAddress   = null,
        //                            IPPort?                  RemotePort      = null,
        //                            Error?                   ErrorMessage    = null,
        //                            MonitoringErrorCategory  ErrorCategory   = MonitoringErrorCategory.None)
        //{

        //    this.Success                     = Success;
        //    this.NTSAuthenticationValid      = NTSAuthenticationValid;
        //    this.UniqueIdMatched             = UniqueIdMatched;
        //    this.T1_ClientSend               = T1_ClientSend;
        //    this.T2_ServerReceive            = T2_ServerReceive;
        //    this.T3_ServerTransmit           = T3_ServerTransmit;
        //    this.T4_ClientReceive            = T4_ClientReceive;
        //    this.Offset                      = Offset;
        //    this.RoundTripDelay              = RoundTripDelay;
        //    this.StopwatchRTT                = StopwatchRTT;
        //    this.LeapIndicator               = LeapIndicator;
        //    this.Stratum                     = Stratum;
        //    this.Poll                        = Poll;
        //    this.Precision                   = Precision;
        //    this.RootDelaySeconds            = RootDelaySeconds;
        //    this.RootDispersionSeconds       = RootDispersionSeconds;
        //    this.ReferenceId                 = ReferenceId;
        //    this.ReferenceTimestamp          = ReferenceTimestamp;
        //    this.NewCookieReceived           = NewCookieReceived;
        //    this.RemainingCookiesAfterQuery  = RemainingCookiesAfterQuery;
        //    this.KissOfDeath                 = KissOfDeath;
        //    this.KissOfDeathCode             = KissOfDeathCode;
        //    this.RemoteHost                  = RemoteHost;
        //    this.RemoteAddress               = RemoteAddress;
        //    this.RemotePort                  = RemotePort;
        //    this.ErrorMessage                = ErrorMessage;
        //    this.ErrorCategory               = ErrorCategory;

        //}

        #endregion


        #region ToJSON()

        public JObject ToJSON()
        {

            var json = JSONObject.Create(

                                 new JProperty("success",                      Success),
                                 new JProperty("ntsAuthValid",                 NTSAuthenticationValid),
                                 new JProperty("uniqueIdMatched",              UniqueIdMatched),

                                 new JProperty("t1_clientSend",                T1_ClientSend.     ToISO8601()),
                                 new JProperty("t2_serverReceive",             T2_ServerReceive.  ToISO8601()),
                                 new JProperty("t3_serverTransmit",            T3_ServerTransmit. ToISO8601()),
                                 new JProperty("t4_clientReceive",             T4_ClientReceive.  ToISO8601()),

                                 new JProperty("offsetMs",                     Math.Round(Offset.        TotalMilliseconds, 6)),
                                 new JProperty("roundTripDelayMs",             Math.Round(RoundTripDelay.TotalMilliseconds, 6)),
                                 new JProperty("stopwatchRttMs",               Math.Round(StopwatchRTT.  TotalMilliseconds, 6)),

                                 new JProperty("leapIndicator",                LeapIndicator),
                                 new JProperty("stratum",                      Stratum),
                                 new JProperty("poll",                         Poll),
                                 new JProperty("precision",                    Precision),
                                 new JProperty("rootDelayMs",                  Math.Round(RootDelaySeconds      * 1000.0, 6)),
                                 new JProperty("rootDispersionMs",             Math.Round(RootDispersionSeconds * 1000.0, 6)),
                                 new JProperty("referenceId",                  ReferenceId),
                                 new JProperty("referenceTimestamp",           ReferenceTimestamp.ToISO8601()),

                                 new JProperty("newCookieReceived",            NewCookieReceived),
                                 new JProperty("kissOfDeath",                  KissOfDeath),

                           RemoteHost      is not null
                               ? new JProperty("remoteHost",                   RemoteHost.      ToString().TrimEnd('.'))
                               : null,

                           RemoteAddress   is not null
                               ? new JProperty("remoteAddress",                NormalizeIPAddress(RemoteAddress.ToString()))
                               : null,

                           RemotePort.HasValue
                               ? new JProperty("remotePort",                   RemotePort.Value.ToUInt16())
                               : null,

                           RemainingCookiesAfterQuery.HasValue
                               ? new JProperty("remainingCookiesAfterQuery",   RemainingCookiesAfterQuery.Value)
                               : null,

                           CookiePoolSize.HasValue
                               ? new JProperty("cookiePoolSize",               CookiePoolSize.Value)
                               : null,

                           CookiePoolMaxSize.HasValue
                               ? new JProperty("cookiePoolMaxSize",            CookiePoolMaxSize.Value)
                               : null,

                           CookiePoolLowWatermark.HasValue
                               ? new JProperty("cookiePoolLowWatermark",       CookiePoolLowWatermark.Value)
                               : null,

                           SeededCookieCount.HasValue
                               ? new JProperty("seededCookieCount",            SeededCookieCount.Value)
                               : null,

                           CookiesReceived.HasValue
                               ? new JProperty("cookiesReceived",              CookiesReceived.Value)
                               : null,

                           CookiesConsumed.HasValue
                               ? new JProperty("cookiesConsumed",              CookiesConsumed.Value)
                               : null,

                           DroppedCookieCount.HasValue
                               ? new JProperty("droppedCookieCount",           DroppedCookieCount.Value)
                               : null,

                           CookiePoolLow.HasValue
                               ? new JProperty("cookiePoolLow",                CookiePoolLow.Value)
                               : null,

                           CookiePoolEmpty.HasValue
                               ? new JProperty("cookiePoolEmpty",              CookiePoolEmpty.Value)
                               : null,

                           KissOfDeathCode is not null
                               ? new JProperty("kissOfDeathCode",              KissOfDeathCode)
                               : null,

                           ErrorCategory != MonitoringErrorCategory.None
                               ? new JProperty("errorCategory",                ErrorCategory.   ToString())
                               : null,

                           ErrorMessage    is not null
                               ? new JProperty("error",                        ErrorMessage.ToJSON())
                               : null

                       );


            return json;

        }

        #endregion


        #region (private static) NormalizeIPAddress(Text)

        private static String NormalizeIPAddress(String Text)

            => System.Net.IPAddress.TryParse(Text, out var ipAddress)
                   ? ipAddress.ToString()
                   : Text;

        #endregion

    }

}
