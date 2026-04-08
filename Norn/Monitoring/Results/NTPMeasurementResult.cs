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
        public Boolean    Success                     { get; init; }

        /// <summary>
        /// Whether the NTS authentication (Unique ID match + AEAD decrypt) succeeded.
        /// </summary>
        public Boolean    NTSAuthenticationValid      { get; init; }

        /// <summary>
        /// Whether the Unique Identifier in the response matched the request.
        /// </summary>
        public Boolean    UniqueIdMatched             { get; init; }


        // ──────────── NTP Timestamps (RFC 5905) ──────────────

        /// <summary>
        /// T1: Time the client sent the request (client clock, high-res Stopwatch).
        /// </summary>
        public DateTime   T1_ClientSend               { get; init; }

        /// <summary>
        /// T2: Time the server received the request (server clock from ReceiveTimestamp).
        /// </summary>
        public DateTime   T2_ServerReceive             { get; init; }

        /// <summary>
        /// T3: Time the server sent the response (server clock from TransmitTimestamp).
        /// </summary>
        public DateTime   T3_ServerTransmit            { get; init; }

        /// <summary>
        /// T4: Time the client received the response (client clock, high-res Stopwatch).
        /// </summary>
        public DateTime   T4_ClientReceive             { get; init; }


        // ──────────── Derived Metrics ──────────────

        /// <summary>
        /// Clock offset: θ = ((T2 - T1) + (T3 - T4)) / 2
        /// Positive means local clock is behind the server.
        /// </summary>
        public TimeSpan   Offset                       { get; init; }

        /// <summary>
        /// Round-trip delay: δ = (T4 - T1) - (T3 - T2)
        /// </summary>
        public TimeSpan   RoundTripDelay               { get; init; }

        /// <summary>
        /// The measured RTT using high-resolution Stopwatch (not NTP timestamps).
        /// This is more reliable for network quality assessment.
        /// </summary>
        public TimeSpan   StopwatchRTT                 { get; init; }


        // ──────────── NTP Header Fields ──────────────

        /// <summary>
        /// Leap Indicator (0 = no warning, 1 = +1s, 2 = -1s, 3 = unsynchronized).
        /// </summary>
        public Byte       LeapIndicator                { get; init; }

        /// <summary>
        /// Stratum (1 = primary, 2-15 = secondary).
        /// </summary>
        public Byte       Stratum                      { get; init; }

        /// <summary>
        /// Poll interval as a log2 value.
        /// </summary>
        public Byte       Poll                         { get; init; }

        /// <summary>
        /// Precision of the server clock as a log2 value.
        /// </summary>
        public SByte      Precision                    { get; init; }

        /// <summary>
        /// Root delay as seconds (converted from NTP 16.16 fixed-point).
        /// </summary>
        public Double     RootDelaySeconds             { get; init; }

        /// <summary>
        /// Root dispersion as seconds (converted from NTP 16.16 fixed-point).
        /// </summary>
        public Double     RootDispersionSeconds        { get; init; }

        /// <summary>
        /// Reference identifier (e.g., "PTB", "GPS", "PPS").
        /// </summary>
        public String     ReferenceId                  { get; init; } = "";

        /// <summary>
        /// When the server clock was last set/corrected.
        /// </summary>
        public DateTime   ReferenceTimestamp            { get; init; }


        // ──────────── NTS Extension Results ──────────────

        /// <summary>
        /// Whether a new cookie was included in the response (cookie rotation health).
        /// </summary>
        public Boolean    NewCookieReceived             { get; init; }

        /// <summary>
        /// Whether a Kiss-o'-Death (KoD) packet was received.
        /// </summary>
        public Boolean    KissOfDeath                   { get; init; }

        /// <summary>
        /// KoD code if received.
        /// </summary>
        public String?    KissOfDeathCode               { get; init; }


        /// <summary>
        /// Error if NTP query failed.
        /// </summary>
        public String?    ErrorMessage                  { get; init; }

        #endregion

        #region ToJSON()

        public JObject ToJSON()
        {

            var json = new JObject(

                           new JProperty("success",                  Success),
                           new JProperty("ntsAuthValid",             NTSAuthenticationValid),
                           new JProperty("uniqueIdMatched",          UniqueIdMatched),

                           new JProperty("t1_clientSend",            T1_ClientSend.   ToString("o")),
                           new JProperty("t2_serverReceive",         T2_ServerReceive.ToString("o")),
                           new JProperty("t3_serverTransmit",        T3_ServerTransmit.ToString("o")),
                           new JProperty("t4_clientReceive",         T4_ClientReceive.ToString("o")),

                           new JProperty("offsetMs",                 Math.Round(Offset.         TotalMilliseconds, 6)),
                           new JProperty("roundTripDelayMs",         Math.Round(RoundTripDelay. TotalMilliseconds, 6)),
                           new JProperty("stopwatchRttMs",           Math.Round(StopwatchRTT.   TotalMilliseconds, 6)),

                           new JProperty("leapIndicator",            LeapIndicator),
                           new JProperty("stratum",                  Stratum),
                           new JProperty("poll",                     Poll),
                           new JProperty("precision",                Precision),
                           new JProperty("rootDelayMs",              Math.Round(RootDelaySeconds      * 1000.0, 6)),
                           new JProperty("rootDispersionMs",         Math.Round(RootDispersionSeconds * 1000.0, 6)),
                           new JProperty("referenceId",              ReferenceId),
                           new JProperty("referenceTimestamp",       ReferenceTimestamp.ToString("o")),

                           new JProperty("newCookieReceived",        NewCookieReceived),
                           new JProperty("kissOfDeath",              KissOfDeath)

                       );

            if (KissOfDeathCode is not null)
                json.Add("kissOfDeathCode", KissOfDeathCode);

            if (ErrorMessage is not null)
                json.Add("error", ErrorMessage);

            return json;

        }

        #endregion

    }

}
