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
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// What a server showed of NTPv5 (draft-ietf-ntp-ntpv5-10), in the three ways a client
    /// can find out: whether it echoes the negotiation magic in NTPv4 (§ 12), whether it
    /// answers a plain NTPv5 request and what its Server Information says (§ 7.6), and whether
    /// its key exchange agrees to NTS for NTPv5 and the agreed query is answered (§ 11).
    /// </summary>
    /// <remarks>
    /// Null in a field means "not found out": no valid NTPv4 response to read the echo from,
    /// or a key exchange that was not tried, as over SSH. False means asked and answered no.
    /// </remarks>
    /// <param name="Timestamp">When the server was probed.</param>
    public sealed record NTPv5CapabilityResult(DateTimeOffset Timestamp)
    {

        #region Properties

        /// <summary>
        /// § 12: whether a valid plain NTPv4 response echoed the magic; null where no valid
        /// one came.
        /// </summary>
        public Boolean?         AdvertisedInNTPv4    { get; init; }

        /// <summary>
        /// Why the NTPv4 query got no valid response.
        /// </summary>
        public String?          NTPv4Error           { get; init; }

        /// <summary>
        /// Whether a plain NTPv5 request got a valid response (§ 9.4).
        /// </summary>
        public Boolean          PlainNTPv5           { get; init; }

        /// <summary>
        /// Why the plain NTPv5 request got no valid response.
        /// </summary>
        public String?          PlainNTPv5Error      { get; init; }

        /// <summary>
        /// Why the valid plain NTPv5 response is not usable for synchronization (§ 9.5), or
        /// None where it is.
        /// </summary>
        public NTPv5Unusable?   PlainUnusable        { get; init; }

        /// <summary>
        /// The versions of the Server Information (§ 7.6), one bit for each.
        /// </summary>
        public UInt16?          SupportedVersions    { get; init; }

        /// <summary>
        /// The flags of the Server Information.
        /// </summary>
        public NTPv5Flags?      SupportedFlags       { get; init; }

        /// <summary>
        /// The stratum of the valid plain NTPv5 response.
        /// </summary>
        public Byte?            Stratum              { get; init; }

        /// <summary>
        /// The offset the plain NTPv5 exchange measured.
        /// </summary>
        public TimeSpan?        Offset               { get; init; }

        /// <summary>
        /// The delay the plain NTPv5 exchange measured.
        /// </summary>
        public TimeSpan?        Delay                { get; init; }

        /// <summary>
        /// § 11: whether the key exchange agreed to NTPv5 (0x8001) when it was offered first;
        /// null where it was not tried or failed.
        /// </summary>
        public Boolean?         NTSNegotiated        { get; init; }

        /// <summary>
        /// Whether the NTS-protected NTPv5 query after it was answered and authenticated;
        /// null where there was no key exchange that agreed to NTPv5.
        /// </summary>
        public Boolean?         NTSQuery             { get; init; }

        /// <summary>
        /// Why the key exchange or the NTS query failed.
        /// </summary>
        public String?          NTSError             { get; init; }

        /// <summary>
        /// Whether this is the result of an earlier probe, held until the next is due.
        /// </summary>
        public Boolean          FromCache            { get; init; }

        /// <summary>
        /// Whether the server showed NTPv5 in any of the three ways.
        /// </summary>
        public Boolean          SupportsNTPv5
            => AdvertisedInNTPv4 == true || PlainNTPv5 || NTSNegotiated == true;

        #endregion


        #region ToJSON()

        /// <summary>
        /// The result as JSON.
        /// </summary>
        public JObject ToJSON()

            => JSONObject.Create(

                         new JProperty("timestamp",           Timestamp.ToString("o")),
                         new JProperty("draft",               NTPv5Draft.Identification),
                         new JProperty("supportsNTPv5",       SupportsNTPv5),
                         new JProperty("plainNTPv5",          PlainNTPv5),
                         new JProperty("fromCache",           FromCache),

                   AdvertisedInNTPv4.HasValue
                       ? new JProperty("advertisedInNTPv4", AdvertisedInNTPv4.Value)
                       : null,

                   NTPv4Error is not null
                       ? new JProperty("ntpv4Error",        NTPv4Error)
                       : null,

                   PlainNTPv5Error is not null
                       ? new JProperty("plainNTPv5Error",   PlainNTPv5Error)
                       : null,

                   PlainUnusable.HasValue
                       ? new JProperty("plainUnusable",     PlainUnusable.Value.ToString())
                       : null,

                   SupportedVersions.HasValue
                       ? new JProperty("supportedVersions", SupportedVersions.Value)
                       : null,

                   SupportedFlags.HasValue
                       ? new JProperty("supportedFlags",    (UInt16) SupportedFlags.Value)
                       : null,

                   Stratum.HasValue
                       ? new JProperty("stratum",           Stratum.Value)
                       : null,

                   Offset.HasValue
                       ? new JProperty("offsetMs",          Math.Round(Offset.Value.TotalMilliseconds, 3))
                       : null,

                   Delay.HasValue
                       ? new JProperty("delayMs",           Math.Round(Delay.Value.TotalMilliseconds, 3))
                       : null,

                   NTSNegotiated.HasValue
                       ? new JProperty("ntsNegotiated",     NTSNegotiated.Value)
                       : null,

                   NTSQuery.HasValue
                       ? new JProperty("ntsQuery",          NTSQuery.Value)
                       : null,

                   NTSError is not null
                       ? new JProperty("ntsError",          NTSError)
                       : null

               );

        #endregion

    }

}
