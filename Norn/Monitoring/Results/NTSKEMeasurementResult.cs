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

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// NTS-KE (Key Establishment) handshake measurement.
    /// </summary>
    public class NTSKEMeasurementResult
    {

        #region Properties

        /// <summary>
        /// Whether the NTS-KE handshake succeeded.
        /// </summary>
        public Boolean               Success                  { get; init; }

        /// <summary>
        /// Total duration of the NTS-KE exchange (TCP connect + TLS handshake + NTS-KE protocol).
        /// </summary>
        public TimeSpan              TotalDuration             { get; init; }

        /// <summary>
        /// Duration of the TCP connection establishment only.
        /// </summary>
        public TimeSpan              TCPConnectDuration        { get; init; }

        /// <summary>
        /// Duration of the TLS 1.3 handshake.
        /// </summary>
        public TimeSpan              TLSHandshakeDuration      { get; init; }

        /// <summary>
        /// Duration of the NTS-KE protocol exchange (after TLS handshake).
        /// </summary>
        public TimeSpan              NTSKEProtocolDuration     { get; init; }

        /// <summary>
        /// Number of cookies received.
        /// </summary>
        public UInt16                NumberOfCookies           { get; init; }

        /// <summary>
        /// The AEAD algorithm negotiated.
        /// </summary>
        public String?               AEADAlgorithm            { get; init; }

        /// <summary>
        /// The NTP server hostname negotiated (if different from NTS-KE server).
        /// </summary>
        public String?               NTPServerNegotiated       { get; init; }

        /// <summary>
        /// The NTP port negotiated (if different from 123).
        /// </summary>
        public UInt16?               NTPPortNegotiated         { get; init; }


        // ──────────── TLS Certificate Info ──────────────

        /// <summary>
        /// TLS certificate details.
        /// </summary>
        public TLSCertificateInfo?   CertificateInfo           { get; init; }

        /// <summary>
        /// The TLS cipher suite used.
        /// </summary>
        public String?               TLSCipherSuite            { get; init; }

        /// <summary>
        /// The TLS protocol version negotiated.
        /// </summary>
        public String?               TLSVersion                { get; init; }


        /// <summary>
        /// Error if NTS-KE failed.
        /// </summary>
        public String?               ErrorMessage              { get; init; }

        #endregion

        #region ToJSON()

        public JObject ToJSON()
        {

            var json = new JObject(
                           new JProperty("success",                 Success),
                           new JProperty("totalDurationMs",         Math.Round(TotalDuration.TotalMilliseconds,        3)),
                           new JProperty("tcpConnectDurationMs",    Math.Round(TCPConnectDuration.TotalMilliseconds,   3)),
                           new JProperty("tlsHandshakeDurationMs",  Math.Round(TLSHandshakeDuration.TotalMilliseconds, 3)),
                           new JProperty("ntskeProtocolDurationMs", Math.Round(NTSKEProtocolDuration.TotalMilliseconds, 3)),
                           new JProperty("numberOfCookies",         NumberOfCookies)
                       );

            if (AEADAlgorithm is not null)
                json.Add("aeadAlgorithm", AEADAlgorithm);

            if (NTPServerNegotiated is not null)
                json.Add("ntpServerNegotiated", NTPServerNegotiated);

            if (NTPPortNegotiated.HasValue)
                json.Add("ntpPortNegotiated", NTPPortNegotiated.Value);

            if (CertificateInfo is not null)
                json.Add("certificate", CertificateInfo.ToJSON());

            if (TLSCipherSuite is not null)
                json.Add("tlsCipherSuite", TLSCipherSuite);

            if (TLSVersion is not null)
                json.Add("tlsVersion", TLSVersion);

            if (ErrorMessage is not null)
                json.Add("error", ErrorMessage);

            return json;

        }

        #endregion

    }

}
