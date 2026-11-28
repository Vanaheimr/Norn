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

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTPOverTLS
{

    /// <summary>
    /// The outcome of one NTP-over-TLS query: the time, or why there is none.
    /// </summary>
    public sealed record NTPOverTLSResult
    {

        #region Properties

        /// <summary>
        /// Whether a response came that may be used for synchronization.
        /// </summary>
        public Boolean            Success                 { get; init; }

        /// <summary>
        /// Why not, where it did not.
        /// </summary>
        public String?            ErrorMessage            { get; init; }

        /// <summary>
        /// The requirement of BSI TR-03109-5 by which a response was ignored, e.g.
        /// "REQ.TA.NTP.ProcessResponse.30" - or null, where none was or the query failed before.
        /// </summary>
        public String?            IgnoredBy               { get; init; }

        /// <summary>
        /// The message that was sent: the 48 octets of NTPv4, or the NTPv5 message without its length.
        /// </summary>
        public Byte[]?            RequestBytes            { get; init; }

        /// <summary>
        /// The message that came back, as <see cref="RequestBytes"/>.
        /// </summary>
        public Byte[]?            ResponseBytes           { get; init; }

        /// <summary>
        /// The version of NTP the exchange was in: 4, or 5 (section 6.1 of the white paper
        /// "Secure Time Synchronization").
        /// </summary>
        public Byte               Version                 { get; init; } = 4;

        /// <summary>
        /// The NTPv4 response, with T1 and T4 of this client.
        /// </summary>
        public NTPPacket?         Response                { get; init; }

        /// <summary>
        /// The NTPv5 response, where the exchange was NTPv5 and it parsed.
        /// </summary>
        public NTPv5Packet?       NTPv5Response           { get; init; }

        /// <summary>
        /// Whether the NTPv4 request offered NTPv5, with the magic of draft-ietf-ntp-ntpv5 § 12
        /// in its reference timestamp.
        /// </summary>
        public Boolean            NTPv5Offered            { get; init; }

        /// <summary>
        /// Whether the server's NTPv4 response echoed that magic: it speaks NTPv5.
        /// </summary>
        public Boolean            NTPv5Echoed             { get; init; }

        /// <summary>
        /// theta of RFC 5905 § 8: how far the server's clock is ahead of this client's.
        /// </summary>
        public TimeSpan?          ClockOffset             { get; init; }

        /// <summary>
        /// delta of RFC 5905 § 8: the round trip, without the server's time.
        /// </summary>
        public TimeSpan?          RoundTripDelay          { get; init; }

        /// <summary>
        /// The maximum error of § 7.3.2.1 of the guideline: "rootdelay/2+rootdisp" of the
        /// response, how far the server's time may be from that of its reference.
        /// </summary>
        public TimeSpan?          MaximumError            { get; init; }

        /// <summary>
        /// The server's transmit timestamp T3, as a date.
        /// </summary>
        public DateTime?          ServerTransmitTime      { get; init; }

        /// <summary>
        /// The TLS version that was negotiated.
        /// </summary>
        public String?            TLSVersion              { get; init; }

        /// <summary>
        /// The cipher suite that was negotiated.
        /// </summary>
        public String?            CipherSuite             { get; init; }

        /// <summary>
        /// The certificate the server showed.
        /// </summary>
        public X509Certificate2?  ServerCertificate       { get; init; }

        /// <summary>
        /// What judging it found.
        /// </summary>
        public SslPolicyErrors?   CertificatePolicyErrors { get; init; }

        /// <summary>
        /// Whether the server asked for a client certificate.
        /// </summary>
        public Boolean            ClientCertificateRequested { get; init; }

        /// <summary>
        /// Whether one was sent.
        /// </summary>
        public Boolean            ClientCertificateSent   { get; init; }

        #endregion


        public override String ToString()

            => Success
                   ? $"offset {ClockOffset?.TotalMilliseconds:F3} ms, delay {RoundTripDelay?.TotalMilliseconds:F3} ms over {TLSVersion}"
                   : IgnoredBy is not null
                         ? $"ignored by {IgnoredBy}: {ErrorMessage}"
                         : ErrorMessage ?? "failed";

    }

}
