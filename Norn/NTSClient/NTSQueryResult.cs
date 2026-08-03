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

using System.Net;

using org.GraphDefined.Vanaheimr.Norn.NTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// A structured result for a single NTS-authenticated NTP query.
    /// </summary>
    public class NTSQueryResult
    {

        #region Properties

        public Boolean                Success                      { get; }

        public NTPPacket?             Response                     { get; }

        public String?                ErrorMessage                 { get; }

        public NTSQueryErrorCategory  ErrorCategory                { get; }

        public IPEndPoint?            RemoteEndPoint               { get; }

        public String                 RemoteDescription            { get; }

        public Byte[]?                UsedCookie                   { get; }

        public Int32                  RemainingCookiesAfterQuery   { get; }

        public Int32                  Attempts                     { get; }

        public Int64?                 SendStopwatchTimestamp       { get; }

        public Int64?                 ReceiveStopwatchTimestamp    { get; }

        public TimeSpan?              StopwatchRoundTripTime       { get; }

        public UInt64?                DestinationTimestamp         { get; }

        public Boolean                NewCookieReceived            { get; }

        public NTSCookiePoolDiagnostics? CookiePoolDiagnostics     { get; }

        public NTSResponseValidationResult? ResponseValidation      { get; }

        /// <summary>
        /// The RFC 9769 measurement this response completed, when it was an interleaved one.
        /// </summary>
        /// <remarks>
        /// Null for an ordinary response, where <see cref="NTPPacket.ClockOffset"/> on the
        /// response is the measurement. An interleaved one cannot be expressed that way: three
        /// of its four timestamps belong to the previous exchange, and only the transmit
        /// timestamp comes from the packet in hand.
        /// </remarks>
        public InterleavedMeasurement?      InterleavedMeasurement  { get; }

        public NTSQueryDiagnostics          Diagnostics             { get; }

        #endregion

        #region Constructor(s)

        public NTSQueryResult(Boolean                Success,
                              NTPPacket?             Response,
                              String?                ErrorMessage,
                              NTSQueryErrorCategory  ErrorCategory,
                              IPEndPoint?            RemoteEndPoint,
                              String?                RemoteDescription,
                              Byte[]?                UsedCookie,
                              Int32                  RemainingCookiesAfterQuery,
                              Int32                  Attempts,
                              Int64?                 SendStopwatchTimestamp      = null,
                              Int64?                 ReceiveStopwatchTimestamp   = null,
                               UInt64?                DestinationTimestamp        = null,
                               Boolean                NewCookieReceived           = false,
                               NTSCookiePoolDiagnostics? CookiePoolDiagnostics     = null,
                               NTSResponseValidationResult? ResponseValidation      = null,
                               InterleavedMeasurement?   InterleavedMeasurement      = null)
        {

            this.Success                     = Success;
            this.Response                    = Response;
            this.ErrorMessage                = ErrorMessage;
            this.ErrorCategory               = ErrorCategory;
            this.RemoteEndPoint              = RemoteEndPoint;
            this.RemoteDescription           = RemoteDescription ?? RemoteEndPoint?.ToString() ?? "";
            this.UsedCookie                  = UsedCookie;
            this.RemainingCookiesAfterQuery  = RemainingCookiesAfterQuery;
            this.Attempts                    = Attempts;
            this.SendStopwatchTimestamp      = SendStopwatchTimestamp;
            this.ReceiveStopwatchTimestamp   = ReceiveStopwatchTimestamp;
            this.DestinationTimestamp        = DestinationTimestamp;
            this.NewCookieReceived           = NewCookieReceived;
            this.CookiePoolDiagnostics       = CookiePoolDiagnostics;
            this.InterleavedMeasurement      = InterleavedMeasurement;
            this.ResponseValidation          = ResponseValidation;

            if (SendStopwatchTimestamp.HasValue &&
                ReceiveStopwatchTimestamp.HasValue)
            {
                this.StopwatchRoundTripTime = TimeSpan.FromTicks(
                                                  (Int64) ((ReceiveStopwatchTimestamp.Value - SendStopwatchTimestamp.Value) *
                                                          ((Double) TimeSpan.TicksPerSecond / System.Diagnostics.Stopwatch.Frequency))
                                              );
            }

            this.Diagnostics = new NTSQueryDiagnostics(
                                   this.RemoteEndPoint,
                                   this.RemoteDescription,
                                   this.SendStopwatchTimestamp,
                                   this.ReceiveStopwatchTimestamp,
                                   this.StopwatchRoundTripTime,
                                   this.DestinationTimestamp,
                                   this.NewCookieReceived,
                                   this.CookiePoolDiagnostics,
                                   this.ResponseValidation
                               );

        }

        #endregion

        #region SuccessResult(...)

        public static NTSQueryResult SuccessResult(NTPPacket?   Response,
                                                   IPEndPoint?  RemoteEndPoint,
                                                   String       RemoteDescription,
                                                   Byte[]?      UsedCookie,
                                                   Int32        RemainingCookiesAfterQuery,
                                                    Int32        Attempts,
                                                    Boolean      NewCookieReceived,
                                                    NTSCookiePoolDiagnostics? CookiePoolDiagnostics = null,
                                                    NTSResponseValidationResult? ResponseValidation  = null,
                                                    InterleavedMeasurement?   InterleavedMeasurement = null)

            => new (
                   Success:                     true,
                   Response:                    Response,
                   ErrorMessage:                null,
                   ErrorCategory:               NTSQueryErrorCategory.None,
                   RemoteEndPoint:              RemoteEndPoint,
                   RemoteDescription:           RemoteDescription,
                   UsedCookie:                  UsedCookie,
                   RemainingCookiesAfterQuery:  RemainingCookiesAfterQuery,
                   Attempts:                    Attempts,
                   SendStopwatchTimestamp:      Response?.SendStopwatchTimestamp,
                   ReceiveStopwatchTimestamp:   Response?.ReceiveStopwatchTimestamp,
                    DestinationTimestamp:        Response?.DestinationTimestamp,
                    NewCookieReceived:           NewCookieReceived,
                    CookiePoolDiagnostics:       CookiePoolDiagnostics,
                    ResponseValidation:          ResponseValidation,
                    InterleavedMeasurement:      InterleavedMeasurement
                );

        #endregion

        #region Failed(...)

        public static NTSQueryResult Failed(String                 ErrorMessage,
                                            NTSQueryErrorCategory  ErrorCategory,
                                            IPEndPoint?            RemoteEndPoint              = null,
                                            String?                RemoteDescription           = null,
                                            Byte[]?                UsedCookie                  = null,
                                            Int32                  RemainingCookiesAfterQuery  = 0,
                                            Int32                  Attempts                    = 1,
                                            NTPPacket?             Response                    = null,
                                            Int64?                 SendStopwatchTimestamp      = null,
                                            Int64?                 ReceiveStopwatchTimestamp   = null,
                                             UInt64?                DestinationTimestamp        = null,
                                             NTSCookiePoolDiagnostics? CookiePoolDiagnostics    = null,
                                             NTSResponseValidationResult? ResponseValidation     = null)

            => new (
                   Success:                     false,
                   Response:                    Response,
                   ErrorMessage:                ErrorMessage,
                   ErrorCategory:               ErrorCategory,
                   RemoteEndPoint:              RemoteEndPoint,
                   RemoteDescription:           RemoteDescription,
                   UsedCookie:                  UsedCookie,
                   RemainingCookiesAfterQuery:  RemainingCookiesAfterQuery,
                   Attempts:                    Attempts,
                   SendStopwatchTimestamp:      SendStopwatchTimestamp,
                    ReceiveStopwatchTimestamp:   ReceiveStopwatchTimestamp,
                    DestinationTimestamp:        DestinationTimestamp,
                    CookiePoolDiagnostics:       CookiePoolDiagnostics,
                    ResponseValidation:          ResponseValidation
                );

        #endregion

        #region FailedWithPacket(...)

        public static NTSQueryResult FailedWithPacket(String                 ErrorMessage,
                                                      NTSQueryErrorCategory  ErrorCategory,
                                                      IPEndPoint?            RemoteEndPoint              = null,
                                                      String?                RemoteDescription           = null,
                                                      Byte[]?                UsedCookie                  = null,
                                                      Int32                  RemainingCookiesAfterQuery  = 0,
                                                      Int32                  Attempts                    = 1,
                                                      Int64?                 SendStopwatchTimestamp      = null,
                                                      Int64?                 ReceiveStopwatchTimestamp   = null,
                                                       UInt64?                DestinationTimestamp        = null,
                                                       NTSCookiePoolDiagnostics? CookiePoolDiagnostics    = null,
                                                       NTSResponseValidationResult? ResponseValidation     = null)

            => new (
                   Success:                     false,
                   Response:                    new NTPPacket(ErrorMessage),
                   ErrorMessage:                ErrorMessage,
                   ErrorCategory:               ErrorCategory,
                   RemoteEndPoint:              RemoteEndPoint,
                   RemoteDescription:           RemoteDescription,
                   UsedCookie:                  UsedCookie,
                   RemainingCookiesAfterQuery:  RemainingCookiesAfterQuery,
                   Attempts:                    Attempts,
                   SendStopwatchTimestamp:      SendStopwatchTimestamp,
                    ReceiveStopwatchTimestamp:   ReceiveStopwatchTimestamp,
                    DestinationTimestamp:        DestinationTimestamp,
                    CookiePoolDiagnostics:       CookiePoolDiagnostics,
                    ResponseValidation:          ResponseValidation
                );

        #endregion

        #region FailedWithClassifiedPacket(...)

        public static NTSQueryResult FailedWithClassifiedPacket(String       ErrorMessage,
                                                                IPEndPoint?  RemoteEndPoint              = null,
                                                                String?      RemoteDescription           = null,
                                                                Byte[]?      UsedCookie                  = null,
                                                                Int32        RemainingCookiesAfterQuery  = 0,
                                                                Int32        Attempts                    = 1,
                                                                 Int64?       SendStopwatchTimestamp      = null,
                                                                 Int64?       ReceiveStopwatchTimestamp   = null,
                                                                 UInt64?      DestinationTimestamp        = null,
                                                                 NTSCookiePoolDiagnostics? CookiePoolDiagnostics = null,
                                                                 NTPPacket?   Response                    = null,
                                                                 NTSResponseValidationResult? ResponseValidation = null)

            => new (
                   Success:                     false,
                    Response:                    Response ?? new NTPPacket(ErrorMessage),
                    ErrorMessage:                ErrorMessage,
                    ErrorCategory:               ClassifyNTPError(ErrorMessage),
                   RemoteEndPoint:              RemoteEndPoint,
                   RemoteDescription:           RemoteDescription,
                   UsedCookie:                  UsedCookie,
                   RemainingCookiesAfterQuery:  RemainingCookiesAfterQuery,
                   Attempts:                    Attempts,
                   SendStopwatchTimestamp:      SendStopwatchTimestamp,
                    ReceiveStopwatchTimestamp:   ReceiveStopwatchTimestamp,
                    DestinationTimestamp:        DestinationTimestamp,
                    CookiePoolDiagnostics:       CookiePoolDiagnostics,
                    ResponseValidation:          ResponseValidation
                );

        #endregion


        #region (private static) ClassifyNTPError   (ErrorMessage)

        private static NTSQueryErrorCategory ClassifyNTPError(String? ErrorMessage)
        {

            if (ErrorMessage is null)
                return NTSQueryErrorCategory.Unknown;

            if (ErrorMessage.Contains("timeout", StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("No 1st NTP response", StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("No 2nd NTP response", StringComparison.OrdinalIgnoreCase))
                return NTSQueryErrorCategory.NTPTimeout;

            if (ErrorMessage.Contains("SIV", StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("Unique", StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("decrypt", StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("auth", StringComparison.OrdinalIgnoreCase))
                return NTSQueryErrorCategory.NTSAuthentication;

            if (ErrorMessage.Contains("KoD", StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("Kiss", StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("RATE", StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("NTSN", StringComparison.OrdinalIgnoreCase))
                return NTSQueryErrorCategory.KissOfDeath;

            if (ErrorMessage.Contains("socket", StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("network", StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("receive exception", StringComparison.OrdinalIgnoreCase))
                return NTSQueryErrorCategory.Network;

            if (ErrorMessage.Contains("parse", StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("protocol", StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("prefix", StringComparison.OrdinalIgnoreCase))
                return NTSQueryErrorCategory.Protocol;

            return NTSQueryErrorCategory.Unknown;

        }

        #endregion

    }

}
