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

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// A structured result for one NTS-KE exchange.
    /// </summary>
    public class NTSKEResult
    {

        #region Properties

        public Boolean             Success         { get; }

        public NTSKE_Response?     Response        { get; }

        public String?             ErrorMessage    { get; }

        public NTSKEErrorCategory  ErrorCategory   { get; }

        public NTSKE_TimingInfo?   TimingInfo      { get; }

        public NTSKE_TLSInfo?      TLSInfo         { get; }

        #endregion

        #region Constructor(s)

        public NTSKEResult(Boolean             Success,
                           NTSKE_Response?     Response,
                           String?             ErrorMessage,
                           NTSKEErrorCategory  ErrorCategory,
                           NTSKE_TimingInfo?   TimingInfo,
                           NTSKE_TLSInfo?      TLSInfo)
        {

            this.Success        = Success;
            this.Response       = Response;
            this.ErrorMessage   = ErrorMessage;
            this.ErrorCategory  = ErrorCategory;
            this.TimingInfo     = TimingInfo;
            this.TLSInfo        = TLSInfo;

        }

        #endregion


        #region SuccessResult(Response)

        public static NTSKEResult SuccessResult(NTSKE_Response Response)

            => new (
                   Success:        true,
                   Response:       Response,
                   ErrorMessage:   null,
                   ErrorCategory:  NTSKEErrorCategory.None,
                   TimingInfo:     Response.TimingInfo,
                   TLSInfo:        Response.TLSInfo
               );

        #endregion


        #region Failed(ErrorMessage, ...)

        public static NTSKEResult Failed(String              ErrorMessage,
                                         NTSKE_TimingInfo?   TimingInfo  = null,
                                         NTSKE_TLSInfo?      TLSInfo     = null)

            => new (
                   Success:        false,
                   Response:       new NTSKE_Response(
                                       ErrorMessage,
                                       TimingInfo,
                                       TLSInfo
                                   ),
                   ErrorMessage:   ErrorMessage,
                   ErrorCategory:  ClassifyNTSKEError(ErrorMessage),
                   TimingInfo:     TimingInfo,
                   TLSInfo:        TLSInfo
               );

        #endregion

        #region Failed(ErrorMessage, ErrorCategory, ...)

        public static NTSKEResult Failed(String              ErrorMessage,
                                         NTSKEErrorCategory  ErrorCategory,
                                         NTSKE_TimingInfo?   TimingInfo  = null,
                                         NTSKE_TLSInfo?      TLSInfo     = null)

            => new (
                   Success:        false,
                   Response:       new NTSKE_Response(
                                       ErrorMessage,
                                       TimingInfo,
                                       TLSInfo
                                   ),
                   ErrorMessage:   ErrorMessage,
                   ErrorCategory:  ErrorCategory,
                   TimingInfo:     TimingInfo,
                   TLSInfo:        TLSInfo
               );

        #endregion


        #region (private static) ClassifyNTSKEError (ErrorMessage)

        private static NTSKEErrorCategory ClassifyNTSKEError(String? ErrorMessage)
        {

            if (ErrorMessage is null)
                return NTSKEErrorCategory.Unknown;


            if (ErrorMessage.Contains("No IP address",              StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("Name or service not known",  StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("nodename",                   StringComparison.OrdinalIgnoreCase))

                return NTSKEErrorCategory.DNS;


            if (ErrorMessage.Contains("certificate",                StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("certificate_unknown",        StringComparison.OrdinalIgnoreCase))

                return NTSKEErrorCategory.TLSCertificate;


            if (ErrorMessage.Contains("TLS",                        StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("handshake",                  StringComparison.OrdinalIgnoreCase))

                return NTSKEErrorCategory.TLSHandshake;


            if (ErrorMessage.Contains("connect",                    StringComparison.OrdinalIgnoreCase))
                return NTSKEErrorCategory.TCPConnect;


            if (ErrorMessage.Contains("timeout",                    StringComparison.OrdinalIgnoreCase))
                return NTSKEErrorCategory.Timeout;


            if (ErrorMessage.Contains("unknown critical record",     StringComparison.OrdinalIgnoreCase))
                return NTSKEErrorCategory.UnknownCriticalRecord;

            if (ErrorMessage.Contains("Error record",                StringComparison.OrdinalIgnoreCase))
                return NTSKEErrorCategory.ServerError;

            if (ErrorMessage.Contains("Warning record",              StringComparison.OrdinalIgnoreCase))
                return NTSKEErrorCategory.ServerWarning;

            if (ErrorMessage.Contains("did not negotiate",           StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("did not provide",             StringComparison.OrdinalIgnoreCase))
                return NTSKEErrorCategory.MissingRequiredRecord;

            if (ErrorMessage.Contains("unsupported next protocol",   StringComparison.OrdinalIgnoreCase))
                return NTSKEErrorCategory.UnsupportedProtocol;

            if (ErrorMessage.Contains("unsupported AEAD",            StringComparison.OrdinalIgnoreCase))
                return NTSKEErrorCategory.UnsupportedAlgorithm;

            if (ErrorMessage.Contains("parse",                      StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("NTS-KE",                     StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("EndOfMessage",               StringComparison.OrdinalIgnoreCase) ||
                ErrorMessage.Contains("exceeded",                   StringComparison.OrdinalIgnoreCase))

                return NTSKEErrorCategory.Protocol;


            return NTSKEErrorCategory.Exception;

        }

        #endregion


    }

}
