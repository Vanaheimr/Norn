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
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.Logging;

using org.GraphDefined.Vanaheimr.Norn.NTS.NTSKERecords;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.HTTPAPI
{

    /// <summary>
    /// The Norn HTTP API.
    /// </summary>
    public partial class NornHTTPAPI
    {

        /// <summary>
        /// The Norn HTTP API logger.
        /// </summary>
        public class HTTPAPILogger : HTTPServerLogger
        {

            #region Data

            /// <summary>
            /// The default context of this logger.
            /// </summary>
            public const String DefaultContext = "NornDroneHTTPAPILogger";

            #endregion

            #region Properties

            /// <summary>
            /// The linked NTS HTTPAPI.
            /// </summary>
            public NornHTTPAPI  HTTPAPI    { get; }

            #endregion

            #region Constructor(s)

            #region HTTPAPILogger(HTTPAPI, Context = DefaultContext, LogFileCreator = null)

            /// <summary>
            /// Create a new NornDroneHTTPAPI logger using the default logging delegates.
            /// </summary>
            /// <param name="HTTPAPI">A NTS HTTPAPI.</param>
            /// <param name="Context">A context of this API.</param>
            /// <param name="LogFileCreator">A delegate to create a log file from the given context and log file name.</param>
            public HTTPAPILogger(NornHTTPAPI              HTTPAPI,
                                 String                   LoggingPath,
                                 String                   Context          = DefaultContext,
                                 LogfileCreatorDelegate?  LogFileCreator   = null)

                : this(HTTPAPI,
                       LoggingPath,
                       Context,
                       null,
                       null,
                       null,
                       null,
                       LogFileCreator: LogFileCreator)

            { }

            #endregion

            #region HTTPAPILogger(HTTPAPI, Context, ... Logging delegates ...)

            /// <summary>
            /// Create a new NornDroneHTTPAPI logger using the given logging delegates.
            /// </summary>
            /// <param name="HTTPAPI">A NTS HTTPAPI.</param>
            /// <param name="Context">A context of this API.</param>
            /// 
            /// <param name="LogHTTPRequest_toConsole">A delegate to log incoming HTTP requests to console.</param>
            /// <param name="LogHTTPResponse_toConsole">A delegate to log HTTP requests/responses to console.</param>
            /// <param name="LogHTTPRequest_toDisc">A delegate to log incoming HTTP requests to disc.</param>
            /// <param name="LogHTTPResponse_toDisc">A delegate to log HTTP requests/responses to disc.</param>
            /// 
            /// <param name="LogHTTPRequest_toNetwork">A delegate to log incoming HTTP requests to a network target.</param>
            /// <param name="LogHTTPResponse_toNetwork">A delegate to log HTTP requests/responses to a network target.</param>
            /// <param name="LogHTTPRequest_toHTTPSSE">A delegate to log incoming HTTP requests to a HTTP server sent events source.</param>
            /// <param name="LogHTTPResponse_toHTTPSSE">A delegate to log HTTP requests/responses to a HTTP server sent events source.</param>
            /// 
            /// <param name="LogHTTPError_toConsole">A delegate to log HTTP errors to console.</param>
            /// <param name="LogHTTPError_toDisc">A delegate to log HTTP errors to disc.</param>
            /// <param name="LogHTTPError_toNetwork">A delegate to log HTTP errors to a network target.</param>
            /// <param name="LogHTTPError_toHTTPSSE">A delegate to log HTTP errors to a HTTP server sent events source.</param>
            /// 
            /// <param name="LogFileCreator">A delegate to create a log file from the given context and log file name.</param>
            public HTTPAPILogger(NornHTTPAPI                  HTTPAPI,
                                 String                       LoggingPath,
                                 String                       Context,

                                 HTTPRequestLoggerDelegate?   LogHTTPRequest_toConsole    = null,
                                 HTTPResponseLoggerDelegate?  LogHTTPResponse_toConsole   = null,
                                 HTTPRequestLoggerDelegate?   LogHTTPRequest_toDisc       = null,
                                 HTTPResponseLoggerDelegate?  LogHTTPResponse_toDisc      = null,

                                 HTTPRequestLoggerDelegate?   LogHTTPRequest_toNetwork    = null,
                                 HTTPResponseLoggerDelegate?  LogHTTPResponse_toNetwork   = null,
                                 HTTPRequestLoggerDelegate?   LogHTTPRequest_toHTTPSSE    = null,
                                 HTTPResponseLoggerDelegate?  LogHTTPResponse_toHTTPSSE   = null,

                                 HTTPResponseLoggerDelegate?  LogHTTPError_toConsole      = null,
                                 HTTPResponseLoggerDelegate?  LogHTTPError_toDisc         = null,
                                 HTTPResponseLoggerDelegate?  LogHTTPError_toNetwork      = null,
                                 HTTPResponseLoggerDelegate?  LogHTTPError_toHTTPSSE      = null,

                                 LogfileCreatorDelegate?      LogFileCreator              = null)

                : base(HTTPAPI.HTTPServer,
                       LoggingPath,
                       Context,

                       LogHTTPRequest_toConsole,
                       LogHTTPResponse_toConsole,
                       LogHTTPRequest_toDisc,
                       LogHTTPResponse_toDisc,

                       LogHTTPRequest_toNetwork,
                       LogHTTPResponse_toNetwork,
                       LogHTTPRequest_toHTTPSSE,
                       LogHTTPResponse_toHTTPSSE,

                       LogHTTPError_toConsole,
                       LogHTTPError_toDisc,
                       LogHTTPError_toNetwork,
                       LogHTTPError_toHTTPSSE,

                       LogFileCreator)

            {

                this.HTTPAPI = HTTPAPI ?? throw new ArgumentNullException(nameof(HTTPAPI), "The given NTS HTTPAPI must not be null!");

                #region OnGETServerInfos

                RegisterEvent2("OnGETServerInfosHTTPRequest",
                               handler => HTTPAPI.OnGETServerInfosHTTPRequest  += handler,
                               handler => HTTPAPI.OnGETServerInfosHTTPRequest -= handler,
                               "GETServerInfos", "Request",  "All").
                    RegisterDefaultConsoleLogTarget(this).
                    RegisterDefaultDiscLogTarget(this);

                RegisterEvent2("OnGETServerInfosHTTPResponse",
                               handler => HTTPAPI.OnGETServerInfosHTTPResponse += handler,
                               handler => HTTPAPI.OnGETServerInfosHTTPResponse -= handler,
                               "GETServerInfos", "Response", "All").
                    RegisterDefaultConsoleLogTarget(this).
                    RegisterDefaultDiscLogTarget(this);

                #endregion

            }

            #endregion

            #endregion


        }

    }


}
