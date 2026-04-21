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

using System.Reflection;
using System.Collections.Concurrent;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.TCP;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.Logging;
using org.GraphDefined.Vanaheimr.Hermod.Sockets;

using org.GraphDefined.Vanaheimr.Norn.Monitoring;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Drone.HTTPAPI
{

    /// <summary>
    /// Norn HTTPAPI extention methods.
    /// </summary>
    public static class NornDroneHTTPAPIExtensions
    {

        #region ParseRoamingNetwork(this HTTPRequest, HTTPServer, out RoamingNetwork, out HTTPResponse)

        ///// <summary>
        ///// Parse the given HTTP request and return the roaming network
        ///// for the given HTTP hostname and HTTP query parameter
        ///// or an HTTP error response.
        ///// </summary>
        ///// <param name="HTTPRequest">A HTTP request.</param>
        ///// <param name="HTTPServer">A HTTP server.</param>
        ///// <param name="RoamingNetwork">The roaming network.</param>
        ///// <param name="HTTPResponse">A HTTP error response.</param>
        ///// <returns>True, when roaming network was found; false else.</returns>
        //public static Boolean ParseRoamingNetwork(this HTTPRequest                             HTTPRequest,
        //                                          HTTPServer<RoamingNetworks, RoamingNetwork>  HTTPServer,
        //                                          out RoamingNetwork                           RoamingNetwork,
        //                                          out HTTPResponse                             HTTPResponse)
        //{

        //    if (HTTPServer == null)
        //        Console.WriteLine("HTTPServer == null!");

        //    #region Initial checks

        //    if (HTTPRequest == null)
        //        throw new ArgumentNullException("HTTPRequest",  "The given HTTP request must not be null!");

        //    if (HTTPServer == null)
        //        throw new ArgumentNullException("HTTPServer",   "The given HTTP server must not be null!");

        //    #endregion

        //    RoamingNetwork_Id RoamingNetworkId;
        //                      RoamingNetwork    = null;
        //                      HTTPResponse      = null;

        //    if (HTTPRequest.ParsedURLParameters.Length < 1)
        //    {

        //        HTTPResponse = new HTTPResponse.Builder(HTTPRequest) {
        //            HTTPStatusCode  = HTTPStatusCode.BadRequest,
        //            Server          = HTTPServer.DefaultServerName,
        //            Date            = Timestamp.Now,
        //        };

        //        return false;

        //    }

        //    if (!RoamingNetwork_Id.TryParse(HTTPRequest.ParsedURLParameters[0], out RoamingNetworkId))
        //    {

        //        HTTPResponse = new HTTPResponse.Builder(HTTPRequest) {
        //            HTTPStatusCode  = HTTPStatusCode.BadRequest,
        //            Server          = HTTPServer.DefaultServerName,
        //            Date            = Timestamp.Now,
        //            ContentType     = HTTPContentType.Application.JSON_UTF8,
        //            Content         = @"{ ""description"": ""Invalid RoamingNetworkId!"" }".ToUTF8Bytes()
        //        };

        //        return false;

        //    }

        //    RoamingNetwork  = HTTPServer.
        //                          GetAllTenants(HTTPRequest.Host).
        //                          FirstOrDefault(roamingnetwork => roamingnetwork.Id == RoamingNetworkId);

        //    if (RoamingNetwork == null) {

        //        HTTPResponse = new HTTPResponse.Builder(HTTPRequest) {
        //            HTTPStatusCode  = HTTPStatusCode.NotFound,
        //            Server          = HTTPServer.DefaultServerName,
        //            Date            = Timestamp.Now,
        //            ContentType     = HTTPContentType.Application.JSON_UTF8,
        //            Content         = @"{ ""description"": ""Unknown RoamingNetworkId!"" }".ToUTF8Bytes()
        //        };

        //        return false;

        //    }

        //    return true;

        //}

        #endregion


    }


    /// <summary>
    /// A HTTP API to configure and access a Norn drone.
    /// </summary>
    public partial class NornDroneHTTPAPI : AHTTPExtAPIExtension1<HTTPExtAPI>
    {

        #region Data

        /// <summary>
        /// The default HTTP URI prefix.
        /// </summary>
        public     static readonly  HTTPPath            DefaultURLPathPrefix      = HTTPPath.Parse("webapi");

        /// <summary>
        /// The default HTTP service name.
        /// </summary>
        public new const            String              DefaultHTTPServiceName    = $"Norn {Version.String} HTTPAPI";

        /// <summary>
        /// The default HTTP realm, if HTTP Basic Authentication is used.
        /// </summary>
        public     const            String              DefaultHTTPRealm          = $"Norn {Version.String} HTTPAPI";

        /// <summary>
        /// The HTTP root for embedded ressources.
        /// </summary>
        public     const            String              HTTPRoot                  = "org.graphdefined.vanaheimr.norn.HTTPAPI.HTTPRoot.";


        //ToDo: http://www.iana.org/form/media-types

        ///// <summary>
        ///// The HTTP content type for serving Norn+ JSON data.
        ///// </summary>
        //public static readonly      HTTPContentType     NornPlusJSONContentType   = new ("application", "vnd.NornPlus+json", "utf-8", null, null);

        ///// <summary>
        ///// The HTTP content type for serving Norn+ HTML data.
        ///// </summary>
        //public static readonly      HTTPContentType     NornPlusHTMLContentType   = new ("application", "vnd.NornPlus+html", "utf-8", null, null);


        public static readonly      HTTPEventSource_Id  DebugLogId                = HTTPEventSource_Id.Parse($"Norn{Version.String}_debugLog");


        private readonly ConcurrentDictionary<DateTimeOffset, MeasurementRound>  measurementRounds = [];

        #endregion

        #region Properties

        /// <summary>
        /// The HTTP realm, if HTTP Basic Authentication is used.
        /// </summary>
        public String                                     HTTPRealm               { get; }

        /// <summary>
        /// An enumeration of logins for an optional HTTP Basic Authentication.
        /// </summary>
        public IEnumerable<KeyValuePair<String, String>>  HTTPLogins              { get; }

        public HTTPAPILogger?                             Logger                  { get; set; }


        /// <summary>
        /// An enumeration of all measurement rounds.
        /// </summary>
        public IEnumerable<MeasurementRound>              MeasurementRounds
            => measurementRounds.Values;

        #endregion

        #region Events

        #region (protected internal) GetRootRequest      (Request)

        /// <summary>
        /// An event sent whenever a GET / request was received.
        /// </summary>
        public HTTPRequestLogEvent OnGetRootRequest = new();

        /// <summary>
        /// An event sent whenever a GET / request was received.
        /// </summary>
        /// <param name="Timestamp">The timestamp of the request.</param>
        /// <param name="API">The Common API.</param>
        /// <param name="Request">A HTTP request.</param>
        protected internal Task GetRootRequest(DateTimeOffset       Timestamp,
                                               Hermod.HTTP.HTTPAPI  API,
                                               HTTPRequest          Request,
                                               CancellationToken    CancellationToken)

            => OnGetRootRequest.WhenAll(
                   Timestamp,
                   API,
                   Request,
                   CancellationToken
               );

        #endregion

        #region (protected internal) GetRootResponse     (Response)

        /// <summary>
        /// An event sent whenever a GET / response was sent.
        /// </summary>
        public HTTPResponseLogEvent OnGetRootResponse = new();

        /// <summary>
        /// An event sent whenever a GET / response was sent.
        /// </summary>
        /// <param name="Timestamp">The timestamp of the request.</param>
        /// <param name="API">The Common API.</param>
        /// <param name="Request">A HTTP request.</param>
        /// <param name="Response">A HTTP response.</param>
        protected internal Task GetRootResponse(DateTimeOffset       Timestamp,
                                                Hermod.HTTP.HTTPAPI  API,
                                                HTTPRequest          Request,
                                                HTTPResponse         Response,
                                                CancellationToken    CancellationToken)

            => OnGetRootResponse.WhenAll(
                   Timestamp,
                   API,
                   Request,
                   Response,
                   CancellationToken
               );

        #endregion


        #region (protected internal) GETServerInfosHTTPRequest  (Request)

        /// <summary>
        /// An event sent whenever a GETServerInfos request was received.
        /// </summary>
        public HTTPRequestLogEvent OnGETServerInfosHTTPRequest = new ();

        /// <summary>
        /// An event sent whenever a GETServerInfos request was received.
        /// </summary>
        /// <param name="Timestamp">The timestamp of the request.</param>
        /// <param name="API">The HTTP API.</param>
        /// <param name="Request">A HTTP request.</param>
        protected internal Task GETServerInfosHTTPRequest(DateTimeOffset       Timestamp,
                                                          Hermod.HTTP.HTTPAPI  API,
                                                          HTTPRequest          Request,
                                                          CancellationToken    CancellationToken)

            => OnGETServerInfosHTTPRequest.WhenAll(
                   Timestamp,
                   API,
                   Request,
                   CancellationToken
               );

        #endregion

        #region (protected internal) GETServerInfosHTTPResponse (Response)

        /// <summary>
        /// An event sent whenever a GETServerInfos response was sent.
        /// </summary>
        public HTTPResponseLogEvent OnGETServerInfosHTTPResponse = new ();

        /// <summary>
        /// An event sent whenever a GETServerInfos response was sent.
        /// </summary>
        /// <param name="Timestamp">The timestamp of the request.</param>
        /// <param name="API">The HTTP API.</param>
        /// <param name="Request">A HTTP request.</param>
        /// <param name="Response">A HTTP response.</param>
        protected internal Task GETServerInfosHTTPResponse(DateTimeOffset       Timestamp,
                                                           Hermod.HTTP.HTTPAPI  API,
                                                           HTTPRequest          Request,
                                                           HTTPResponse         Response,
                                                           CancellationToken    CancellationToken)

            => OnGETServerInfosHTTPResponse.WhenAll(
                   Timestamp,
                   API,
                   Request,
                   Response,
                   CancellationToken
               );

        #endregion

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Attach the Norn HTTP API to the given HTTP server.
        /// </summary>
        public NornDroneHTTPAPI(HTTPExtAPI                     HTTPAPI,

                                IEnumerable<HTTPHostname>?     Hostnames                 = null,
                                HTTPPath?                      RootPath                  = null,
                                IEnumerable<HTTPContentType>?  HTTPContentTypes          = null,
                                I18NString?                    Description               = null,

                                HTTPPath?                      BasePath                  = null,  // For URL prefixes in HTML!

                                String?                        ExternalDNSName           = null,
                                String?                        HTTPServerName            = DefaultHTTPServerName,
                                String?                        HTTPServiceName           = DefaultHTTPServiceName,
                                String?                        APIVersionHash            = null,
                                JObject?                       APIVersionHashes          = null,

                                EMailAddress?                  APIRobotEMailAddress      = null,
                                String?                        APIRobotGPGPassphrase     = null,
                                ISMTPClient?                   SMTPClient                = null,

                                Boolean?                       IsDevelopment             = null,
                                IEnumerable<String>?           DevelopmentServers        = null,
                                //Boolean?                       SkipURLTemplates          = false,
                                String?                        DatabaseFileName          = null,//DefaultAssetsDBFileName,
                                Boolean?                       DisableNotifications      = false,

                                Boolean?                       DisableLogging            = null,
                                String?                        LoggingContext            = null,
                                String?                        LoggingPath               = null,
                                String?                        LogfileName               = null,
                                LogfileCreatorDelegate?        LogfileCreator            = null)

            : base(Description ?? I18NString.Create("Norn HTTP API"),
                   HTTPAPI,
                   RootPath,
                   BasePath,

                   ExternalDNSName,
                   HTTPServerName,
                   HTTPServiceName,
                   APIVersionHash,
                   APIVersionHashes,

                   IsDevelopment,
                   DevelopmentServers,
                   DisableLogging,
                   LoggingPath,
                   LogfileName
                   //LogfileCreator is not null
                   //    ? (loggingPath, context, logfileName) => LogfileCreator(loggingPath, null, context, logfileName)
                   //    : (loggingPath, context, logfileName) => String.Concat(
                   //                                                 loggingPath + Path.DirectorySeparatorChar,
                   //                                              //   remoteParty is not null
                   //                                              //       ? remoteParty.Id.ToString() + Path.DirectorySeparatorChar
                   //                                              //       : null,
                   //                                                 context is not null ? context + "_" : "",
                   //                                                 logfileName, "_",
                   //                                                 Timestamp.Now.Year, "-",
                   //                                                 Timestamp.Now.Month.ToString("D2"),
                   //                                                 ".log"
                   //                                             )
                   )

        {

            this.HTTPRealm             = HTTPRealm.IsNotNullOrEmpty() ? HTTPRealm : DefaultHTTPRealm;
            this.HTTPLogins            = HTTPLogins ?? [];

            // Link HTTP events...
        //    HTTPServer.RequestLog     += (HTTPProcessor, ServerTimestamp, Request)                                 => RequestLog. WhenAll(HTTPProcessor, ServerTimestamp, Request);
        //    HTTPServer.ResponseLog    += (HTTPProcessor, ServerTimestamp, Request, Response)                       => ResponseLog.WhenAll(HTTPProcessor, ServerTimestamp, Request, Response);
        //    HTTPServer.ErrorLog       += (HTTPProcessor, ServerTimestamp, Request, Response, Error, LastException) => ErrorLog.   WhenAll(HTTPProcessor, ServerTimestamp, Request, Response, Error, LastException);

            //var LogfilePrefix          = "HTTPSSEs" + Path.DirectorySeparatorChar;

            RegisterURLTemplates();

            if (!this.DisableLogging)
                Logger                    = new HTTPAPILogger(
                                                this,
                                                LoggingPath ?? AppContext.BaseDirectory,
                                                LoggingContext,
                                                LogFileCreator:   LogfileCreator is not null
                                                                      ? LogfileCreator
                                                                      : (loggingPath,
                                                                         context,
                                                                         logfileName) => String.Concat(
                                                                                             loggingPath + Path.DirectorySeparatorChar,
                                                                                             context is not null
                                                                                                 ? context + "_"
                                                                                                 : "",
                                                                                             logfileName, "_",
                                                                                             Timestamp.Now.Year, "-",
                                                                                             Timestamp.Now.Month.ToString("D2"),
                                                                                             ".log"
                                                                                         )
                                            );

        }

        #endregion


        public Task AddMeasurementRound(MeasurementRound MeasurementRound)
        {

            measurementRounds.TryAdd(
                MeasurementRound.Timestamp,
                MeasurementRound
            );

            return Task.CompletedTask;

        }



        #region (private) RegisterURLTemplates()

        #region Manage HTTP Resources

        private readonly Tuple<String, Assembly>[] resourceAssemblies = [
            new Tuple<String, Assembly>(NornDroneHTTPAPI.HTTPRoot, typeof(NornDroneHTTPAPI).Assembly),
            new Tuple<String, Assembly>(HTTPExtAPI.      HTTPRoot, typeof(HTTPExtAPI).      Assembly)
        ];

        #region (protected override) GetResourceStream       (ResourceName)

        protected override Stream? GetResourceStream(String ResourceName)

            => GetResourceStream(
                   ResourceName,
                   resourceAssemblies
               );

        #endregion

        #region (protected override) GetResourceMemoryStream (ResourceName)

        protected override MemoryStream? GetResourceMemoryStream(String ResourceName)

            => GetResourceMemoryStream(
                   ResourceName,
                   resourceAssemblies
               );

        #endregion

        #region (protected override) GetResourceString       (ResourceName)

        protected override String GetResourceString(String ResourceName)

            => GetResourceString(
                   ResourceName,
                   resourceAssemblies
               );

        #endregion

        #region (protected override) GetResourceBytes        (ResourceName)

        protected override Byte[] GetResourceBytes(String ResourceName)

            => GetResourceBytes(
                   ResourceName,
                   resourceAssemblies
               );

        #endregion

        #region (protected override) MixWithHTMLTemplate     (ResourceName)

        protected override String MixWithHTMLTemplate(String ResourceName)

            => MixWithHTMLTemplate(
                   ResourceName,
                   resourceAssemblies
               );

        #endregion

        #region (protected override) MixWithHTMLTemplate     (ResourceName, HTMLConverter)

        protected override String MixWithHTMLTemplate(String ResourceName, Func<String, String> HTMLConverter)

            => MixWithHTMLTemplate(
                   ResourceName,
                   HTMLConverter,
                   resourceAssemblies
               );

        #endregion

        #endregion


        /// <summary>
        /// The following will register HTTP endpoints serving JSON
        /// representations of the Norn drone and its measurements.
        /// </summary>
        private void RegisterURLTemplates()
        {

            #region ~/

            #region OPTIONS  ~/

            HTTPBaseAPI.AddHandler(

                HTTPMethod.OPTIONS,
                URLPathPrefix,
                request =>

                    Task.FromResult(
                        new HTTPResponse.Builder(request) {
                            HTTPStatusCode             = HTTPStatusCode.OK,
                            Server                     = HTTPServiceName,
                            Date                       = Timestamp.Now,
                            AccessControlAllowOrigin   = "*",
                            AccessControlAllowMethods  = [ "OPTIONS", "GET" ],
                            Allow                      = [ HTTPMethod.OPTIONS, HTTPMethod.GET ],
                            AccessControlAllowHeaders  = [ "Authorization" ],
                            Connection                 = ConnectionType.KeepAlive
                        }.AsImmutable)

            );

            #endregion

            #region GET      ~/

            HTTPBaseAPI.AddHandler(

                HTTPMethod.GET,
                URLPathPrefix,
                HTTPContentType.Text.PLAIN,
                HTTPRequestLogger:   GetRootRequest,
                HTTPResponseLogger:  GetRootResponse,
                HTTPDelegate:        request =>

                    Task.FromResult(
                        new HTTPResponse.Builder(request) {
                            HTTPStatusCode             = HTTPStatusCode.OK,
                            Server                     = HTTPServiceName,
                            Date                       = Timestamp.Now,
                            AccessControlAllowOrigin   = "*",
                            AccessControlAllowMethods  = [ "OPTIONS", "GET" ],
                            AccessControlAllowHeaders  = [ "Authorization" ],
                            ContentType                = HTTPContentType.Text.PLAIN,
                            Content                    = "This is a Norn Drone HTTP service!".ToUTF8Bytes(),
                            Connection                 = ConnectionType.KeepAlive,
                            Vary                       = "Accept"
                        }.AsImmutable)

            );


            HTTPBaseAPI.AddHandler(

                HTTPMethod.GET,
                URLPathPrefix,
                HTTPContentType.Application.JSON_UTF8,
                HTTPRequestLogger:   GetRootRequest,
                HTTPResponseLogger:  GetRootResponse,
                HTTPDelegate:        request =>

                    Task.FromResult(
                        new HTTPResponse.Builder(request) {
                            HTTPStatusCode             = HTTPStatusCode.OK,
                            Server                     = HTTPServiceName,
                            Date                       = Timestamp.Now,
                            AccessControlAllowOrigin   = "*",
                            AccessControlAllowMethods  = [ "OPTIONS", "GET" ],
                            AccessControlAllowHeaders  = [ "Authorization" ],
                            ContentType                = HTTPContentType.Application.JSON_UTF8,
                            Content                    = JSONObject.Create(
                                                             new JProperty(
                                                                 "message",
                                                                 "This is a Norn Drone HTTP service!"
                                                             )
                                                         ).ToUTF8Bytes(),
                            Connection                 = ConnectionType.KeepAlive,
                            Vary                       = "Accept"
                        }.AsImmutable),

                AllowReplacement: URLReplacement.Allow

            );

            #endregion

            #endregion

        }

        #endregion


    }

}
