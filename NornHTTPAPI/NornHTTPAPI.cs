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
using System.Security.Authentication;

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

using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.HTTPAPI
{

    /// <summary>
    /// Norn HTTPAPI extention methods.
    /// </summary>
    public static class NornHTTPAPIExtensions
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
    public partial class NornHTTPAPI : AHTTPExtAPIExtension1<HTTPExtAPI>
    {

        #region Data

        /// <summary>
        /// The default HTTP URI prefix.
        /// </summary>
        public new static readonly  HTTPPath            DefaultURLPathPrefix      = HTTPPath.Parse("webapi");

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
        public new const            String              HTTPRoot                  = "org.graphdefined.vanaheimr.norn.HTTPAPI.HTTPRoot.";


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
        public String                                       HTTPRealm               { get; }

        /// <summary>
        /// An enumeration of logins for an optional HTTP Basic Authentication.
        /// </summary>
        public IEnumerable<KeyValuePair<String, String>>    HTTPLogins              { get; }


        /// <summary>
        /// Send debug information via HTTP Server Sent Events.
        /// </summary>
        public HTTPEventSource<JObject>                     DebugLog                { get; }


        public HTTPAPILogger?                               Logger                  { get; set; }

        public NTSServer                                    NTSServer               { get; }

        #endregion

        #region Events

        #region Generic HTTP server logging

        ///// <summary>
        ///// An event called whenever a HTTP request came in.
        ///// </summary>
        //public HTTPRequestLogEvent   RequestLog    = new HTTPRequestLogEvent();

        ///// <summary>
        ///// An event called whenever a HTTP request could successfully be processed.
        ///// </summary>
        //public HTTPResponseLogEvent  ResponseLog   = new HTTPResponseLogEvent();

        ///// <summary>
        ///// An event called whenever a HTTP request resulted in an error.
        ///// </summary>
        //public HTTPErrorLogEvent     ErrorLog      = new HTTPErrorLogEvent();

        #endregion


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
                                                          CancellationToken    CancellationToken = default)

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
                                                           CancellationToken    CancellationToken = default)

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
        /// Attach the Norn HTTPAPI to the given HTTP server.
        /// </summary>
        /// <param name="NTSServer">The NTS server.</param>
        public NornHTTPAPI(NTSServer                      NTSServer,
                           HTTPExtAPI                     HTTPAPI,

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

                           HTTPPath?                      AdditionalURLPathPrefix   = null,
                           Boolean?                       LocationsAsOpenData       = null,
                           Boolean?                       TariffsAsOpenData         = null,
                           Boolean?                       AllowDowngrades           = null,

                           String?                        RemotePartyDBFileName     = null,

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

            this.NTSServer             = NTSServer;

            this.HTTPRealm             = HTTPRealm.IsNotNullOrEmpty() ? HTTPRealm : DefaultHTTPRealm;
            this.HTTPLogins            = HTTPLogins ?? [];

            // Link HTTP events...
            //HTTPServer.RequestLog     += (HTTPProcessor, ServerTimestamp, Request)                                 => RequestLog. WhenAll(HTTPProcessor, ServerTimestamp, Request);
            //HTTPServer.ResponseLog    += (HTTPProcessor, ServerTimestamp, Request, Response)                       => ResponseLog.WhenAll(HTTPProcessor, ServerTimestamp, Request, Response);
            //HTTPServer.ErrorLog       += (HTTPProcessor, ServerTimestamp, Request, Response, Error, LastException) => ErrorLog.   WhenAll(HTTPProcessor, ServerTimestamp, Request, Response, Error, LastException);

            //var LogfilePrefix          = "HTTPSSEs" + Path.DirectorySeparatorChar;

            //this.DebugLog              = this.AddJSONEventSource(
            //                                 EventIdentification:      DebugLogId,
            //                                 URLTemplate:              this.URLPathPrefix + "debugLog",
            //                                 MaxNumberOfCachedEvents:  10000,
            //                                 RetryInterval:            TimeSpan.FromSeconds(5),
            //                                 EnableLogging:            true,
            //                                 LogfilePrefix:            LogfilePrefix
            //                             );

            RegisterURLTemplates();

            //this.RequestTimeout        = RequestTimeout;

        }

        #endregion


        #region (private) RegisterURLTemplates()

        #region Manage HTTP Resources

        private readonly Tuple<String, Assembly>[] resourceAssemblies = [
            new Tuple<String, Assembly>(NornHTTPAPI.HTTPRoot, typeof(NornHTTPAPI).Assembly),
            new Tuple<String, Assembly>(HTTPExtAPI. HTTPRoot, typeof(HTTPExtAPI). Assembly)
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
        /// The following will register HTTP overlays for text/html
        /// showing a html representation of the Norn common API!
        /// </summary>
        private void RegisterURLTemplates()
        {

            #region / (HTTPRoot)

            //this.MapResourceAssemblyFolder(
            //    HTTPHostname.Any,
            //    URLPathPrefix,
            //    HTTPRoot,
            //    DefaultFilename: "index.html"
            //);

            #endregion


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
                HTTPPath.Root,
                HTTPContentType.Text.HTML_UTF8,
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
                            Content                    = "Hello world!".ToUTF8Bytes(),
                                                         //MixWithHTMLTemplate(
                                                         //    "index.shtml"
                                                         //).ToUTF8Bytes(),
                            Connection                 = ConnectionType.Close,
                            Vary                       = "Accept"
                        }.AsImmutable)

            );

            #endregion

            #endregion


            #region ~/serverInfos

            #region OPTIONS  ~/serverInfos

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

            #region GET      ~/serverInfos

//            HTTPServer.AddMethodCallback(

//                this,
//                HTTPHostname.Any,
//                HTTPMethod.GET,
//                URLPathPrefix + "serverInfos",
//                HTTPContentType.Application.JSON_UTF8,
//                HTTPRequestLogger:   GETServerInfosHTTPRequest,
//                HTTPResponseLogger:  GETServerInfosHTTPResponse,
//                HTTPDelegate:        request => {

//                    #region numberOfRequestedNTSCookies

//                    var numberOfRequestedNTSCookies = request.QueryString.GetUInt16("n") ?? 7;

//                    //if (request.ParsedURLParameters.Length < 1)
//                    //    return Task.FromResult(
//                    //               new HTTPResponse.Builder(request) {
//                    //                   HTTPStatusCode             = HTTPStatusCode.BadRequest,
//                    //                   //AccessControlAllowMethods  = [ "OPTIONS", "GET", "POST", "PUT", "DELETE" ],
//                    //                   AccessControlAllowHeaders  = [ "Authorization" ]
//                    //               }.AsImmutable
//                    //           );

//                    //var ocationId = Location_Id.TryParse(Request.ParsedURLParameters[0]);

//                    //if (!LocationId.HasValue)
//                    //{

//                    //    OCPIResponseBuilder = new OCPIResponse.Builder(Request) {
//                    //        StatusCode           = 2001,
//                    //        StatusMessage        = "Invalid location identification!",
//                    //        HTTPResponseBuilder  = new HTTPResponse.Builder(Request.HTTPRequest) {
//                    //            HTTPStatusCode             = HTTPStatusCode.BadRequest,
//                    //            //AccessControlAllowMethods  = [ "OPTIONS", "GET", "POST", "PUT", "DELETE" ],
//                    //            AccessControlAllowHeaders  = [ "Authorization" ]
//                    //        }
//                    //    };

//                    //    return false;

//                    //}

//                    #endregion

//                    return Task.FromResult(
//                               new HTTPResponse.Builder(request) {
//                                   HTTPStatusCode             = HTTPStatusCode.OK,
//                                   Server                     = HTTPServiceName,
//                                   Date                       = Timestamp.Now,
//                                   AccessControlAllowOrigin   = "*",
//                                   AccessControlAllowMethods  = [ "OPTIONS", "GET" ],
////                                   AccessControlAllowHeaders  = [ "Authorization" ],
//                                   ContentType                = HTTPContentType.Application.JSON_UTF8,
//                                   Content                    = NTSServer.GetServerInfos(numberOfRequestedNTSCookies).First().ToJSON().ToUTF8Bytes(),
//                                   Connection                 = ConnectionType.Close,
//                                   Vary                       = "Accept"
//                               }.AsImmutable
//                           );

//                }

//            );

            #endregion

            #endregion


        }

        #endregion


    }

}
