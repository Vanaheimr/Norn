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
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SMTP;
using org.GraphDefined.Vanaheimr.Hermod.Logging;
using org.GraphDefined.Vanaheimr.Hermod.Sockets;
using org.GraphDefined.Vanaheimr.Hermod.Sockets.TCP;

using org.GraphDefined.Vanaheimr.Norn.Drone.HTTPAPI;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;
using org.GraphDefined.Vanaheimr.Hermod.HTTPTest;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Drone.WebAPI
{

    /// <summary>
    /// Norn WebAPI extention methods.
    /// </summary>
    public static class NornDroneWebAPIExtensions
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
    /// A HTTP API to configure and access the NTS-KE/NTS UDP server.
    /// </summary>
    public partial class NornDroneWebAPI : AHTTPExtAPIXExtension2<NornDroneHTTPAPI, HTTPExtAPIX>
    {

        #region Data

        /// <summary>
        /// The default HTTP URL prefix.
        /// </summary>
        public     static readonly  HTTPPath            DefaultURLPathPrefix      = HTTPPath.Parse("webapi");

        /// <summary>
        /// The default HTTP server name.
        /// </summary>
        public new const            String              DefaultHTTPServerName     = "Open Charging Cloud OCPI WebAPI";

        /// <summary>
        /// The default HTTP service name.
        /// </summary>
        public new const            String              DefaultHTTPServiceName    = "Open Charging Cloud OCPI WebAPI";

        /// <summary>
        /// The HTTP root for embedded resources.
        /// </summary>
        public     const            String              HTTPRoot                  = "org.graphdefined.vanaheimr.norn.WebAPI.HTTPRoot.";


        //ToDo: http://www.iana.org/form/media-types

        ///// <summary>
        ///// The HTTP content type for serving Norn+ JSON data.
        ///// </summary>
        //public static readonly      HTTPContentType     NornPlusJSONContentType   = new ("application", "vnd.NornPlus+json", "utf-8", null, null);

        ///// <summary>
        ///// The HTTP content type for serving Norn+ HTML data.
        ///// </summary>
        //public static readonly      HTTPContentType     NornPlusHTMLContentType   = new ("application", "vnd.NornPlus+html", "utf-8", null, null);


        public static readonly      HTTPEventSource_Id  DefaultDebugLogId    = HTTPEventSource_Id.Parse($"NornDrone_{Version.String}_debugLog");

        /// <summary>
        /// The default WebAPI logfile name.
        /// </summary>
        public  const               String              DefaultLogfileName   = "OCPI_WebAPI.log";



        private readonly ConcurrentDictionary<DateTimeOffset, MeasurementRound>  measurementRounds = [];

        #endregion

        #region Properties

        public NornDroneHTTPAPI          NornHTTPAPI
            => HTTPBaseAPI;

        /// <summary>
        /// The HTTP URI prefix.
        /// </summary>
        public HTTPPath?                 OverlayURLPathPrefix    { get; }

        /// <summary>
        /// The HTTP URI prefix.
        /// </summary>
        public HTTPPath?                 APIURLPathPrefix        { get; }

        /// <summary>
        /// Make use of HTTP Server Sent Events for debug information.
        /// </summary>
        public ServiceSettings           UseHTTPSSE              { get; }

        /// <summary>
        /// Debug information via HTTP Server Sent Events.
        /// </summary>
        public HTTPEventSource<JObject>  DebugLog                { get; }

        /// <summary>
        /// The Norn WebAPI logger.
        /// </summary>
        public WebAPILogger?             Logger                  { get; set; }

        #endregion

        #region Events

        #region (protected internal) GetRootRequest      (Request)

        /// <summary>
        /// An event sent whenever a GET / request was received.
        /// </summary>
        public HTTPRequestLogEventX OnGetRootRequest = new();

        /// <summary>
        /// An event sent whenever a GET / request was received.
        /// </summary>
        /// <param name="Timestamp">The timestamp of the request.</param>
        /// <param name="API">The Common API.</param>
        /// <param name="Request">A HTTP request.</param>
        protected internal Task GetRootRequest(DateTimeOffset     Timestamp,
                                               HTTPAPIX           API,
                                               HTTPRequest        Request,
                                               CancellationToken  CancellationToken)

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
        public HTTPResponseLogEventX OnGetRootResponse = new();

        /// <summary>
        /// An event sent whenever a GET / response was sent.
        /// </summary>
        /// <param name="Timestamp">The timestamp of the request.</param>
        /// <param name="API">The Common API.</param>
        /// <param name="Request">A HTTP request.</param>
        /// <param name="Response">A HTTP response.</param>
        protected internal Task GetRootResponse(DateTimeOffset     Timestamp,
                                                HTTPAPIX           API,
                                                HTTPRequest        Request,
                                                HTTPResponse       Response,
                                                CancellationToken  CancellationToken)

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
        public HTTPRequestLogEventX OnGETServerInfosHTTPRequest = new ();

        /// <summary>
        /// An event sent whenever a GETServerInfos request was received.
        /// </summary>
        /// <param name="Timestamp">The timestamp of the request.</param>
        /// <param name="API">The HTTP API.</param>
        /// <param name="Request">A HTTP request.</param>
        protected internal Task GETServerInfosHTTPRequest(DateTimeOffset     Timestamp,
                                                          HTTPAPIX           API,
                                                          HTTPRequest        Request,
                                                          CancellationToken  CancellationToken)

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
        public HTTPResponseLogEventX OnGETServerInfosHTTPResponse = new ();

        /// <summary>
        /// An event sent whenever a GETServerInfos response was sent.
        /// </summary>
        /// <param name="Timestamp">The timestamp of the request.</param>
        /// <param name="API">The HTTP API.</param>
        /// <param name="Request">A HTTP request.</param>
        /// <param name="Response">A HTTP response.</param>
        protected internal Task GETServerInfosHTTPResponse(DateTimeOffset     Timestamp,
                                                           HTTPAPIX           API,
                                                           HTTPRequest        Request,
                                                           HTTPResponse       Response,
                                                           CancellationToken  CancellationToken)

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
        /// Attach the Norn WebAPI to the given HTTP server.
        /// </summary>
        /// <param name="HTTPAPI">The Norn Drone HTTP API.</param>
        public NornDroneWebAPI(NornDroneHTTPAPI         HTTPAPI,

                               HTTPPath?                OverlayURLPathPrefix   = null,
                               HTTPPath?                APIURLPathPrefix       = null,
                               HTTPPath?                WebAPIURLPathPrefix    = null,
                               HTTPPath?                BasePath               = null,  // For URL prefixes in HTML!

                               I18NString?              Description            = null,

                               ServiceSettings?         UseHTTPSSE             = null,
                               HTTPEventSource_Id?      DebugLogId             = null,

                               String?                  ExternalDNSName        = null,
                               String?                  HTTPServerName         = DefaultHTTPServerName,
                               String?                  HTTPServiceName        = DefaultHTTPServiceName,
                               String?                  APIVersionHash         = null,
                               JObject?                 APIVersionHashes       = null,

                               Boolean?                 IsDevelopment          = null,
                               IEnumerable<String>?     DevelopmentServers     = null,
                               Boolean?                 DisableNotifications   = null,
                               Boolean?                 DisableLogging         = null,
                               String?                  LoggingPath            = null,
                               String?                  LogfileName            = null,
                               LogfileCreatorDelegate?  LogfileCreator         = null)

            : base(HTTPAPI,
                   HTTPAPI.URLPathPrefix + WebAPIURLPathPrefix,
                   HTTPAPI.URLPathPrefix + BasePath,

                   Description     ?? I18NString.Create("OCPI Common Web API"),

                   ExternalDNSName,
                   HTTPServerName  ?? DefaultHTTPServerName,
                   HTTPServiceName ?? DefaultHTTPServiceName,
                   APIVersionHash,
                   APIVersionHashes,

                   IsDevelopment,
                   DevelopmentServers,
                   DisableLogging,
                   LoggingPath,
                   LogfileName     ?? DefaultLogfileName,
                   LogfileCreator)

        {

            this.OverlayURLPathPrefix  = HTTPAPI.URLPathPrefix + OverlayURLPathPrefix;
            this.APIURLPathPrefix      = HTTPAPI.URLPathPrefix + APIURLPathPrefix;

            this.UseHTTPSSE            = UseHTTPSSE ?? ServiceSettings.Disabled;

            this.DebugLog              = HTTPBaseAPI.HTTPBaseAPI.AddJSONEventSource(
                                             EventSourceId:            DebugLogId ?? DefaultDebugLogId,
                                             MaxNumberOfCachedEvents:  1000,
                                             RetryInterval :           TimeSpan.FromSeconds(5),
                                             EnableLogging:            true,
                                             LogfilePrefix:            this.LoggingPath + "HTTPSSEs" + Path.DirectorySeparatorChar
                                         );

            RegisterURLTemplates();

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
            new Tuple<String, Assembly>(NornDroneWebAPI.HTTPRoot, typeof(NornDroneWebAPI).Assembly),
            new Tuple<String, Assembly>(HTTPExtAPI.     HTTPRoot, typeof(HTTPExtAPI).     Assembly)
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
        /// The following will register HTTP endpoints serving HTML pages, JavaScript
        /// and CSS files for the Norn drone and its measurements.
        /// </summary>
        private void RegisterURLTemplates()
        {

            #region / (HTTPRoot)

            NornHTTPAPI.HTTPBaseAPI.MapResourceAssemblyFolder(
                HTTPHostname.Any,
                URLPathPrefix,
                HTTPRoot,
                RequireAuthentication:  false,
                DefaultFilename:       "index.html"
            );

            #endregion


            if (OverlayURLPathPrefix.HasValue)
            {

                #region GET ~/

                NornHTTPAPI.HTTPBaseAPI.AddHandler(

                    HTTPMethod.GET,
                    OverlayURLPathPrefix.Value,
                    HTTPContentType.Text.HTML_UTF8,
                    HTTPDelegate: request =>

                        Task.FromResult(
                            new HTTPResponse.Builder(request) {
                                HTTPStatusCode             = HTTPStatusCode.OK,
                                Server                     = HTTPServiceName,
                                Date                       = Timestamp.Now,
                                AccessControlAllowOrigin   = "*",
                                AccessControlAllowMethods  = [ "OPTIONS", "GET" ],
                                AccessControlAllowHeaders  = [ "Authorization" ],
                                ContentType                = HTTPContentType.Text.HTML_UTF8,
                                Content                    = MixWithHTMLTemplate(
                                                                 "index.shtml",
                                                                 html => html.Replace("{{versionPath}}", "")
                                                             ).ToUTF8Bytes(),
                                Connection                 = ConnectionType.KeepAlive,
                                Vary                       = "Accept"
                            }.AsImmutable),

                    AllowReplacement: URLReplacement.Allow

                );

                #endregion


                #region GET ~/debugLog

                if (UseHTTPSSE != ServiceSettings.Disabled)
                {

                    HTTPBaseAPI.HTTPBaseAPI.MapJSONEventSource(
                        DebugLog,
                        OverlayURLPathPrefix.Value + "debugLog",
                        RequireAuthentication:  UseHTTPSSE == ServiceSettings.RequiresAuthentication
                    );

                    NornHTTPAPI.HTTPBaseAPI.AddHandler(

                        HTTPMethod.GET,
                        OverlayURLPathPrefix.Value + "debug",
                        HTTPContentType.Text.HTML_UTF8,
                        HTTPDelegate: async request => {

                            #region Check authentication

                            if (request.User == null &&
                                UseHTTPSSE == ServiceSettings.RequiresAuthentication)
                            {

                                //ToDo: Maybe redirect to a login page instead of sending a 401?
                                return new HTTPResponse.Builder(request) {
                                           HTTPStatusCode             = HTTPStatusCode.Unauthorized,
                                           Server                     = HTTPServerName,
                                           Date                       = Timestamp.Now,
                                           AccessControlAllowOrigin   = "*",
                                           AccessControlAllowMethods  = [ "GET" ],
                                           AccessControlAllowHeaders  = [ "Content-Type", "Accept", "Authorization" ],
                                           Connection                 = ConnectionType.Close,
                                           Vary                       = "Accept"
                                       }.AsImmutable;

                            }

                            #endregion


                            return new HTTPResponse.Builder(request) {
                                       HTTPStatusCode             = HTTPStatusCode.OK,
                                       Server                     = HTTPServerName,
                                       Date                       = Timestamp.Now,
                                       AccessControlAllowOrigin   = "*",
                                       AccessControlAllowMethods  = [ "GET" ],
                                       AccessControlAllowHeaders  = [ "Content-Type", "Accept", "Authorization" ],
                                       ContentType                = HTTPContentType.Text.HTML_UTF8,
                                       Content                    = MixWithHTMLTemplate("debugLog.debugLog.shtml").ToUTF8Bytes(),
                                       Connection                 = ConnectionType.KeepAlive,
                                       Vary                       = "Accept"
                                   }.AsImmutable;

                        }

                    );

                }

                #endregion


                #region GET ~/support

                NornHTTPAPI.HTTPBaseAPI.AddHandler(

                    HTTPMethod.GET,
                    OverlayURLPathPrefix.Value + "/support",
                    HTTPContentType.Text.HTML_UTF8,
                    HTTPDelegate: request =>

                        Task.FromResult(
                            new HTTPResponse.Builder(request) {
                                HTTPStatusCode             = HTTPStatusCode.OK,
                                Server                     = HTTPServerName,
                                Date                       = Timestamp.Now,
                                AccessControlAllowOrigin   = "*",
                                AccessControlAllowMethods  = [ "GET" ],
                                AccessControlAllowHeaders  = [ "Content-Type", "Accept", "Authorization" ],
                                ContentType                = HTTPContentType.Text.HTML_UTF8,
                                Content                    = MixWithHTMLTemplate("support.support.shtml").ToUTF8Bytes(),
                                Connection                 = ConnectionType.KeepAlive,
                                Vary                       = "Accept"
                            }.AsImmutable
                        )

                );

                #endregion

                #region GET ~/favicon.png

                NornHTTPAPI.HTTPBaseAPI.AddHandler(

                    HTTPMethod.GET,
                    OverlayURLPathPrefix.Value + "/favicon.png",
                    //HTTPContentType.Image.PNG,
                    HTTPDelegate: request =>

                        Task.FromResult(
                            new HTTPResponse.Builder(request) {
                                HTTPStatusCode             = HTTPStatusCode.OK,
                                Server                     = HTTPServerName,
                                Date                       = Timestamp.Now,
                                AccessControlAllowOrigin   = "*",
                                AccessControlAllowMethods  = [ "GET" ],
                                AccessControlAllowHeaders  = [ "Content-Type", "Accept", "Authorization" ],
                                ContentType                = HTTPContentType.Image.PNG,
                                Content                    = GetResourceBytes("images.favicon_big.png"),
                                Connection                 = ConnectionType.KeepAlive
                            }.AsImmutable
                        )

                );

                #endregion

            }

        }

        #endregion


    }

}
