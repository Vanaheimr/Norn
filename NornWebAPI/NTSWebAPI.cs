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

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS.WebAPI
{

    /// <summary>
    /// Norn WebAPI extention methods.
    /// </summary>
    public static class NTSWebAPIExtensions
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
    public partial class NTSWebAPI : HTTPExtAPI
    {

        #region Data

        /// <summary>
        /// The default HTTP URI prefix.
        /// </summary>
        public new static readonly  HTTPPath            DefaultURLPathPrefix      = HTTPPath.Parse("webapi");

        /// <summary>
        /// The default HTTP service name.
        /// </summary>
        public new const            String              DefaultHTTPServiceName    = $"Norn {Version.String} WebAPI";

        /// <summary>
        /// The default HTTP realm, if HTTP Basic Authentication is used.
        /// </summary>
        public     const            String              DefaultHTTPRealm          = $"Norn {Version.String} WebAPI";

        /// <summary>
        /// The HTTP root for embedded ressources.
        /// </summary>
        public new const            String              HTTPRoot                  = "org.graphdefined.vanaheimr.norn.WebAPI.HTTPRoot.";


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


        public NTSServer                                    NTSServer               { get; }

        public WebAPILogger?                                Logger                  { get; set; }


        /// <summary>
        /// The default request timeout for new CPO/EMSP clients.
        /// </summary>
        //public TimeSpan?                                    RequestTimeout          { get; set; }

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
        protected internal Task GETServerInfosHTTPRequest(DateTimeOffset  Timestamp,
                                                          HTTPAPI         API,
                                                          HTTPRequest     Request)

            => OnGETServerInfosHTTPRequest.WhenAll(
                   Timestamp,
                   API ?? this,
                   Request
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
        protected internal Task GETServerInfosHTTPResponse(DateTimeOffset  Timestamp,
                                                           HTTPAPI         API,
                                                           HTTPRequest     Request,
                                                           HTTPResponse    Response)

            => OnGETServerInfosHTTPResponse.WhenAll(
                   Timestamp,
                   API ?? this,
                   Request,
                   Response
               );

        #endregion

        #endregion

        #region Constructor(s)

        static NTSWebAPI()
        {
            // Using static variables within normal constructors seems to
            // have a problem setting them up to their expected values!
        }

        #region NTSWebAPI(NTSServer, HTTPHostname, ...)

        /// <summary>
        /// Attach the Norn WebAPI to the given HTTP server.
        /// </summary>
        /// <param name="NTSServer">The NTS server.</param>
        public NTSWebAPI(NTSServer                                                  NTSServer,

                         HTTPHostname                                               HTTPHostname,
                         String?                                                    ExternalDNSName                  = null,
                         IPPort?                                                    HTTPServerPort                   = null,
                         HTTPPath?                                                  BasePath                         = null,
                         String?                                                    HTTPServerName                   = DefaultHTTPServerName,

                         HTTPPath?                                                  URLPathPrefix                    = null,
                         String?                                                    HTTPServiceName                  = DefaultHTTPServiceName,
                         String?                                                    HTMLTemplate                     = null,
                         JObject?                                                   APIVersionHashes                 = null,

                         ServerCertificateSelectorDelegate?                         ServerCertificateSelector        = null,
                         RemoteTLSClientCertificateValidationHandler<IHTTPServer>?  ClientCertificateValidator       = null,
                         LocalCertificateSelectionHandler?                          LocalCertificateSelector         = null,
                         SslProtocols?                                              AllowedTLSProtocols              = null,
                         Boolean?                                                   ClientCertificateRequired        = null,
                         Boolean?                                                   CheckCertificateRevocation       = null,

                         ServerThreadNameCreatorDelegate?                           ServerThreadNameCreator          = null,
                         ServerThreadPriorityDelegate?                              ServerThreadPrioritySetter       = null,
                         Boolean?                                                   ServerThreadIsBackground         = null,
                         ConnectionIdBuilder?                                       ConnectionIdBuilder              = null,
                         TimeSpan?                                                  ConnectionTimeout                = null,
                         UInt32?                                                    MaxClientConnections             = null,

                         Organization_Id?                                           AdminOrganizationId              = null,
                         EMailAddress?                                              APIRobotEMailAddress             = null,
                         String?                                                    APIRobotGPGPassphrase            = null,
                         ISMTPClient?                                               SMTPClient                       = null,

                         PasswordQualityCheckDelegate?                              PasswordQualityCheck             = null,
                         HTTPCookieName?                                            CookieName                       = null,
                         Boolean                                                    UseSecureCookies                 = true,
                         TimeSpan?                                                  MaxSignInSessionLifetime         = null,
                         Languages?                                                 DefaultLanguage                  = null,
                         Byte?                                                      MinUserIdLength                  = null,
                         Byte?                                                      MinRealmLength                   = null,
                         Byte?                                                      MinUserNameLength                = null,
                         Byte?                                                      MinUserGroupIdLength             = null,
                         UInt16?                                                    MinAPIKeyLength                  = null,
                         Byte?                                                      MinMessageIdLength               = null,
                         Byte?                                                      MinOrganizationIdLength          = null,
                         Byte?                                                      MinOrganizationGroupIdLength     = null,
                         Byte?                                                      MinNotificationMessageIdLength   = null,
                         Byte?                                                      MinNewsPostingIdLength           = null,
                         Byte?                                                      MinNewsBannerIdLength            = null,
                         Byte?                                                      MinFAQIdLength                   = null,

                         Boolean?                                                   DisableMaintenanceTasks          = null,
                         TimeSpan?                                                  MaintenanceInitialDelay          = null,
                         TimeSpan?                                                  MaintenanceEvery                 = null,

                         Boolean?                                                   DisableWardenTasks               = null,
                         TimeSpan?                                                  WardenInitialDelay               = null,
                         TimeSpan?                                                  WardenCheckEvery                 = null,

                         IEnumerable<URLWithAPIKey>?                                RemoteAuthServers                = null,
                         IEnumerable<APIKey_Id>?                                    RemoteAuthAPIKeys                = null,

                         Boolean?                                                   IsDevelopment                    = null,
                         IEnumerable<String>?                                       DevelopmentServers               = null,
                         Boolean                                                    SkipURLTemplates                 = false,
                         String?                                                    DatabaseFileName                 = DefaultHTTPExtAPI_DatabaseFileName,
                         Boolean                                                    DisableNotifications             = false,
                         Boolean                                                    DisableLogging                   = false,
                         String?                                                    LoggingPath                      = null,
                         String?                                                    LogfileName                      = DefaultHTTPExtAPI_LogfileName,
                         LogfileCreatorDelegate?                                    LogfileCreator                   = null,
                         DNSClient?                                                 DNSClient                        = null,
                         Boolean                                                    AutoStart                        = false)

            : base(HTTPHostname,
                   ExternalDNSName,
                   HTTPServerPort,
                   BasePath,
                   HTTPServerName,

                   URLPathPrefix,
                   HTTPServiceName,
                   HTMLTemplate,
                   APIVersionHashes,

                   ServerCertificateSelector,
                   ClientCertificateValidator,
                   LocalCertificateSelector,
                   AllowedTLSProtocols,
                   ClientCertificateRequired,
                   CheckCertificateRevocation,

                   ServerThreadNameCreator,
                   ServerThreadPrioritySetter,
                   ServerThreadIsBackground,
                   ConnectionIdBuilder,
                   ConnectionTimeout,
                   MaxClientConnections,

                   AdminOrganizationId,
                   APIRobotEMailAddress,
                   APIRobotGPGPassphrase,
                   SMTPClient,

                   PasswordQualityCheck,
                   CookieName,
                   UseSecureCookies,
                   MaxSignInSessionLifetime,
                   DefaultLanguage,
                   MinUserIdLength,
                   MinRealmLength,
                   MinUserNameLength,
                   MinUserGroupIdLength,
                   MinAPIKeyLength,
                   MinMessageIdLength,
                   MinOrganizationIdLength,
                   MinOrganizationGroupIdLength,
                   MinNotificationMessageIdLength,
                   MinNewsPostingIdLength,
                   MinNewsBannerIdLength,
                   MinFAQIdLength,

                   DisableMaintenanceTasks,
                   MaintenanceInitialDelay,
                   MaintenanceEvery,

                   DisableWardenTasks,
                   WardenInitialDelay,
                   WardenCheckEvery,

                   RemoteAuthServers,
                   RemoteAuthAPIKeys,

                   IsDevelopment,
                   DevelopmentServers,
                   SkipURLTemplates,
                   DatabaseFileName,
                   DisableNotifications,
                   DisableLogging,
                   LoggingPath,
                   LogfileName,
                   LogfileCreator,
                   DNSClient ?? NTSServer.DNSClient,

                   AutoStart: false)

        {

            this.NTSServer             = NTSServer;

            this.HTTPRealm             = HTTPRealm.IsNotNullOrEmpty() ? HTTPRealm : DefaultHTTPRealm;
            this.HTTPLogins            = HTTPLogins ?? [];

            // Link HTTP events...
            HTTPServer.RequestLog     += (HTTPProcessor, ServerTimestamp, Request)                                 => RequestLog. WhenAll(HTTPProcessor, ServerTimestamp, Request);
            HTTPServer.ResponseLog    += (HTTPProcessor, ServerTimestamp, Request, Response)                       => ResponseLog.WhenAll(HTTPProcessor, ServerTimestamp, Request, Response);
            HTTPServer.ErrorLog       += (HTTPProcessor, ServerTimestamp, Request, Response, Error, LastException) => ErrorLog.   WhenAll(HTTPProcessor, ServerTimestamp, Request, Response, Error, LastException);

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

        #region NTSWebAPI(NTSServer, HTTPServer,   ...)

        /// <summary>
        /// Attach the Norn WebAPI to the given HTTP server.
        /// </summary>
        /// <param name="NTSServer">The NTS server.</param>
        public NTSWebAPI(NTSServer                                   NTSServer,

                         HTTPServer                                  HTTPServer,
                         HTTPHostname?                               HTTPHostname              = null,
                         String?                                     ExternalDNSName           = "",
                         String?                                     HTTPServiceName           = DefaultHTTPServiceName,

                         HTTPPath?                                   BasePath                  = null,

                         String                                      HTTPRealm                 = DefaultHTTPRealm,
                         IEnumerable<KeyValuePair<String, String>>?  HTTPLogins                = null,

                         HTTPPath?                                   URLPathPrefix             = null,
                         String?                                     HTMLTemplate              = null,
                         JObject?                                    APIVersionHashes          = null,

                         Boolean?                                    DisableMaintenanceTasks   = false,
                         TimeSpan?                                   MaintenanceInitialDelay   = null,
                         TimeSpan?                                   MaintenanceEvery          = null,

                         Boolean?                                    DisableWardenTasks        = false,
                         TimeSpan?                                   WardenInitialDelay        = null,
                         TimeSpan?                                   WardenCheckEvery          = null,

                         //Boolean                                     SkipURLTemplates          = true,

                         Boolean?                                    IsDevelopment             = false,
                         IEnumerable<String>?                        DevelopmentServers        = null,
                         Boolean?                                    DisableLogging            = false,
                         String?                                     LoggingPath               = null,
                         String?                                     LogfileName               = null,
                         LogfileCreatorDelegate?                     LogfileCreator            = null

                         //TimeSpan?                                   RequestTimeout            = null
                        )

            : base(HTTPServer,
                   HTTPHostname,
                   ExternalDNSName,
                   HTTPServiceName,
                   BasePath,

                   URLPathPrefix,
                   HTMLTemplate,
                   APIVersionHashes,

                   DisableMaintenanceTasks,
                   MaintenanceInitialDelay,
                   MaintenanceEvery,

                   DisableWardenTasks,
                   WardenInitialDelay,
                   WardenCheckEvery,

                   IsDevelopment,
                   DevelopmentServers,
                   DisableLogging,
                   LoggingPath,
                   LogfileName,
                   LogfileCreator,

                   AutoStart: false)

        {

            this.NTSServer             = NTSServer;

            this.HTTPRealm             = HTTPRealm.IsNotNullOrEmpty() ? HTTPRealm : DefaultHTTPRealm;
            this.HTTPLogins            = HTTPLogins ?? [];

            // Link HTTP events...
            HTTPServer.RequestLog     += (HTTPProcessor, ServerTimestamp, Request)                                 => RequestLog. WhenAll(HTTPProcessor, ServerTimestamp, Request);
            HTTPServer.ResponseLog    += (HTTPProcessor, ServerTimestamp, Request, Response)                       => ResponseLog.WhenAll(HTTPProcessor, ServerTimestamp, Request, Response);
            HTTPServer.ErrorLog       += (HTTPProcessor, ServerTimestamp, Request, Response, Error, LastException) => ErrorLog.   WhenAll(HTTPProcessor, ServerTimestamp, Request, Response, Error, LastException);

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

        #endregion


        #region (private) RegisterURLTemplates()

        #region Manage HTTP Resources

        #region (protected override) GetResourceStream       (ResourceName)

        protected override Stream? GetResourceStream(String ResourceName)

            => GetResourceStream(
                   ResourceName,
                   new Tuple<String, System.Reflection.Assembly>(NTSWebAPI.HTTPRoot, typeof(NTSWebAPI).Assembly),
                   new Tuple<String, System.Reflection.Assembly>(HTTPExtAPI.HTTPRoot, typeof(HTTPExtAPI).Assembly),
                   new Tuple<String, System.Reflection.Assembly>(HTTPAPI.   HTTPRoot, typeof(HTTPAPI).   Assembly)
               );

        #endregion

        #region (protected override) GetResourceMemoryStream (ResourceName)

        protected override MemoryStream? GetResourceMemoryStream(String ResourceName)

            => GetResourceMemoryStream(
                   ResourceName,
                   new Tuple<String, System.Reflection.Assembly>(NTSWebAPI.HTTPRoot, typeof(NTSWebAPI).Assembly),
                   new Tuple<String, System.Reflection.Assembly>(HTTPExtAPI.HTTPRoot, typeof(HTTPExtAPI).Assembly),
                   new Tuple<String, System.Reflection.Assembly>(HTTPAPI.   HTTPRoot, typeof(HTTPAPI).   Assembly)
               );

        #endregion

        #region (protected override) GetResourceString       (ResourceName)

        protected override String GetResourceString(String ResourceName)

            => GetResourceString(
                   ResourceName,
                   new Tuple<String, System.Reflection.Assembly>(NTSWebAPI.HTTPRoot, typeof(NTSWebAPI).Assembly),
                   new Tuple<String, System.Reflection.Assembly>(HTTPExtAPI.HTTPRoot, typeof(HTTPExtAPI).Assembly),
                   new Tuple<String, System.Reflection.Assembly>(HTTPAPI.   HTTPRoot, typeof(HTTPAPI).   Assembly)
               );

        #endregion

        #region (protected override) GetResourceBytes        (ResourceName)

        protected override Byte[] GetResourceBytes(String ResourceName)

            => GetResourceBytes(
                   ResourceName,
                   new Tuple<String, System.Reflection.Assembly>(NTSWebAPI.HTTPRoot, typeof(NTSWebAPI).Assembly),
                   new Tuple<String, System.Reflection.Assembly>(HTTPExtAPI.HTTPRoot, typeof(HTTPExtAPI).Assembly),
                   new Tuple<String, System.Reflection.Assembly>(HTTPAPI.   HTTPRoot, typeof(HTTPAPI).   Assembly)
               );

        #endregion

        #region (protected override) MixWithHTMLTemplate     (ResourceName)

        protected override String MixWithHTMLTemplate(String ResourceName)

            => MixWithHTMLTemplate(
                   ResourceName,
                   new Tuple<String, System.Reflection.Assembly>(NTSWebAPI.HTTPRoot, typeof(NTSWebAPI).Assembly),
                   new Tuple<String, System.Reflection.Assembly>(HTTPExtAPI.HTTPRoot, typeof(HTTPExtAPI).Assembly),
                   new Tuple<String, System.Reflection.Assembly>(HTTPAPI.   HTTPRoot, typeof(HTTPAPI).   Assembly)
               );

        #endregion

        #region (protected override) MixWithHTMLTemplate     (ResourceName, HTMLConverter)

        protected override String MixWithHTMLTemplate(String ResourceName, Func<String, String> HTMLConverter)

            => MixWithHTMLTemplate(
                   ResourceName,
                   HTMLConverter,
                   new Tuple<String, System.Reflection.Assembly>(NTSWebAPI.HTTPRoot, typeof(NTSWebAPI).Assembly),
                   new Tuple<String, System.Reflection.Assembly>(HTTPExtAPI.HTTPRoot, typeof(HTTPExtAPI).Assembly),
                   new Tuple<String, System.Reflection.Assembly>(HTTPAPI.   HTTPRoot, typeof(HTTPAPI).   Assembly)
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

            this.MapResourceAssemblyFolder(
                HTTPHostname.Any,
                URLPathPrefix,
                HTTPRoot,
                DefaultFilename: "index.html"
            );

            #endregion


            #region GET ~/

            HTTPServer.AddMethodCallback(

                this,
                HTTPHostname.Any,
                HTTPMethod.GET,
                HTTPPath.Root,
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
                                                             "index.shtml"
                                                         ).ToUTF8Bytes(),
                            Connection                 = ConnectionType.Close,
                            Vary                       = "Accept"
                        }.AsImmutable)

            );

            #endregion


            #region ~/serverInfos

            #region OPTIONS  ~/serverInfos

            HTTPServer.AddMethodCallback(

                this,
                HTTPHostname.Any,
                HTTPMethod.OPTIONS,
                URLPathPrefix + "serverInfos",
                HTTPDelegate: request =>

                    Task.FromResult(
                        new HTTPResponse.Builder(request) {
                            HTTPStatusCode             = HTTPStatusCode.OK,
                            Allow                      = [ HTTPMethod.OPTIONS, HTTPMethod.GET ],
                            AccessControlAllowMethods  = [ "OPTIONS", "GET" ],
                            AccessControlAllowHeaders  = [ "Authorization" ]
                        }.AsImmutable
                    )

            );

            #endregion

            #region GET      ~/serverInfos

            HTTPServer.AddMethodCallback(

                this,
                HTTPHostname.Any,
                HTTPMethod.GET,
                URLPathPrefix + "serverInfos",
                HTTPContentType.Application.JSON_UTF8,
                HTTPRequestLogger:   GETServerInfosHTTPRequest,
                HTTPResponseLogger:  GETServerInfosHTTPResponse,
                HTTPDelegate:        request => {

                    #region numberOfRequestedNTSCookies

                    var numberOfRequestedNTSCookies = request.QueryString.GetUInt16("n") ?? 7;

                    //if (request.ParsedURLParameters.Length < 1)
                    //    return Task.FromResult(
                    //               new HTTPResponse.Builder(request) {
                    //                   HTTPStatusCode             = HTTPStatusCode.BadRequest,
                    //                   //AccessControlAllowMethods  = [ "OPTIONS", "GET", "POST", "PUT", "DELETE" ],
                    //                   AccessControlAllowHeaders  = [ "Authorization" ]
                    //               }.AsImmutable
                    //           );

                    //var ocationId = Location_Id.TryParse(Request.ParsedURLParameters[0]);

                    //if (!LocationId.HasValue)
                    //{

                    //    OCPIResponseBuilder = new OCPIResponse.Builder(Request) {
                    //        StatusCode           = 2001,
                    //        StatusMessage        = "Invalid location identification!",
                    //        HTTPResponseBuilder  = new HTTPResponse.Builder(Request.HTTPRequest) {
                    //            HTTPStatusCode             = HTTPStatusCode.BadRequest,
                    //            //AccessControlAllowMethods  = [ "OPTIONS", "GET", "POST", "PUT", "DELETE" ],
                    //            AccessControlAllowHeaders  = [ "Authorization" ]
                    //        }
                    //    };

                    //    return false;

                    //}

                    #endregion

                    return Task.FromResult(
                               new HTTPResponse.Builder(request) {
                                   HTTPStatusCode             = HTTPStatusCode.OK,
                                   Server                     = HTTPServiceName,
                                   Date                       = Timestamp.Now,
                                   AccessControlAllowOrigin   = "*",
                                   AccessControlAllowMethods  = [ "OPTIONS", "GET" ],
//                                   AccessControlAllowHeaders  = [ "Authorization" ],
                                   ContentType                = HTTPContentType.Application.JSON_UTF8,
                                   Content                    = NTSServer.GetServerInfos(numberOfRequestedNTSCookies).First().ToJSON().ToUTF8Bytes(),
                                   Connection                 = ConnectionType.Close,
                                   Vary                       = "Accept"
                               }.AsImmutable
                           );

                }

            );

            #endregion

            #endregion


        }

        #endregion


    }

}
