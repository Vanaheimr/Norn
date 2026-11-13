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
        /// The HTTP root for embedded ressources.
        /// </summary>
        public new const            String              HTTPRoot                  = "org.graphdefined.vanaheimr.norn.HTTPAPI.HTTPRoot.";


        public static readonly      HTTPEventSource_Id  DebugLogId                = HTTPEventSource_Id.Parse($"Norn{Version.String}_debugLog");


        private readonly ConcurrentDictionary<DateTimeOffset, MeasurementRound>  measurementRounds = [];

        #endregion

        #region Properties


        /// <summary>
        /// Send debug information via HTTP Server Sent Events.
        /// </summary>
        public HTTPEventSource<JObject>                     DebugLog                { get; }


        public HTTPAPILogger?                               Logger                  { get; set; }

        public NTSServer                                    NTSServer               { get; }

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
                           ISMTPSubmissionClient?         SMTPClient                = null,

                           HTTPPath?                      AdditionalURLPathPrefix   = null,


                           Boolean?                       IsDevelopment             = null,
                           IEnumerable<String>?           DevelopmentServers        = null,
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
                   )

        {

            this.NTSServer             = NTSServer;


            RegisterURLTemplates();


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
                            AccessControlAllowMethods  = [ HTTPMethod.OPTIONS, HTTPMethod.GET ],
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

                // As what it is: plain text. It was registered as HTML, which is what
                // the web API on top of this one registers its page as - and a second
                // handler for one path and one content type is refused, so that the
                // web API could not be made at all.
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
                            AccessControlAllowMethods  = [ HTTPMethod.OPTIONS, HTTPMethod.GET ],
                            AccessControlAllowHeaders  = [ "Authorization" ],
                            ContentType                = HTTPContentType.Text.PLAIN,
                            Content                    = "Hello world!".ToUTF8Bytes(),
                            Connection                 = ConnectionType.Close,
                            Vary                       = "Accept"
                        }.AsImmutable)

            );

            #endregion

            #endregion


        }

        #endregion


    }

}
