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
    /// TLS certificate information captured during NTS-KE handshake.
    /// </summary>
    public class TLSCertificateInfo
    {

        #region Properties

        public String?              Subject                    { get; init; }
        public String?              Issuer                     { get; init; }
        public DateTimeOffset?      NotBefore                  { get; init; }
        public DateTimeOffset?      NotAfter                   { get; init; }
        public Int32?               DaysUntilExpiry            { get; init; }
        public String?              SerialNumber               { get; init; }
        public String?              Thumbprint                 { get; init; }
        public String?              SignatureAlgorithm         { get; init; }
        public String?              PublicKeyAlgorithm         { get; init; }
        public Int32?               PublicKeySize              { get; init; }
        public IEnumerable<String>  SubjectAlternativeNames    { get; init; } = [];
        public String?              PolicyErrors               { get; init; }

        #endregion


        #region ToJSON()

        public JObject ToJSON()
        {

            var json = JSONObject.Create(

                           Subject.                IsNotNullOrEmpty()
                               ? new JProperty("subject",                   Subject)
                               : null,

                           Issuer.                 IsNotNullOrEmpty()
                               ? new JProperty("issuer",                    Issuer)
                               : null,

                           NotBefore.              HasValue
                               ? new JProperty("notBefore",                 NotBefore. Value.ToISO8601())
                               : null,

                           NotAfter.               HasValue
                               ? new JProperty("notAfter",                  NotAfter.  Value.ToISO8601())
                               : null,

                           DaysUntilExpiry.        HasValue
                               ? new JProperty("daysUntilExpiry",           DaysUntilExpiry.Value)
                               : null,

                           SerialNumber.           IsNotNullOrEmpty()
                               ? new JProperty("serialNumber",              SerialNumber)
                               : null,

                           Thumbprint.             IsNotNullOrEmpty()
                               ? new JProperty("thumbprint",                Thumbprint)
                               : null,

                           SignatureAlgorithm.     IsNotNullOrEmpty()
                               ? new JProperty("signatureAlgorithm",        SignatureAlgorithm)
                               : null,

                           PublicKeyAlgorithm.     IsNotNullOrEmpty()
                               ? new JProperty("publicKeyAlgorithm",        PublicKeyAlgorithm)
                               : null,

                           PublicKeySize.          HasValue
                               ? new JProperty("publicKeySize",             PublicKeySize.Value)
                               : null,

                           SubjectAlternativeNames.Any()
                               ? new JProperty("subjectAlternativeNames",   new JArray(SubjectAlternativeNames))
                               : null,

                           PolicyErrors is not null
                               ? new JProperty("policyErrors",              PolicyErrors)
                               : null

            );

            return json;

        }

        #endregion

    }

}
