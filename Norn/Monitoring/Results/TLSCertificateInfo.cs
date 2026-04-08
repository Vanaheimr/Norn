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

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// TLS certificate information captured during NTS-KE handshake.
    /// </summary>
    public class TLSCertificateInfo
    {

        #region Properties

        public String?    Subject             { get; init; }
        public String?    Issuer              { get; init; }
        public DateTime?  NotBefore           { get; init; }
        public DateTime?  NotAfter            { get; init; }
        public Int32?     DaysUntilExpiry     { get; init; }
        public String?    SerialNumber        { get; init; }
        public String?    Thumbprint          { get; init; }
        public String?    SignatureAlgorithm  { get; init; }
        public String?    PublicKeyAlgorithm  { get; init; }
        public Int32?     PublicKeySize       { get; init; }

        #endregion

        #region ToJSON()

        public JObject ToJSON()
        {

            var json = new JObject();

            if (Subject            is not null) json.Add("subject",            Subject);
            if (Issuer             is not null) json.Add("issuer",             Issuer);
            if (NotBefore.  HasValue)          json.Add("notBefore",          NotBefore. Value.ToString("o"));
            if (NotAfter.   HasValue)          json.Add("notAfter",           NotAfter.  Value.ToString("o"));
            if (DaysUntilExpiry.HasValue)      json.Add("daysUntilExpiry",    DaysUntilExpiry.Value);
            if (SerialNumber   is not null)    json.Add("serialNumber",       SerialNumber);
            if (Thumbprint     is not null)    json.Add("thumbprint",         Thumbprint);
            if (SignatureAlgorithm is not null) json.Add("signatureAlgorithm", SignatureAlgorithm);
            if (PublicKeyAlgorithm is not null) json.Add("publicKeyAlgorithm", PublicKeyAlgorithm);
            if (PublicKeySize.HasValue)        json.Add("publicKeySize",      PublicKeySize.Value);

            return json;

        }

        #endregion

    }

}
