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

using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// A single NTS server endpoint to monitor.
    /// </summary>
    public class NTSServerEndpoint
    {

        public DomainName  Hostname     { get; set; }
        public IPPort      NTSKEPort    { get; set; }
        public IPPort      NTPPort      { get; set; }
        public Boolean     Enabled      { get; set; }

        /// <summary>
        /// Which servers are asked first. Lower is earlier, and servers sharing
        /// a value are asked at the same time.
        /// </summary>
        /// <remarks>
        /// From the Secure Time Synchronization white paper, where this is the
        /// Priority of an NTP client. A group walks its priorities in order and
        /// stops at the first one that answers well enough - so a band exists to
        /// be preferred, not merely to be sorted.
        ///
        /// Everything defaults to the same value, which is a group whose servers
        /// are all asked together. That is the right arrangement for several
        /// equivalent public servers and the wrong one for a local server with a
        /// distant fallback behind it, which is what this is for.
        /// </remarks>
        public Byte        Priority     { get; set; }

        /// <summary>
        /// The certificates this server's NTS-KE certificate must chain to, or
        /// none to use whatever the machine trusts.
        /// </summary>
        /// <remarks>
        /// A set of certificates rather than a named group: naming them is how
        /// the device model of a charging protocol refers to them, and that is
        /// its business rather than this library's. Whoever configures a group
        /// there resolves the name and hands the certificates over.
        /// </remarks>
        public IEnumerable<X509Certificate2>?  RootCAs                { get; set; }

        /// <summary>
        /// The AEAD algorithms to offer during the key exchange, or none for
        /// this client's own defaults.
        /// </summary>
        public IEnumerable<AEADAlgorithms>?    OfferedAEADAlgorithms  { get; set; }

        /// <summary>
        /// What decides whether this server's NTS-KE certificate is believed, or
        /// none for the usual rule: a chain to whatever the machine trusts, issued
        /// for this host.
        /// </summary>
        /// <remarks>
        /// Asked at every key exchange with this server, with the certificate,
        /// the chain built for it and what building it found - so that whoever
        /// configures the server can hold it to more than the machine does: a
        /// fingerprint of its own or of its root, a root the machine has never
        /// heard of, and a record of what it found either way. A key exchange it
        /// refuses is one that did not happen, and the server is not asked for
        /// the time.
        ///
        /// Never written into a configuration file: it is code, not a setting.
        /// </remarks>
        [JsonIgnore]
        public RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient>?  RemoteCertificateValidator  { get; set; }

        public NTSServerEndpoint(DomainName                                                     Hostname,
                                 IPPort?                                                        NTSKEPort                    = null,
                                 IPPort?                                                        NTPPort                      = null,
                                 Boolean                                                        Enabled                      = true,
                                 Byte                                                           Priority                     = 0,
                                 IEnumerable<X509Certificate2>?                                 RootCAs                      = null,
                                 IEnumerable<AEADAlgorithms>?                                   OfferedAEADAlgorithms        = null,
                                 RemoteTLSServerCertificateValidationHandler<NTSKE_TLSClient>?  RemoteCertificateValidator   = null)
        {

            this.Hostname                    = Hostname;
            this.NTSKEPort                   = NTSKEPort ?? NTSClient.DefaultNTSKE_Port;
            this.NTPPort                     = NTPPort   ?? NTSClient.DefaultNTP_Port;
            this.Enabled                     = Enabled;
            this.Priority                    = Priority;
            this.RootCAs                     = RootCAs;
            this.OfferedAEADAlgorithms       = OfferedAEADAlgorithms;
            this.RemoteCertificateValidator  = RemoteCertificateValidator;

        }

        /// <summary>
        /// Parameterless constructor for JSON deserialization
        /// </summary>
        public NTSServerEndpoint()
            : this(DomainName.Empty)
        { }

    }

}
