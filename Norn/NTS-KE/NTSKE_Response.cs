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

using System.Text;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// The Network Time Security Key Establishment (NTS-KE) response.
    /// </summary>
    public class NTSKE_Response
    {

        #region Properties

        /// <summary>
        /// The enumeration of NTS-KE records.
        /// </summary>
        public IEnumerable<NTSKE_Record>  NTSKERecords    { get; } = [];

        /// <summary>
        /// The TLS client-to-server Key.
        /// </summary>
        public Byte[]                     C2SKey          { get; } = [];

        /// <summary>
        /// The TLS server-to-client Key.
        /// </summary>
        public Byte[]                     S2CKey          { get; } = [];

        /// <summary>
        /// An optional error message.
        /// </summary>
        public String?                    ErrorMessage    { get; }

        /// <summary>
        /// Optional timing information for the NTS-KE exchange.
        /// </summary>
        public NTSKE_TimingInfo?          TimingInfo      { get; }

        /// <summary>
        /// Optional TLS certificate and handshake information for the NTS-KE exchange.
        /// </summary>
        public NTSKE_TLSInfo?             TLSInfo         { get; }

        /// <summary>
        /// The negotiated NTPv4 server names or IP literals, if announced by NTS-KE.
        /// </summary>
        public IEnumerable<String>        NTPv4ServerNames { get; } = [];

        /// <summary>
        /// The negotiated NTPv4 server names that can be represented as DNS domain names.
        /// </summary>
        public IEnumerable<DomainName>    NTPv4Servers    { get; } = [];

        /// <summary>
        /// The negotiated NTPv4 UDP ports, if announced by NTS-KE.
        /// </summary>
        public IEnumerable<IPPort>        NTPv4Ports      { get; } = [];

        /// <summary>
        /// Warning messages returned by the NTS-KE server.
        /// </summary>
        public IEnumerable<String>        WarningMessages { get; } = [];


        /// <summary>
        /// The AEAD algorithm the key exchange settled on (RFC 8915 § 4.1.5).
        /// </summary>
        /// <remarks>
        /// <para>
        /// Read from the records rather than stored, so that it cannot disagree with what the
        /// server actually said. Everything downstream depends on it: how long the exported keys
        /// are, how the Authenticator extension field is sealed, and how long its nonce is.
        /// </para>
        /// <para>
        /// A response with no Algorithm Negotiation record falls back to AES-SIV-CMAC-256, which
        /// § 5.1 makes the one every implementation has. In practice this does not arise —
        /// <c>NTSKERecordValidator</c> rejects a response without one — but a property that
        /// returns null here would push the same fallback out to four call sites that each have
        /// to remember it.
        /// </para>
        /// </remarks>
        public AEADAlgorithms             AEADAlgorithm
        {
            get
            {

                var record = NTSKERecords.
                                 FirstOrDefault(ntsKERecord => ntsKERecord.Type == NTSKE_RecordTypes.AEADAlgorithmNegotiation);

                return record?.Body.Length >= 2
                           ? (AEADAlgorithms) ((record.Body[0] << 8) | record.Body[1])
                           : NTSAEAD.Default;

            }
        }


        /// <summary>
        /// The NTS-KE cookies.
        /// </summary>
        public IEnumerable<Byte[]>        Cookies

            => NTSKERecords.
                   Where (ntsKERecord => ntsKERecord.Type == NTSKE_RecordTypes.NewCookieForNTPv4).
                   Select(ntsKERecord => ntsKERecord.Body);


        /// <summary>
        /// The NTS Public Keys.
        /// </summary>
        public IEnumerable<PublicKey>     PublicKeys

            => NTSKERecords.
                   Where (ntsKERecord => ntsKERecord.Type == NTSKE_RecordTypes.NTSPublicKey).
                   Select(ntsKERecord => PublicKey.Parse(ntsKERecord.Body));

        #endregion

        #region Constructor(s)

        #region NTSKE_Response(NTSKE_Record, C2SKey, S2CKey, ...)

        /// <summary>
        /// Create a new NTS-KE response.
        /// </summary>
        /// <param name="NTSKERecords">The enumeration of NTS-KE records.</param>
        /// <param name="C2SKey">The TLS client-to-server Key.</param>
        /// <param name="S2CKey">The TLS server-to-client Key.</param>
        /// 
        public NTSKE_Response(IEnumerable<NTSKE_Record>  NTSKERecords,
                              Byte[]                     C2SKey,
                              Byte[]                     S2CKey,
                              NTSKE_TimingInfo?          TimingInfo   = null,
                              NTSKE_TLSInfo?             TLSInfo      = null)
        {

            this.NTSKERecords  = NTSKERecords;
            this.C2SKey        = C2SKey;
            this.S2CKey        = S2CKey;
            this.TimingInfo    = TimingInfo;
            this.TLSInfo       = TLSInfo;

            this.NTPv4ServerNames = NTSKERecords.
                                     Where (ntsKERecord => ntsKERecord.Type == NTSKE_RecordTypes.NTPv4ServerNegotiation).
                                     Select(ntsKERecord => Encoding.ASCII.GetString(ntsKERecord.Body).TrimEnd('\0')).
                                     Where (server      => server.IsNotNullOrEmpty()).
                                     ToArray();

            this.NTPv4Servers  = this.NTPv4ServerNames.
                                      Where(server => DomainName.TryParse(server, out _, out _)).
                                      Select(DomainName.Parse).
                                      ToArray();

            this.NTPv4Ports    = NTSKERecords.
                                     Where (ntsKERecord =>  ntsKERecord.Type == NTSKE_RecordTypes.NTPv4PortNegotiation).
                                     Where (ntsKERecord =>  ntsKERecord.Body.Length == 2).
                                     Select(ntsKERecord => (UInt16) (ntsKERecord.Body[0] << 8) | ntsKERecord.Body[1]).
                                     Where (port        =>  port > 0).
                                     Select(IPPort.Parse);

            this.WarningMessages = NTSKERecords.
                                       Where (ntsKERecord => ntsKERecord.Type == NTSKE_RecordTypes.Warning).
                                       Select(FormatWarning);

        }

        #endregion

        #region NTSKE_Response(ErrorMessage, ...)

        /// <summary>
        /// Create a new NTS-KE error response.
        /// </summary>
        /// <param name="ErrorMessage">The error message.</param>
        public NTSKE_Response(String             ErrorMessage,
                              NTSKE_TimingInfo?  TimingInfo   = null,
                              NTSKE_TLSInfo?     TLSInfo      = null)
        {

            this.ErrorMessage  = ErrorMessage;
            this.TimingInfo    = TimingInfo;
            this.TLSInfo       = TLSInfo;

        }

        #endregion

        #endregion


        #region (private static) FormatRecordBody(Record)

        /// <summary>
        /// Render a Warning record for a human.
        /// </summary>
        /// <remarks>
        /// RFC 8915 § 4.1.4 defines the body as a 16-bit unsigned integer, not as text, so
        /// decoding it as a string yields control characters where the code should be.
        /// </remarks>
        private static String FormatWarning(NTSKE_Record Record)

            => Record.Body.Length == 2
                   ? $"warning code {(UInt16) ((Record.Body[0] << 8) | Record.Body[1])}"
                   : $"malformed warning record ({FormatRecordBody(Record)})";


        private static String FormatRecordBody(NTSKE_Record Record)
        {

            if (Record.Body.Length == 0)
                return "<empty>";

            var text = Encoding.UTF8.GetString(Record.Body).TrimEnd('\0');

            return String.IsNullOrWhiteSpace(text)
                       ? BitConverter.ToString(Record.Body)
                       : text;

        }

        #endregion

        #region (private) FormatHostnamesAndPorts(Hostnames, Ports)

        private static String FormatHostnamesAndPorts(IEnumerable<DomainName>  Hostnames,
                                                      IEnumerable<IPPort>      Ports)
        {

            var results    = new List<String>();
            var hostnames  = Hostnames.Where(hostname => hostname.IsNotNullOrEmpty()).ToList();
            var ports      = Ports.                                                   ToList();

            if (ports.Count == 0)
                ports.Add(IPPort.NTP);

            if (hostnames.Count == 0)
                return $"NTPv4 Port(s): {ports.Select(port => port.ToString()).AggregateWith(", ")}";

            for (var i=0; i<hostnames.Count; i++)
            {

                var host = hostnames[i].ToString().TrimEnd('.');

                results.Add(
                    System.Net.IPAddress.TryParse(host, out var ipAddress) &&
                    ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                        ? $"[{host}]:{ports[Math.Min(i, ports.Count - 1)]}"
                        : $"{host}:{ports[Math.Min(i, ports.Count - 1)]}"
                );

            }

            return $"NTPv4 Server(s): {results.AggregateWith(", ")}";

        }

        #endregion

        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => ErrorMessage is not null

                   ? ErrorMessage

                   : String.Concat(

                         $"{NTSKERecords.Count()} NTS-KE records",

                          NTPv4Servers.Any() || NTPv4Ports.Any()
                              ? $", {FormatHostnamesAndPorts(NTPv4Servers, NTPv4Ports)}"
                              : "",

                         C2SKey.Length > 0
                             ? $", C2S-Key: {BitConverter.ToString(C2SKey)}"
                             : "",

                         S2CKey.Length > 0
                             ? $", S2C-Key: {BitConverter.ToString(S2CKey)}"
                             : ""

                     );

        #endregion

    }

}
