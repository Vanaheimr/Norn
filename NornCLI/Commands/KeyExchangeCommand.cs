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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.CLI.Commands
{

    /// <summary>
    /// <c>norn ke</c> — run the key exchange and stop, reporting what was agreed.
    /// </summary>
    /// <remarks>
    /// Separate from <c>query</c> because the two fail for unrelated reasons. Most of what goes
    /// wrong with NTS goes wrong here — a certificate that does not validate, a TLS version, an
    /// ALPN mismatch, an AEAD neither side has — and none of it is visible in "the query timed
    /// out". This command exists so that the first question an operator asks can be answered
    /// without the UDP leg confusing the answer.
    /// </remarks>
    public static class KeyExchangeCommand
    {

        public const String Usage = """
            Usage: norn ke <host> [options]

              Run the RFC 8915 key exchange and report what was negotiated.

            Options:
              --ke-port <n>       NTS-KE port (default: 4460)
              --timeout <s>       How long to wait (default: 10)
              --ipv4, --ipv6      Force an address family (default: prefer IPv6)
              --insecure          Do not validate the server's TLS certificate.
              --public-keys       Also ask for the public keys used for signed responses.
              --json              Emit one JSON object instead of text.

            Exit codes:
              0  the key exchange completed
              1  it did not
              2  the command line could not be understood
            """;


        public static IEnumerable<String> ValuedOptions
            => [ "--ke-port", "--timeout" ];


        public static async Task<Int32> Run(CommandLine        Arguments,
                                            Output             Output,
                                            CancellationToken  CancellationToken)
        {

            var insecure    = Arguments.Flag("--insecure");
            var publicKeys  = Arguments.Flag("--public-keys");
            var ipv4        = Arguments.Flag("--ipv4");
            var ipv6        = Arguments.Flag("--ipv6");
            var kePort      = Arguments.PortValue("--ke-port");
            var timeout     = Arguments.SecondsValue("--timeout") ?? TimeSpan.FromSeconds(10);

            Arguments.ThrowOnUnknownOptions();

            if (Arguments.Positionals.Count != 1)
                throw new UsageException("Expected exactly one host name.");

            if (ipv4 && ipv6)
                throw new UsageException("--ipv4 and --ipv6 contradict each other.");

            if (!DomainName.TryParse(Arguments.Positionals[0], out var hostname, out var hostnameError))
                throw new UsageException($"'{Arguments.Positionals[0]}' is not a host name: {hostnameError}");

            if (insecure)
                Output.Note("norn: --insecure: the certificate is not being checked, so this says " +
                            "nothing about who answered.");


            var client   = new NTSClient(
                               hostname,
                               NTSKE_Port:                  kePort is not null ? IPPort.Parse(kePort.Value) : null,
                               IPVersionPreference:         ipv4 ? IPVersionPreference.IPv4Only
                                                                : ipv6 ? IPVersionPreference.IPv6Only
                                                                       : null,
                               Timeout:                     timeout,
                               RemoteCertificateValidator:  insecure
                                                                ? (sender, certificate, chain, tlsClient, policyErrors)
                                                                      => TLSValidationResult.Success()
                                                                : null
                           );

            var result   = await client.GetNTSKERecords(
                                     RequestNTSPublicKeys:  publicKeys,
                                     CancellationToken:     CancellationToken
                                 );

            var json     = new JObject(
                               new JProperty("host",     hostname.Trimmed),
                               new JProperty("success",  result.Success)
                           );

            Output.Line($"NTS-KE with {hostname.Trimmed}");
            Output.Line();

            #region What the connection was

            var tls = result.TLSInfo;

            if (tls is not null)
            {

                Output.Field("TLS version",   tls.NegotiatedTLSVersion);
                Output.Field("Cipher suite",  tls.NegotiatedCipherSuite);
                Output.Field("ALPN",          tls.NegotiatedApplicationProtocol);

                var certificate = tls.ServerCertificate;

                if (certificate is not null)
                {

                    Output.Field("Subject",     certificate.Subject);
                    Output.Field("Issuer",      certificate.Issuer);
                    Output.Field("Valid until", certificate.NotAfter.ToUniversalTime().ToString("u"));
                    Output.Field("SAN",         String.Join(", ", certificate.GetDNSNamePatterns().
                                                                      Select(pattern => pattern.FullName).
                                                                      Concat(certificate.GetIIPAddresses().
                                                                                 Select(address => address.ToString()))));

                    if (tls.CertificatePolicyErrors is not null &&
                        tls.CertificatePolicyErrors.Value != System.Net.Security.SslPolicyErrors.None)
                    {
                        Output.Field("Policy errors", tls.CertificatePolicyErrors.Value.ToString());
                    }

                }

                json.Add(new JProperty("tls", new JObject(
                    new JProperty("version",      tls.NegotiatedTLSVersion),
                    new JProperty("cipherSuite",  tls.NegotiatedCipherSuite),
                    new JProperty("alpn",         tls.NegotiatedApplicationProtocol),
                    new JProperty("subject",      certificate?.Subject),
                    new JProperty("issuer",       certificate?.Issuer),
                    new JProperty("notAfter",     certificate?.NotAfter.ToUniversalTime()),
                    new JProperty("policyErrors", tls.CertificatePolicyErrors?.ToString())
                )));

            }

            #endregion

            #region What it cost

            var timing = result.TimingInfo;

            if (timing is not null)
            {

                Output.Field("Resolved",      String.Join(", ", timing.ResolvedIPAddresses.Select(address => address.ToString())));
                Output.Field("Connected to",  timing.ConnectedIPAddress?.ToString());
                Output.Field("DNS",           Output.Duration(timing.DNSLookupDuration));
                Output.Field("TCP connect",   Output.Duration(timing.TCPConnectDuration));
                Output.Field("TLS handshake", Output.Duration(timing.TLSHandshakeDuration));
                Output.Field("NTS-KE",        Output.Duration(timing.NTSKEProtocolDuration));
                Output.Field("Total",         Output.Duration(timing.TotalDuration));

                json.Add(new JProperty("timing", new JObject(
                    new JProperty("dnsMilliseconds",           timing.DNSLookupDuration?.TotalMilliseconds),
                    new JProperty("tcpConnectMilliseconds",    timing.TCPConnectDuration?.TotalMilliseconds),
                    new JProperty("tlsHandshakeMilliseconds",  timing.TLSHandshakeDuration?.TotalMilliseconds),
                    new JProperty("ntsKEMilliseconds",         timing.NTSKEProtocolDuration?.TotalMilliseconds),
                    new JProperty("totalMilliseconds",         timing.TotalDuration?.TotalMilliseconds),
                    new JProperty("connectedTo",               timing.ConnectedIPAddress?.ToString())
                )));

            }

            #endregion

            if (!result.Success || result.Response is null)
            {

                Output.Error($"the key exchange failed: {result.ErrorMessage}");

                json.Add(new JProperty("error",    result.ErrorMessage));
                json.Add(new JProperty("category", result.ErrorCategory.ToString()));

                Output.Json(json);

                return 1;

            }

            #region What was agreed

            var response = result.Response;

            Output.Line();
            Output.Field("Cookies",        response.Cookies.Count().ToString());
            Output.Field("Cookie size",    response.Cookies.Any()
                                               ? $"{response.Cookies.First().Length} octets"
                                               : null);

            // The two negotiation records of § 4.1.7 and § 4.1.8 are the whole reason a key
            // exchange host and a time host need not be the same machine, and the commonest
            // thing to be surprised by: a query that goes somewhere other than the name typed.
            if (response.NTPv4ServerNames.Any())
                Output.Field("NTP server", String.Join(", ", response.NTPv4ServerNames));

            if (response.NTPv4Ports.Any())
                Output.Field("NTP port",   String.Join(", ", response.NTPv4Ports.Select(port => port.ToString())));

            foreach (var warning in response.WarningMessages)
                Output.Note($"norn: the server sent a warning: {warning}");

            if (publicKeys)
                Output.Field("Public keys", response.PublicKeys.Count().ToString());

            Output.Line();
            Output.Line("  Records");

            foreach (var record in response.NTSKERecords)
                Output.Line($"    {(record.IsCritical ? "critical " : "         ")}{record.Type,-30} {record.Length,4} octets");

            json.Add(new JProperty("cookies",          response.Cookies.Count()));
            json.Add(new JProperty("cookieOctets",     response.Cookies.FirstOrDefault()?.Length));
            json.Add(new JProperty("ntpv4Servers",     new JArray(response.NTPv4ServerNames)));
            json.Add(new JProperty("ntpv4Ports",       new JArray(response.NTPv4Ports.Select(port => (Int32) port.ToUInt16()))));
            json.Add(new JProperty("warnings",         new JArray(response.WarningMessages)));
            json.Add(new JProperty("publicKeys",       response.PublicKeys.Count()));
            json.Add(new JProperty("records",          new JArray(
                                                           response.NTSKERecords.Select(record => new JObject(
                                                               new JProperty("type",     record.Type.ToString()),
                                                               new JProperty("critical", record.IsCritical),
                                                               new JProperty("octets",   record.Length)
                                                           )))));

            #endregion

            Output.Json(json);

            return 0;

        }

    }

}
