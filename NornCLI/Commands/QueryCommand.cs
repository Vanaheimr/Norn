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
using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.CLI.Commands
{

    /// <summary>
    /// <c>norn query</c> — ask a server what time it is, and say how much to believe the answer.
    /// </summary>
    public static class QueryCommand
    {

        public const String Usage = """
            Usage: norn query <host> [options]

              Measure the clock offset against an NTS or plain NTP server.

            Options:
              --port <n>          NTP port (default: 123)
              --ke-port <n>       NTS-KE port (default: 4460)
              --plain             Plain NTPv4, without NTS. No key exchange, no authentication.
              --count <n>         How many queries to send (default: 1)
              --interval <s>      Seconds between queries (default: 1)
              --timeout <s>       How long to wait for each leg (default: 5)
              --interleaved       Use the RFC 9769 interleaved mode. Needs --count 2 or more:
                                  the first exchange of an association is always basic.
              --ipv4, --ipv6      Force an address family (default: prefer IPv6)
              --insecure          Do not validate the server's TLS certificate.
              --json              Emit one JSON object instead of text.

            Exit codes:
              0  a usable measurement came back
              1  the query failed, or the server refused it
              2  the command line could not be understood
            """;


        public static IEnumerable<String> ValuedOptions
            => [ "--port", "--ke-port", "--count", "--interval", "--timeout" ];


        public static async Task<Int32> Run(CommandLine        Arguments,
                                            Output             Output,
                                            CancellationToken  CancellationToken)
        {

            #region Read the command line

            var plain        = Arguments.Flag("--plain");
            var interleaved  = Arguments.Flag("--interleaved");
            var insecure     = Arguments.Flag("--insecure");
            var ipv4         = Arguments.Flag("--ipv4");
            var ipv6         = Arguments.Flag("--ipv6");
            var ntpPort      = Arguments.PortValue("--port");
            var kePort       = Arguments.PortValue("--ke-port");
            var count        = Arguments.CountValue("--count", 1);
            var interval     = Arguments.SecondsValue("--interval") ?? TimeSpan.FromSeconds(1);
            var timeout      = Arguments.SecondsValue("--timeout")  ?? TimeSpan.FromSeconds(5);

            Arguments.ThrowOnUnknownOptions();

            if (Arguments.Positionals.Count != 1)
                throw new UsageException("Expected exactly one host name.");

            if (ipv4 && ipv6)
                throw new UsageException("--ipv4 and --ipv6 contradict each other.");

            if (!DomainName.TryParse(Arguments.Positionals[0], out var hostname, out var hostnameError))
                throw new UsageException($"'{Arguments.Positionals[0]}' is not a host name: {hostnameError}");

            if (interleaved && count < 2)
                Output.Note("norn: --interleaved with a single query can only measure in the basic " +
                            "mode; RFC 9769 section 2 makes the first request of an association basic. " +
                            "Pass --count 2 or more.");

            if (insecure && !plain)
                Output.Note("norn: --insecure: the server's certificate is not being checked, so " +
                            "nothing here shows you are talking to the server you named.");

            #endregion

            var client = new NTSClient(
                             hostname,
                             NTSKE_Port:                  kePort  is not null ? IPPort.Parse(kePort.Value)  : null,
                             NTP_Port:                    ntpPort is not null ? IPPort.Parse(ntpPort.Value) : null,
                             IPVersionPreference:         ipv4 ? IPVersionPreference.IPv4Only
                                                              : ipv6 ? IPVersionPreference.IPv6Only
                                                                     : null,
                             Timeout:                     timeout,
                             RemoteCertificateValidator:  insecure
                                                              ? (sender, certificate, chain, tlsClient, policyErrors)
                                                                    => TLSValidationResult.Success()
                                                              : null,
                             InterleavedMode:             interleaved
                         );

            #region The key exchange, unless this is plain NTP

            NTSKE_Response? keyExchange = null;

            if (!plain)
            {

                var keResult = await client.GetNTSKERecords(CancellationToken: CancellationToken);

                if (!keResult.Success || keResult.Response is null)
                {

                    Output.Error($"the key exchange with {hostname.Trimmed} failed: {keResult.ErrorMessage}");
                    Output.Json(new JObject(
                        new JProperty("host",     hostname.Trimmed),
                        new JProperty("success",  false),
                        new JProperty("stage",    "nts-ke"),
                        new JProperty("error",    keResult.ErrorMessage),
                        new JProperty("category", keResult.ErrorCategory.ToString())
                    ));

                    return 1;

                }

                keyExchange = keResult.Response;

                foreach (var warning in keyExchange.WarningMessages)
                    Output.Note($"norn: the server sent a warning: {warning}");

            }

            #endregion

            #region The queries

            var measurements = new List<JObject>();
            var succeeded    = 0;

            Output.Line($"{(plain ? "NTP" : "NTS")} query to {hostname.Trimmed}");
            Output.Line();

            for (var i = 0; i < count; i++)
            {

                if (i > 0)
                    await Task.Delay(interval, CancellationToken).ConfigureAwait(false);

                var result = await client.QueryTime(
                                       NTSKEResponse:      keyExchange,
                                       CancellationToken:  CancellationToken
                                   );

                measurements.Add(Describe(result, Output, count > 1 ? i + 1 : null));

                if (result.Success)
                    succeeded++;

            }

            #endregion

            #region Report

            if (count > 1)
            {

                var offsets = measurements.
                                  Where (measurement => measurement["offsetMilliseconds"]?.Type == JTokenType.Float ||
                                                        measurement["offsetMilliseconds"]?.Type == JTokenType.Integer).
                                  Select(measurement => measurement["offsetMilliseconds"]!.Value<Double>()).
                                  ToArray();

                Output.Line();
                Output.Field("Answered",  $"{succeeded} of {count}");

                if (offsets.Length > 1)
                {
                    Output.Field("Offset, median", $"{Median(offsets):+0.000000;-0.000000;0.000000} ms");
                    Output.Field("Offset, spread", $"{offsets.Max() - offsets.Min():0.000000} ms");
                }

            }

            Output.Json(new JObject(
                new JProperty("host",          hostname.Trimmed),
                new JProperty("nts",           !plain),
                new JProperty("success",       succeeded > 0),
                new JProperty("answered",      succeeded),
                new JProperty("sent",          count),
                new JProperty("measurements",  new JArray(measurements))
            ));

            // On stderr as well as in the report above, because a run that learned nothing has
            // to say so where a caller is listening. Everything printed so far went to stdout,
            // which a script redirects away — and a command that exits non-zero in silence
            // leaves whoever reads the log guessing.
            if (succeeded == 0)
                Output.Error(count > 1
                                 ? $"none of the {count} queries to {hostname.Trimmed} was answered."
                                 : $"the query to {hostname.Trimmed} failed: {measurements[0]["error"]?.Value<String>()}");

            #endregion

            // Any answer at all is a success: a client that asks four times and is heard once
            // has still learned the time, and a script polling a flaky link should not be told
            // its server is down because one datagram went missing.
            return succeeded > 0 ? 0 : 1;

        }


        #region (private) Describe(Result, Output, Index)

        /// <summary>
        /// Print one measurement, and return the same thing as JSON.
        /// </summary>
        private static JObject Describe(NTSQueryResult  Result,
                                        Output          Output,
                                        Int32?          Index)
        {

            var json = new JObject();

            if (Index is not null)
            {
                Output.Line($"  #{Index}");
                json.Add(new JProperty("index", Index.Value));
            }

            json.Add(new JProperty("success", Result.Success));

            if (Result.RemoteEndPoint is not null)
            {
                Output.Field("Server",     Result.RemoteEndPoint.ToString());
                json.Add(new JProperty("server", Result.RemoteEndPoint.ToString()));
            }

            // A Kiss-o'-Death first, and on its own. It is the one answer that is not a
            // measurement but an instruction, and burying it under a row of empty fields is how
            // an operator misses that they are being rate-limited.
            if (Result.KissOfDeath is not null)
            {

                var kiss = Result.KissOfDeath.Value;

                Output.Field("Kiss-o'-Death", $"{kiss.Code} -- {Explain(kiss)}");

                json.Add(new JProperty("kissOfDeath", new JObject(
                    new JProperty("code",         kiss.Code),
                    new JProperty("pollExponent", kiss.PollExponent),
                    new JProperty("action",       kiss.Action.ToString())
                )));

            }

            if (!Result.Success)
            {

                // Not when a kiss was already reported. A Kiss-o'-Death fails every NTS check
                // there is — no authenticator, no cookie, an unauthenticated identifier — and
                // printing all of them buries the one line that says what happened under four
                // that follow from it inevitably.
                if (Result.KissOfDeath is null)
                    Output.Field("Failed", Result.ErrorMessage);

                json.Add(new JProperty("error",    Result.ErrorMessage));
                json.Add(new JProperty("category", Result.ErrorCategory.ToString()));

                Output.Line();

                return json;

            }

            var response  = Result.Response!;

            // An interleaved measurement is not the packet's own arithmetic: three of its four
            // timestamps belong to the previous exchange. Reporting the packet's numbers beside
            // it would be reporting the basic-mode answer the interleaved mode exists to improve
            // on.
            var offset    = Result.InterleavedMeasurement?.ClockOffset    ?? response.ClockOffset;
            var delay     = Result.InterleavedMeasurement?.RoundtripDelay ?? response.RoundTripDelay;

            Output.Field("Offset",        Output.Offset(offset));
            Output.Field("Delay",         Output.Duration(delay));
            Output.Field("Network RTT",   Output.Duration(Result.StopwatchRoundTripTime));
            Output.Field("Stratum",       response.Stratum.ToString());
            Output.Field("Reference",     response.ReferenceIdentifier.ToString(response.Stratum));
            Output.Field("Leap",          response.LI switch { 0 => "none",
                                                               1 => "last minute has 61 seconds",
                                                               2 => "last minute has 59 seconds",
                                                               _ => "unsynchronized" });
            Output.Field("Precision",     $"2^{response.Precision} s");
            Output.Field("Root delay",    Output.Duration(TimeSpan.FromSeconds(response.RootDelay      / 65536.0)));
            Output.Field("Root disp.",    Output.Duration(TimeSpan.FromSeconds(response.RootDispersion / 65536.0)));
            Output.Field("Mode",          Result.InterleavedMeasurement is not null ? "interleaved (RFC 9769)" : "basic");

            if (Result.UsedCookie is not null)
                Output.Field("Cookies left", Result.RemainingCookiesAfterQuery.ToString());

            Output.Line();

            json.Add(new JProperty("offsetMilliseconds",         offset?.TotalMilliseconds));
            json.Add(new JProperty("delayMilliseconds",          delay?.TotalMilliseconds));
            json.Add(new JProperty("networkRTTMilliseconds",     Result.StopwatchRoundTripTime?.TotalMilliseconds));
            json.Add(new JProperty("stratum",                    response.Stratum));
            json.Add(new JProperty("referenceIdentifier",        response.ReferenceIdentifier.ToString(response.Stratum)));
            json.Add(new JProperty("leapIndicator",              response.LI));
            json.Add(new JProperty("precision",                  response.Precision));
            json.Add(new JProperty("rootDelaySeconds",           response.RootDelay      / 65536.0));
            json.Add(new JProperty("rootDispersionSeconds",      response.RootDispersion / 65536.0));
            json.Add(new JProperty("interleaved",                Result.InterleavedMeasurement is not null));
            json.Add(new JProperty("remainingCookies",           Result.RemainingCookiesAfterQuery));

            return json;

        }

        #endregion

        #region (private) Explain(Kiss) / Median(Values)

        private static String Explain(NTPKissOfDeath Kiss)

            => Kiss.Action switch {
                   NTPKissAction.Demobilize         => "the server has refused this client access; it should not be queried again",
                   NTPKissAction.ReducePollingRate  => $"the server is rate-limiting this client and asks for a poll interval of 2^{Kiss.PollExponent} s",
                   NTPKissAction.RenegotiateNTS     => "the server could not use the NTS cookie; a new key exchange is needed",
                   _                                => "no protocol significance (RFC 5905 section 7.4 d)"
               };


        private static Double Median(Double[] Values)
        {

            var sorted = Values.Order().ToArray();

            return sorted.Length % 2 == 1
                       ? sorted[sorted.Length / 2]
                       : (sorted[sorted.Length / 2 - 1] + sorted[sorted.Length / 2]) / 2;

        }

        #endregion

    }

}
