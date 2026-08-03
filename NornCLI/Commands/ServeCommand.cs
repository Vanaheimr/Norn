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

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.CLI.Commands
{

    /// <summary>
    /// <c>norn serve</c> — run an NTS-protected NTP server until interrupted.
    /// </summary>
    public static class ServeCommand
    {

        public const String Usage = """
            Usage: norn serve [options]

              Run an NTS-KE and NTP server until interrupted.

            Options:
              --port <n>          NTP port to listen on (default: 123)
              --ke-port <n>       NTS-KE port to listen on (default: 4460)
              --listen <address>  Address to bind (default: 0.0.0.0; use :: for both families)
              --cert <file>       TLS certificate, PEM. Without one a fresh self-signed
                                  certificate is generated per connection, which no client
                                  can be told to trust in advance.
              --key <file>        The certificate's private key, PEM. Required with --cert.
              --advertise <host>  Host name to put in the NTPv4 Server Negotiation record,
                                  for clients that reach this server under another name.
              --master-keys <f>   Where to persist the cookie master keys (default: none, so
                                  every restart invalidates every cookie in the field).
              --rate-limit <s>    Average seconds between answers per client address. Without
                                  this the server answers everything it can.
              --burst <n>         Requests one address may fire back to back (default: 8).
              --no-interleaved    Refuse the RFC 9769 interleaved mode.
              --auth-interleaved  Offer the interleaved mode only to authenticated clients.
              --stratum <n>       Stratum to report (default: 1).
              --refid <text>      Reference identifier to report (default: LOCL).
              --quiet             Do not print per-request logging.

            Exit codes:
              0  the server ran and was shut down cleanly
              1  it could not start
              2  the command line could not be understood
            """;


        public static IEnumerable<String> ValuedOptions
            => [ "--port", "--ke-port", "--listen", "--cert", "--key", "--advertise",
                 "--master-keys", "--rate-limit", "--burst", "--stratum", "--refid" ];


        public static async Task<Int32> Run(CommandLine        Arguments,
                                            Output             Output,
                                            CancellationToken  CancellationToken)
        {

            #region Read the command line

            var quiet            = Arguments.Flag("--quiet");
            var noInterleaved    = Arguments.Flag("--no-interleaved");
            var authInterleaved  = Arguments.Flag("--auth-interleaved");
            var ntpPort          = Arguments.PortValue("--port");
            var kePort           = Arguments.PortValue("--ke-port");
            var listen           = Arguments.Value("--listen");
            var certificatePath  = Arguments.Value("--cert");
            var keyPath          = Arguments.Value("--key");
            var advertise        = Arguments.Value("--advertise");
            var masterKeys       = Arguments.Value("--master-keys");
            var rateLimit        = Arguments.SecondsValue("--rate-limit");
            var burst            = Arguments.CountValue("--burst", 8);
            var stratum          = Arguments.CountValue("--stratum", 1);
            var refid            = Arguments.Value("--refid", "LOCL")!;

            Arguments.ThrowOnUnknownOptions();

            if (Arguments.Positionals.Count != 0)
                throw new UsageException($"'serve' takes no positional arguments, but got '{Arguments.Positionals[0]}'.");

            if (noInterleaved && authInterleaved)
                throw new UsageException("--no-interleaved and --auth-interleaved contradict each other.");

            if (certificatePath is not null != (keyPath is not null))
                throw new UsageException("--cert and --key go together; neither works without the other.");

            if (stratum is < 1 or > 15)
                throw new UsageException($"--stratum must be between 1 and 15, but was {stratum}.");

            if (refid.Length is 0 or > 4)
                throw new UsageException($"--refid is at most four characters, but was '{refid}'.");

            IIPAddress? listenAddress = null;

            if (listen is not null &&
                !IPAddress.TryParse(listen, out listenAddress))
            {
                throw new UsageException($"--listen needs an IP address, but was '{listen}'.");
            }

            #endregion

            #region Load the certificate, if one was named

            X509Certificate?         certificate  = null;
            ECPrivateKeyParameters?  privateKey   = null;

            if (certificatePath is not null && keyPath is not null)
            {

                try
                {
                    certificate = ReadPem<X509Certificate>(certificatePath);
                    privateKey  = ReadPrivateKey(keyPath);
                }
                catch (Exception e)
                {
                    Output.Error($"the certificate could not be loaded: {e.Message}");
                    return 1;
                }

            }

            else
                Output.Note("norn: no --cert given, so a fresh self-signed certificate is made " +
                            "for every connection. Usable for a first look; no client can be " +
                            "told to trust it in advance.");

            #endregion

            var server = new NTSServer(

                             NTSKEPort:            kePort  is not null ? IPPort.Parse(kePort.Value)  : null,
                             NTSPort:              ntpPort is not null ? IPPort.Parse(ntpPort.Value) : null,
                             ListenIPAddress:      listenAddress,

                             // Null unless asked for. The default writes rotating cookie master
                             // keys into masterKeys.json in whatever directory the tool happened
                             // to be run from, which is a surprising place for a secret to
                             // appear.
                             MasterKeysFilePath:   masterKeys,

                             ExternalURLs:         advertise is not null
                                                       ? [ URL.Parse($"udp://{advertise}:{ntpPort ?? 123}") ]
                                                       : null,

                             TLSCertificate:       certificate,
                             TLSPrivateKey:        privateKey,

                             Stratum:              (Byte) stratum,
                             ReferenceIdentifier:  NTP.ReferenceIdentifier.From(refid),

                             InterleavedMode:      noInterleaved   ? InterleavedModePolicy.Disabled
                                                 : authInterleaved ? InterleavedModePolicy.AuthenticatedOnly
                                                                   : InterleavedModePolicy.Everyone,

                             RateLimiter:          rateLimit is not null
                                                       ? new NTPRateLimiter(
                                                             MinimumInterval:  rateLimit,
                                                             Burst:            burst
                                                         )
                                                       : null

                         );

            try
            {
                await server.Start(CancellationToken);
            }
            catch (Exception e)
            {
                Output.Error($"the server could not start: {e.Message}");
                return 1;
            }

            Output.Line($"NTS-KE  listening on {server.ListenIPAddress}:{server.TCPPort}/tcp");
            Output.Line($"NTP     listening on {server.ListenIPAddress}:{server.UDPPort}/udp");
            Output.Line($"Stratum {server.Stratum}, reference {server.ReferenceIdentifier.ToString(server.Stratum)}, " +
                        $"precision 2^{NTSServerPrecision(server)} s");
            Output.Line($"Interleaved mode: {server.InterleavedMode}");
            Output.Line($"Rate limiting: {(server.RateLimiter is not null
                                               ? $"one answer per {server.RateLimiter.MinimumInterval.TotalSeconds:0.###} s per address, burst {server.RateLimiter.Burst}"
                                               : "off")}");
            Output.Line();
            Output.Line("Ctrl-C to stop.");
            Output.Line();

            #region Run until interrupted

            var stopping = new TaskCompletionSource();

            using var registration = CancellationToken.Register(() => stopping.TrySetResult());

            // Handled rather than left to the runtime so that the sockets are closed and the
            // final counters printed. A time server killed mid-flight is not a disaster, but a
            // server that cannot say what it did is harder to operate than one that can.
            void OnCancel(Object? sender, ConsoleCancelEventArgs e)
            {
                e.Cancel = true;
                stopping.TrySetResult();
            }

            Console.CancelKeyPress += OnCancel;

            try
            {

                if (!quiet)
                {

                    var reporting = ReportMetrics(server, Output, stopping.Task);

                    await stopping.Task.ConfigureAwait(false);
                    await reporting.ConfigureAwait(false);

                }

                else
                    await stopping.Task.ConfigureAwait(false);

            }
            finally
            {
                Console.CancelKeyPress -= OnCancel;
            }

            #endregion

            Output.Line();
            Output.Line("Shutting down.");

            await server.ShutdownAsync();

            Output.Line($"  {server.Metrics}");

            return 0;

        }


        #region (private) ReportMetrics(Server, Output, Stopping)

        /// <summary>
        /// Print the counters whenever they change, so that a server left running says what it
        /// is doing without being asked.
        /// </summary>
        /// <remarks>
        /// On a change rather than on a timer: a quiet server should print nothing at all rather
        /// than a line a second saying so, and a busy one should not print a line per request
        /// either. What an operator wants to see is that the numbers are moving.
        /// </remarks>
        private static async Task ReportMetrics(NTSServer  Server,
                                                Output     Output,
                                                Task       Stopping)
        {

            var previous = Server.Metrics.ToString();

            while (!Stopping.IsCompleted)
            {

                await Task.WhenAny(Stopping, Task.Delay(TimeSpan.FromSeconds(1))).ConfigureAwait(false);

                var current = Server.Metrics.ToString();

                if (current != previous)
                {
                    Output.Line($"  {current}");
                    previous = current;
                }

            }

        }

        #endregion

        #region (private) ReadPem / ReadPrivateKey / NTSServerPrecision

        private static T ReadPem<T>(String Path) where T : class
        {

            using var reader = new StreamReader(Path);

            var content = new PemReader(reader).ReadObject()
                              ?? throw new InvalidDataException($"'{Path}' holds no PEM object.");

            return content as T
                       ?? throw new InvalidDataException($"'{Path}' holds a {content.GetType().Name}, not a {typeof(T).Name}.");

        }


        /// <summary>
        /// Read a PEM private key, whether it is wrapped in a key pair or stands alone.
        /// </summary>
        /// <remarks>
        /// Both shapes are in the wild and neither is wrong: "openssl ecparam -genkey" writes a
        /// key pair, while a key extracted from a PKCS#8 file arrives as the private key by
        /// itself. Accepting only one of them would fail on whichever the operator happens to
        /// have, with an error naming a BouncyCastle type rather than anything actionable.
        /// </remarks>
        private static ECPrivateKeyParameters ReadPrivateKey(String Path)
        {

            using var reader = new StreamReader(Path);

            var content = new PemReader(reader).ReadObject()
                              ?? throw new InvalidDataException($"'{Path}' holds no PEM object.");

            return content switch {
                       ECPrivateKeyParameters key                                             => key,
                       Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair { Private: ECPrivateKeyParameters key }  => key,
                       _ => throw new InvalidDataException(
                                $"'{Path}' holds a {content.GetType().Name}; an EC private key is needed. " +
                                 "Norn's NTS-KE endpoint signs with ECDSA.")
                   };

        }


        private static Int32 NTSServerPrecision(NTSServer Server)

            => (Int32) Math.Floor(Math.Log2(Server.ClockResolution.TotalSeconds));

        #endregion

    }

}
