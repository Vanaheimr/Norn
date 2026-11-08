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

using System.Net;
using System.Text;
using System.Net.Sockets;
using System.Diagnostics;
using System.Buffers.Binary;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTS.NTSKERecords;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// NTS-KE over SSH with OpenSSH as the client: <c>ssh -s ntske/1@open.charging.cloud</c>
    /// carries the records, as section 8.5 of the white paper suggests for tests, and the keys
    /// derived from its answer must work for NTP.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every OpenSSH client found on this machine is tried, e.g. the one of Windows and the one
    /// of Git for Windows, which are different versions with different default algorithms. The
    /// test is ignored when there is none.
    /// </para>
    /// <para>
    /// OpenSSH runs without any configuration of its own: no config file, no agent, no keys but
    /// a fresh one from <c>ssh-keygen</c>, and a known_hosts file that pins the host key of the
    /// server, so that nothing on the machine changes the outcome.
    /// </para>
    /// </remarks>
    [TestFixture]
    [Category("LocalIntegration")]
    public class NTSKE_OpenSSH_Tests
    {

        #region OpenSSH clients

        private static IEnumerable<TestCaseData> OpenSSHClients()
        {

            var candidates = new List<String>();

            if (OperatingSystem.IsWindows())
                candidates.Add(Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh.exe"));

            foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
                candidates.Add(Path.Combine(directory.Trim('"'), OperatingSystem.IsWindows() ? "ssh.exe" : "ssh"));

            var clients = candidates.Where (File.Exists).
                                     Where (path => File.Exists(KeygenNextTo(path))).
                                     Select(Path.GetFullPath).
                                     Distinct(StringComparer.OrdinalIgnoreCase).
                                     ToArray();

            if (clients.Length == 0)
            {
                yield return new TestCaseData("").SetArgDisplayNames("none").
                                 Ignore("No OpenSSH client with ssh-keygen next to it was found.");
                yield break;
            }

            foreach (var client in clients)
                yield return new TestCaseData(client).SetArgDisplayNames(client);

        }

        private static String KeygenNextTo(String SSHPath)

            => Path.Combine(Path.GetDirectoryName(SSHPath)!,
                            OperatingSystem.IsWindows() ? "ssh-keygen.exe" : "ssh-keygen");

        #endregion


        #region KeyExchangeThroughOpenSSH_ThenNTP(SSHPath)

        [TestCaseSource(nameof(OpenSSHClients))]
        public async Task KeyExchangeThroughOpenSSH_ThenNTP(String SSHPath)
        {

            await using var setup  = await Setup.CreateAsync(SSHPath);
            var ntsClient          = setup.NewNTSClient();

            var (exitCode, responseBytes, stdErr) = await setup.RunSubsystemAsync(
                                                              NTSKE_SSH.SubsystemName,
                                                              ntsClient.BuildNTSKERequest(OverSSH: true)
                                                          );

            Assert.That(exitCode,             Is.EqualTo(0),    stdErr);
            Assert.That(responseBytes.Length, Is.GreaterThan(0), stdErr);

            // What the Norn client does after reading the answer from its own SSH channel, done
            // here by hand on the bytes OpenSSH handed over.
            Assert.That(NTSKE_Record.TryParse(responseBytes, out var records, out var parseError), Is.True, parseError);
            Assert.That(NTSKERecordValidator.ValidateServerResponse(records!, out var validationError, out _, OverSSH: true), Is.True, validationError);

            var aead        = new NTSKE_Response(records!, [], []).AEADAlgorithm;
            var keyBinding  = records!.OfType<SSHKeyBinding>().Single();

            Assert.That(keyBinding.TryGetSelection(out var method, out var ntsKESecret, out var selectionError), Is.True, selectionError);
            Assert.That(method, Is.EqualTo(SSHKeyBindingMethods.Transport));

            var (c2sKey, s2cKey) = NTSKE_ExportedKeys.ExportAll(NTSKE_ExportedKeys.TransportedSecretExporter(ntsKESecret!)).
                                                      For(aead, CompliantExporterContext: true);

            // A query the server can decrypt and the client can verify proves that both sides
            // arrived at the same keys, with OpenSSH in between.
            var ntsQueryResult = await ntsClient.QueryTime(NTSKEResponse: new NTSKE_Response(records!, c2sKey, s2cKey),
                                                           Timeout:       TimeSpan.FromSeconds(10));

            Assert.That(ntsQueryResult.Success, Is.True, ntsQueryResult.ErrorMessage);

        }

        #endregion

        #region ARequestWithoutKeyBindingThroughOpenSSH_ExitsWithOne(SSHPath)

        [TestCaseSource(nameof(OpenSSHClients))]
        public async Task ARequestWithoutKeyBindingThroughOpenSSH_ExitsWithOne(String SSHPath)
        {

            await using var setup  = await Setup.CreateAsync(SSHPath);

            NTSKE_Record[] request = [
                NTSKE_Record.NTSNextProtocolNegotiation,
                NTSKE_Record.AEADAlgorithmNegotiation([ AEADAlgorithms.AES_SIV_CMAC_256 ]),
                NTSKE_Record.EndOfMessage
            ];

            var (exitCode, responseBytes, stdErr) = await setup.RunSubsystemAsync(
                                                              NTSKE_SSH.SubsystemName,
                                                              request.ToByteArray()
                                                          );

            // The answer is an Error record, and the exit status says so to a script that only
            // looks at that.
            Assert.That(exitCode, Is.EqualTo(1), stdErr);
            Assert.That(NTSKE_Record.TryParse(responseBytes, out var records, out var parseError), Is.True, parseError);

            var error = records!.Single(record => record.Type == NTSKE_RecordTypes.Error);

            Assert.That((NTSKEErrorCodes) ((error.Body[0] << 8) | error.Body[1]), Is.EqualTo(NTSKEErrorCodes.BadRequest));

        }

        #endregion

        #region AnotherSubsystemThroughOpenSSH_IsRefused(SSHPath)

        [TestCaseSource(nameof(OpenSSHClients))]
        public async Task AnotherSubsystemThroughOpenSSH_IsRefused(String SSHPath)
        {

            await using var setup  = await Setup.CreateAsync(SSHPath);

            var (exitCode, responseBytes, stdErr) = await setup.RunSubsystemAsync(
                                                              "ntske/2@open.charging.cloud",
                                                              setup.NewNTSClient().BuildNTSKERequest(OverSSH: true)
                                                          );

            Assert.That(exitCode,      Is.Not.EqualTo(0));
            Assert.That(responseBytes, Is.Empty);
            Assert.That(stdErr,        Does.Contain("subsystem request failed"));

        }

        #endregion


        #region (private class) Setup

        /// <summary>
        /// A fresh client key from ssh-keygen, an NTS server that admits exactly that key, and a
        /// known_hosts file that pins the host key of the server.
        /// </summary>
        private sealed class Setup : IAsyncDisposable
        {

            private readonly String         sshPath;
            private readonly DirectoryInfo  directory;
            private readonly NTSServer      server;
            private readonly IPPort         sshPort;
            private readonly IPPort         ntpPort;

            private String KeyFile         => Slashed(Path.Combine(directory.FullName, "id_ed25519"));
            private String KnownHostsFile  => Slashed(Path.Combine(directory.FullName, "known_hosts"));

            private Setup(String SSHPath, DirectoryInfo Directory, NTSServer Server, IPPort SSHPort, IPPort NTPPort)
            {
                this.sshPath    = SSHPath;
                this.directory  = Directory;
                this.server     = Server;
                this.sshPort    = SSHPort;
                this.ntpPort    = NTPPort;
            }

            public static async Task<Setup> CreateAsync(String SSHPath)
            {

                var directory = Directory.CreateTempSubdirectory("norn-ntske-openssh-");
                var keyFile   = Path.Combine(directory.FullName, "id_ed25519");

                var (exitCode, _, stdErr) = await RunAsync(KeygenNextTo(SSHPath),
                                                           [ "-q", "-t", "ed25519", "-N", "", "-C", "norn-test", "-f", Slashed(keyFile) ],
                                                           []);

                Assert.That(exitCode, Is.EqualTo(0), stdErr);

                var clientKeyBlob = Convert.FromBase64String(File.ReadAllText(keyFile + ".pub").Split(' ')[1]);

                var sshPort = FindFreeTCPPort();
                var ntpPort = FindFreeUDPPort();

                var server  = new NTSServer(
                                  NTSKEPort:           FindFreeTCPPort(),
                                  NTSPort:             ntpPort,
                                  MasterKeysFilePath:  null,
                                  SSHPort:             sshPort,
                                  SSHAuthenticator:    SshUserAuthenticator.ForAuthorizedKeys(clientKeyBlob)
                              );

                await server.Start();

                // The host key, pinned under the name OpenSSH looks it up by for a port other
                // than 22.
                var hostKey = server.SSHHostKeys[0].PublicKeyBlob;

                File.WriteAllText(Path.Combine(directory.FullName, "known_hosts"),
                                  $"[127.0.0.1]:{sshPort} {KeyTypeOf(hostKey)} {Convert.ToBase64String(hostKey)}\n");

                return new Setup(SSHPath, directory, server, sshPort, ntpPort);

            }

            public NTSClient NewNTSClient()

                => new (
                       Hermod.DNS.DomainName.Localhost,
                       NTP_Port:             ntpPort,
                       IPVersionPreference:  IPVersionPreference.IPv4Only
                   );

            /// <summary>
            /// ssh -s: open the subsystem, write the request to its standard input, close it, and
            /// collect everything that comes back until OpenSSH exits.
            /// </summary>
            public Task<(Int32 ExitCode, Byte[] StdOut, String StdErr)> RunSubsystemAsync(String  Subsystem,
                                                                                         Byte[]  Request)

                => RunAsync(sshPath,
                            [
                                "-F", "none",
                                "-T", "-s",
                                "-p", sshPort.ToString(),
                                "-l", "ntske",
                                "-i", KeyFile,
                                "-o", "IdentitiesOnly=yes",
                                "-o", "IdentityAgent=none",
                                "-o", "BatchMode=yes",
                                "-o", "StrictHostKeyChecking=yes",
                                "-o", $"UserKnownHostsFile={KnownHostsFile}",
                                "-o", $"GlobalKnownHostsFile={KnownHostsFile}",
                                "-o", "ConnectTimeout=10",
                                "-o", "LogLevel=ERROR",
                                "127.0.0.1",
                                Subsystem
                            ],
                            Request);

            public async ValueTask DisposeAsync()
            {

                await server.ShutdownAsync();

                try
                {
                    directory.Delete(recursive: true);
                }
                catch
                { }

            }

            private static String Slashed(String Path)
                => Path.Replace('\\', '/');

            private static String KeyTypeOf(Byte[] PublicKeyBlob)
            {
                var length = (Int32) BinaryPrimitives.ReadUInt32BigEndian(PublicKeyBlob);
                return Encoding.ASCII.GetString(PublicKeyBlob, 4, length);
            }

        }

        #endregion

        #region (private static) RunAsync(Program, Arguments, StdIn)

        private static async Task<(Int32 ExitCode, Byte[] StdOut, String StdErr)> RunAsync(String    Program,
                                                                                         String[]  Arguments,
                                                                                         Byte[]    StdIn)
        {

            var startInfo = new ProcessStartInfo(Program) {
                                RedirectStandardInput   = true,
                                RedirectStandardOutput  = true,
                                RedirectStandardError   = true,
                                UseShellExecute         = false,
                                CreateNoWindow          = true
                            };

            foreach (var argument in Arguments)
                startInfo.ArgumentList.Add(argument);

            using var process  = Process.Start(startInfo)!;
            using var timeout  = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            var stdOut         = new MemoryStream();
            var stdOutTask     = process.StandardOutput.BaseStream.CopyToAsync(stdOut, timeout.Token);
            var stdErrTask     = process.StandardError.ReadToEndAsync(timeout.Token);

            // The request, then end of file: OpenSSH passes it on as the EOF of the channel.
            await process.StandardInput.BaseStream.WriteAsync(StdIn, timeout.Token);
            await process.StandardInput.BaseStream.FlushAsync(timeout.Token);
            process.StandardInput.Close();

            try
            {
                await process.WaitForExitAsync(timeout.Token);
                await stdOutTask;
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                Assert.Fail($"{Path.GetFileName(Program)} did not finish within 30 seconds.");
            }

            return (process.ExitCode, stdOut.ToArray(), await stdErrTask);

        }

        #endregion

        #region (private static) FindFreeTCPPort() / FindFreeUDPPort()

        private static IPPort FindFreeTCPPort()
        {

            var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();

            var port = ((IPEndPoint) listener.LocalEndpoint).Port;
            listener.Stop();

            return IPPort.Parse(port);

        }

        private static IPPort FindFreeUDPPort()
        {

            using var udpClient = new UdpClient(new IPEndPoint(System.Net.IPAddress.Loopback, 0));

            return IPPort.Parse(((IPEndPoint) udpClient.Client.LocalEndPoint!).Port);

        }

        #endregion

    }

}
