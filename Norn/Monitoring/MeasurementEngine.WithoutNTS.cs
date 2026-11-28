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

using System.Diagnostics;
using System.Collections.Concurrent;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.NTPv5;
using org.GraphDefined.Vanaheimr.Norn.NTPOverTLS;

using IPAddress = org.GraphDefined.Vanaheimr.Hermod.IPAddress;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// The servers that are measured without NTS: NTP over TLS, NTP over SSH,
    /// and NTP without any authentication - see <see cref="NTSServerEndpoint.Protection"/>.
    /// </summary>
    public partial class MeasurementEngine
    {

        #region (private sealed class) WithoutNTSState

        /// <summary>
        /// What is kept of a server measured without NTS from one round to the next:
        /// the client its queries go through, the negotiation of NTPv5 where it is
        /// offered, and over SSH the channel and, where it is the engine's own, the
        /// connection the channel runs on.
        /// </summary>
        private sealed class WithoutNTSState(String     Settings,
                                             NTSClient  Client) : IAsyncDisposable
        {

            public String                    Settings     { get; }      = Settings;
            public NTSClient                 Client       { get; }      = Client;
            public NTPv5VersionNegotiation   Negotiation  { get; }      = new();
            public SemaphoreSlim             Turn         { get; }      = new(1, 1);
            public SSHClient?                SSH          { get; set; }
            public Boolean                   SSHIsShared  { get; set; }
            public NTPOverSSHChannel?        Channel      { get; set; }

            /// <summary>
            /// Whether it was let go of: a measurement that waited for its turn
            /// on it takes the state made since instead.
            /// </summary>
            public Boolean                   Disposed     { get; private set; }

            /// <summary>
            /// Close the channel, and the connection where it is the engine's own -
            /// a shared one goes on without the channel.
            /// </summary>
            public async ValueTask CloseChannel()
            {

                var channel  = Channel;
                var ssh      = SSH;

                Channel      = null;
                SSH          = null;

                if (channel is not null)
                    try { await channel.DisposeAsync().ConfigureAwait(false); } catch { }

                if (ssh is not null && !SSHIsShared)
                    try { await ssh.DisposeAsync().ConfigureAwait(false); } catch { }

            }

            /// <remarks>
            /// After the measurement that has its turn, never under it: the turn is
            /// waited for, and given back - not disposed, as a measurement may still
            /// be waiting for it, and would wait for ever.
            /// </remarks>
            public async ValueTask DisposeAsync()
            {

                await Turn.WaitAsync().ConfigureAwait(false);

                try
                {

                    if (Disposed)
                        return;

                    Disposed = true;

                    await CloseChannel().ConfigureAwait(false);
                    Client.Dispose();

                }
                finally
                {
                    Turn.Release();
                }

            }

        }

        #endregion

        #region Data

        /// <summary>
        /// What is kept of each server measured without NTS, by its host name.
        /// </summary>
        private readonly ConcurrentDictionary<DomainName, WithoutNTSState> withoutNTS = [];

        #endregion


        #region (private static) SettingsOf(Server)

        /// <summary>
        /// What the state kept of a server was made for: another protection, port or
        /// version makes a new one.
        /// </summary>
        private static String SettingsOf(NTSServerEndpoint Server)

            => $"{Server.Protection}|{Server.NTPPort}|{String.Join(",", Server.EffectiveNTPVersions)}";

        #endregion

        #region (private) ForgetWithoutNTS(Hostname)

        /// <summary>
        /// Let go of what is kept of a server measured without NTS: its channel and
        /// connection over SSH are closed, and its negotiation of NTPv5 starts anew.
        /// </summary>
        private Boolean ForgetWithoutNTS(DomainName Hostname)
        {

            if (!withoutNTS.TryRemove(Hostname, out var state))
                return false;

            _ = state.DisposeAsync().AsTask();
            return true;

        }

        #endregion

        #region (private) DisposeWithoutNTS()

        private async ValueTask DisposeWithoutNTS()
        {
            foreach (var hostname in withoutNTS.Keys.ToArray())
                if (withoutNTS.TryRemove(hostname, out var state))
                    await state.DisposeAsync().ConfigureAwait(false);
        }

        #endregion


        #region (private) MeasureWithoutNTS(Server, RoundId, DNS, DNSClient, Preflight, TotalStopwatch, CancellationToken)

        /// <summary>
        /// Measure a server whose time is protected by its TLS connection or SSH channel,
        /// or not at all: no key exchange, no cookie, and nothing of NTS.
        /// </summary>
        /// <remarks>
        /// A server is asked the way it is configured for, and no other: one whose TLS
        /// connection or SSH channel cannot be had did not answer, and is never asked
        /// over UDP instead (section 10.7 of "NTS Key Establishment over SSH").
        /// </remarks>
        private async Task<NTSMeasurementResult> MeasureWithoutNTS(NTSServerEndpoint    Server,
                                                                   Guid                 RoundId,
                                                                   DNSResolutionResult  DNS,
                                                                   DNSClient            DNSClient,
                                                                   Boolean              Preflight,
                                                                   Stopwatch            TotalStopwatch,
                                                                   CancellationToken    CancellationToken)
        {

            NTSMeasurementResult Result(NTPMeasurementResult? NTP, Boolean PreflightSent = false, Error? ErrorMessage = null, MonitoringErrorCategory? ErrorCategory = null)
            {

                TotalStopwatch.Stop();

                return new NTSMeasurementResult(Server.Hostname, RoundId, Timestamp: timeProvider.GetUtcNow()) {
                           DNS             = DNS,
                           NTSKEFromCache  = false,
                           NTP             = NTP,
                           PreflightSent   = PreflightSent,
                           Success         = NTP?.Success == true,
                           ErrorMessage    = ErrorMessage  ?? NTP?.ErrorMessage,
                           ErrorCategory   = ErrorCategory ?? NTP?.ErrorCategory ?? MonitoringErrorCategory.Unknown,
                           TotalDuration   = TotalStopwatch.Elapsed
                       };

            }

            // Over SSH the connection reaches the server, by whatever name or peer it is
            // handed out for; over TLS and UDP the name is where the time comes from.
            if (Server.Protection != NTPProtection.NTPOverSSH && !DNS.Success)
                return Result(null,
                              ErrorMessage:   DNS.ErrorMessage ?? Error.Create($"'{Server.Hostname.Trimmed}' resolved to no address."),
                              ErrorCategory:  MonitoringErrorCategory.DNS);

            var state = StateWithoutNTS(Server, DNSClient);

            await state.Turn.WaitAsync(CancellationToken).ConfigureAwait(false);

            // Let go of while it waited - its settings changed, or its key exchange
            // was forgotten: the state made since.
            while (state.Disposed)
            {
                state.Turn.Release();
                state = StateWithoutNTS(Server, DNSClient);
                await state.Turn.WaitAsync(CancellationToken).ConfigureAwait(false);
            }

            try
            {

                // In a TLS connection of its own every time: NTPv4 as chapter 7 of BSI
                // TR-03109-5 has it, NTPv5 behind its length (section 6.1 of the white
                // paper), or NTPv4 offering NTPv5 - the negotiation kept with the state.
                if (Server.Protection == NTPProtection.NTPOverTLS)
                {

                    var preflightSent = false;

                    if (Preflight)
                    {
                        await QueryOverTLS(Server, DNS, state, CancellationToken).ConfigureAwait(false);
                        preflightSent = true;
                    }

                    return Result(await MeasureOverTLS(Server, DNS, state, CancellationToken).ConfigureAwait(false), preflightSent);

                }

                if (Server.Protection == NTPProtection.NTPOverSSH)
                {

                    if (Server.ConnectOverSSH is null)
                        return Result(Failed(NTPProtection.NTPOverSSH, FirstVersion(Server), $"{Server.Hostname.Trimmed} is to be asked over SSH, and nothing hands out a connection to it.", MonitoringErrorCategory.SSH));

                    if (state.Channel?.IsOpen != true)
                    {

                        await state.CloseChannel().ConfigureAwait(false);

                        try
                        {

                            state.SSH          = await Server.ConnectOverSSH(CancellationToken).ConfigureAwait(false);
                            state.SSHIsShared  = Server.SSHConnectionIsShared;
                            state.Channel      = await NTPOverSSHChannel.OpenAsync(state.SSH, CancellationToken).ConfigureAwait(false);

                        }
                        catch (OperationCanceledException) when (CancellationToken.IsCancellationRequested)
                        {
                            await state.CloseChannel().ConfigureAwait(false);
                            throw;
                        }
                        catch (Exception e)
                        {

                            var connected = state.SSH is not null;

                            await state.CloseChannel().ConfigureAwait(false);

                            return Result(Failed(NTPProtection.NTPOverSSH,
                                                 FirstVersion(Server),
                                                 connected
                                                     ? $"NTP over SSH: the channel to {Server.Hostname.Trimmed} could not be opened: {e.Message}"
                                                     : $"NTP over SSH: no SSH connection to {Server.Hostname.Trimmed}: {e.Message}",
                                                 MonitoringErrorCategory.SSH));

                        }

                    }

                }

                var preflight = false;

                if (Preflight)
                {
                    await QueryWithoutNTS(Server, state, CancellationToken).ConfigureAwait(false);
                    preflight = true;
                }

                var measured = await QueryWithoutNTS(Server, state, CancellationToken).ConfigureAwait(false);

                // A channel the server ended is opened anew at the next round (section 10.5).
                if (state.Channel is { IsOpen: false })
                    await state.CloseChannel().ConfigureAwait(false);

                return Result(measured, preflight);

            }
            finally
            {
                state.Turn.Release();
            }

        }

        #endregion

        #region (private) StateWithoutNTS(Server, DNSClient)

        private WithoutNTSState StateWithoutNTS(NTSServerEndpoint  Server,
                                                DNSClient          DNSClient)
        {

            var settings = SettingsOf(Server);

            while (true)
            {

                if (withoutNTS.TryGetValue(Server.Hostname, out var held))
                {

                    if (held.Settings == settings)
                        return held;

                    if (withoutNTS.TryRemove(new KeyValuePair<DomainName, WithoutNTSState>(Server.Hostname, held)))
                        _ = held.DisposeAsync().AsTask();

                    continue;

                }

                var made = new WithoutNTSState(settings,
                                               new NTSClient(Server.Hostname,
                                                             NTP_Port:      Server.NTPPort,
                                                             Timeout:       config.NTPTimeout,
                                                             DNSClient:     DNSClient,
                                                             TimeProvider:  timeProvider));

                if (withoutNTS.TryAdd(Server.Hostname, made))
                    return made;

                _ = made.DisposeAsync().AsTask();

            }

        }

        #endregion

        #region (private static) FirstVersion(Server)

        private static Byte FirstVersion(NTSServerEndpoint Server)

            => Server.EffectiveNTPVersions[0];

        #endregion

        #region (private) QueryWithoutNTS(Server, State, CancellationToken)

        /// <summary>
        /// One query over SSH or UDP, in the version <see cref="NTSServerEndpoint.NTPVersions"/>
        /// says: NTPv4, NTPv5, or NTPv4 offering NTPv5 where NTPv5 comes first and NTPv4 after it.
        /// </summary>
        private async Task<NTPMeasurementResult> QueryWithoutNTS(NTSServerEndpoint  Server,
                                                                 WithoutNTSState    State,
                                                                 CancellationToken  CancellationToken)
        {

            var versions  = Server.EffectiveNTPVersions;
            var channel   = State.Channel;
            var access    = config.RespectKissOfDeath ? AccessStateFor(Server.Hostname) : null;
            var sw        = Stopwatch.StartNew();

            access?.RecordQuery(timeProvider.GetUtcNow());

            try
            {

                if (versions[0] == 5 && versions.Contains((Byte) 4))
                {

                    var negotiated = channel is not null
                                         ? await State.Client.QueryNegotiatedOverSSH(channel, State.Negotiation, config.NTPTimeout, access, CancellationToken).ConfigureAwait(false)
                                         : await State.Client.QueryNegotiated       (         State.Negotiation, config.NTPTimeout, access, CancellationToken).ConfigureAwait(false);

                    sw.Stop();

                    return negotiated.NTPv5 is not null
                               ? FromNTPv5(Server, negotiated.NTPv5, sw.Elapsed)
                               : FromNTPv4(Server, negotiated.NTPv4!, sw.Elapsed);

                }

                if (versions[0] == 5)
                {

                    var v5 = channel is not null
                                 ? await State.Client.QueryNTPv5OverSSH(channel, Timeout: config.NTPTimeout, AccessState: access, CancellationToken: CancellationToken).ConfigureAwait(false)
                                 : await State.Client.QueryNTPv5       (         Timeout: config.NTPTimeout, AccessState: access, CancellationToken: CancellationToken).ConfigureAwait(false);

                    sw.Stop();

                    return FromNTPv5(Server, v5, sw.Elapsed);

                }

                var v4 = channel is not null
                             ? await State.Client.QueryTimeOverSSH(channel, Timeout: config.NTPTimeout, CancellationToken: CancellationToken).ConfigureAwait(false)
                             : await State.Client.QueryTime       (         Timeout: config.NTPTimeout, CancellationToken: CancellationToken).ConfigureAwait(false);

                sw.Stop();

                return FromNTPv4(Server, v4, sw.Elapsed);

            }
            catch (OperationCanceledException) when (CancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception e)
            {

                sw.Stop();

                return Failed(Server.Protection, versions[0], $"NTP exception: {e.Message}", MonitoringErrorCategory.Exception);

            }

        }

        #endregion

        #region (private) FromNTPv4(Server, Query, Elapsed)

        /// <summary>
        /// What an NTPv4 query without NTS came to, as a measurement.
        /// </summary>
        private NTPMeasurementResult FromNTPv4(NTSServerEndpoint  Server,
                                               NTSQueryResult     Query,
                                               TimeSpan           Elapsed)
        {

            var rtt       = Query.StopwatchRoundTripTime ?? Elapsed;
            var address   = Query.RemoteEndPoint is not null ? (IPAddress?) IPAddress.FromDotNet(Query.RemoteEndPoint.Address) : null;
            var port      = Query.RemoteEndPoint is not null ? IPPort.Parse(Query.RemoteEndPoint.Port)            : Server.NTPPort;
            var response  = Query.Response;

            if (response is null || !Query.Success || response.ErrorMessage is not null)
            {

                var kiss = Query.KissOfDeath;

                // Inside an SSH channel a kiss is the server's own word, as the channel
                // authenticates it; over UDP it is anybody's who saw the request.
                if (kiss is not null && config.RespectKissOfDeath)
                    AccessStateFor(Server.Hostname).Apply(kiss.Value,
                                                          timeProvider.GetUtcNow(),
                                                          Server.Protection == NTPProtection.NTPOverSSH
                                                              ? NTPKissTrust.Authenticated
                                                              : NTPKissTrust.Unprotected);

                return new NTPMeasurementResult {
                           Success          = false,
                           Protection       = Server.Protection,
                           StopwatchRTT     = rtt,
                           ErrorMessage     = Error.Create(Query.ErrorMessage ?? response?.ErrorMessage ?? "No NTP response."),
                           KissOfDeath      = kiss is not null,
                           KissOfDeathCode  = kiss?.Code,
                           ErrorCategory    = kiss is not null
                                                  ? MonitoringErrorCategory.KissOfDeath
                                                  : MapNTSQueryErrorCategory(Query.ErrorCategory),
                           RemoteHost       = Server.Hostname,
                           RemoteAddress    = address,
                           RemotePort       = port
                       };

            }

            if (config.RespectKissOfDeath)
                AccessStateFor(Server.Hostname).RecordAnswer();

            var t1          = NTPPacket.NTPTimestampToDateTime(response.OriginateTimestamp,     timeProvider);
            var t2          = NTPPacket.NTPTimestampToDateTime(response.ReceiveTimestamp,       timeProvider);
            var t3          = NTPPacket.NTPTimestampToDateTime(response.TransmitTimestamp ?? 0, timeProvider);
            var t4          = response.DestinationTimestamp.HasValue
                                  ? NTPPacket.NTPTimestampToDateTime(response.DestinationTimestamp.Value, timeProvider)
                                  : t1.Add(rtt);

            var offset      = response.ClockOffset    ?? TimeSpan.FromTicks(((t2 - t1).Ticks + (t3 - t4).Ticks) / 2);
            var delay       = response.RoundTripDelay ?? ((t4 - t1) - (t3 - t2));

            if (delay < TimeSpan.Zero)
                delay = TimeSpan.Zero;

            var correction  = OffsetCorrection(Server.DelayAsymmetry,
                                               Server.DelayVarAsymmetry,
                                               delay,
                                               ShortestRecentDelay(Server.Hostname, delay));

            return new NTPMeasurementResult {

                       Success                = true,
                       Protection             = Server.Protection,
                       NTSAuthenticationValid = false,
                       UniqueIdMatched        = false,

                       T1_ClientSend          = t1,
                       T2_ServerReceive       = t2,
                       T3_ServerTransmit      = t3,
                       T4_ClientReceive       = t4,

                       Offset                 = offset + correction,
                       MeasuredOffset         = offset,
                       OffsetCorrection       = correction,
                       RoundTripDelay         = delay,
                       StopwatchRTT           = rtt,
                       RemoteHost             = Server.Hostname,
                       RemoteAddress          = address,
                       RemotePort             = port,

                       LeapIndicator          = response.LI,
                       Stratum                = response.Stratum,
                       Poll                   = response.Poll,
                       Precision              = response.Precision,
                       RootDelaySeconds       = response.RootDelay      / 65536.0,
                       RootDispersionSeconds  = response.RootDispersion / 65536.0,
                       ReferenceId            = response.ReferenceIdentifier.ToString(response.Stratum),
                       ReferenceTimestamp     = NTPPacket.NTPTimestampToDateTime(response.ReferenceTimestamp, timeProvider)

                   };

        }

        #endregion

        #region (private) FromNTPv5(Server, Query, Elapsed)

        /// <summary>
        /// What an NTPv5 query without NTS came to, as a measurement - with the checks of
        /// MeasureNTPv5.
        /// </summary>
        private NTPMeasurementResult FromNTPv5(NTSServerEndpoint  Server,
                                               NTPv5QueryResult   Query,
                                               TimeSpan           Elapsed)
        {

            var rtt      = Query.RoundTripTime ?? Elapsed;
            var address  = Query.RemoteEndPoint is not null ? (IPAddress?) IPAddress.FromDotNet(Query.RemoteEndPoint.Address) : null;
            var port     = Query.RemoteEndPoint is not null ? IPPort.Parse(Query.RemoteEndPoint.Port)            : Server.NTPPort;

            NTPMeasurementResult NotMeasured(String Message, MonitoringErrorCategory Category, Boolean Kiss = false)

                => new () {
                       Success          = false,
                       Protection       = Server.Protection,
                       NTPVersion       = 5,
                       StopwatchRTT     = rtt,
                       ErrorMessage     = Error.Create(Message),
                       ErrorCategory    = Category,
                       KissOfDeath      = Kiss,
                       KissOfDeathCode  = Kiss ? "NTPv5 poll 127" : null,
                       RemoteHost       = Server.Hostname,
                       RemoteAddress    = address,
                       RemotePort       = port
                   };

            if (!Query.Success)
                return NotMeasured(Query.ErrorMessage ?? "NTPv5 query failed!",
                                   Query.ErrorCategory == NTSQueryErrorCategory.KissOfDeath
                                       ? MonitoringErrorCategory.KissOfDeath
                                       : MapNTSQueryErrorCategory(Query.ErrorCategory),
                                   Query.ErrorCategory == NTSQueryErrorCategory.KissOfDeath);

            if (Query.Response is not NTPv5Packet response ||
                Query.Measurement is not NTPv5Measurement measurement)
                return NotMeasured($"The NTPv5 response cannot be measured with: {Query.Unusable}.", MonitoringErrorCategory.Unknown);

            if (Query.IsLoop)
                return NotMeasured("The server's reference IDs contain this client's own: a loop (§ 7.4).", MonitoringErrorCategory.Unknown);

            if (Query.Unusable is NTPv5Unusable.MissingTimestamps or NTPv5Unusable.Timescale)
                return NotMeasured($"The NTPv5 response is not usable: {Query.Unusable} (§ 9.5).", MonitoringErrorCategory.Unknown);

            if (config.RespectKissOfDeath && !response.Poll.Equals((SByte) 127))
                AccessStateFor(Server.Hostname).RecordAnswer();

            var offset      = measurement.BestOffset;
            var delay       = measurement.BestDelay;
            var correction  = OffsetCorrection(Server.DelayAsymmetry,
                                               Server.DelayVarAsymmetry,
                                               delay,
                                               ShortestRecentDelay(Server.Hostname, delay));

            return new NTPMeasurementResult {

                       Success                = true,
                       Protection             = Server.Protection,
                       NTPVersion             = 5,
                       Interleaved            = measurement.Interleaved,
                       NTSAuthenticationValid = false,
                       UniqueIdMatched        = false,

                       T1_ClientSend          = measurement.T1,
                       T2_ServerReceive       = measurement.T2,
                       T3_ServerTransmit      = measurement.T3,
                       T4_ClientReceive       = measurement.T4,

                       Offset                 = offset + correction,
                       MeasuredOffset         = offset,
                       OffsetCorrection       = correction,
                       RoundTripDelay         = delay,
                       StopwatchRTT           = rtt,
                       RemoteHost             = Server.Hostname,
                       RemoteAddress          = address,
                       RemotePort             = port,

                       LeapIndicator          = (Byte) (response.Flags.HasFlag(NTPv5Flags.Unsynchronized) ? 3 : 0),
                       Stratum                = response.Stratum,
                       Poll                   = (Byte) Math.Max((SByte) 0, response.Poll),
                       Precision              = response.Precision,
                       RootDelaySeconds       = response.RootDelayTime?.TotalSeconds      ?? Double.PositiveInfinity,
                       RootDispersionSeconds  = response.RootDispersionTime?.TotalSeconds ?? Double.PositiveInfinity

                   };

        }

        #endregion

        #region (private) QueryOverTLS(Server, DNS, State, CancellationToken) / MeasureOverTLS(Server, DNS, State, CancellationToken)

        /// <summary>
        /// One query of NTP over TLS, in a TLS connection of its own: to the addresses the
        /// name servers of the round gave, its certificate checked against its name - in the
        /// version <see cref="NTSServerEndpoint.NTPVersions"/> says.
        /// </summary>
        private Task<NTPOverTLSResult> QueryOverTLS(NTSServerEndpoint    Server,
                                                    DNSResolutionResult  DNS,
                                                    WithoutNTSState      State,
                                                    CancellationToken    CancellationToken)
        {

            var client    = new NTPOverTLSClient(Server.Hostname.Trimmed,
                                                 Server.NTPPort,
                                                 Server.NTPOverTLSCertificateValidator,
                                                 Timeout:       config.NTPTimeout,
                                                 TimeProvider:  timeProvider,
                                                 ConnectTo:     [ .. DNS.IPv6Addresses.Select(address => address.ToDotNet()),
                                                                  .. DNS.IPv4Addresses.Select(address => address.ToDotNet()) ]);

            var versions  = Server.EffectiveNTPVersions;

            return versions[0] == 5 && versions.Contains((Byte) 4)
                       ? client.QueryNegotiated(State.Negotiation, CancellationToken: CancellationToken)
                       : versions[0] == 5
                             ? client.QueryNTPv5(CancellationToken: CancellationToken)
                             : client.QueryTime (CancellationToken: CancellationToken);

        }

        /// <summary>
        /// A measurement of NTP over TLS: the response checked as chapter 7 of BSI
        /// TR-03109-5 has it - or as section 6.1 of the white paper has it for NTPv5 -, the
        /// offset and the delay as the client computed them.
        /// </summary>
        private async Task<NTPMeasurementResult> MeasureOverTLS(NTSServerEndpoint    Server,
                                                                DNSResolutionResult  DNS,
                                                                WithoutNTSState      State,
                                                                CancellationToken    CancellationToken)
        {

            var sw = Stopwatch.StartNew();

            if (config.RespectKissOfDeath)
                AccessStateFor(Server.Hostname).RecordQuery(timeProvider.GetUtcNow());

            var query = await QueryOverTLS(Server, DNS, State, CancellationToken).ConfigureAwait(false);

            sw.Stop();

            if (!query.Success                                                ||
                (query.Response is null && query.NTPv5Response is null)        ||
                query.ClockOffset    is null                                  ||
                query.RoundTripDelay is null)
                return new NTPMeasurementResult {
                           Success        = false,
                           Protection     = NTPProtection.NTPOverTLS,
                           NTPVersion     = query.Version,
                           StopwatchRTT   = sw.Elapsed,
                           ErrorMessage   = Error.Create($"NTP over TLS: {query.ErrorMessage ?? "no response"}{(query.IgnoredBy is not null ? $" ({query.IgnoredBy})" : "")}"),
                           ErrorCategory  = query.ServerCertificate is null && query.TLSVersion is null
                                                ? MonitoringErrorCategory.TCPConnect
                                                : MonitoringErrorCategory.TLSHandshake,
                           RemoteHost     = Server.Hostname,
                           RemotePort     = Server.NTPPort
                       };

            if (config.RespectKissOfDeath)
                AccessStateFor(Server.Hostname).RecordAnswer();

            var offset      = query.ClockOffset.Value;
            var delay       = query.RoundTripDelay.Value < TimeSpan.Zero ? TimeSpan.Zero : query.RoundTripDelay.Value;

            // Once: the shortest recent delay takes this one in.
            var correction5 = OffsetCorrection(Server.DelayAsymmetry,
                                               Server.DelayVarAsymmetry,
                                               delay,
                                               ShortestRecentDelay(Server.Hostname, delay));

            // In NTPv5 the server's T3 is when it sent the response; T1, T2 and T4 are what
            // the offset and the delay make of it, as below for NTPv4.
            if (query.NTPv5Response is NTPv5Packet v5)
            {

                var sent = query.ServerTransmitTime is DateTime transmitted
                               ? new DateTimeOffset(DateTime.SpecifyKind(transmitted, DateTimeKind.Utc))
                               : timeProvider.GetUtcNow() + offset - delay / 2;

                return new NTPMeasurementResult {

                           Success                = true,
                           Protection             = NTPProtection.NTPOverTLS,
                           NTPVersion             = 5,
                           NTSAuthenticationValid = false,
                           UniqueIdMatched        = false,

                           T1_ClientSend          = sent - offset - delay / 2,
                           T2_ServerReceive       = sent,
                           T3_ServerTransmit      = sent,
                           T4_ClientReceive       = sent - offset + delay / 2,

                           Offset                 = offset + correction5,
                           MeasuredOffset         = offset,
                           OffsetCorrection       = correction5,
                           RoundTripDelay         = delay,
                           StopwatchRTT           = sw.Elapsed,
                           RemoteHost             = Server.Hostname,
                           RemotePort             = Server.NTPPort,

                           LeapIndicator          = (Byte) (v5.Flags.HasFlag(NTPv5Flags.Unsynchronized) ? 3 : 0),
                           Stratum                = v5.Stratum,
                           Poll                   = (Byte) Math.Max((SByte) 0, v5.Poll),
                           Precision              = v5.Precision,
                           RootDelaySeconds       = v5.RootDelayTime?.TotalSeconds      ?? Double.PositiveInfinity,
                           RootDispersionSeconds  = v5.RootDispersionTime?.TotalSeconds ?? Double.PositiveInfinity

                       };

            }

            var response    = query.Response!;
            var correction  = correction5;

            // The request carries random bits where its transmit timestamp would be
            // (data minimization, REQ.TA.NTP.BuildRequest.40), so T1 and T4 are what
            // the offset and the delay make of the server's T2 and T3.
            var t2          = NTPPacket.NTPTimestampToDateTime(response.ReceiveTimestamp,       timeProvider);
            var t3          = NTPPacket.NTPTimestampToDateTime(response.TransmitTimestamp ?? 0, timeProvider);
            var t1          = t2 - offset - delay / 2;
            var t4          = t3 - offset + delay / 2;

            return new NTPMeasurementResult {

                       Success                = true,
                       Protection             = NTPProtection.NTPOverTLS,
                       NTSAuthenticationValid = false,
                       UniqueIdMatched        = false,

                       T1_ClientSend          = t1,
                       T2_ServerReceive       = t2,
                       T3_ServerTransmit      = t3,
                       T4_ClientReceive       = t4,

                       Offset                 = offset + correction,
                       MeasuredOffset         = offset,
                       OffsetCorrection       = correction,
                       RoundTripDelay         = delay,
                       StopwatchRTT           = sw.Elapsed,
                       RemoteHost             = Server.Hostname,
                       RemotePort             = Server.NTPPort,

                       LeapIndicator          = response.LI,
                       Stratum                = response.Stratum,
                       Poll                   = response.Poll,
                       Precision              = response.Precision,
                       RootDelaySeconds       = response.RootDelay      / 65536.0,
                       RootDispersionSeconds  = response.RootDispersion / 65536.0,
                       ReferenceId            = response.ReferenceIdentifier.ToString(response.Stratum),
                       ReferenceTimestamp     = NTPPacket.NTPTimestampToDateTime(response.ReferenceTimestamp, timeProvider)

                   };

        }

        #endregion

        #region (private static) Failed(Protection, Version, Message, Category)

        private static NTPMeasurementResult Failed(NTPProtection            Protection,
                                                   Byte                     Version,
                                                   String                   Message,
                                                   MonitoringErrorCategory  Category)

            => new () {
                   Success        = false,
                   Protection     = Protection,
                   NTPVersion     = Version,
                   ErrorMessage   = Error.Create(Message),
                   ErrorCategory  = Category
               };

        #endregion

    }

}
