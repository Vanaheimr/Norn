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

namespace org.GraphDefined.Vanaheimr.Norn.Monitoring
{

    /// <summary>
    /// How the time of a server is protected: the Mode of an NTP client in the
    /// Secure Time Synchronization white paper (section 3.2.4), without its
    /// version, which is <see cref="NTSServerEndpoint.NTPVersions"/>.
    /// </summary>
    /// <remarks>
    /// Configured per server, never negotiated: a server of one protection is
    /// never asked in another, and an engine never falls back from one to the
    /// next by itself - an attacker who blocks a port must not be able to bring
    /// a client down to a weaker protection.
    /// </remarks>
    public enum NTPProtection
    {

        /// <summary>
        /// NTS (RFC 8915): a key exchange over TLS, or over SSH where the
        /// endpoint's ConnectOverSSH says so, and every NTP message
        /// authenticated with its keys. Mode NTS or NTSSSH.
        /// </summary>
        NTS,

        /// <summary>
        /// NTP over TLS after chapter 7 of BSI TR-03109-5, and NTPv5 after
        /// section 6.1 of the paper: each request in a TLS connection of its
        /// own, the server held to its certificate. Mode NTPTLS, for a smart
        /// meter gateway (section 6 of the paper).
        /// </summary>
        NTPOverTLS,

        /// <summary>
        /// NTP over SSH after section 10 of the white paper "NTS Key Establishment
        /// over SSH": the NTP messages in a channel of an SSH connection, the
        /// server held to its host key by whoever hands out the connection
        /// (<see cref="NTSServerEndpoint.ConnectOverSSH"/>). Mode NTPSSH.
        /// </summary>
        NTPOverSSH,

        /// <summary>
        /// NTP over UDP without any authentication. Mode NTP, which the legal
        /// group must never use; an answer is anybody's on the way.
        /// </summary>
        None

    }

}
