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

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// NTS-KE over SSH: the white paper "NTS Key Establishment over SSH" of Open Charging
    /// Technology, which runs the records of RFC 8915 in an SSH subsystem instead of over TLS, so
    /// that a private network needs no PKI for NTS.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Everything but the transport stays as RFC 8915 has it: the same records, the same cookies,
    /// and NTP afterwards exactly as before — the NTP server cannot tell over which channel the
    /// keys were agreed. The server is authenticated by its SSH host key, the client by its SSH
    /// key, and one new record, SSH Key Binding, says where the keys come from now that there is
    /// no TLS exporter.
    /// </para>
    /// <para>
    /// Both options of the white paper are implemented: option A, the exporter of the SSH
    /// connection, which Hermod derives from its key exchange, with a nonce the server sends in
    /// that record for every key exchange, and option B, a secret transported in that record.
    /// Option B is mandatory. Every key exchange gets keys of its own with either, so a client may
    /// make as many on one connection as it likes.
    /// </para>
    /// </remarks>
    public static class NTSKE_SSH
    {

        /// <summary>
        /// The SSH subsystem NTS-KE runs in (section 3.1 of the white paper).
        /// </summary>
        /// <remarks>
        /// The ALPN token "ntske/1" of RFC 8915, unchanged, in the private namespace of the domain
        /// that defines it. A standardized successor would drop the domain and register "ntske/1"
        /// with IANA; an incompatible one would be "ntske/2@open.charging.cloud".
        /// </remarks>
        public const String SubsystemName = "ntske/1@open.charging.cloud";

    }

}
