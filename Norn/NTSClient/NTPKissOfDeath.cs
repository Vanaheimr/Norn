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

using org.GraphDefined.Vanaheimr.Norn.NTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// What RFC 5905 § 7.4 requires a client to do about a kiss code.
    /// </summary>
    public enum NTPKissAction
    {

        /// <summary>
        /// Nothing. § 7.4 d: "Other than the above conditions, KoD packets have no protocol
        /// significance and are discarded after inspection." The measurement is lost either way,
        /// but the association is not.
        /// </summary>
        Ignore,

        /// <summary>
        /// Poll this server less often. § 7.4 b, for the "RATE" code.
        /// </summary>
        ReducePollingRate,

        /// <summary>
        /// Stop talking to this server. § 7.4 a, for "DENY" and "RSTR".
        /// </summary>
        Demobilize,

        /// <summary>
        /// Run NTS-KE again: the cookies held are no longer usable. RFC 8915 § 5.7's NTS NAK,
        /// which is a Kiss-o'-Death in form but says nothing about how welcome the client is.
        /// </summary>
        RenegotiateNTS

    }


    /// <summary>
    /// A Kiss-o'-Death packet a server sent, once it has been established that this client should
    /// believe it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The believing is the point of this type, and the reason reading a kiss code is not merely
    /// a matter of looking at the reference identifier. A KoD is the one kind of NTP packet whose
    /// whole content is an instruction — stop asking, or ask less often — and RFC 8633 § 5.4 is
    /// blunt about where that leads: "Kiss-o'-Death (KoD) packets can be used in denial-of-service
    /// attacks ... And KoD packets are commonly accepted even when not cryptographically
    /// authenticated, which increases the risk."
    /// </para>
    /// <para>
    /// Two defences follow from that, and this type holds one of them. § 5.4: "a client MUST only
    /// accept a KoD packet if it has a valid origin timestamp" — an off-path attacker who cannot
    /// see the request cannot echo it, so the same test that keeps forged time out keeps forged
    /// instructions out. The other defence, not accepting the server's poll value at face value,
    /// belongs to <see cref="NTPServerAccessState"/>, which is what acts on the instruction.
    /// </para>
    /// </remarks>
    /// <param name="Code">The four-character kiss code from the reference identifier field.</param>
    /// <param name="PollExponent">
    /// The Poll field of the kiss: a server asking for a rate is asking through this. Advice, not
    /// an order — see <see cref="NTPServerAccessState.Apply"/>.
    /// </param>
    public readonly record struct NTPKissOfDeath(String  Code,
                                                 Byte    PollExponent)
    {

        /// <summary>
        /// What RFC 5905 § 7.4 says to do about this code.
        /// </summary>
        /// <remarks>
        /// The unrecognized case is deliberately the same as the "no protocol significance" case,
        /// which is what § 7.4 c asks for explicitly of experimental codes — "Kiss codes
        /// beginning with the ASCII character 'X' are for unregistered experimentation and
        /// development and MUST be ignored if not recognized" — and what § 7.4 d asks for of
        /// everything else. RFC 9748 later reserved the whole <c>X…</c> space in the IANA
        /// registry for the same purpose, so the rule is not going anywhere.
        /// </remarks>
        public NTPKissAction Action

            => Code switch {

                   // § 7.4 a
                   "DENY" or
                   "RSTR" => NTPKissAction.Demobilize,

                   // § 7.4 b
                   "RATE" => NTPKissAction.ReducePollingRate,

                   // RFC 8915 § 5.7
                   "NTSN" => NTPKissAction.RenegotiateNTS,

                   // § 7.4 c and d
                   _      => NTPKissAction.Ignore

               };


        /// <summary>
        /// Whether this code is one of RFC 5905 § 7.4 c's experimental codes, which a client must
        /// ignore rather than guess at.
        /// </summary>
        public Boolean IsExperimental

            => Code.StartsWith('X');


        /// <summary>
        /// Read a Kiss-o'-Death out of a response, if that is what it is and if this client has
        /// grounds to believe it.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Three things have to hold. The stratum must be zero, which is what makes the reference
        /// identifier a kiss code at all rather than a clock source. The code must be printable
        /// ASCII, because a kiss code is defined as such — "four-character ASCII strings that are
        /// left justified and zero filled", so up to four characters once the filling is dropped
        /// — and a stratum-0 packet carrying arbitrary bytes there is not making a statement this
        /// client can read.
        /// </para>
        /// <para>
        /// And the origin timestamp must match the request — RFC 8633 § 5.4. The match is the
        /// RFC 9769 § 2 one, so that an interleaved association is not made to distrust every
        /// kiss it is sent: a response echoing the request's receive timestamp is as much a
        /// response to it as one echoing the transmit timestamp.
        /// </para>
        /// </remarks>
        /// <param name="Response">The response as received.</param>
        /// <param name="Request">
        /// The request it should be answering. Without it there is nothing to check the origin
        /// timestamp against, and an unverifiable kiss is not accepted.
        /// </param>
        /// <param name="Kiss">The kiss, when there is one to be had.</param>
        public static Boolean TryRead(NTPPacket           Response,
                                      NTPPacket?          Request,
                                      out NTPKissOfDeath  Kiss)
        {

            Kiss = default;

            if (Response.Stratum != 0)
                return false;

            var code = Response.ReferenceIdentifier.AsASCII;

            if (code.Length is 0 or > 4 ||
                !code.All(character => character is >= '!' and <= '~'))
            {
                return false;
            }

            if (Request is null)
                return false;

            if (InterleavedAssociation.Classify(Response,
                                                Request.ReceiveTimestamp,
                                                Request.TransmitTimestamp ?? 0) == InterleavedResponseMode.Bogus)
            {
                return false;
            }

            Kiss = new NTPKissOfDeath(code, Response.Poll);

            return true;

        }


        /// <summary>
        /// The kiss code and what this client will do about it.
        /// </summary>
        public override String ToString()

            => $"{Code} (poll {PollExponent}, {Action})";

    }

}
