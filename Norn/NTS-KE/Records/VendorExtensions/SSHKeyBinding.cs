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

using System.Diagnostics.CodeAnalysis;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    /// <summary>
    /// Where the keys of NTS-KE over SSH come from: the methods of the SSH Key Binding record.
    /// </summary>
    public enum SSHKeyBindingMethods : UInt16
    {

        /// <summary>
        /// Option A: the SSH exporter of the connection. A nonce of
        /// <see cref="NTSKE_ExportedKeys.ExporterNonceLength"/> octets in the response, which the
        /// server chooses afresh for every key exchange.
        /// </summary>
        Exporter   = 0x0001,

        /// <summary>
        /// Option B: a secret the server sends, <see cref="NTSKE_ExportedKeys.TransportedSecretLength"/>
        /// octets in the response. Mandatory to implement, so every client offers it.
        /// </summary>
        Transport  = 0x0002

    }

}

namespace org.GraphDefined.Vanaheimr.Norn.NTS.NTSKERecords
{

    /// <summary>
    /// NTS-KE SSH Key Binding — section 5 of the white paper "NTS Key Establishment over SSH".
    /// </summary>
    /// <remarks>
    /// <para>
    /// In a request the body is one entry per method offered, in order of preference: a 16-bit
    /// method id, a 16-bit data length and that many octets of data for the method. Neither
    /// <see cref="SSHKeyBindingMethods.Exporter"/> nor <see cref="SSHKeyBindingMethods.Transport"/>
    /// takes data from the client; the length is there so that a later method may, without an older
    /// server reading its data as method ids. In a response the body is the one method the server
    /// selected, followed by the data of that method: the nonce for
    /// <see cref="SSHKeyBindingMethods.Exporter"/>, the secret for
    /// <see cref="SSHKeyBindingMethods.Transport"/>.
    /// </para>
    /// <para>
    /// The two directions are read by two methods rather than told apart by the record itself,
    /// because the record cannot know which way it travelled.
    /// </para>
    /// </remarks>
    public class SSHKeyBinding : NTSKE_Record
    {

        /// <summary>
        /// Create a new NTS-KE SSH Key Binding record.
        /// </summary>
        /// <param name="IsCritical">Whether an unrecognized record must cause an error.</param>
        /// <param name="Body">The methods of a request, or the selection of a response.</param>
        public SSHKeyBinding(Boolean  IsCritical,
                             Byte[]   Body)

            : base(IsCritical,
                   NTSKE_RecordTypes.SSHKeyBinding,
                   Body)

        { }


        #region TryGetOffer(out Offer, out ErrorResponse)

        /// <summary>
        /// Read the body as a request: the entries the client offers, most preferred first, each a
        /// method id with the data the client gives for it.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Methods this implementation does not know are kept, not refused, with their data: the
        /// server selects the first method of the list it supports, so a client may well offer one
        /// it has never heard of before the one it has.
        /// </para>
        /// <para>
        /// Refused: a body without an entry, an entry or its data cut short, octets after the last
        /// entry, and data for <see cref="SSHKeyBindingMethods.Exporter"/> or
        /// <see cref="SSHKeyBindingMethods.Transport"/>, which take none from the client.
        /// </para>
        /// </remarks>
        /// <param name="Offer">The offered methods with their data, most preferred first.</param>
        /// <param name="ErrorResponse">Why the body is not a list of entries.</param>
        public Boolean TryGetOffer([NotNullWhen(true)]  out IReadOnlyList<(UInt16 Method, Byte[] Data)>?  Offer,
                                   [NotNullWhen(false)] out String?                                         ErrorResponse)
        {

            Offer          = null;
            ErrorResponse  = null;

            if (Body.Length == 0)
            {
                ErrorResponse = "The SSH Key Binding record offers no method.";
                return false;
            }

            var entries  = new List<(UInt16, Byte[])>();
            var offset   = 0;

            while (offset < Body.Length)
            {

                if (Body.Length - offset < 4)
                {
                    ErrorResponse = $"The SSH Key Binding body ends {Body.Length - offset} octet(s) into an entry, which takes four for its method id and data length.";
                    return false;
                }

                var method  = (UInt16) ((Body[offset]     << 8) | Body[offset + 1]);
                var length  =           (Body[offset + 2] << 8) | Body[offset + 3];

                offset += 4;

                if (Body.Length - offset < length)
                {
                    ErrorResponse = $"The SSH Key Binding entry of method 0x{method:x4} says {length} octet(s) of data, but the body has {Body.Length - offset} left.";
                    return false;
                }

                if (length > 0 && method is (UInt16) SSHKeyBindingMethods.Exporter or (UInt16) SSHKeyBindingMethods.Transport)
                {
                    ErrorResponse = $"The SSH Key Binding entry of method 0x{method:x4} carries {length} octet(s) of data, but that method takes none from the client.";
                    return false;
                }

                entries.Add((method, Body[offset..(offset + length)]));

                offset += length;

            }

            Offer = entries;
            return true;

        }

        #endregion

        #region TryGetOfferedMethods(out Methods, out ErrorResponse)

        /// <summary>
        /// Read the body as a request: the methods the client offers, most preferred first, without
        /// their data - see <see cref="TryGetOffer"/>.
        /// </summary>
        /// <param name="Methods">The offered method ids, most preferred first.</param>
        /// <param name="ErrorResponse">Why the body is not a list of entries.</param>
        public Boolean TryGetOfferedMethods([NotNullWhen(true)]  out UInt16[]?  Methods,
                                            [NotNullWhen(false)] out String?    ErrorResponse)
        {

            Methods = null;

            if (!TryGetOffer(out var offer, out ErrorResponse))
                return false;

            Methods = [.. offer.Select(entry => entry.Method)];
            return true;

        }

        #endregion

        #region TryGetSelection(out Method, out MethodData, out ErrorResponse)

        /// <summary>
        /// Read the body as a response: the method the server selected, and the data it sent with
        /// it.
        /// </summary>
        /// <param name="Method">The selected method.</param>
        /// <param name="MethodData">The nonce of <see cref="SSHKeyBindingMethods.Exporter"/>, or the secret of <see cref="SSHKeyBindingMethods.Transport"/>.</param>
        /// <param name="ErrorResponse">Why the body is not a selection this implementation can use.</param>
        public Boolean TryGetSelection(out                  SSHKeyBindingMethods  Method,
                                       [NotNullWhen(true)]  out Byte[]?           MethodData,
                                       [NotNullWhen(false)] out String?           ErrorResponse)
        {

            Method         = default;
            MethodData     = null;
            ErrorResponse  = null;

            if (Body.Length < 2)
            {
                ErrorResponse = $"The SSH Key Binding response is {Body.Length} octets, too short for a method id.";
                return false;
            }

            var method = (UInt16) ((Body[0] << 8) | Body[1]);

            switch ((SSHKeyBindingMethods) method)
            {

                case SSHKeyBindingMethods.Exporter:

                    if (Body.Length != 2 + NTSKE_ExportedKeys.ExporterNonceLength)
                    {
                        ErrorResponse = $"The SSH Key Binding response selects the exporter, whose nonce is {NTSKE_ExportedKeys.ExporterNonceLength} octets, but carries {Body.Length - 2}.";
                        return false;
                    }

                    Method       = SSHKeyBindingMethods.Exporter;
                    MethodData   = Body[2..];
                    return true;

                case SSHKeyBindingMethods.Transport:

                    if (Body.Length != 2 + NTSKE_ExportedKeys.TransportedSecretLength)
                    {
                        ErrorResponse = $"The SSH Key Binding response selects the transport, whose secret is {NTSKE_ExportedKeys.TransportedSecretLength} octets, but carries {Body.Length - 2}.";
                        return false;
                    }

                    Method       = SSHKeyBindingMethods.Transport;
                    MethodData   = Body[2..];
                    return true;

                default:
                    ErrorResponse = $"The SSH Key Binding response selects the unknown method 0x{method:x4}.";
                    return false;

            }

        }

        #endregion

    }

}
