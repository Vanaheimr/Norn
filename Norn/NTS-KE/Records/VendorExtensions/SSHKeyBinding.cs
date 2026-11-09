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
    /// In a request the body is a list of 16-bit method ids in order of preference. In a response
    /// it is the one method the server selected, followed by the data of that method: the nonce for
    /// <see cref="SSHKeyBindingMethods.Exporter"/>, the secret for
    /// <see cref="SSHKeyBindingMethods.Transport"/>.
    /// </para>
    /// <para>
    /// The two directions are read by two methods rather than told apart by the record itself,
    /// because the record cannot know which way it travelled: a response of 34 octets reads just
    /// as well as a request offering 17 methods.
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


        #region TryGetOfferedMethods(out Methods, out ErrorResponse)

        /// <summary>
        /// Read the body as a request: the methods the client offers, most preferred first.
        /// </summary>
        /// <remarks>
        /// Method ids this implementation does not know are kept, not refused: the server selects
        /// the first method of the list it supports, so a client may well offer one it has never
        /// heard of before the one it has.
        /// </remarks>
        /// <param name="Methods">The offered method ids, most preferred first.</param>
        /// <param name="ErrorResponse">Why the body is not a list of methods.</param>
        public Boolean TryGetOfferedMethods([NotNullWhen(true)]  out UInt16[]?  Methods,
                                            [NotNullWhen(false)] out String?    ErrorResponse)
        {

            Methods        = null;
            ErrorResponse  = null;

            if (Body.Length == 0)
            {
                ErrorResponse = "The SSH Key Binding record offers no method.";
                return false;
            }

            if (Body.Length % 2 != 0)
            {
                ErrorResponse = $"The SSH Key Binding body is {Body.Length} octets, which is not a whole number of 16-bit method ids.";
                return false;
            }

            Methods = new UInt16[Body.Length / 2];

            for (var i = 0; i < Methods.Length; i++)
                Methods[i] = (UInt16) ((Body[i * 2] << 8) | Body[i * 2 + 1]);

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
