/*
 * Copyright (c) 2010-2025 GraphDefined GmbH <achim.friedland@graphdefined.com>
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
    /// Network Time Security Key Establishment (NTS-KE) record extension methods.
    /// </summary>
    public static class NTSKERecordExtensions
    {

        /// <summary>
        /// Convert the given NTS-KE records to a byte array.
        /// </summary>
        /// <param name="NTSKERecords">An enumeration of NTS-KE records.</param>
        public static Byte[] ToByteArray(this IEnumerable<NTSKE_Record> NTSKERecords)
        {

            using var ms = new MemoryStream();

            foreach (var ntsKERecord in NTSKERecords)
                ms.Write(ntsKERecord.ToByteArray(), 0, ntsKERecord.ToByteArray().Length);

            return ms.ToArray();

        }

    }


    /// <summary>
    /// The Network Time Security Key Establishment (NTS-KE) record (RFC 8915).
    /// </summary>
    /// <param name="IsCritical">Whether an unrecognized record must cause an error.</param>
    /// <param name="Type">The type of the record.</param>
    /// <param name="Body">The optional data of the record.</param>
    public class NTSKE_Record(Boolean            IsCritical,
                              NTSKE_RecordTypes  Type,
                              Byte[]?            Body   = null)
    {

        #region Properties

        /// <summary>
        /// Whether an unrecognized record must cause an error.
        /// </summary>
        public Boolean           IsCritical    { get; } = IsCritical;

        /// <summary>
        /// The type of the record.
        /// </summary>
        public NTSKE_RecordTypes  Type          { get; } = Type;

        /// <summary>
        /// The data of the record.
        /// </summary>
        public Byte[]             Body          { get; } = Body ?? [];

        /// <summary>
        /// Length of the record data.
        /// </summary>
        public UInt16             Length        { get; } = (UInt16) (Body?.Length ?? 0);

        #endregion


        #region TryParse(Buffer, out NTSKERecords, out ErrorResponse)

        // NTS-KE Client Request
        // 8001 0002 0000
        // 8004 0002 000f
        // 8000 0000

        // NTS-KE Server Response
        // 8001 0002 0000
        // 8004 0002 000f
        // 0005 0064 e157c67c54f94390fbb930a259d5438e5bd89c18c0e3c5e0d18c0c4a72741e7d634d1a06ae5539805515b03aa756462ca77f479fb368d026dcebf0af426b073936506ae693f169327c5a5eba8b7f4254c9dd382aea59fa1f7dd47a681d4105316ef63153
        // 0005 0064 e157c67c932d10869d717e0b9c864d07faa7478f55e64e3bfea56448dc8f72d57172db5428bb2a4b2f7aa9d32fe3b2c31134e3113aa36c5ce0b618a9634463653960fe672c78bf5846c6f16b34cc20246fd0a11625af9085a159b07851454f0241e3828a
        // 0005 0064 e157c67c6113c3776e098e743a8aecffce82e880496daccaaf9440a494157d82be894a03c59f5cd6bfc0b93145367400e00db6d334c912184a03eecbd1db14bf1f26e7fb12556dc7ff8e0dde49972de5db2c4825f323ba668e5c36419694771446654746
        // 0005 0064 e157c67c22aedc90c00997fbeb508f6e6923460fc5130036f13d807da55910fa8d9ad7b24d4636dd822b59e5df274c380536c5d0080561cca3758eda5015422b9857b89e3cf3f075242bc25ae6725c779ede7a006617f2959380da32b2b44ff32499db59
        // 0005 0064 e157c67c8cb8afc1a79c90a0bd88e7d3ea24fa8182cdc750e37ac4f6f515302b10cdfdf972845221fe86f409ac225841c5404f360c6f680fe50f7c91bc2dde900f0741cc198d6073963316ea9400f4881c6c359cf6524ed09d98829bc862dbfda137e1fc
        // 0005 0064 e157c67cac5362c0d8e4d8f043557871eed408ac4eb361f39ff6aa5c12f11563584e8103e1351cf2a4672845fc5bed6128e2ffb54a5bc402cb3f1f7c09b69ab35ffe096072d5767722d011c8a60ca9fe1963f68c5887f163b5430af96e22aa62943fe29d
        // 0005 0064 e157c67c8869d5681d34853d66b1f41147650aaf0d33c0979b7f0aa1a99259674035913ea10585923a7f468b4a1e7d1e0c300e6e476c09e2ff93a0fa4161696b32c6f7e84e58866be6aa8a42fbad4bb1d4af15d0dd6a04c4a43a2f31bc6f633e6140e528
        // 0005 0064 e157c67c6995cfd339caeca4c4deb45f8ffdbb6a10b56f62c5e34dc2a2868e05e1376b44b22904f0f23070cabcdf6d70b4d5a2170aef53acae00edb1ee37bb50368e140593022582ea50c8149afa4a64cf1451168700ba94b8a2722c45be3f72f18ff74e
        // 8000 0000

        /// <summary>
        /// Try to parse the NTS-KE response records.
        /// </summary>
        /// <param name="Buffer">The raw NTS-KE data from the server.</param>
        /// <param name="NTSKERecords">The parsed NTS-KE records.</param>
        /// <param name="ErrorResponse">An optional error message.</param>
        public static Boolean TryParse(Byte[]                                               Buffer,
                                       [NotNullWhen(true)]  out IEnumerable<NTSKE_Record>?  NTSKERecords,
                                       [NotNullWhen(false)] out String?                     ErrorResponse)
        {

            ErrorResponse  = null;
            NTSKERecords   = [];

            var records    = new List<NTSKE_Record>();
            var offset     = 0;

            while (offset + 4 <= Buffer.Length)
            {

                // 16 bits: [CriticalBit (1) + RecordType (15)]
                // 16 bits: BodyLength (big-endian)
                // Body:    [BodyLength bytes]

                var critical    =                       (Buffer[offset] & 0x80) != 0;
                var type        = (NTSKE_RecordTypes) (((Buffer[offset] & 0x7F) << 8) | Buffer[offset + 1]);
                var bodyLength  = (UInt16)             ((Buffer[offset +2 ]     << 8) | Buffer[offset + 3]);
                offset += 4;

                if (offset + bodyLength > Buffer.Length)
                {
                    ErrorResponse = "NTS-KE record claims more body bytes than available!";
                    return false;
                }

                var body = new Byte[bodyLength];
                Array.Copy(Buffer, offset, body, 0, bodyLength);
                offset += bodyLength;

                records.Add(
                    new NTSKE_Record(
                        critical,
                        type,
                        body
                    )
                );

            }

            NTSKERecords = records;
            return true;

        }

        #endregion

        #region ToByteArray()

        public Byte[] ToByteArray()
        {

            var data = new Byte[4 + Body.Length];

            // 16 bits: [CriticalBit (1) + RecordType (15)]
            var typeField = (UInt16) ((IsCritical ? 0x8000 : 0x0000) | (UInt16) Type);
            data[0] = (Byte) (typeField >> 8);
            data[1] = (Byte) (typeField & 0xFF);

            // 16 bits: BodyLength (big-endian)
            data[2] = (Byte) (Body.Length >> 8);
            data[3] = (Byte) (Body.Length & 0xFF);

            // Copy body
            Buffer.BlockCopy(Body, 0, data, 4, Body.Length);

            return data;

        }

        #endregion


        #region Static methods

        /// <summary>
        /// The end of the message
        /// </summary>
        public static NTSKE_Record  EndOfMessage
            => new (true,       NTSKE_RecordTypes.EndOfMessage);

        /// <summary>
        /// NTS Next Protocol Negotiation
        /// </summary>
        public static NTSKE_Record  NTSNextProtocolNegotiation
            => new (true,       NTSKE_RecordTypes.NTSNextProtocolNegotiation,   [0x00, 0x00]);

        /// <summary>
        /// NTS Error
        /// </summary>
        public static NTSKE_Record  Error(Byte[] Error)
            => new (true,       NTSKE_RecordTypes.Error,                        Error);

        /// <summary>
        /// NTS Warning
        /// </summary>
        public static NTSKE_Record  Warning(Byte[] Warning)
            => new (true,       NTSKE_RecordTypes.Warning,                      Warning);

        /// <summary>
        /// NTS AEAD Algorithm Negotiation
        /// </summary>
        /// <param name="Algorithm">The algorithm to be negotiated.</param>
        public static NTSKE_Record  AEADAlgorithmNegotiation(AEADAlgorithms Algorithm = AEADAlgorithms.AES_SIV_CMAC_256)
            => new (true,       NTSKE_RecordTypes.AEADAlgorithmNegotiation,     Algorithm.GetBytes());

        /// <summary>
        /// NTS New Cookie for NTPv4
        /// </summary>
        /// <param name="IsCritical">Whether the record is critical.</param>
        /// <param name="NTSCookie">The new NTS cookie.</param>
        public static NTSKE_Record  NewCookieForNTPv4(Byte[] NTSCookie, Boolean IsCritical = true)
            => new (IsCritical, NTSKE_RecordTypes.NewCookieForNTPv4,            NTSCookie);

        /// <summary>
        /// NTS NTPv4 Server Negotiation
        /// </summary>
        /// <param name="ServerInformation">The NTP server information.</param>
        public static NTSKE_Record  NTPv4ServerNegotiation(Byte[] ServerInformation)
            => new (true,        NTSKE_RecordTypes.NTPv4ServerNegotiation,       ServerInformation);

        /// <summary>
        /// NTS NTPv4 Port Negotiation
        /// </summary>
        /// <param name="PortInformation">The NTP port information.</param>
        public static NTSKE_Record  NTPv4PortNegotiation(Byte[] PortInformation)
            => new (true,        NTSKE_RecordTypes.NTPv4PortNegotiation,         PortInformation);



        /// <summary>
        /// NTS Request Public Key
        /// </summary>
        public static NTSKE_Record  NTSRequestPublicKey()
            => new (
                   false,
                   NTSKE_RecordTypes.NTSRequestPublicKey
               );

        /// <summary>
        /// NTS Public Key
        /// </summary>
        /// <param name="PublicKey">The public key to be requested.</param>
        public static NTSKE_Record  NTSPublicKey(PublicKey PublicKey)
            => new (
                   false,
                   NTSKE_RecordTypes.NTSPublicKey,
                   PublicKey.ToByteArray()
               );

        #endregion


        #region (override) ToString()

        /// <summary>
        /// Return a text representation of this object.
        /// </summary>
        public override String ToString()

            => $"{Type.Description()} ({Type}, {(IsCritical ? "critical" : "non critical")}, Length={Body.Length} Body=[{BitConverter.ToString(Body)}]";

        #endregion

    }

}
