﻿/*
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

using System.Diagnostics.CodeAnalysis;

namespace org.GraphDefined.Vanaheimr.Norn.NTS
{

    public static class AEADAlgorithmsExtensions
    {

        public static Byte[] GetBytes(this AEADAlgorithms AEADAlgorithm)
        {

            var bytes = BitConverter.GetBytes((UInt16) AEADAlgorithm);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);

            return bytes;

        }


        public static Boolean TryParse(String                                    Text,
                                       [NotNullWhen(true)]  out AEADAlgorithms?  AEADAlgorithm,
                                       [NotNullWhen(false)] out String?          ErrorResponse)
        {

            AEADAlgorithm = Text switch {

                "AES_128_GCM"            => AEADAlgorithms.AES_128_GCM,
                "AES_256_GCM"            => AEADAlgorithms.AES_256_GCM,
                "AES_128_CCM"            => AEADAlgorithms.AES_128_CCM,
                "AES_256_CCM"            => AEADAlgorithms.AES_256_CCM,
                "AES_128_GCM_8"          => AEADAlgorithms.AES_128_GCM_8,
                "AES_256_GCM_8"          => AEADAlgorithms.AES_256_GCM_8,
                "AES_128_GCM_12"         => AEADAlgorithms.AES_128_GCM_12,
                "AES_256_GCM_12"         => AEADAlgorithms.AES_256_GCM_12,
                "AES_128_CCM_SHORT"      => AEADAlgorithms.AES_128_CCM_SHORT,
                "AES_256_CCM_SHORT"      => AEADAlgorithms.AES_256_CCM_SHORT,
                "AES_128_CCM_SHORT_8"    => AEADAlgorithms.AES_128_CCM_SHORT_8,
                "AES_256_CCM_SHORT_8"    => AEADAlgorithms.AES_256_CCM_SHORT_8,
                "AES_128_CCM_SHORT_12"   => AEADAlgorithms.AES_128_CCM_SHORT_12,
                "AES_256_CCM_SHORT_12"   => AEADAlgorithms.AES_256_CCM_SHORT_12,
                "AES_SIV_CMAC_256"       => AEADAlgorithms.AES_SIV_CMAC_256,
                "AES_SIV_CMAC_384"       => AEADAlgorithms.AES_SIV_CMAC_384,
                "AES_SIV_CMAC_512"       => AEADAlgorithms.AES_SIV_CMAC_512,
                "AES_128_CCM_8"          => AEADAlgorithms.AES_128_CCM_8,
                "AES_256_CCM_8"          => AEADAlgorithms.AES_256_CCM_8,
                "AES_128_OCB_TAGLEN128"  => AEADAlgorithms.AES_128_OCB_TAGLEN128,
                "AES_128_OCB_TAGLEN96"   => AEADAlgorithms.AES_128_OCB_TAGLEN96,
                "AES_128_OCB_TAGLEN64"   => AEADAlgorithms.AES_128_OCB_TAGLEN64,
                "AES_192_OCB_TAGLEN128"  => AEADAlgorithms.AES_192_OCB_TAGLEN128,
                "AES_192_OCB_TAGLEN96"   => AEADAlgorithms.AES_192_OCB_TAGLEN96,
                "AES_192_OCB_TAGLEN64"   => AEADAlgorithms.AES_192_OCB_TAGLEN64,
                "AES_256_OCB_TAGLEN128"  => AEADAlgorithms.AES_256_OCB_TAGLEN128,
                "AES_256_OCB_TAGLEN96"   => AEADAlgorithms.AES_256_OCB_TAGLEN96,
                "AES_256_OCB_TAGLEN64"   => AEADAlgorithms.AES_256_OCB_TAGLEN64,
                "CHACHA20_POLY1305"      => AEADAlgorithms.CHACHA20_POLY1305,
                "AES_128_GCM_SIV"        => AEADAlgorithms.AES_128_GCM_SIV,
                "AES_256_GCM_SIV"        => AEADAlgorithms.AES_256_GCM_SIV,
                "AEGIS128L"              => AEADAlgorithms.AEGIS128L,
                "AEGIS256"               => AEADAlgorithms.AEGIS256,

                _                        => null

            };

            ErrorResponse = AEADAlgorithm is null
                ? "Unknown AEAD algorithm!"
                : null;

            return AEADAlgorithm is not null;

        }

        public static String AsText(this AEADAlgorithms AEADAlgorithm)

            => AEADAlgorithm switch {

                AEADAlgorithms.AES_128_GCM            => "AES_128_GCM",
                AEADAlgorithms.AES_256_GCM            => "AES_256_GCM",
                AEADAlgorithms.AES_128_CCM            => "AES_128_CCM",
                AEADAlgorithms.AES_256_CCM            => "AES_256_CCM",
                AEADAlgorithms.AES_128_GCM_8          => "AES_128_GCM_8",
                AEADAlgorithms.AES_256_GCM_8          => "AES_256_GCM_8",
                AEADAlgorithms.AES_128_GCM_12         => "AES_128_GCM_12",
                AEADAlgorithms.AES_256_GCM_12         => "AES_256_GCM_12",
                AEADAlgorithms.AES_128_CCM_SHORT      => "AES_128_CCM_SHORT",
                AEADAlgorithms.AES_256_CCM_SHORT      => "AES_256_CCM_SHORT",
                AEADAlgorithms.AES_128_CCM_SHORT_8    => "AES_128_CCM_SHORT_8",
                AEADAlgorithms.AES_256_CCM_SHORT_8    => "AES_256_CCM_SHORT_8",
                AEADAlgorithms.AES_128_CCM_SHORT_12   => "AES_128_CCM_SHORT_12",
                AEADAlgorithms.AES_256_CCM_SHORT_12   => "AES_256_CCM_SHORT_12",
                AEADAlgorithms.AES_SIV_CMAC_256       => "AES_SIV_CMAC_256",
                AEADAlgorithms.AES_SIV_CMAC_384       => "AES_SIV_CMAC_384",
                AEADAlgorithms.AES_SIV_CMAC_512       => "AES_SIV_CMAC_512",
                AEADAlgorithms.AES_128_CCM_8          => "AES_128_CCM_8",
                AEADAlgorithms.AES_256_CCM_8          => "AES_256_CCM_8",
                AEADAlgorithms.AES_128_OCB_TAGLEN128  => "AES_128_OCB_TAGLEN128",
                AEADAlgorithms.AES_128_OCB_TAGLEN96   => "AES_128_OCB_TAGLEN96",
                AEADAlgorithms.AES_128_OCB_TAGLEN64   => "AES_128_OCB_TAGLEN64",
                AEADAlgorithms.AES_192_OCB_TAGLEN128  => "AES_192_OCB_TAGLEN128",
                AEADAlgorithms.AES_192_OCB_TAGLEN96   => "AES_192_OCB_TAGLEN96",
                AEADAlgorithms.AES_192_OCB_TAGLEN64   => "AES_192_OCB_TAGLEN64",
                AEADAlgorithms.AES_256_OCB_TAGLEN128  => "AES_256_OCB_TAGLEN128",
                AEADAlgorithms.AES_256_OCB_TAGLEN96   => "AES_256_OCB_TAGLEN96",
                AEADAlgorithms.AES_256_OCB_TAGLEN64   => "AES_256_OCB_TAGLEN64",
                AEADAlgorithms.CHACHA20_POLY1305      => "CHACHA20_POLY1305",
                AEADAlgorithms.AES_128_GCM_SIV        => "AES_128_GCM_SIV",
                AEADAlgorithms.AES_256_GCM_SIV        => "AES_256_GCM_SIV",
                AEADAlgorithms.AEGIS128L              => "AEGIS128L",
                AEADAlgorithms.AEGIS256               => "AEGIS256",

                _                                     => "Unknown AEAD algorithm!"

            };

    }


    /// <summary>
    /// AEAD Algorithms
    /// https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
    /// 
    /// AES Synthetic Initialization Vector Encryption (AES-SIV-CMAC-256)
    /// </summary>
    public enum AEADAlgorithms : UInt16
    {

        AES_128_GCM              = 1,      // [RFC5116]
        AES_256_GCM              = 2,      // [RFC5116]
        AES_128_CCM              = 3,      // [RFC5116]
        AES_256_CCM              = 4,      // [RFC5116]
        AES_128_GCM_8            = 5,      // [RFC5282]
        AES_256_GCM_8            = 6,      // [RFC5282]
        AES_128_GCM_12           = 7,      // [RFC5282]
        AES_256_GCM_12           = 8,      // [RFC5282]
        AES_128_CCM_SHORT        = 9,      // [RFC5282]
        AES_256_CCM_SHORT        = 10,     // [RFC5282]
        AES_128_CCM_SHORT_8      = 11,     // [RFC5282]
        AES_256_CCM_SHORT_8      = 12,     // [RFC5282]
        AES_128_CCM_SHORT_12     = 13,     // [RFC5282]
        AES_256_CCM_SHORT_12     = 14,     // [RFC5282]
        AES_SIV_CMAC_256         = 15,     // [RFC5297]
        AES_SIV_CMAC_384         = 16,     // [RFC5297]
        AES_SIV_CMAC_512         = 17,     // [RFC5297]
        AES_128_CCM_8            = 18,     // [RFC6655]
        AES_256_CCM_8            = 19,     // [RFC6655]
        AES_128_OCB_TAGLEN128    = 20,     // [RFC7253, Section 3.1]
        AES_128_OCB_TAGLEN96     = 21,     // [RFC7253, Section 3.1]
        AES_128_OCB_TAGLEN64     = 22,     // [RFC7253, Section 3.1]
        AES_192_OCB_TAGLEN128    = 23,     // [RFC7253, Section 3.1]
        AES_192_OCB_TAGLEN96     = 24,     // [RFC7253, Section 3.1]
        AES_192_OCB_TAGLEN64     = 25,     // [RFC7253, Section 3.1]
        AES_256_OCB_TAGLEN128    = 26,     // [RFC7253, Section 3.1]
        AES_256_OCB_TAGLEN96     = 27,     // [RFC7253, Section 3.1]
        AES_256_OCB_TAGLEN64     = 28,     // [RFC7253, Section 3.1]
        CHACHA20_POLY1305        = 29,     // [RFC8439]
        AES_128_GCM_SIV          = 30,     // [RFC8452]
        AES_256_GCM_SIV          = 31,     // [RFC8452]
        AEGIS128L                = 32,     // [draft-irtf-cfrg-aegis-aead-08]
        AEGIS256                 = 33,     // [draft-irtf-cfrg-aegis-aead-08]

        // 34-32767     Unassigned
        // 32768-65535  Reserved for Private Use   [RFC5116]

    }

}
