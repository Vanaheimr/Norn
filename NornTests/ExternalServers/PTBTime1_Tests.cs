/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Norn <https://www.github.com/Vanaheimr/Norn>
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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.Tests.NTS
{

    /// <summary>
    /// Test the NTS client against public NTS server 'ptbtime1.ptb.de'
    /// of the Physikalisch-Technische Bundesanstalt (PTB) in Braunschweig, Germany.
    /// https://zeit.ptb.de and https://time.ptb.de/files/ptb-ntp-services.json
    /// </summary>
    [TestFixture]
    [Category("External")]
    [Category("LiveNetwork")]
    [Explicit("Live public NTS/NTP server test; run explicitly when network reachability should be verified.")]
    public class PTBTime1_Tests()
        : ANTSServer_Tests(
              ServerName:                   DomainName.Parse("ptbtime1.ptb.de"),
              ExpectedReferenceIdentifier:  "PTB",
              ExpectedStratum:              1,
              Timeout:                      TimeSpan.FromSeconds(15)
          )
    { }

}
