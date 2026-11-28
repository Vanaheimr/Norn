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

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using org.GraphDefined.Vanaheimr.Norn.NTP;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace org.GraphDefined.Vanaheimr.Norn.NTPv5
{

    /// <summary>
    /// What verifying the NTS of an NTPv5 request established: the keys of its cookie, and
    /// what of the request the authenticator covers.
    /// </summary>
    /// <param name="C2SKey">The client-to-server key of the cookie.</param>
    /// <param name="S2CKey">The server-to-client key of the cookie, to seal the response with.</param>
    /// <param name="AEADAlgorithm">The algorithm of the cookie.</param>
    /// <param name="UniqueIdentifier">The Unique Identifier of the request.</param>
    /// <param name="CookieLength">The octets of the Value of the request's NTS Cookie field.</param>
    /// <param name="Placeholders">The placeholders of the request that are as long as its cookie.</param>
    /// <param name="AuthenticatorIndex">Where among the request's extension fields the authenticator is: the ones before it are authenticated.</param>
    public sealed record NTPv5NTSSession(Byte[]          C2SKey,
                                         Byte[]          S2CKey,
                                         AEADAlgorithms  AEADAlgorithm,
                                         Byte[]          UniqueIdentifier,
                                         Int32           CookieLength,
                                         Int32           Placeholders,
                                         Int32           AuthenticatorIndex);


    /// <summary>
    /// The server's side of NTS for NTPv5: its master keys to unseal a cookie with, and the
    /// current one to seal new ones with.
    /// </summary>
    /// <param name="MasterKeys">The master keys a cookie may have been sealed under.</param>
    /// <param name="CurrentMasterKey">The master key to seal new cookies under.</param>
    /// <param name="TimeProvider">The clock the cookies are stamped with, the one the master keys rotate on.</param>
    /// <param name="MaxCookies">The most cookies one response carries.</param>
    public sealed class NTPv5NTSService(ConcurrentDictionary<UInt64, MasterKey>  MasterKeys,
                                        Func<MasterKey>                          CurrentMasterKey,
                                        TimeProvider?                            TimeProvider   = null,
                                        Int32                                    MaxCookies     = 8)
    {

        /// <summary>
        /// The most cookies one response carries.
        /// </summary>
        public Int32 MaxCookies { get; } = Math.Max(0, MaxCookies);


        /// <summary>
        /// Verify the NTS of an NTPv5 request, as RFC 8915 § 5.7 has a server do and § 11 of
        /// the draft carries over.
        /// </summary>
        public Boolean TryVerify(ReadOnlySpan<Byte>                         Datagram,
                                 NTPv5Packet                                Request,
                                 [NotNullWhen(true)]  out NTPv5NTSSession?  Session,
                                 [NotNullWhen(false)] out String?           ErrorResponse)

            => NTPv5NTS.TryVerifyRequest(Datagram, Request, MasterKeys, out Session, out ErrorResponse);


        /// <summary>
        /// New cookies for the session, each as the octets of an NTS Cookie extension field -
        /// the plaintext the authenticator of the response encrypts.
        /// </summary>
        public IReadOnlyList<Byte[]> MintCookies(NTPv5NTSSession  Session,
                                                 Int32            Count)

            => Count <= 0
                   ? []
                   : [.. CurrentMasterKey().
                             GenerateNTSCookieExtensions(NumberOfCookies:  (UInt16) Math.Min(Count, UInt16.MaxValue),
                                                         C2SKey:           Session.C2SKey,
                                                         S2CKey:           Session.S2CKey,
                                                         AEADAlgorithm:    Session.AEADAlgorithm,
                                                         TimeProvider:     TimeProvider,
                                                         NextProtocol:     NTPv5Draft.NTSNextProtocolId).
                             Select(cookie => cookie.ToByteArray())];

    }


    /// <summary>
    /// NTS for NTPv5, draft-ietf-ntp-ntpv5-10 § 11: the extension fields of RFC 8915 § 5 in an
    /// NTPv5 message, for both ends.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The fields are those of NTPv4 and so is their meaning: a Unique Identifier the response
    /// echoes, the cookie, placeholders for the cookies to come back, and the authenticator
    /// over the header and every field before it, which in a response also carries the new
    /// cookies encrypted. The keys are not those of NTPv4, though: the key exchange agreed to
    /// NTPv5, and RFC 8915 § 5.1 puts the protocol into the exporter context.
    /// </para>
    /// <para>
    /// Their Lengths stay multiples of 4, as RFC 7822 has them in NTPv4 and as NTPv5 § 7 allows:
    /// a field of NTPv4 "can be used in NTPv5 as specified for NTPv4".
    /// </para>
    /// </remarks>
    public static class NTPv5NTS
    {

        #region Data

        /// <summary>
        /// RFC 8915 § 5.3: the shortest Unique Identifier.
        /// </summary>
        public const Int32 MinimumUniqueIdentifierLength = 32;

        /// <summary>
        /// The longest Unique Identifier a NAK echoes, so that an unauthenticated client cannot
        /// make it larger than it has to be.
        /// </summary>
        public const Int32 MaximumEchoedUniqueIdentifierLength = 64;

        /// <summary>
        /// The tag every AEAD of NTS adds to its plaintext: the synthetic IV of AES-SIV, the
        /// tag of AES-GCM-SIV, 16 octets either way.
        /// </summary>
        public const Int32 TagLength = 16;

        #endregion


        #region IsNTS(Type) / IsNTSRequest(Request)

        /// <summary>
        /// Whether the given type is one of the four NTS extension fields.
        /// </summary>
        public static Boolean IsNTS(NTPv5ExtensionTypes Type)

            => Type is NTPv5ExtensionTypes.UniqueIdentifier
                    or NTPv5ExtensionTypes.NTSCookie
                    or NTPv5ExtensionTypes.NTSCookiePlaceholder
                    or NTPv5ExtensionTypes.NTSAuthenticator;

        /// <summary>
        /// Whether the request tries NTS at all: one that does not is a plain one.
        /// </summary>
        public static Boolean IsNTSRequest(NTPv5Packet Request)

            => Request.ExtensionFields.Any(field => IsNTS(field.Type));

        #endregion

        #region OffsetOf(Packet, Index)

        /// <summary>
        /// Where in the message the extension field of the given index begins.
        /// </summary>
        public static Int32 OffsetOf(NTPv5Packet  Packet,
                                     Int32        Index)
        {

            var offset = NTPv5Packet.HeaderLength;

            for (var i = 0; i < Index; i++)
                offset += Packet.ExtensionFields[i].PaddedLength;

            return offset;

        }

        #endregion

        #region (static) Padded(Value)

        /// <summary>
        /// The given value padded with zeros to a multiple of 4, as an NTS field carries it.
        /// </summary>
        public static Byte[] Padded(ReadOnlySpan<Byte> Value)
        {
            var padded = new Byte[(Value.Length + 3) & ~3];
            Value.CopyTo(padded);
            return padded;
        }

        #endregion


        #region TryVerifyRequest(Datagram, Request, MasterKeys, out Session, out ErrorResponse)

        /// <summary>
        /// Verify the NTS of an NTPv5 request: exactly one Unique Identifier of at least 32
        /// octets, exactly one cookie, both before exactly one authenticator; a cookie this
        /// server sealed, for NTPv5; and an authenticator that verifies under its key over the
        /// header and everything before it.
        /// </summary>
        public static Boolean TryVerifyRequest(ReadOnlySpan<Byte>                         Datagram,
                                               NTPv5Packet                                Request,
                                               ConcurrentDictionary<UInt64, MasterKey>    MasterKeys,
                                               [NotNullWhen(true)]  out NTPv5NTSSession?  Session,
                                               [NotNullWhen(false)] out String?           ErrorResponse)
        {

            Session        = null;
            ErrorResponse  = null;

            var fields          = Request.ExtensionFields;
            var authenticators  = fields.Count(field => field.Type == NTPv5ExtensionTypes.NTSAuthenticator);

            if (authenticators != 1)
            {
                ErrorResponse = $"An NTS request carries exactly one authenticator, this one {authenticators}!";
                return false;
            }

            var authenticatorIndex = -1;

            for (var i = 0; i < fields.Count; i++)
                if (fields[i].Type == NTPv5ExtensionTypes.NTSAuthenticator)
                    authenticatorIndex = i;

            // What comes after the authenticator is not covered by it, and none of what NTS
            // depends on may be there.
            if (fields.Skip(authenticatorIndex + 1).Any(field => IsNTS(field.Type)))
            {
                ErrorResponse = "An NTS field after the authenticator is not authenticated!";
                return false;
            }

            var before            = fields.Take(authenticatorIndex).ToArray();
            var uniqueIdentifiers = before.Where(field => field.Type == NTPv5ExtensionTypes.UniqueIdentifier).ToArray();
            var cookies           = before.Where(field => field.Type == NTPv5ExtensionTypes.NTSCookie).ToArray();

            if (uniqueIdentifiers.Length != 1 || uniqueIdentifiers[0].Value.Length < MinimumUniqueIdentifierLength)
            {
                ErrorResponse = $"An NTS request carries exactly one Unique Identifier of at least {MinimumUniqueIdentifierLength} octets!";
                return false;
            }

            if (cookies.Length != 1)
            {
                ErrorResponse = $"An NTS request carries exactly one cookie, this one {cookies.Length}!";
                return false;
            }

            // Unsealing authenticates the cookie under this server's master key and checks it
            // against that key's validity window.
            if (!NTSCookie.TryParse(cookies[0].Value, MasterKeys, out var cookie, out var cookieError))
            {
                ErrorResponse = "Invalid NTS cookie: " + cookieError;
                return false;
            }

            // The keys of an NTPv4 cookie come from the exporter context of NTPv4.
            if (cookie.NextProtocol != NTPv5Draft.NTSNextProtocolId)
            {
                ErrorResponse = $"The NTS cookie was issued for next protocol {cookie.NextProtocol}, not for NTPv5!";
                return false;
            }

            var associatedData  = Datagram[..OffsetOf(Request, authenticatorIndex)];
            var decrypted       = new List<NTPExtension>();

            if (!AuthenticatorAndEncryptedExtension.TryParse(fields[authenticatorIndex].Value,
                                                             associatedData,
                                                             ref decrypted,
                                                             cookie.C2SKey,
                                                             out _,
                                                             out var authenticatorError,
                                                             cookie.AEADAlgorithm))
            {
                ErrorResponse = "The NTS authenticator does not verify: " + authenticatorError;
                return false;
            }

            Session = new NTPv5NTSSession(
                          C2SKey:              cookie.C2SKey,
                          S2CKey:              cookie.S2CKey,
                          AEADAlgorithm:       cookie.AEADAlgorithm,
                          UniqueIdentifier:    uniqueIdentifiers[0].Value,
                          CookieLength:        cookies[0].Value.Length,

                          // RFC 8915 § 5.5: a placeholder counts only as long as the cookie,
                          // so that a client cannot make the response larger with longer ones.
                          Placeholders:        before.Count(field => field.Type         == NTPv5ExtensionTypes.NTSCookiePlaceholder &&
                                                                     field.Value.Length == cookies[0].Value.Length),
                          AuthenticatorIndex:  authenticatorIndex
                      );

            return true;

        }

        #endregion

        #region AuthenticatorLength(AEADAlgorithm, PlaintextLength)

        /// <summary>
        /// The octets of an authenticator field over a plaintext of the given length, header
        /// included: Nonce Length, Ciphertext Length, the nonce and the ciphertext, each padded
        /// to 4 (RFC 8915 § 5.6).
        /// </summary>
        public static Int32 AuthenticatorLength(AEADAlgorithms  AEADAlgorithm,
                                                Int32           PlaintextLength)

            => 4 + 4 +
               ((NTSAEAD.NonceLength(AEADAlgorithm) ?? 16) + 3 & ~3) +
               ((PlaintextLength + TagLength)               + 3 & ~3);

        #endregion

        #region Seal(AssociatedData, Key, AEADAlgorithm, Plaintext = default)

        /// <summary>
        /// The authenticator over the given octets - the message so far - with the given
        /// plaintext encrypted in it.
        /// </summary>
        public static NTPv5ExtensionField Seal(ReadOnlySpan<Byte>  AssociatedData,
                                               Byte[]              Key,
                                               AEADAlgorithms      AEADAlgorithm,
                                               ReadOnlySpan<Byte>  Plaintext   = default)

            => new (NTPv5ExtensionTypes.NTSAuthenticator,
                    AuthenticatorAndEncryptedExtension.Create(Key,
                                                              AssociatedData,
                                                              Plaintext,
                                                              null,
                                                              AEADAlgorithm).Value);

        #endregion


        #region BuildRequest(Request, C2SKey, AEADAlgorithm, Cookie, UniqueIdentifier = null, Placeholders = 0, AfterAuthenticator = null)

        /// <summary>
        /// An NTS-protected NTPv5 request, as a client sends it: the given request with a
        /// Unique Identifier, the cookie and the placeholders after its own fields, then the
        /// authenticator over all of it, then whatever goes after the authenticator - the
        /// Correction field of § 7.7, which is never authenticated.
        /// </summary>
        /// <param name="Request">The request without NTS, its Draft Identification among its fields.</param>
        /// <param name="C2SKey">The client-to-server key of the key exchange.</param>
        /// <param name="AEADAlgorithm">The algorithm of the key exchange.</param>
        /// <param name="Cookie">A cookie of the key exchange for NTPv5.</param>
        /// <param name="UniqueIdentifier">The Unique Identifier, by default 32 random octets.</param>
        /// <param name="Placeholders">How many placeholders to add, for as many cookies more.</param>
        /// <param name="AfterAuthenticator">Fields after the authenticator.</param>
        public static Byte[] BuildRequest(NTPv5Packet                        Request,
                                          Byte[]                             C2SKey,
                                          AEADAlgorithms                     AEADAlgorithm,
                                          Byte[]                             Cookie,
                                          Byte[]?                            UniqueIdentifier     = null,
                                          Int32                              Placeholders         = 0,
                                          IEnumerable<NTPv5ExtensionField>?  AfterAuthenticator   = null)
        {

            var cookie  = Padded(Cookie);

            var fields  = new List<NTPv5ExtensionField>(Request.ExtensionFields) {
                              new (NTPv5ExtensionTypes.UniqueIdentifier, UniqueIdentifier ?? RandomNumberGenerator.GetBytes(MinimumUniqueIdentifierLength)),
                              new (NTPv5ExtensionTypes.NTSCookie,        cookie)
                          };

            for (var i = 0; i < Placeholders; i++)
                fields.Add(new NTPv5ExtensionField(NTPv5ExtensionTypes.NTSCookiePlaceholder, new Byte[cookie.Length]));

            var authenticated  = WithFields(Request, fields).ToByteArray();
            var authenticator  = Seal(authenticated, C2SKey, AEADAlgorithm);

            fields.Add(authenticator);
            fields.AddRange(AfterAuthenticator ?? []);

            return WithFields(Request, fields).ToByteArray();

        }

        #endregion

        #region TryVerifyResponse(Response, UniqueIdentifier, S2CKey, AEADAlgorithm, out Packet, out Cookies, out ErrorResponse)

        /// <summary>
        /// Verify the NTS of an NTPv5 response, as a client must before it believes a word of
        /// it: its Unique Identifier is the request's, exactly one authenticator verifies under
        /// the server-to-client key over everything before it, and the new cookies are what it
        /// decrypts to.
        /// </summary>
        public static Boolean TryVerifyResponse(ReadOnlySpan<Byte>                     Response,
                                                Byte[]                                 UniqueIdentifier,
                                                Byte[]                                 S2CKey,
                                                AEADAlgorithms                         AEADAlgorithm,
                                                [NotNullWhen(true)]  out NTPv5Packet?  Packet,
                                                out IReadOnlyList<Byte[]>              Cookies,
                                                [NotNullWhen(false)] out String?       ErrorResponse)
        {

            Cookies = [];

            if (!NTPv5Packet.TryParse(Response, out Packet, out ErrorResponse))
                return false;

            var fields          = Packet.ExtensionFields;
            var authenticators  = fields.Count(field => field.Type == NTPv5ExtensionTypes.NTSAuthenticator);

            if (authenticators != 1)
            {
                ErrorResponse = $"An NTS response carries exactly one authenticator, this one {authenticators}!";
                Packet        = null;
                return false;
            }

            var authenticatorIndex = fields.ToList().FindIndex(field => field.Type == NTPv5ExtensionTypes.NTSAuthenticator);

            var uniqueIdentifiers  = fields.Take(authenticatorIndex).Where(field => field.Type == NTPv5ExtensionTypes.UniqueIdentifier).ToArray();

            if (uniqueIdentifiers.Length != 1 || !uniqueIdentifiers[0].Value.AsSpan().SequenceEqual(UniqueIdentifier))
            {
                ErrorResponse = "The response does not echo the Unique Identifier of the request!";
                Packet        = null;
                return false;
            }

            var decrypted = new List<NTPExtension>();

            if (!AuthenticatorAndEncryptedExtension.TryParse(fields[authenticatorIndex].Value,
                                                             Response[..OffsetOf(Packet, authenticatorIndex)],
                                                             ref decrypted,
                                                             S2CKey,
                                                             out var authenticator,
                                                             out var authenticatorError,
                                                             AEADAlgorithm))
            {
                ErrorResponse = "The NTS authenticator of the response does not verify: " + authenticatorError;
                Packet        = null;
                return false;
            }

            Cookies = [.. authenticator.EncryptedExtensions.
                              Where (extension => extension.Type == ExtensionTypes.NTSCookie).
                              Select(extension => extension.Value)];

            return true;

        }

        #endregion


        #region (private) WithFields(Packet, Fields)

        private static NTPv5Packet WithFields(NTPv5Packet                       Packet,
                                              IEnumerable<NTPv5ExtensionField>  Fields)

            => new (Mode:               Packet.Mode,
                    Stratum:            Packet.Stratum,
                    Poll:               Packet.Poll,
                    Precision:          Packet.Precision,
                    RootDelay:          Packet.RootDelay,
                    RootDispersion:     Packet.RootDispersion,
                    Timescale:          Packet.Timescale,
                    Era:                Packet.Era,
                    Flags:              Packet.Flags,
                    ServerCookie:       Packet.ServerCookie,
                    ClientCookie:       Packet.ClientCookie,
                    ReceiveTimestamp:   Packet.ReceiveTimestamp,
                    TransmitTimestamp:  Packet.TransmitTimestamp,
                    ExtensionFields:    Fields,
                    Reserved:           Packet.Reserved);

        #endregion

    }

}
