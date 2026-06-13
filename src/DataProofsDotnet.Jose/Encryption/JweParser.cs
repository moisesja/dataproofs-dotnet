using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DataProofsDotnet.Jose.Json;

namespace DataProofsDotnet.Jose.Encryption;

/// <summary>
/// Parses JWE envelopes (PRD FR-14) — General JSON serialization (multi-recipient) and compact
/// serialization — and recovers the decrypted payload bytes. Dispatches on the protected-header
/// <c>alg</c>: <c>ECDH-ES+A256KW</c>, <c>ECDH-1PU+A256KW</c>, or standalone <c>A256KW</c>.
/// </summary>
/// <remarks>
/// Ported from didcomm-dotnet <c>DidComm.Jose.Encryption.JweParser</c> (PRD §1.4 item 2),
/// preserving the order-sensitive behavior contract: strict duplicate-member JSON parsing,
/// <c>crit</c> rejection (RFC 7516 §4.1.13), the <c>enc</c> allow-list and the 1PU
/// <c>A256CBC-HS512</c> pin (draft-04 §2.1 / didcomm FR-ENC-09), <c>apv</c> recipient-list
/// re-derivation before any ECDH (when <c>apv</c> is present — the didcomm commitment recipe;
/// generic JWEs without <c>apv</c> skip it), epk on-curve validation, the skid/apu agreement
/// rule, tag-bound 1PU KEK derivation, and zeroization of every secret in <c>finally</c>
/// blocks. The JWE <c>aad</c> member (JSON-serialization extra AAD, RFC 7516 §7.2.1) is
/// rejected as unsupported rather than silently mis-verified.
/// </remarks>
public static class JweParser
{
    /// <summary>Parse a General-JSON JWE and decrypt for the first recipient kid present in <paramref name="recipientKeys"/>.</summary>
    /// <param name="packed">JWE General JSON serialization.</param>
    /// <param name="recipientKeys">Lookup of recipient private (ECDH) or symmetric (A256KW) JWKs.</param>
    /// <param name="senderKeys">Lookup of sender public keys (ECDH-1PU only; pass <c>null</c> otherwise).</param>
    /// <param name="cryptoProvider">The JOSE crypto provider.</param>
    /// <exception cref="MalformedJoseException">When the JWE shape is invalid.</exception>
    /// <exception cref="JoseCryptoException">When no recipient could be unwrapped or decryption failed.</exception>
    public static JweParseResult Parse(
        string packed,
        IJweRecipientKeyResolver recipientKeys,
        IJweSenderKeyResolver? senderKeys,
        JoseCryptoProvider cryptoProvider)
    {
        ArgumentException.ThrowIfNullOrEmpty(packed);
        ArgumentNullException.ThrowIfNull(recipientKeys);
        ArgumentNullException.ThrowIfNull(cryptoProvider);

        var jwe = ParseStructure(packed);
        var header = JweProtectedHeader.Decode(jwe.ProtectedB64u);

        ValidateHeader(header);

        // Recipient-list commitment (didcomm FR-ENC-13 profile): when the ECDH paths carry an
        // 'apv', it must re-derive from the envelope's recipient kid list. Generic JOSE leaves
        // apv open, so an absent apv skips the check (the KDF then runs with empty PartyVInfo).
        if (!string.IsNullOrEmpty(header.Apv) && header.Alg is JoseAlgorithms.EcdhEsA256Kw or JoseAlgorithms.Ecdh1PuA256Kw)
        {
            var apvRecomputed = ApvComputer.Compute(jwe.Recipients.Select(r => r.Kid));
            if (!string.Equals(apvRecomputed, header.Apv, StringComparison.Ordinal))
                throw new JoseCryptoException(
                    $"JWE 'apv' mismatch (FR-ENC-13). Header={header.Apv}, recomputed from recipient kids={apvRecomputed}.");
        }

        var presentKids = recipientKeys.FindPresent(jwe.Recipients.Select(r => r.Kid));
        if (presentKids.Count == 0)
            throw new JoseCryptoException("No recipient kid in the JWE matches a held private key.");

        var matchedRecipient = jwe.Recipients.First(r => presentKids.Contains(r.Kid));
        var recipientJwk = recipientKeys.TryGet(matchedRecipient.Kid)
            ?? throw new JoseCryptoException($"Key lookup returned no key for kid '{matchedRecipient.Kid}'.");

        return DecryptForRecipient(jwe, header, matchedRecipient, recipientJwk, senderKeys, cryptoProvider);
    }

    /// <summary>
    /// Parse a compact-serialization JWE
    /// (<c>header.encryptedKey.iv.ciphertext.tag</c>) and decrypt with the supplied key.
    /// </summary>
    /// <param name="compact">The compact JWE string.</param>
    /// <param name="recipientKey">
    /// The recipient's private ECDH JWK (for <c>ECDH-ES+A256KW</c>/<c>ECDH-1PU+A256KW</c>) or
    /// the symmetric <c>kty="oct"</c> KEK JWK (for <c>A256KW</c>).
    /// </param>
    /// <param name="senderKeys">Lookup of sender public keys (ECDH-1PU only; pass <c>null</c> otherwise).</param>
    /// <param name="cryptoProvider">The JOSE crypto provider.</param>
    public static JweParseResult ParseCompact(
        string compact,
        Jwk recipientKey,
        IJweSenderKeyResolver? senderKeys,
        JoseCryptoProvider cryptoProvider)
    {
        ArgumentException.ThrowIfNullOrEmpty(compact);
        ArgumentNullException.ThrowIfNull(recipientKey);
        ArgumentNullException.ThrowIfNull(cryptoProvider);

        var segments = compact.Split('.');
        if (segments.Length != 5)
            throw new MalformedJoseException($"Compact JWE must have exactly 5 dot-separated segments; got {segments.Length}.");
        if (segments[0].Length == 0)
            throw new MalformedJoseException("Compact JWE protected-header segment is empty.");
        if (segments[1].Length == 0)
            throw new MalformedJoseException("Compact JWE encrypted-key segment is empty (direct key agreement / direct encryption is not supported).");

        var header = JweProtectedHeader.Decode(segments[0]);
        ValidateHeader(header);

        var kid = header.Kid ?? recipientKey.Kid ?? string.Empty;
        var jwe = new ParsedJwe(
            segments[0],
            [new ParsedRecipient(kid, DecodeB64u(segments[1], "encrypted_key"))],
            DecodeB64u(segments[2], "iv"),
            DecodeB64u(segments[3], "ciphertext"),
            DecodeB64u(segments[4], "tag"));

        return DecryptForRecipient(jwe, header, jwe.Recipients[0], recipientKey, senderKeys, cryptoProvider);
    }

    /// <summary>
    /// Read just enough of a packed General-JSON JWE to surface the recipient kid list and (for
    /// the authenticated path) the <c>skid</c> — no crypto is performed. Lets callers pre-warm
    /// key resolution before invoking the full <see cref="Parse"/>.
    /// </summary>
    /// <param name="packed">JWE General JSON serialization.</param>
    /// <returns>The structural metadata; never <c>null</c>. <c>Skid</c> is <c>null</c> for anonymous-sender envelopes.</returns>
    /// <exception cref="MalformedJoseException">When the input is not a JWE-shaped JSON object.</exception>
    public static JwePeekResult PeekRecipients(string packed)
    {
        ArgumentException.ThrowIfNullOrEmpty(packed);
        var jwe = ParseStructure(packed);
        var header = JweProtectedHeader.Decode(jwe.ProtectedB64u);
        return new JwePeekResult(
            Algorithm: header.Alg,
            Skid: string.IsNullOrEmpty(header.Skid) ? null : header.Skid,
            RecipientKids: jwe.Recipients.Select(r => r.Kid).ToArray());
    }

    private static void ValidateHeader(JweProtectedHeader header)
    {
        // RFC 7516 §4.1.13: a 'crit' header naming extensions the recipient doesn't understand MUST be
        // rejected. This implementation understands no JWE crit extensions, so any 'crit' is fatal.
        if (header.AdditionalMembers is not null && header.AdditionalMembers.ContainsKey("crit"))
            throw new MalformedJoseException("JWE protected header marks an unsupported extension critical ('crit').");

        // Content-encryption allow-list. Reject any 'enc' outside the supported set before deriving
        // a key, and pin the 1PU key-wrap mode to A256CBC-HS512 — draft-madden-04 §2.1 authorizes
        // only the key-committing CBC-HMAC family for non-direct 1PU (didcomm FR-ENC-09). Mirrors
        // the send-side restriction; stops an attacker steering the receiver into an unintended
        // AEAD and avoids an uncaught NotSupportedException surfacing from the AEAD dispatch later.
        if (!JoseAlgorithms.IsSupportedContentEncryption(header.Enc))
            throw new JoseCryptoException($"Unsupported JWE 'enc' '{header.Enc}'.");
        if (string.Equals(header.Alg, JoseAlgorithms.Ecdh1PuA256Kw, StringComparison.Ordinal) &&
            !string.Equals(header.Enc, JoseAlgorithms.A256CbcHs512, StringComparison.Ordinal))
            throw new JoseCryptoException(
                $"ECDH-1PU key wrap requires enc=A256CBC-HS512 (draft-madden-04 §2.1 / FR-ENC-09); got '{header.Enc}'.");
    }

    private static JweParseResult DecryptForRecipient(
        ParsedJwe jwe,
        JweProtectedHeader header,
        ParsedRecipient matchedRecipient,
        Jwk recipientJwk,
        IJweSenderKeyResolver? senderKeys,
        JoseCryptoProvider cryptoProvider)
    {
        var aad = Encoding.ASCII.GetBytes(jwe.ProtectedB64u);
        byte[] kek;
        string senderKid;

        switch (header.Alg)
        {
            case JoseAlgorithms.A256Kw:
            {
                senderKid = string.Empty;
                kek = DecodeOctKey(recipientJwk);
                break;
            }
            case JoseAlgorithms.EcdhEsA256Kw:
            {
                senderKid = string.Empty;
                var ephemeralPubBytes = ExtractEphemeralPublicKey(RequireEpk(header), recipientJwk);
                var apvBytes = string.IsNullOrEmpty(header.Apv) ? [] : DecodeB64u(header.Apv, "apv");
                var apuBytes = string.IsNullOrEmpty(header.Apu) ? [] : DecodeB64u(header.Apu, "apu");
                var recipientPrivBytes = DecodePrivateKey(recipientJwk);
                try
                {
                    kek = EcdhEsKdf.DeriveKeyForReceiver(
                        cryptoProvider.UnderlyingProvider,
                        KeyTypeMapper.FromCurveForKeyAgreement(recipientJwk.Crv!),
                        recipientPrivBytes,
                        ephemeralPubBytes,
                        Encoding.ASCII.GetBytes(header.Alg),
                        apuBytes,
                        apvBytes,
                        keyDataLen: 32);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(recipientPrivBytes);
                }
                break;
            }
            case JoseAlgorithms.Ecdh1PuA256Kw:
            {
                if (senderKeys is null)
                    throw new JoseCryptoException("ECDH-1PU unpack requires a sender-key lookup; none was supplied.");

                // Resolve the sender key id from 'skid' when present, else from 'apu'
                // (= base64url(utf8(skid)); the 1PU draft does not mandate 'skid'). When BOTH are
                // present they MUST agree, so a peer cannot present one sender identity in 'skid' and
                // a different one in 'apu' (didcomm FR-ENC-14/17).
                string skid;
                if (!string.IsNullOrEmpty(header.Skid))
                {
                    skid = header.Skid;
                    if (!string.IsNullOrEmpty(header.Apu) &&
                        !string.Equals(header.Apu, ApuComputer.Compute(skid), StringComparison.Ordinal))
                        throw new JoseCryptoException("ECDH-1PU 'apu' does not match base64url(skid) (FR-ENC-14).");
                }
                else if (!string.IsNullOrEmpty(header.Apu))
                {
                    skid = Encoding.UTF8.GetString(DecodeB64u(header.Apu, "apu"));
                }
                else
                {
                    throw new JoseCryptoException("ECDH-1PU JWE is missing both 'skid' and 'apu' in the protected header (FR-ENC-17): sender identity unresolved.");
                }

                var senderPublicJwk = senderKeys.TryGet(skid)
                    ?? throw new JoseCryptoException($"Could not resolve sender public key for skid '{skid}'.");
                if (!string.Equals(senderPublicJwk.Crv, recipientJwk.Crv, StringComparison.Ordinal))
                    throw new JoseCryptoException(
                        $"ECDH-1PU sender key curve ({senderPublicJwk.Crv}) does not match recipient curve ({recipientJwk.Crv}).");

                senderKid = skid;
                var ephemeralPubBytes = ExtractEphemeralPublicKey(RequireEpk(header), recipientJwk);
                var (_, senderPubBytes) = JwkConversion.ExtractPublicKey(senderPublicJwk);
                var apvBytes = string.IsNullOrEmpty(header.Apv) ? [] : DecodeB64u(header.Apv, "apv");
                // 1PU draft-04 §2.3: PartyUInfo is the UTF-8 bytes of the sender skid (the decoded
                // 'apu'); fall back to utf8(skid) when the peer omitted 'apu'.
                var apuBytes = string.IsNullOrEmpty(header.Apu)
                    ? Encoding.UTF8.GetBytes(skid)
                    : DecodeB64u(header.Apu, "apu");
                var recipientPrivBytes = DecodePrivateKey(recipientJwk);
                try
                {
                    kek = Ecdh1PuKdf.DeriveKeyForReceiver(
                        cryptoProvider.UnderlyingProvider,
                        KeyTypeMapper.FromCurveForKeyAgreement(recipientJwk.Crv!),
                        recipientPrivBytes,
                        ephemeralPubBytes,
                        senderPubBytes,
                        Encoding.ASCII.GetBytes(header.Alg),
                        apuBytes,
                        apvBytes,
                        jwe.Tag,
                        keyDataLen: 32);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(recipientPrivBytes);
                }
                break;
            }
            default:
                throw new JoseCryptoException($"Unsupported JWE 'alg' '{header.Alg}'.");
        }

        byte[] cek;
        try
        {
            cek = cryptoProvider.KeyUnwrap(JoseAlgorithms.A256Kw, kek, matchedRecipient.EncryptedKey);
        }
        catch (CryptographicException ex)
        {
            throw new JoseCryptoException($"AES-KW unwrap failed for recipient kid '{matchedRecipient.Kid}'.", ex);
        }
        catch (ArgumentException ex)
        {
            throw new MalformedJoseException($"JWE 'encrypted_key' has an invalid length for AES-KW (recipient kid '{matchedRecipient.Kid}').", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }

        byte[] plaintext;
        try
        {
            plaintext = cryptoProvider.AeadDecrypt(header.Enc, cek, jwe.Iv, aad, jwe.Ciphertext, jwe.Tag);
        }
        catch (CryptographicException ex)
        {
            throw new JoseCryptoException($"AEAD decryption failed ('{header.Enc}').", ex);
        }
        catch (ArgumentException ex)
        {
            throw new MalformedJoseException($"JWE 'iv' or 'tag' has an invalid length for '{header.Enc}'.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }

        return new JweParseResult(
            Plaintext: plaintext,
            Algorithm: header.Alg,
            ContentEncryption: header.Enc,
            RecipientKid: matchedRecipient.Kid,
            AllRecipientKids: jwe.Recipients.Select(r => r.Kid).ToArray(),
            SenderKid: senderKid,
            IsAuthenticated: !string.IsNullOrEmpty(senderKid));
    }

    private static Jwk RequireEpk(JweProtectedHeader header)
        => header.Epk ?? throw new MalformedJoseException("JWE protected header is missing the 'epk' member required by its ECDH 'alg'.");

    private static byte[] DecodePrivateKey(Jwk recipientJwk)
    {
        if (string.IsNullOrEmpty(recipientJwk.D))
            throw new JoseCryptoException($"Recipient JWK for kid '{recipientJwk.Kid}' is missing private-key material ('d').");
        try
        {
            return Base64Url.Decode(recipientJwk.D);
        }
        catch (FormatException ex)
        {
            throw new MalformedJoseException("Recipient JWK 'd' is not valid base64url.", ex);
        }
    }

    private static byte[] DecodeOctKey(Jwk kekJwk)
    {
        if (!string.Equals(kekJwk.Kty, "oct", StringComparison.Ordinal) || string.IsNullOrEmpty(kekJwk.K))
            throw new JoseCryptoException("A256KW decryption requires a kty=\"oct\" JWK with 'k'.");
        byte[] kek;
        try
        {
            kek = Base64Url.Decode(kekJwk.K);
        }
        catch (FormatException ex)
        {
            throw new MalformedJoseException("A256KW key-encryption key 'k' is not valid base64url.", ex);
        }
        if (kek.Length != 32)
            throw new JoseCryptoException($"A256KW key-encryption key must be 32 bytes; got {kek.Length}.");
        return kek;
    }

    private static byte[] ExtractEphemeralPublicKey(Jwk epk, Jwk recipientJwk)
    {
        if (!string.Equals(recipientJwk.Crv, epk.Crv, StringComparison.Ordinal))
            throw new JoseCryptoException(
                $"Recipient key curve ({recipientJwk.Crv}) does not match JWE 'epk' curve ({epk.Crv}).");
        try
        {
            var (_, bytes) = JwkConversion.ExtractPublicKey(epk);
            return bytes;
        }
        catch (CryptographicException ex)
        {
            // Off-curve epk caught by NetCrypto's EcPointValidator (invalid-curve defense).
            throw new JoseCryptoException("JWE 'epk' is not on the asserted curve.", ex);
        }
        catch (ArgumentException ex)
        {
            throw new JoseCryptoException("JWE 'epk' JWK is malformed.", ex);
        }
    }

    private static ParsedJwe ParseStructure(string packed)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(packed, JoseJson.StrictDocument);
        }
        catch (JsonException ex)
        {
            throw new MalformedJoseException("JWE is not valid JSON.", ex);
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw new MalformedJoseException("JWE root is not a JSON object.");

            // RFC 7516 §7.2.1 'aad' (extra authenticated data for the JSON serialization) changes
            // the AAD construction to protected || '.' || aad. This implementation does not
            // support it; silently ignoring it would mis-verify, so fail closed.
            if (root.TryGetProperty("aad", out _))
                throw new MalformedJoseException("JWE 'aad' member (JSON-serialization additional authenticated data) is not supported.");

            // Every required member is read with an explicit type check so a missing or mistyped
            // member (e.g. a numeric 'iv') yields a MalformedJoseException — the parser's documented
            // failure — rather than a raw KeyNotFoundException / ArgumentNullException at the boundary.
            var protectedB64u = RequireString(root, "protected");
            var iv = DecodeB64u(RequireString(root, "iv"), "iv");
            var ciphertext = DecodeB64u(RequireString(root, "ciphertext"), "ciphertext");
            var tag = DecodeB64u(RequireString(root, "tag"), "tag");

            if (!root.TryGetProperty("recipients", out var recipientsEl) || recipientsEl.ValueKind != JsonValueKind.Array)
                throw new MalformedJoseException("JWE is missing the 'recipients' array.");

            var recipients = new List<ParsedRecipient>();
            foreach (var rec in recipientsEl.EnumerateArray())
            {
                if (rec.ValueKind != JsonValueKind.Object ||
                    !rec.TryGetProperty("header", out var hdr) || hdr.ValueKind != JsonValueKind.Object)
                    throw new MalformedJoseException("JWE recipient is missing its 'header' object.");
                var kid = RequireString(hdr, "kid");
                var encryptedKey = DecodeB64u(RequireString(rec, "encrypted_key"), "encrypted_key");
                recipients.Add(new ParsedRecipient(kid, encryptedKey));
            }

            if (recipients.Count == 0)
                throw new MalformedJoseException("JWE has zero recipients.");

            return new ParsedJwe(protectedB64u, recipients, iv, ciphertext, tag);
        }
    }

    private static string RequireString(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var el) || el.ValueKind != JsonValueKind.String)
            throw new MalformedJoseException($"JWE is missing required string member '{name}'.");
        return el.GetString()!;
    }

    private static byte[] DecodeB64u(string value, string name)
    {
        try
        {
            return Base64Url.Decode(value);
        }
        catch (FormatException ex)
        {
            throw new MalformedJoseException($"JWE member '{name}' is not valid base64url.", ex);
        }
    }

    private sealed record ParsedRecipient(string Kid, byte[] EncryptedKey);
    private sealed record ParsedJwe(string ProtectedB64u, IReadOnlyList<ParsedRecipient> Recipients, byte[] Iv, byte[] Ciphertext, byte[] Tag);
}

/// <summary>Outcome of a successful JWE parse.</summary>
/// <param name="Plaintext">Decrypted bytes.</param>
/// <param name="Algorithm">JOSE <c>alg</c> (<c>ECDH-ES+A256KW</c>, <c>ECDH-1PU+A256KW</c>, or <c>A256KW</c>).</param>
/// <param name="ContentEncryption">JOSE <c>enc</c>.</param>
/// <param name="RecipientKid">The recipient kid whose key actually unwrapped the CEK.</param>
/// <param name="AllRecipientKids">Every recipient kid carried in the envelope.</param>
/// <param name="SenderKid">Sender <c>skid</c> for the authenticated (ECDH-1PU) path; empty string otherwise.</param>
/// <param name="IsAuthenticated">True for ECDH-1PU (authenticated sender); false otherwise.</param>
public sealed record JweParseResult(
    byte[] Plaintext,
    string Algorithm,
    string ContentEncryption,
    string RecipientKid,
    IReadOnlyList<string> AllRecipientKids,
    string SenderKid,
    bool IsAuthenticated);

/// <summary>Structural peek into a JWE — kids only, no decryption.</summary>
/// <param name="Algorithm">Protected-header <c>alg</c> (e.g. <c>ECDH-1PU+A256KW</c>).</param>
/// <param name="Skid">Sender key identifier for the authenticated path; <c>null</c> otherwise.</param>
/// <param name="RecipientKids">Recipient kids in declared order.</param>
public sealed record JwePeekResult(string Algorithm, string? Skid, IReadOnlyList<string> RecipientKids);
