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
        ValidateRecipientCommitment(jwe, header);

        var (matchedRecipient, recipientJwk) = SelectRecipientOrDecoy(jwe, header, recipientKeys);

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
    /// Parse a General-JSON JWE and decrypt with an <b>opaque</b> recipient key (issue #13) — one
    /// that derives the ECDH shared secret without exposing its private scalar (HSM, KMS, keychain,
    /// or <c>NetCrypto.IKeyStore</c>). Use this for the <c>ECDH-ES+A256KW</c> / <c>ECDH-1PU+A256KW</c>
    /// algorithms; <c>A256KW</c> (symmetric) has no ECDH and is served by the synchronous
    /// <see cref="Parse"/>.
    /// </summary>
    /// <param name="packed">JWE General JSON serialization.</param>
    /// <param name="recipientKey">The recipient's opaque ECDH key. The envelope recipient whose
    /// key-wrap it opens is found by trying each <c>encrypted_key</c>; the constant-work decoy
    /// (issue #12) runs when the key's curve does not match the envelope.</param>
    /// <param name="senderKeys">Lookup of sender public keys (ECDH-1PU only; pass <c>null</c> otherwise).</param>
    /// <param name="cryptoProvider">The JOSE crypto provider.</param>
    /// <param name="ct">Cancellation token for the (possibly I/O-bound) key agreement.</param>
    public static Task<JweParseResult> ParseAsync(
        string packed,
        IEcdhKey recipientKey,
        IJweSenderKeyResolver? senderKeys,
        JoseCryptoProvider cryptoProvider,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(packed);
        ArgumentNullException.ThrowIfNull(recipientKey);
        ArgumentNullException.ThrowIfNull(cryptoProvider);

        var jwe = ParseStructure(packed);
        var header = JweProtectedHeader.Decode(jwe.ProtectedB64u);

        ValidateHeader(header);
        ValidateRecipientCommitment(jwe, header);

        return DecryptForRecipientAsync(jwe, header, recipientKey, senderKeys, cryptoProvider, ct);
    }

    /// <summary>
    /// Parse a compact-serialization JWE and decrypt with an <b>opaque</b> recipient key (issue #13).
    /// ECDH algorithms only — see <see cref="ParseAsync"/>.
    /// </summary>
    /// <param name="compact">The compact JWE string.</param>
    /// <param name="recipientKey">The recipient's opaque ECDH key.</param>
    /// <param name="senderKeys">Lookup of sender public keys (ECDH-1PU only; pass <c>null</c> otherwise).</param>
    /// <param name="cryptoProvider">The JOSE crypto provider.</param>
    /// <param name="ct">Cancellation token for the (possibly I/O-bound) key agreement.</param>
    public static Task<JweParseResult> ParseCompactAsync(
        string compact,
        IEcdhKey recipientKey,
        IJweSenderKeyResolver? senderKeys,
        JoseCryptoProvider cryptoProvider,
        CancellationToken ct = default)
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

        var kid = header.Kid ?? string.Empty;
        var jwe = new ParsedJwe(
            segments[0],
            [new ParsedRecipient(kid, DecodeB64u(segments[1], "encrypted_key"))],
            DecodeB64u(segments[2], "iv"),
            DecodeB64u(segments[3], "ciphertext"),
            DecodeB64u(segments[4], "tag"));

        return DecryptForRecipientAsync(jwe, header, recipientKey, senderKeys, cryptoProvider, ct);
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

    /// <summary>
    /// Recipient-list commitment (didcomm FR-ENC-13 profile): when the ECDH paths carry an
    /// <c>apv</c>, it must re-derive from the envelope's recipient kid list. Generic JOSE leaves apv
    /// open, so an absent apv skips the check (the KDF then runs with empty PartyVInfo). Runs before
    /// key selection and depends only on envelope content, so it is timing-uniform across held/decoy.
    /// </summary>
    private static void ValidateRecipientCommitment(ParsedJwe jwe, JweProtectedHeader header)
    {
        if (!string.IsNullOrEmpty(header.Apv) && header.Alg is JoseAlgorithms.EcdhEsA256Kw or JoseAlgorithms.Ecdh1PuA256Kw)
        {
            var apvRecomputed = ApvComputer.Compute(jwe.Recipients.Select(r => r.Kid));
            if (!string.Equals(apvRecomputed, header.Apv, StringComparison.Ordinal))
                throw new JoseCryptoException(
                    $"JWE 'apv' mismatch (FR-ENC-13). Header={header.Apv}, recomputed from recipient kids={apvRecomputed}.");
        }
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

    /// <summary>
    /// Choose the recipient and decryption key the decrypt runs against — the constant-work defense
    /// for the recipient-key enumeration oracle (issue #12). When the holder has a key whose curve
    /// matches the envelope's key-agreement (<c>epk</c>) curve, that real recipient and key are
    /// returned. Otherwise a per-process <see cref="DecoyKeyCache">decoy</see> private key on the
    /// envelope's work curve is substituted, so <see cref="DecryptForRecipient"/> performs the same
    /// ECDH / key-unwrap work and fails uniformly at unwrap rather than fast-failing before any
    /// cryptography.
    /// </summary>
    /// <remarks>
    /// The work curve is taken from the envelope alone (the <c>epk</c> curve for the ECDH
    /// algorithms), never from a held key: a held key on the <i>wrong</i> curve would otherwise
    /// fast-fail at the recipient/epk curve check before the ECDH and so leak possession. The
    /// recipient list is scanned in full (no early-out on first match) so the selection cost does not
    /// depend on which index matched. This makes the parser's <i>own</i> post-resolution path
    /// constant-work; a held key whose curve matches still decrypts normally. The supplied
    /// <see cref="IJweRecipientKeyResolver"/> is outside this guarantee — a fully constant-time
    /// decrypt additionally requires its <c>FindPresent</c>/<c>TryGet</c> to be timing-independent of
    /// which kids are held.
    /// </remarks>
    private static (ParsedRecipient Recipient, Jwk Key) SelectRecipientOrDecoy(
        ParsedJwe jwe,
        JweProtectedHeader header,
        IJweRecipientKeyResolver recipientKeys)
    {
        var present = new HashSet<string>(
            recipientKeys.FindPresent(jwe.Recipients.Select(r => r.Kid)), StringComparer.Ordinal);

        ParsedRecipient? matched = null;
        Jwk? matchedKey = null;
        foreach (var recipient in jwe.Recipients)
        {
            if (!present.Contains(recipient.Kid))
                continue;
            var key = recipientKeys.TryGet(recipient.Kid);
            if (matched is null && key is not null && IsUsableForEnvelope(key, header))
            {
                matched = recipient;
                matchedKey = key;
            }
        }

        if (matched is not null && matchedKey is not null)
            return (matched, matchedKey);

        // No held key usable for this envelope — run the decoy so the work (and the failure) matches
        // the held path. The matched recipient is irrelevant on the decoy path (the decrypt always
        // fails before producing a result); recipients[0] is guaranteed present by ParseStructure.
        return (jwe.Recipients[0], DecoyForEnvelope(header));
    }

    /// <summary>
    /// Whether a held key can actually decrypt this envelope: for ECDH it must sit on the envelope's
    /// work (<c>epk</c>) curve; for standalone <c>A256KW</c> it must be a symmetric <c>oct</c> key.
    /// </summary>
    private static bool IsUsableForEnvelope(Jwk key, JweProtectedHeader header)
    {
        if (string.Equals(header.Alg, JoseAlgorithms.A256Kw, StringComparison.Ordinal))
            return string.Equals(key.Kty, "oct", StringComparison.Ordinal) && !string.IsNullOrEmpty(key.K);

        // Require actual private-key material: a curve-matching but public-only JWK cannot decrypt,
        // so it takes the decoy path and fails with the uniform message rather than a distinct
        // "missing 'd'" throw (which would otherwise be a — holder-misconfiguration-only — signal).
        var workCurve = header.Epk?.Crv;
        return DecoyKeyCache.IsSupportedAgreementCurve(workCurve)
            && string.Equals(key.Crv, workCurve, StringComparison.Ordinal)
            && !string.IsNullOrEmpty(key.D);
    }

    /// <summary>The decoy key to substitute when no held key is usable for this envelope.</summary>
    /// <remarks>
    /// For a supported <c>epk</c> curve the decoy sits on that curve, so the full ECDH runs and the
    /// decrypt fails at AES-KW unwrap. For an absent or unsupported work curve (a structural fault
    /// that fast-fails at <c>RequireEpk</c> / the curve check before any ECDH — identically whether
    /// or not a key is held), a placeholder decoy on a supported curve is returned; it is never used
    /// for an ECDH because the structural throw fires first.
    /// </remarks>
    private static Jwk DecoyForEnvelope(JweProtectedHeader header)
    {
        if (string.Equals(header.Alg, JoseAlgorithms.A256Kw, StringComparison.Ordinal))
            return DecoyKeyCache.OctKek();

        var workCurve = header.Epk?.Crv;
        return DecoyKeyCache.IsSupportedAgreementCurve(workCurve)
            ? DecoyKeyCache.ForCurve(workCurve!)
            : DecoyKeyCache.ForCurve(JoseAlgorithms.CrvX25519);
    }

    /// <summary>
    /// The single, recipient-agnostic message every post-selection decrypt failure throws (issue
    /// #12, "uniform failure"). A key-unwrap failure (wrong/decoy key), an AEAD-integrity failure
    /// (held key, tampered content), and a malformed <c>iv</c>/<c>tag</c>/<c>encrypted_key</c> length
    /// must be indistinguishable — same type (<see cref="JoseCryptoException"/>), same message, no
    /// recipient kid, no inner cause — or the exception itself re-leaks recipient-key possession that
    /// the constant-work timing defense already closes. A failure here means the JWE did not decrypt;
    /// it is intentionally not a finer diagnostic.
    /// </summary>
    private const string DecryptFailureMessage = "JWE could not be decrypted.";

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
                var (skid, senderPubBytes, apuBytes) = ResolveSender(header, senderKeys, recipientJwk.Crv);
                senderKid = skid;
                var ephemeralPubBytes = ExtractEphemeralPublicKey(RequireEpk(header), recipientJwk);
                var apvBytes = string.IsNullOrEmpty(header.Apv) ? [] : DecodeB64u(header.Apv, "apv");
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
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            throw new JoseCryptoException(DecryptFailureMessage);
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
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            throw new JoseCryptoException(DecryptFailureMessage);
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

    /// <summary>
    /// The opaque-key (issue #13) counterpart to <see cref="DecryptForRecipient"/>: derives the
    /// wrapping key through the <see cref="IEcdhKey"/> (so the private scalar never enters this
    /// package) and carries the same constant-work decoy defense (issue #12) as the sync path.
    /// ECDH algorithms only; <c>A256KW</c> has no key agreement and is served by the sync parser.
    /// </summary>
    private static async Task<JweParseResult> DecryptForRecipientAsync(
        ParsedJwe jwe,
        JweProtectedHeader header,
        IEcdhKey recipientKey,
        IJweSenderKeyResolver? senderKeys,
        JoseCryptoProvider cryptoProvider,
        CancellationToken ct)
    {
        if (header.Alg is not (JoseAlgorithms.EcdhEsA256Kw or JoseAlgorithms.Ecdh1PuA256Kw))
            throw new JoseCryptoException(
                $"Async JWE parse supports only the ECDH key-agreement algorithms (ECDH-ES+A256KW, ECDH-1PU+A256KW); got '{header.Alg}'.");

        var aad = Encoding.ASCII.GetBytes(jwe.ProtectedB64u);
        var epk = RequireEpk(header);

        // Constant-work (issue #12): use the real key only when its curve matches the envelope's work
        // curve; otherwise a decoy on the work curve so the ECDH cost and failure are uniform.
        var ecdhKey = ResolveEcdhKeyOrDecoy(recipientKey, header, cryptoProvider);
        var ephemeralPubBytes = ExtractEphemeralPublicKey(epk, ecdhKey.Crv);
        var apvBytes = string.IsNullOrEmpty(header.Apv) ? [] : DecodeB64u(header.Apv, "apv");
        var algId = Encoding.ASCII.GetBytes(header.Alg);

        byte[] kek;
        string senderKid;
        if (string.Equals(header.Alg, JoseAlgorithms.EcdhEsA256Kw, StringComparison.Ordinal))
        {
            senderKid = string.Empty;
            var apuBytes = string.IsNullOrEmpty(header.Apu) ? [] : DecodeB64u(header.Apu, "apu");
            kek = await EcdhEsKdf.DeriveKeyForReceiverAsync(
                ecdhKey, ephemeralPubBytes, algId, apuBytes, apvBytes, 32, ct).ConfigureAwait(false);
        }
        else
        {
            var (skid, senderPubBytes, apuBytes) = ResolveSender(header, senderKeys, ecdhKey.Crv);
            senderKid = skid;
            kek = await Ecdh1PuKdf.DeriveKeyForReceiverAsync(
                ecdhKey, ephemeralPubBytes, senderPubBytes, algId, apuBytes, apvBytes, jwe.Tag, 32, ct).ConfigureAwait(false);
        }

        return UnwrapAnyAndDecrypt(jwe, header, kek, senderKid, aad, cryptoProvider);
    }

    /// <summary>
    /// The opaque ECDH key to actually agree with: the real <paramref name="recipientKey"/> when its
    /// curve matches the envelope work curve, else a <see cref="DecoyKeyCache">decoy</see> on the work
    /// curve (issue #12). For an absent/unsupported work curve a placeholder decoy is returned; the
    /// structural curve-mismatch throw in <see cref="ExtractEphemeralPublicKey(Jwk, string?)"/> fires
    /// before any ECDH, identically whether or not the real key would have matched.
    /// </summary>
    private static IEcdhKey ResolveEcdhKeyOrDecoy(IEcdhKey recipientKey, JweProtectedHeader header, JoseCryptoProvider cryptoProvider)
    {
        var workCurve = header.Epk?.Crv;
        if (DecoyKeyCache.IsSupportedAgreementCurve(workCurve)
            && string.Equals(recipientKey.Crv, workCurve, StringComparison.Ordinal))
            return recipientKey;

        var decoyCurve = DecoyKeyCache.IsSupportedAgreementCurve(workCurve) ? workCurve! : JoseAlgorithms.CrvX25519;
        var decoy = DecoyKeyCache.ForCurve(decoyCurve);
        return new RawEcdhKey(decoy.Crv!, Base64Url.Decode(decoy.D!), cryptoProvider);
    }

    /// <summary>
    /// Find which recipient key-wrap the (opaque-key-derived) <paramref name="kek"/> opens, then AEAD-
    /// decrypt. The full recipient list is scanned — the first opened wins, later candidates are
    /// zeroized — so the unwrap-attempt count does not depend on which recipient matched. A decoy KEK
    /// opens none and the call fails uniformly. Zeroizes <paramref name="kek"/> and the CEK.
    /// </summary>
    private static JweParseResult UnwrapAnyAndDecrypt(
        ParsedJwe jwe,
        JweProtectedHeader header,
        byte[] kek,
        string senderKid,
        byte[] aad,
        JoseCryptoProvider cryptoProvider)
    {
        byte[]? cek = null;
        ParsedRecipient? matched = null;
        try
        {
            foreach (var recipient in jwe.Recipients)
            {
                byte[] candidate;
                try
                {
                    candidate = cryptoProvider.KeyUnwrap(JoseAlgorithms.A256Kw, kek, recipient.EncryptedKey);
                }
                catch (CryptographicException)
                {
                    continue;
                }
                catch (ArgumentException)
                {
                    continue;
                }

                if (cek is null)
                {
                    cek = candidate;
                    matched = recipient;
                }
                else
                {
                    CryptographicOperations.ZeroMemory(candidate);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }

        if (cek is null || matched is null)
            throw new JoseCryptoException(DecryptFailureMessage);

        try
        {
            var plaintext = cryptoProvider.AeadDecrypt(header.Enc, cek, jwe.Iv, aad, jwe.Ciphertext, jwe.Tag);
            return new JweParseResult(
                Plaintext: plaintext,
                Algorithm: header.Alg,
                ContentEncryption: header.Enc,
                RecipientKid: matched.Kid,
                AllRecipientKids: jwe.Recipients.Select(r => r.Kid).ToArray(),
                SenderKid: senderKid,
                IsAuthenticated: !string.IsNullOrEmpty(senderKid));
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            throw new JoseCryptoException(DecryptFailureMessage);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }
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
        => ExtractEphemeralPublicKey(epk, recipientJwk.Crv);

    private static byte[] ExtractEphemeralPublicKey(Jwk epk, string? recipientCrv)
    {
        if (!string.Equals(recipientCrv, epk.Crv, StringComparison.Ordinal))
            throw new JoseCryptoException(
                $"Recipient key curve ({recipientCrv}) does not match JWE 'epk' curve ({epk.Crv}).");
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

    /// <summary>
    /// Resolve the authenticated sender of an ECDH-1PU envelope from <c>skid</c>/<c>apu</c> and look
    /// up its public key. Shared by the sync and async (opaque-key) 1PU receive paths. The sender
    /// identity is pinned by the protected header and validated against the recipient's
    /// <paramref name="recipientCrv"/>; none of these checks depend on which recipient private key is
    /// held, so they are timing-uniform across the held and decoy (issue #12) paths.
    /// </summary>
    private static (string Skid, byte[] SenderPublicKey, byte[] Apu) ResolveSender(
        JweProtectedHeader header, IJweSenderKeyResolver? senderKeys, string? recipientCrv)
    {
        if (senderKeys is null)
            throw new JoseCryptoException("ECDH-1PU unpack requires a sender-key lookup; none was supplied.");

        // Resolve the sender key id from 'skid' when present, else from 'apu'
        // (= base64url(utf8(skid)); the 1PU draft does not mandate 'skid'). When BOTH are present
        // they MUST agree, so a peer cannot present one sender identity in 'skid' and a different one
        // in 'apu' (didcomm FR-ENC-14/17).
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
        if (!string.Equals(senderPublicJwk.Crv, recipientCrv, StringComparison.Ordinal))
            throw new JoseCryptoException(
                $"ECDH-1PU sender key curve ({senderPublicJwk.Crv}) does not match recipient curve ({recipientCrv}).");

        var (_, senderPubBytes) = JwkConversion.ExtractPublicKey(senderPublicJwk);
        // 1PU draft-04 §2.3: PartyUInfo is the UTF-8 bytes of the sender skid (the decoded 'apu');
        // fall back to utf8(skid) when the peer omitted 'apu'.
        var apuBytes = string.IsNullOrEmpty(header.Apu)
            ? Encoding.UTF8.GetBytes(skid)
            : DecodeB64u(header.Apu, "apu");
        return (skid, senderPubBytes, apuBytes);
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
