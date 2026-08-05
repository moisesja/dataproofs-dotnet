using System.Text;
using System.Text.Json;
using DataProofsDotnet.Jose.Json;

namespace DataProofsDotnet.Jose.Signing;

/// <summary>
/// Parses and verifies JWS envelopes (PRD FR-13): compact serialization, Flattened and General
/// JSON serializations, and detached-payload variants (RFC 7515 Appendix F).
/// </summary>
/// <remarks>
/// Ported from didcomm-dotnet <c>DidComm.Jose.Signing.JwsParser</c> (PRD §1.4 item 2),
/// preserving its behavior contract: <c>crit</c> rejection (RFC 7515 §4.1.11), <c>b64=false</c>
/// rejection (RFC 7797 unencoded payloads are unsupported; detached payloads remain
/// base64url-encoded), alg↔key-curve binding (algorithm-confusion defense), protected/unprotected
/// header parameter-name disjointness (RFC 7515 §5.2 step 4), and
/// first-verifying-signature-wins with the last failure rethrown when none verifies.
/// Additions over the porting source: <c>alg="none"</c> hard rejection, compact and detached
/// parsing.
/// </remarks>
public static class JwsParser
{
    /// <summary>
    /// Parse a JSON-serialization JWS (Flattened or General), verify at least one signature,
    /// and return the payload alongside the verified signer info.
    /// </summary>
    /// <param name="packed">JWS JSON string (General or Flattened serialization).</param>
    /// <param name="resolveSignerPublicJwk">
    /// Function from signer <c>kid</c> to the verifier's public JWK. Returns <c>null</c> when
    /// the kid is unknown; null is treated as "skip this signature, try the next".
    /// </param>
    /// <param name="cryptoProvider">Crypto provider used to verify (NetCrypto-backed).</param>
    /// <exception cref="MalformedJoseException">When the JWS structure is invalid.</exception>
    /// <exception cref="JoseCryptoException">When no signature verifies.</exception>
    public static JwsParseResult Parse(
        string packed,
        Func<string, Jwk?> resolveSignerPublicJwk,
        IJoseCryptoProvider cryptoProvider)
        => ParseJsonCore(packed, detachedPayload: null, resolveSignerPublicJwk, cryptoProvider);

    /// <summary>
    /// Parse a JSON-serialization JWS whose payload travels detached (RFC 7515 Appendix F).
    /// The serialized object must omit the <c>payload</c> member; the caller supplies the bytes.
    /// </summary>
    /// <param name="packed">JWS JSON string without a <c>payload</c> member.</param>
    /// <param name="detachedPayload">The detached payload bytes.</param>
    /// <param name="resolveSignerPublicJwk">Signer kid → public JWK resolver.</param>
    /// <param name="cryptoProvider">Crypto provider used to verify.</param>
    public static JwsParseResult Parse(
        string packed,
        ReadOnlySpan<byte> detachedPayload,
        Func<string, Jwk?> resolveSignerPublicJwk,
        IJoseCryptoProvider cryptoProvider)
        => ParseJsonCore(packed, Base64Url.Encode(detachedPayload), resolveSignerPublicJwk, cryptoProvider);

    /// <summary>Parse and verify a compact-serialization JWS (<c>header.payload.signature</c>).</summary>
    /// <param name="compact">The compact JWS string.</param>
    /// <param name="resolveSignerPublicJwk">
    /// Signer kid → public JWK resolver. Invoked with the protected header's <c>kid</c>, or the
    /// empty string when the header carries none.
    /// </param>
    /// <param name="cryptoProvider">Crypto provider used to verify.</param>
    public static JwsParseResult ParseCompact(
        string compact,
        Func<string, Jwk?> resolveSignerPublicJwk,
        IJoseCryptoProvider cryptoProvider)
        => ParseCompactCore(compact, detachedPayload: null, resolveSignerPublicJwk, cryptoProvider);

    /// <summary>
    /// Parse and verify a compact JWS whose payload travels detached (empty middle segment,
    /// RFC 7515 Appendix F).
    /// </summary>
    /// <param name="compact">The compact JWS string with an empty payload segment.</param>
    /// <param name="detachedPayload">The detached payload bytes.</param>
    /// <param name="resolveSignerPublicJwk">Signer kid → public JWK resolver.</param>
    /// <param name="cryptoProvider">Crypto provider used to verify.</param>
    public static JwsParseResult ParseCompact(
        string compact,
        ReadOnlySpan<byte> detachedPayload,
        Func<string, Jwk?> resolveSignerPublicJwk,
        IJoseCryptoProvider cryptoProvider)
        => ParseCompactCore(compact, Base64Url.Encode(detachedPayload), resolveSignerPublicJwk, cryptoProvider);

    private static JwsParseResult ParseCompactCore(
        string compact,
        string? detachedPayload,
        Func<string, Jwk?> resolveSignerPublicJwk,
        IJoseCryptoProvider cryptoProvider)
    {
        ArgumentException.ThrowIfNullOrEmpty(compact);
        ArgumentNullException.ThrowIfNull(resolveSignerPublicJwk);
        ArgumentNullException.ThrowIfNull(cryptoProvider);

        var segments = compact.Split('.');
        if (segments.Length != 3)
            throw new MalformedJoseException($"Compact JWS must have exactly 3 dot-separated segments; got {segments.Length}.");
        if (segments[0].Length == 0)
            throw new MalformedJoseException("Compact JWS protected-header segment is empty.");
        if (segments[2].Length == 0)
            throw new MalformedJoseException("Compact JWS signature segment is empty.");

        string payloadB64u;
        if (segments[1].Length == 0)
        {
            payloadB64u = detachedPayload
                ?? throw new MalformedJoseException(
                    "Compact JWS has an empty payload segment (detached payload, RFC 7515 Appendix F); use the overload that supplies the payload bytes.");
        }
        else
        {
            if (detachedPayload is not null)
                throw new MalformedJoseException("Compact JWS carries an embedded payload; a detached payload must not also be supplied.");
            payloadB64u = segments[1];
        }

        var protectedB64u = segments[0];
        var protectedHeader = JwsProtectedHeader.Decode(protectedB64u);
        var kid = protectedHeader.Kid;
        var signature = DecodeSignature(segments[2]);

        return VerifySignatures(
            payloadB64u,
            [new RawSignature(protectedB64u, protectedHeader, kid, signature)],
            resolveSignerPublicJwk,
            cryptoProvider);
    }

    private static JwsParseResult ParseJsonCore(
        string packed,
        string? detachedPayload,
        Func<string, Jwk?> resolveSignerPublicJwk,
        IJoseCryptoProvider cryptoProvider)
    {
        ArgumentException.ThrowIfNullOrEmpty(packed);
        ArgumentNullException.ThrowIfNull(resolveSignerPublicJwk);
        ArgumentNullException.ThrowIfNull(cryptoProvider);

        // Malformed bytes (truncated frame, trailing junk, duplicate member, over-deep nesting)
        // must surface as the documented MalformedJoseException — never as a raw System.Text.Json
        // exception — so a caller's catch (MalformedJoseException) is not bypassed. This runs
        // pre-verification on attacker-supplied input, same contract the JWE/JWT parsers uphold
        // (JweParser.ParseStructure, JwtClaims.Parse); see issue #15.
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(packed, JoseJson.StrictDocument);
        }
        catch (JsonException ex)
        {
            throw new MalformedJoseException("JWS is not valid JSON.", ex);
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw new MalformedJoseException("JWS root is not a JSON object.");

            string payloadB64u;
            if (root.TryGetProperty("payload", out var payloadElement))
            {
                if (payloadElement.ValueKind != JsonValueKind.String)
                    throw new MalformedJoseException("JWS is missing required 'payload' string.");
                if (detachedPayload is not null)
                    throw new MalformedJoseException("JWS carries an embedded 'payload'; a detached payload must not also be supplied.");
                payloadB64u = payloadElement.GetString()!;
            }
            else
            {
                payloadB64u = detachedPayload
                    ?? throw new MalformedJoseException("JWS is missing required 'payload' string.");
            }

            var signatures = ExtractSignatures(root).ToList();
            if (signatures.Count == 0)
                throw new MalformedJoseException("JWS contains no signatures.");

            return VerifySignatures(payloadB64u, signatures, resolveSignerPublicJwk, cryptoProvider);
        }
    }

    private static JwsParseResult VerifySignatures(
        string payloadB64u,
        IReadOnlyList<RawSignature> signatures,
        Func<string, Jwk?> resolveSignerPublicJwk,
        IJoseCryptoProvider cryptoProvider)
    {
        byte[] payloadBytes;
        try
        {
            payloadBytes = payloadB64u.Length == 0 ? [] : Base64Url.Decode(payloadB64u);
        }
        catch (FormatException ex)
        {
            throw new MalformedJoseException("JWS 'payload' is not valid base64url.", ex);
        }

        Exception? lastFailure = null;
        foreach (var sig in signatures)
        {
            var publicJwk = resolveSignerPublicJwk(sig.Kid);
            if (publicJwk is null)
            {
                lastFailure = new JoseCryptoException($"No verifier public JWK supplied for signer kid '{sig.Kid}'.");
                continue;
            }

            try
            {
                var header = sig.ProtectedHeader;

                // RFC 7515 §4.1.1 requires 'alg'; "none" (RFC 7518 §3.6) is never accepted —
                // an unsigned JWS must not be confusable with a signed one (AC-3 negative path).
                if (string.IsNullOrEmpty(header.Alg) || string.Equals(header.Alg, "none", StringComparison.OrdinalIgnoreCase))
                {
                    lastFailure = new MalformedJoseException("JWS protected header 'alg' is missing or \"none\"; unsigned JWS is not accepted.");
                    continue;
                }

                // RFC 7515 §4.1.11: reject a 'crit' header that names extensions we don't understand —
                // we understand none. RFC 7797: reject b64=false (unencoded payload); this parser always
                // base64url-decodes the payload. Both land in the extension-data bag.
                if (header.AdditionalMembers is not null)
                {
                    if (header.AdditionalMembers.ContainsKey("crit"))
                    {
                        lastFailure = new MalformedJoseException("JWS protected header marks an unsupported extension critical ('crit').");
                        continue;
                    }
                    if (header.AdditionalMembers.TryGetValue("b64", out var b64) && b64.ValueKind == JsonValueKind.False)
                    {
                        lastFailure = new MalformedJoseException("JWS with b64=false (unencoded payload, RFC 7797) is not supported.");
                        continue;
                    }
                }

                if (string.IsNullOrEmpty(publicJwk.Crv))
                {
                    lastFailure = new JoseCryptoException($"Verifier public JWK for kid '{sig.Kid}' is missing 'crv'.");
                    continue;
                }

                if (!string.Equals(header.Alg, KeyTypeMapper.ToJwsAlgorithm(publicJwk.Crv), StringComparison.Ordinal))
                {
                    lastFailure = new JoseCryptoException(
                        $"JWS protected 'alg' ({header.Alg}) does not match the public key's curve ({publicJwk.Crv}).");
                    continue;
                }

                var signingInput = Encoding.ASCII.GetBytes(sig.ProtectedB64u + "." + payloadB64u);
                var (_, publicKeyBytes) = JwkConversion.ExtractPublicKey(publicJwk);
                if (!cryptoProvider.Verify(header.Alg, publicKeyBytes, signingInput, sig.Signature))
                {
                    lastFailure = new JoseCryptoException($"JWS signature did not verify for kid '{sig.Kid}'.");
                    continue;
                }

                // Surface the kid that resolved the verifying key, and say which header it came
                // from. RFC 7515 §4.1.4 permits 'kid' in either header; ExtractSignatures has
                // already enforced that it cannot be in both. Empty only when neither header has
                // one. DIDComm v2.1 states no placement rule, but its Appendix C.2 examples and
                // both reference implementations use the unprotected header, so dropping it (the
                // behavior before #10) broke signed/authcrypt interop.
                //
                // What a caller may conclude differs sharply by header, and the flag is the only
                // way to tell:
                //
                //  * Protected — the signature covers the kid, so it is an authenticated
                //    statement by the signer.
                //  * Unprotected — the kid is ONLY the key-selection hint that happened to resolve
                //    the verifying key. It is NOT an authenticated identity. The tempting argument
                //    ("a rewritten kid resolves a key the attacker cannot sign under, so it fails")
                //    holds only if resolveSignerPublicJwk is injective, and nothing here requires
                //    that: a resolver pinned to one key, or an ordinary DID document listing the
                //    same key under two verification-method ids, both let an intermediary relabel
                //    the kid to another identifier that resolves the same key material — the
                //    signature still verifies and this line reports the attacker's choice. That is
                //    exactly the case RFC 7515 §6 carves out by making its exemption conditional on
                //    the kid feeding nothing but key selection.
                //
                // Membership, not emptiness, decides the flag: RFC 7515 §4.1.4 requires 'kid' to be
                // a string, not a non-empty one, so a signed "kid":"" is valid and must not be
                // reported as unprotected (the Kid property alone cannot distinguish it from an
                // absent member, which is also the empty-string sentinel).
                var kidIsProtected = header.HasKidMember;
                var verifiedKid = kidIsProtected ? header.Kid : (sig.Kid ?? string.Empty);
                return new JwsParseResult(header.Alg, verifiedKid, payloadBytes)
                {
                    Typ = header.Typ,
                    SignerKidIsProtected = kidIsProtected,
                };
            }
            catch (Exception ex) when (ex is JoseCryptoException or MalformedJoseException)
            {
                lastFailure = ex;
            }
            catch (NotSupportedException ex)
            {
                // Out-of-scope algorithm or curve (e.g. ES512) — surface the documented crypto
                // failure rather than leaking the dispatch exception (AC-3 negative path).
                lastFailure = new JoseCryptoException($"JWS algorithm is not supported: {ex.Message}", ex);
            }
            catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or ArgumentException)
            {
                // Fail closed (FR-23): an attacker-controlled verifier JWK can be off-curve /
                // point-at-infinity (CryptographicException from the EC invalid-curve defense in
                // JwkConversion.ExtractPublicKey / crypto.Verify) or carry a malformed kty/crv
                // (ArgumentException). These must not escape the parser — treat them as "this
                // signature did not verify" and fall through to the next signature, exactly as
                // the JoseCryptoException path does. OperationCanceledException is excluded by the
                // type filter so cooperative cancellation still propagates.
                lastFailure = new JoseCryptoException($"JWS signature did not verify for kid '{sig.Kid}': {ex.Message}", ex);
            }
        }

        if (lastFailure is null)
            throw new JoseCryptoException("No JWS signature verified.");
        throw lastFailure;
    }

    private static IEnumerable<RawSignature> ExtractSignatures(JsonElement root)
    {
        // Flattened and General are distinct JSON serializations. A hybrid object is ambiguous and
        // could otherwise make the Flattened fast path ignore malformed/overlapping entries in a
        // sibling signatures[] array, so reject the mixed shape before selecting either path.
        if (root.TryGetProperty("signature", out _) && root.TryGetProperty("signatures", out _))
        {
            throw new MalformedJoseException(
                "JWS cannot mix Flattened 'signature' and General 'signatures' members.");
        }

        // Flattened: payload + protected + (optional header) + signature at the top level. Both
        // 'signature' and 'protected' must be strings; otherwise this is not a flattened JWS and we
        // fall through (an empty result then surfaces as a clean "no signatures" malformed error).
        if (root.TryGetProperty("signature", out var sigEl) && sigEl.ValueKind == JsonValueKind.String
            && root.TryGetProperty("protected", out var protEl) && protEl.ValueKind == JsonValueKind.String)
        {
            var protB64u = protEl.GetString()!;
            var protectedHeader = JwsProtectedHeader.DecodeWithMemberNames(protB64u);
            var kid = ReadUnprotectedKid(root, protectedHeader.MemberNames);
            if (string.IsNullOrEmpty(kid))
            {
                // Kid MAY live only in protected; pull it from there as a fallback.
                kid = protectedHeader.Header.Kid;
            }

            yield return new RawSignature(
                protB64u,
                protectedHeader.Header,
                kid,
                DecodeSignature(sigEl.GetString()!));
            yield break;
        }

        // General: payload + signatures: [ { protected, header, signature }, … ]
        if (root.TryGetProperty("signatures", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in arr.EnumerateArray())
            {
                if (entry.ValueKind != JsonValueKind.Object
                    || !entry.TryGetProperty("protected", out var protElement) || protElement.ValueKind != JsonValueKind.String
                    || !entry.TryGetProperty("signature", out var sigElement) || sigElement.ValueKind != JsonValueKind.String)
                    throw new MalformedJoseException("JWS signature entry is missing a string 'protected' or 'signature'.");

                var protB64u = protElement.GetString()!;
                var protectedHeader = JwsProtectedHeader.DecodeWithMemberNames(protB64u);
                var kid = ReadUnprotectedKid(entry, protectedHeader.MemberNames);
                if (string.IsNullOrEmpty(kid))
                    kid = protectedHeader.Header.Kid;
                yield return new RawSignature(
                    protB64u,
                    protectedHeader.Header,
                    kid,
                    DecodeSignature(sigElement.GetString()!));
            }
        }
    }

    // Validates the complete unprotected header namespace, then reads its 'kid' hint. RFC 7515
    // §5.2 step 4 requires the protected and unprotected parameter-name sets to be disjoint — an
    // overlap is malformed even when the duplicate values match. This runs while all raw
    // signatures are extracted, before key resolution or cryptographic verification (issue #19).
    // Returns empty when 'header' or 'kid' is absent (the caller falls back to the protected kid).
    // Any present non-string 'kid', including JSON null, remains malformed
    // per §4.1.4 and surfaces as MalformedJoseException (issue #15).
    private static string ReadUnprotectedKid(JsonElement container, IReadOnlySet<string> protectedMemberNames)
    {
        if (!container.TryGetProperty("header", out var hdr))
            return string.Empty;
        if (hdr.ValueKind != JsonValueKind.Object)
            throw new MalformedJoseException("JWS unprotected 'header' must be a JSON object.");

        foreach (var member in hdr.EnumerateObject())
        {
            if (protectedMemberNames.Contains(member.Name))
            {
                throw new MalformedJoseException(
                    $"JWS protected and unprotected headers must be disjoint; parameter '{member.Name}' appears in both.");
            }
        }

        if (!hdr.TryGetProperty("kid", out var kidEl))
            return string.Empty;
        if (kidEl.ValueKind != JsonValueKind.String)
            throw new MalformedJoseException("JWS unprotected header 'kid' must be a string.");
        return kidEl.GetString()!;
    }

    private static byte[] DecodeSignature(string b64u)
    {
        try
        {
            return Base64Url.Decode(b64u);
        }
        catch (FormatException ex)
        {
            throw new MalformedJoseException("JWS 'signature' is not valid base64url.", ex);
        }
    }

    private readonly record struct RawSignature(
        string ProtectedB64u,
        JwsProtectedHeader ProtectedHeader,
        string Kid,
        byte[] Signature);
}

/// <summary>Outcome of a successful JWS parse: payload bytes plus verified signer metadata.</summary>
/// <param name="SignatureAlgorithm">JOSE <c>alg</c> of the verified signature (e.g. <c>"EdDSA"</c>).</param>
/// <param name="SignerKid">The <c>kid</c> that resolved the key under which the signature verified.
/// <b>Check <see cref="JwsParseResult.SignerKidIsProtected"/> before treating this as a signer
/// identity.</b> When that flag is <c>true</c> the signature covers the <c>kid</c> and it is an
/// authenticated statement by the signer. When it is <c>false</c> — the kid came from the
/// per-signature unprotected header, or neither header carried one and this is empty — the value is
/// <i>only</i> the key-selection hint that happened to resolve the verifying key: it is not
/// authenticated, and must not be used as a proof purpose, verification relationship, or
/// authorization input. An intermediary can rewrite an unprotected <c>kid</c> to any other
/// identifier that resolves the same key material — a resolver pinned to one key, or a DID document
/// listing one key under several verification-method ids — and the signature still verifies.
/// The protected header's <c>kid</c> is preferred whenever the member is present, including a valid
/// empty-string value. DIDComm v2.1 states no placement rule, but its published examples and both
/// reference implementations carry the signer kid unprotected (issue #10).</param>
/// <param name="PayloadBytes">Raw decoded payload bytes.</param>
public sealed record JwsParseResult(string SignatureAlgorithm, string SignerKid, byte[] PayloadBytes)
{
    /// <summary>
    /// The integrity-protected <c>typ</c> header parameter (RFC 7515 §4.1.9), or <c>null</c> when
    /// the protected header carried none. Useful for explicit-typing checks (RFC 8725 §3.11) to
    /// prevent cross-context token confusion.
    /// </summary>
    public string? Typ { get; init; }

    /// <summary>
    /// Whether <see cref="SignerKid"/> came from the integrity-protected header — that is, whether
    /// the signature covers it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>true</c> whenever the protected header carried a <c>kid</c> member — including a valid
    /// empty-string value, which RFC 7515 §4.1.4 permits (it requires a string, not a non-empty
    /// one). <c>false</c> means the kid was read from the per-signature unprotected header, or that
    /// neither header carried one (<see cref="SignerKid"/> is then empty). Both placements are
    /// §4.1.4-conformant; DIDComm v2.1 states no placement rule, but its Appendix C.2 examples and
    /// both reference implementations use the unprotected one, which is what
    /// <see cref="JwsKidPlacement.Auto"/> emits for that media type.
    /// </para>
    /// <para>
    /// Check this before using <see cref="SignerKid"/> for anything beyond recording which key
    /// verified. RFC 7515 §6 draws the line exactly here: these parameters "MUST be integrity
    /// protected <em>if</em> the information that they convey is to be utilized in a trust
    /// decision; however, if the only information used in the trust decision is a key, these
    /// parameters need not be integrity protected". An unprotected kid satisfies that exemption as
    /// a key hint and nothing more. It is <b>not</b> an authenticated identity: the argument that a
    /// rewritten kid resolves a key the attacker cannot sign under holds only for an
    /// <i>injective</i> resolver, and neither this parser nor RFC 7515 requires one. A resolver
    /// pinned to a single key, or a DID document listing one key under several
    /// verification-method ids, both let an intermediary relabel the kid to another identifier
    /// resolving the same key material — verification still succeeds and
    /// <see cref="SignerKid"/> reports the attacker's choice. A verifier that derives a proof
    /// purpose, verification relationship, or authorization scope from the kid must therefore
    /// require <c>SignerKidIsProtected</c>, which also fails closed when no kid was present at all.
    /// </para>
    /// <para>
    /// This describes the signature that actually verified — first-verifying-signature-wins. In a
    /// multi-signature envelope mixing both placements, reordering the <c>signatures</c> array can
    /// therefore change the reported value, so a "require a signed kid" policy may reject an
    /// envelope that does contain a valid protected-kid signature. That direction is safe (it
    /// rejects, it never trusts an unprotected kid as a protected one), but a caller needing every
    /// signature's placement must inspect the envelope itself.
    /// </para>
    /// </remarks>
    public bool SignerKidIsProtected { get; init; }
}
