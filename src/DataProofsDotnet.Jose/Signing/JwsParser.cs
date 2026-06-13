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
/// base64url-encoded), alg↔key-curve binding (algorithm-confusion defense), the kid placement
/// rule (protected and unprotected <c>kid</c> must agree when both present), and
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
        var kid = JwsProtectedHeader.Decode(protectedB64u).Kid;
        var signature = DecodeSignature(segments[2]);

        return VerifySignatures(
            payloadB64u,
            [new RawSignature(protectedB64u, kid, signature)],
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

        using var doc = JsonDocument.Parse(packed, JoseJson.StrictDocument);
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
                var header = JwsProtectedHeader.Decode(sig.ProtectedB64u);

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

                // The JWS spec allows 'kid' in either the protected or the unprotected header.
                // When both are present they MUST match; when only one is present, use that one.
                if (!string.IsNullOrEmpty(header.Kid)
                    && !string.IsNullOrEmpty(sig.Kid)
                    && !string.Equals(header.Kid, sig.Kid, StringComparison.Ordinal))
                {
                    lastFailure = new MalformedJoseException(
                        $"JWS protected 'kid' ({header.Kid}) does not match the unprotected header 'kid' ({sig.Kid}).");
                    continue;
                }

                var signingInput = Encoding.ASCII.GetBytes(sig.ProtectedB64u + "." + payloadB64u);
                var (_, publicKeyBytes) = JwkConversion.ExtractPublicKey(publicJwk);
                if (!cryptoProvider.Verify(header.Alg, publicKeyBytes, signingInput, sig.Signature))
                {
                    lastFailure = new JoseCryptoException($"JWS signature did not verify for kid '{sig.Kid}'.");
                    continue;
                }

                return new JwsParseResult(header.Alg, sig.Kid, payloadBytes);
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
        }

        if (lastFailure is null)
            throw new JoseCryptoException("No JWS signature verified.");
        throw lastFailure;
    }

    private static IEnumerable<RawSignature> ExtractSignatures(JsonElement root)
    {
        // Flattened: payload + protected + (optional header) + signature at the top level. Both
        // 'signature' and 'protected' must be strings; otherwise this is not a flattened JWS and we
        // fall through (an empty result then surfaces as a clean "no signatures" malformed error).
        if (root.TryGetProperty("signature", out var sigEl) && sigEl.ValueKind == JsonValueKind.String
            && root.TryGetProperty("protected", out var protEl) && protEl.ValueKind == JsonValueKind.String)
        {
            var kid = root.TryGetProperty("header", out var hdr) && hdr.ValueKind == JsonValueKind.Object
                ? hdr.TryGetProperty("kid", out var kEl) ? kEl.GetString() ?? string.Empty : string.Empty
                : string.Empty;

            var protB64u = protEl.GetString()!;
            if (string.IsNullOrEmpty(kid))
            {
                // Kid MAY live only in protected; pull it from there as a fallback.
                kid = JwsProtectedHeader.Decode(protB64u).Kid;
            }

            yield return new RawSignature(protB64u, kid, DecodeSignature(sigEl.GetString()!));
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
                var kid = entry.TryGetProperty("header", out var hdr2) && hdr2.ValueKind == JsonValueKind.Object
                    ? hdr2.TryGetProperty("kid", out var kEl) ? kEl.GetString() ?? string.Empty : string.Empty
                    : string.Empty;
                if (string.IsNullOrEmpty(kid))
                    kid = JwsProtectedHeader.Decode(protB64u).Kid;
                yield return new RawSignature(protB64u, kid, DecodeSignature(sigElement.GetString()!));
            }
        }
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

    private readonly record struct RawSignature(string ProtectedB64u, string Kid, byte[] Signature);
}

/// <summary>Outcome of a successful JWS parse: payload bytes plus verified signer metadata.</summary>
/// <param name="SignatureAlgorithm">JOSE <c>alg</c> of the verified signature (e.g. <c>"EdDSA"</c>).</param>
/// <param name="SignerKid">The verified signer key identifier (empty when the JWS carried none).</param>
/// <param name="PayloadBytes">Raw decoded payload bytes.</param>
public sealed record JwsParseResult(string SignatureAlgorithm, string SignerKid, byte[] PayloadBytes);
