using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Signing;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// Issues SD-JWTs (RFC 9901 §5): walks an input claims set against a <see cref="DisclosureFrame"/>,
/// replaces selectively disclosable claims with salted-hash digests (object properties into
/// <c>_sd</c> arrays, array elements into <c>{"...": digest}</c> placeholders, recursively),
/// adds decoy digests, writes <c>_sd_alg</c> and an optional <c>cnf</c> Holder key, signs the
/// resulting payload as a JWS through a NetCrypto <see cref="JwsSigner"/>, and returns the
/// combined issuance string. Stateless and thread-safe.
/// </summary>
public static class SdJwtIssuer
{
    /// <summary>The result of issuing an SD-JWT: the combined serialization plus its parts.</summary>
    /// <param name="Issuance">The full SD-JWT compact serialization (<c>issuer-JWT~D1~…~Dn~</c>).</param>
    /// <param name="IssuerJwt">The signed issuer JWT (the issuance string's first element).</param>
    /// <param name="Disclosures">Every Disclosure produced, in creation order.</param>
    public sealed record Result(string Issuance, string IssuerJwt, IReadOnlyList<Disclosure> Disclosures);

    /// <summary>
    /// Issue an SD-JWT from an input claims set and a disclosure frame.
    /// </summary>
    /// <param name="claims">The input claims set (a JSON object). Not mutated.</param>
    /// <param name="frame">Which claims are selectively disclosable.</param>
    /// <param name="signer">The Issuer's NetCrypto-backed JWS signer.</param>
    /// <param name="options">Issuance options (hash algorithm, decoys, holder cnf key).</param>
    /// <param name="typ">The issuer-JWT <c>typ</c> protected-header value (e.g. <c>example+sd-jwt</c>, <c>dc+sd-jwt</c>).</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    /// <exception cref="MalformedJoseException">
    /// When the frame references a claim shape the claims set does not have, or the SD-JWT would not verify: an
    /// <c>_sd_alg</c> below the top level (RFC 9901 §4.1.1), a duplicate member name, a Disclosure named <c>_sd</c> or
    /// <c>...</c>, a top-level <c>nbf</c> or <c>exp</c> that is not a NumericDate (a JSON number of seconds, RFC 7519
    /// §4.1; a <see cref="DateTimeOffset"/> serializes as a string) or is one outside -62135596800 to 253402300799
    /// (0001-01-01 to 9999-12-31, which RFC 7519 allows and the verifier refuses), or anything else in its content that
    /// <see cref="SdJwtVerifier"/> refuses when every Disclosure is presented. The time is not judged: an SD-JWT whose
    /// <c>nbf</c> is in the future, or whose <c>exp</c> has passed, is issued, and fails verification until, or from,
    /// then. A value the serializer cannot write at all, such as a non-finite <see cref="double"/>, fails as it always
    /// has, with the serializer's exception.
    /// </exception>
    public static async Task<Result> IssueAsync(
        JsonObject claims,
        DisclosureFrame frame,
        JwsSigner signer,
        SdJwtIssuerOptions? options = null,
        string? typ = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(frame);
        ArgumentNullException.ThrowIfNull(signer);

        options ??= new SdJwtIssuerOptions();
        if (!SdHashAlgorithm.IsSupported(options.HashAlgorithm))
            throw new MalformedJoseException($"Unsupported SD-JWT '_sd_alg' value '{options.HashAlgorithm}'.");
        if (options.DecoyDigestCount < 0)
            throw new ArgumentOutOfRangeException(nameof(options), "DecoyDigestCount must be non-negative.");

        var crypto = new JoseCryptoProvider();
        var disclosures = new List<Disclosure>();

        var payload = (JsonObject)ApplyFrame((JsonObject)claims.DeepClone(), frame, options, crypto, disclosures);

        payload["_sd_alg"] = options.HashAlgorithm;
        if (options.HolderConfirmationKey is not null)
            payload["cnf"] = BuildConfirmation(options.HolderConfirmationKey);

        var payloadBytes = CompactJwt.SerializePayload(payload);
        EnsureReconstructs(payloadBytes, disclosures, options.HashAlgorithm);
        var issuerJwt = await JwsBuilder.BuildCompactAsync(payloadBytes, signer, typ: typ, detachedPayload: false, cancellationToken)
            .ConfigureAwait(false);

        var issuance = string.Concat(issuerJwt, "~",
            disclosures.Count == 0 ? string.Empty : string.Join("~", disclosures.Select(d => d.Encoded)) + "~");
        // Normalize: when there are no disclosures the issuance is "<jwt>~".
        if (disclosures.Count == 0)
            issuance = issuerJwt + "~";

        return new Result(issuance, issuerJwt, disclosures);
    }

    private static JsonNode ApplyFrame(
        JsonObject obj,
        DisclosureFrame frame,
        SdJwtIssuerOptions options,
        JoseCryptoProvider crypto,
        List<Disclosure> disclosures)
    {
        var sdDigests = new List<string>();

        foreach (var (claimName, entry) in frame.Entries)
        {
            if (!obj.TryGetPropertyValue(claimName, out var value))
                throw new MalformedJoseException($"DisclosureFrame references claim '{claimName}' that is not present in the claims set.");

            switch (entry.Kind)
            {
                case DisclosureFrame.FrameKind.WholeValue:
                {
                    obj.Remove(claimName);
                    var salt = SaltSource.Generate(crypto);
                    var disclosure = Disclosure.ForObjectProperty(salt, claimName, value);
                    disclosures.Add(disclosure);
                    sdDigests.Add(disclosure.ComputeDigest(options.HashAlgorithm));
                    break;
                }

                case DisclosureFrame.FrameKind.NestedObject:
                {
                    if (value is not JsonObject nestedObj)
                        throw new MalformedJoseException($"DisclosureFrame marks claim '{claimName}' as an object, but its value is not a JSON object.");

                    // Recurse: rewrite the nested object so its named sub-claims become _sd digests.
                    var rewritten = (JsonObject)ApplyFrame((JsonObject)nestedObj.DeepClone(), entry.Nested!, options, crypto, disclosures);

                    if (entry.Recursive)
                    {
                        // §6.3: wrap the rewritten object in its own Disclosure; the parent keeps
                        // only the digest of that Disclosure.
                        obj.Remove(claimName);
                        var salt = SaltSource.Generate(crypto);
                        var disclosure = Disclosure.ForObjectProperty(salt, claimName, rewritten);
                        disclosures.Add(disclosure);
                        sdDigests.Add(disclosure.ComputeDigest(options.HashAlgorithm));
                    }
                    else
                    {
                        // §6.2: the object stays in the clear, carrying its own _sd array.
                        obj[claimName] = rewritten;
                    }
                    break;
                }

                case DisclosureFrame.FrameKind.ArrayElements:
                {
                    if (value is not JsonArray array)
                        throw new MalformedJoseException($"DisclosureFrame marks claim '{claimName}' as an array, but its value is not a JSON array.");

                    var newArray = new JsonArray();
                    for (var i = 0; i < array.Count; i++)
                    {
                        if (entry.ArrayIndices!.Contains(i))
                        {
                            var salt = SaltSource.Generate(crypto);
                            var disclosure = Disclosure.ForArrayElement(salt, array[i]);
                            disclosures.Add(disclosure);
                            var digest = disclosure.ComputeDigest(options.HashAlgorithm);
                            // The explicit JsonNode cast selects the non-generic Add: JsonArray.Add<T> is reflection-based.
                            newArray.Add((JsonNode)new JsonObject { ["..."] = digest });
                        }
                        else
                        {
                            newArray.Add(array[i]?.DeepClone());
                        }
                    }
                    obj[claimName] = newArray;
                    break;
                }
            }
        }

        // Decoys (RFC 9901 §4.2.7): random digest-shaped strings with no Disclosure behind them.
        for (var i = 0; i < options.DecoyDigestCount; i++)
            sdDigests.Add(GenerateDecoyDigest(options.HashAlgorithm, crypto));

        if (sdDigests.Count > 0)
        {
            // RFC 9901 §4.2.4.1 RECOMMENDS sorting the _sd digests so their order does not leak the
            // original claim order. Matches the worked-example payloads.
            sdDigests.Sort(StringComparer.Ordinal);
            var sd = new JsonArray();
            foreach (var d in sdDigests)
                sd.Add((JsonNode)d);
            obj["_sd"] = sd;
        }

        return obj;
    }

    /// <summary>
    /// Refuses to sign an SD-JWT that <see cref="SdJwtVerifier"/> would refuse to reconstruct with every Disclosure
    /// presented: the payload bytes and the encoded Disclosures are parsed back and reconstructed as a verifier would.
    /// A caller's claims set can carry what RFC 9901 forbids, such as an <c>_sd_alg</c> below the top level (§4.1.1),
    /// a member name twice (RFC 7519 §4), a Disclosure named <c>_sd</c> or <c>...</c>, or a top-level <c>nbf</c> or
    /// <c>exp</c> that is not a NumericDate or lies outside the years 0001 to 9999, read in the processed payload as the
    /// verifier reads it; the frame copies it as given, and a .NET object inside a <see cref="JsonValue"/> only shows
    /// it once serialized, which is why the serialized form is checked.
    /// </summary>
    /// <exception cref="MalformedJoseException">When the SD-JWT would not reconstruct.</exception>
    private static void EnsureReconstructs(byte[] payloadBytes, IReadOnlyList<Disclosure> disclosures, string sdAlg)
    {
        try
        {
            var signed = JsonNode.Parse(payloadBytes, documentOptions: new JsonDocumentOptions { AllowDuplicateProperties = false })
                as JsonObject ?? throw new MalformedJoseException("The SD-JWT payload is not a JSON object.");
            var parsed = disclosures.Select(d => Disclosure.Parse(d.Encoded)).ToList();
            var processed = SdJwtReconstructor.Reconstruct(signed, parsed, sdAlg);

            // The verifier refuses a present top-level nbf or exp that is not a NumericDate (RFC 9901 §7.1 step 6,
            // RFC 7519 §4.1), at any time. Only the shape is checked here: an Issuer may sign a credential that
            // becomes valid later, or one already expired.
            if (ValidityWindow.ShapeViolation(processed) is { } violation)
                throw new MalformedJoseException(violation);
        }
        catch (JsonException ex)
        {
            throw new MalformedJoseException(
                "The SD-JWT payload does not serialize to a JSON object with unique member names (RFC 7519 §4); it is not issued.", ex);
        }
        catch (MalformedJoseException ex)
        {
            throw new MalformedJoseException($"The SD-JWT would not verify, so it is not issued: {ex.Message}", ex);
        }
    }

    private static string GenerateDecoyDigest(string sdAlg, JoseCryptoProvider crypto)
    {
        // A decoy is the digest of a random salt-length value — indistinguishable from a real
        // digest, but no Disclosure produces it (RFC 9901 §4.2.7).
        Span<byte> buffer = stackalloc byte[SaltSource.SaltByteLength];
        crypto.Fill(buffer);
        return SdHashAlgorithm.ComputeDigest(sdAlg, Base64Url.Encode(buffer));
    }

    private static JsonObject BuildConfirmation(Jwk holderKey)
    {
        // cnf = { "jwk": { public members only } } (RFC 7800 / RFC 9901 §6).
        var jwk = new JsonObject { ["kty"] = holderKey.Kty };
        if (holderKey.Crv is not null) jwk["crv"] = holderKey.Crv;
        if (holderKey.X is not null) jwk["x"] = holderKey.X;
        if (holderKey.Y is not null) jwk["y"] = holderKey.Y;
        return new JsonObject { ["jwk"] = jwk };
    }
}
