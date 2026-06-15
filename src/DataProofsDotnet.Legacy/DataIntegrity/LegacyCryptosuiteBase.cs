using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc;
using NetCid;
using NetCrypto;

namespace DataProofsDotnet.Legacy.DataIntegrity;

/// <summary>
/// Shared mechanics of the legacy Linked-Data-Signature cryptosuites
/// (<c>Ed25519Signature2020</c>, <c>EcdsaSecp256r1Signature2019</c>), implementing
/// zcap-dotnet's 2020-era wire convention byte-for-byte.
/// </summary>
/// <remarks>
/// <para>
/// This is deliberately NOT the 2022/2019 "separate proof-config + hash-concat" mechanic
/// of <c>JcsCryptosuite</c>/<c>RdfcCryptosuite</c> — those algorithms are wrong for this
/// family, which is why these suites do not subclass them.
/// </para>
/// <list type="bullet">
/// <item><description><see cref="LegacyCanonicalization.Jcs"/> (the back-compat default):
/// the signing input is <c>JCS(document-with-nested-proof)</c> — the document with the
/// proof (minus <c>proofValue</c>) re-inserted under a <c>proof</c> member. The canonical
/// UTF-8 bytes are fed DIRECTLY to the signer; the primitive hashes internally (Ed25519
/// over the message, P-256 ECDSA over <c>SHA-256(message)</c>).</description></item>
/// <item><description><see cref="LegacyCanonicalization.Rdfc"/>: the signing input is
/// <c>SHA-256(RDFC(proofOptions+@context)) ‖ SHA-256(RDFC(document))</c> — proof-options
/// hash FIRST, the 64-byte concatenation fed directly to the signer.</description></item>
/// </list>
/// <para>
/// The legacy family carries NO <c>cryptosuite</c> member on the wire and dispatches by
/// proof <c>type</c>. Two variants of the same algorithm share that <c>type</c>, so this
/// suite verifies under both conventions (the construction-time variant first), making the
/// JCS/RDFC distinction transparent to the verifier. The bridge to the DataProofs pipeline
/// (which strips the proof before calling) is re-nesting the proof at sign/verify time.
/// Immutable and thread-safe after construction (NFR-4).
/// </para>
/// <para>
/// <b>Limitations (fail-closed / documented).</b>
/// <list type="bullet">
/// <item><description><b>Proof chains:</b> the JCS convention nests only the single current
/// proof, so it cannot bind a W3C proof chain. When the unsecured document already carries a
/// <c>proof</c> member (the pipeline injects predecessors there for <c>previousProof</c>
/// chains), JCS <em>fails closed</em> — create throws, verify does not pass. Use the RDFC
/// variant (predecessors live in the canonicalized document) or a 2022/2019 suite for chains.
/// </description></item>
/// <item><description><b>RDFC + undefined terms:</b> RDF Dataset Canonicalization binds only
/// terms defined in the active JSON-LD <c>@context</c>; members not defined there — including
/// unmodeled proof extensions such as <c>capabilityChain</c> under a context that does not
/// define them — are dropped during JSON-LD expansion and are therefore NOT cryptographically
/// bound. This is inherent to JSON-LD/RDFC and shared with the conformant <c>rdfc-*</c> suites.
/// The <see cref="LegacyCanonicalization.Jcs"/> default binds every member verbatim; prefer it
/// for documents/proofs carrying unmodeled extension members, or use an <c>@context</c> that
/// defines every term.</description></item>
/// </list>
/// </para>
/// </remarks>
internal abstract class LegacyCryptosuiteBase : ICryptosuite
{
    private protected static readonly DefaultCryptoProvider Crypto = new();

    private readonly LegacyCanonicalization _canonicalization;
    private readonly IRdfCanonicalizer? _rdfCanonicalizer;

    /// <param name="canonicalization">The canonicalization mechanic the create path uses
    /// (JCS is the back-compat default).</param>
    /// <param name="rdfCanonicalizer">The RDFC canonicalizer; defaults to the offline-default
    /// <see cref="RdfcDocumentCanonicalizer"/> when <see cref="LegacyCanonicalization.Rdfc"/>
    /// is selected. A canonicalizer is always retained so verify can fall back to RDFC.</param>
    protected LegacyCryptosuiteBase(
        LegacyCanonicalization canonicalization,
        IRdfCanonicalizer? rdfCanonicalizer)
    {
        _canonicalization = canonicalization;
        // Always keep a canonicalizer available: verify tries JCS then falls back to RDFC
        // (and vice-versa) regardless of the create-path variant. Construct the offline
        // default lazily-but-eagerly here so the suite stays immutable and thread-safe.
        _rdfCanonicalizer = rdfCanonicalizer ?? new RdfcDocumentCanonicalizer();
    }

    /// <summary>The legacy proof <c>type</c> string (e.g. <c>Ed25519Signature2020</c>).</summary>
    protected abstract string LegacyProofType { get; }

    /// <inheritdoc />
    public abstract string Name { get; }

    /// <inheritdoc />
    public IReadOnlyCollection<string> SupportedProofTypes => [LegacyProofType];

    /// <summary>Whether the given key type is usable with this suite.</summary>
    protected abstract bool IsSupportedKeyType(KeyType keyType);

    /// <summary>
    /// Normalizes the signer's raw signature to the legacy wire form, or returns
    /// <c>null</c> when the encoding is unrecognized. Ed25519 is the 64-byte identity;
    /// P-256 transcodes DER → IEEE P1363.
    /// </summary>
    protected abstract byte[]? NormalizeSignature(byte[] signature, KeyType keyType);

    /// <summary>Verifies the wire-form signature over <paramref name="signingInput"/>.</summary>
    protected abstract bool VerifySignature(
        PublicKeyMaterial publicKey, ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature);

    /// <inheritdoc />
    public async Task<DataIntegrityProof> CreateProofAsync(
        JsonElement unsecuredDocument,
        DataIntegrityProof proofOptions,
        ISigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(proofOptions);
        ArgumentNullException.ThrowIfNull(signer);

        if (unsecuredDocument.ValueKind != JsonValueKind.Object)
        {
            throw new ProofGenerationException("The document to secure must be a JSON object.");
        }

        if (!IsSupportedKeyType(signer.KeyType))
        {
            throw new ProofGenerationException(
                $"Key type {signer.KeyType} is not supported by the {Name} cryptosuite.");
        }

        // The legacy family is dispatched by type and names its algorithm by type. Accept
        // either the default Data Integrity type or this suite's own legacy type on the way
        // in; always EMIT the legacy type on the wire.
        if (!string.Equals(proofOptions.Type, DataIntegrityProof.DataIntegrityProofType, StringComparison.Ordinal)
            && !string.Equals(proofOptions.Type, LegacyProofType, StringComparison.Ordinal))
        {
            throw new ProofGenerationException(
                $"Proof options type must be '{DataIntegrityProof.DataIntegrityProofType}' or '{LegacyProofType}'.");
        }

        // Accept proof options whose cryptosuite names this suite (pipeline dispatch via
        // GetByName), but the legacy wire shape MUST NOT carry a cryptosuite member.
        if (proofOptions.Cryptosuite is { } requestedSuite
            && !string.Equals(requestedSuite, Name, StringComparison.Ordinal))
        {
            throw new ProofGenerationException(
                $"Proof options cryptosuite '{requestedSuite}' does not match '{Name}'.");
        }

        if (string.IsNullOrEmpty(proofOptions.ProofPurpose))
        {
            throw new ProofGenerationException("Proof options must declare a proofPurpose.");
        }

        if (string.IsNullOrEmpty(proofOptions.VerificationMethod))
        {
            throw new ProofGenerationException("Proof options must declare a verificationMethod.");
        }

        // proofConfig is what rides on the wire (and, minus proofValue, what is signed):
        // legacy type, NO cryptosuite, no proofValue. @context handling differs by variant.
        var proofConfig = proofOptions with
        {
            Type = LegacyProofType,
            Cryptosuite = null,
            ProofValue = null,
        };

        // The JCS 2020-era convention nests the single current proof under "proof"; it has no
        // representation for a W3C proof chain. The pipeline injects predecessor proofs under the
        // document's "proof" member for chains (DataIntegrityProofPipeline), so a JCS create over
        // such a document would silently drop them — fail closed instead. The RDFC variant binds
        // chains (the predecessors live in the canonicalized document), as do the 2022/2019 suites.
        if (_canonicalization == LegacyCanonicalization.Jcs && HasProofMember(unsecuredDocument))
        {
            throw new ProofGenerationException(
                "The legacy JCS Linked-Data-Signature convention cannot secure a document that "
                + "already carries a 'proof' member (e.g. a W3C proof chain): those bytes would not "
                + "be bound. Use the RDFC variant or a 2022/2019 Data Integrity suite for proof chains.");
        }

        byte[] signingInput;
        try
        {
            signingInput = _canonicalization == LegacyCanonicalization.Rdfc
                ? BuildRdfcSigningInput(unsecuredDocument, WithDocumentContext(proofConfig, unsecuredDocument), signer.KeyType)
                : BuildJcsSigningInput(unsecuredDocument, proofConfig);
        }
        catch (JcsFormatException ex)
        {
            throw new ProofGenerationException(
                "The document or proof configuration could not be JCS-canonicalized.", ex);
        }
        catch (RdfCanonicalizationException ex)
        {
            throw new ProofGenerationException(
                "The document or proof configuration could not be RDFC-canonicalized.", ex);
        }

        var rawSignature = await signer.SignAsync(signingInput, cancellationToken).ConfigureAwait(false);
        var signature = NormalizeSignature(rawSignature, signer.KeyType)
            ?? throw new ProofGenerationException("The signer returned a signature in an unrecognized encoding.");

        // For JCS the wire proof carries no @context (zcap nests the proof verbatim, without
        // one); for RDFC the proof options carry the document's @context. Either way the
        // emitted proof must equal the proofConfig that was used to build the signing input.
        var wireProof = _canonicalization == LegacyCanonicalization.Rdfc
            ? WithDocumentContext(proofConfig, unsecuredDocument)
            : proofConfig;

        return wireProof with
        {
            ProofValue = Multibase.Encode(signature, MultibaseEncoding.Base58Btc),
        };
    }

    /// <inheritdoc />
    public ProofVerificationResult VerifyProof(
        JsonElement unsecuredDocument,
        DataIntegrityProof proof,
        PublicKeyMaterial publicKey)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(publicKey);

        try
        {
            if (unsecuredDocument.ValueKind != JsonValueKind.Object)
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The secured document must be a JSON object.", proof);
            }

            // Legacy family: dispatch is by type; cryptosuite MUST be absent on the wire.
            if (!string.Equals(proof.Type, LegacyProofType, StringComparison.Ordinal))
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError,
                    $"The proof type is not supported by the {Name} cryptosuite.", proof);
            }

            if (proof.Cryptosuite is not null)
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError,
                    "A legacy Linked-Data-Signature proof must not carry a cryptosuite.", proof);
            }

            if (!IsSupportedKeyType(publicKey.KeyType))
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError,
                    $"Key type {publicKey.KeyType} is not supported by the {Name} cryptosuite.", proof);
            }

            if (string.IsNullOrEmpty(proof.ProofValue))
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The proof carries no proofValue.", proof);
            }

            // The legacy family REQUIRES base58-btc multibase proofValues ('z' header).
            if (!Multibase.TryDecode(proof.ProofValue, out var signature, out var encoding)
                || encoding != MultibaseEncoding.Base58Btc)
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The proofValue is not base58-btc multibase.", proof);
            }

            // The proof configuration is the proof without proofValue (and never a cryptosuite).
            var proofConfig = proof with { Cryptosuite = null, ProofValue = null };

            // A verifier cannot tell JCS from RDFC by the proof alone (same type, no
            // cryptosuite). Try the construction-time variant first, then the other. NOTE: when the
            // first variant does not verify, the second attempt re-canonicalizes the same document —
            // a second canonicalization pass on the hot verify path. Construct the suite with the
            // canonicalization its corpus actually uses so the common case verifies on the first try.
            var first = _canonicalization;
            var second = first == LegacyCanonicalization.Jcs
                ? LegacyCanonicalization.Rdfc
                : LegacyCanonicalization.Jcs;

            if (TryVerifyVariant(unsecuredDocument, proofConfig, publicKey, signature, first, out var firstTransformError)
                || TryVerifyVariant(unsecuredDocument, proofConfig, publicKey, signature, second, out var secondTransformError))
            {
                return ProofVerificationResult.Success(proof);
            }

            // If BOTH variants failed only because canonicalization could not be performed,
            // surface a transformation error; otherwise the signature simply did not verify.
            return firstTransformError && secondTransformError
                ? ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofTransformationError,
                    "The document or proof configuration could not be canonicalized.", proof)
                : ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The signature did not verify.", proof);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Fail closed on anything unexpected; never throw for hostile input (FR-3).
            return ProofVerificationResult.Failure(
                ProofProblemCodes.ProofVerificationError,
                $"Verification failed unexpectedly ({ex.GetType().Name}).", proof);
        }
    }

    /// <summary>
    /// Attempts verification under a single canonicalization variant. Returns <c>true</c>
    /// when the signature verifies; sets <paramref name="transformationFailed"/> when the
    /// failure was a canonicalization error (so the caller can distinguish a bad signature
    /// from an untransformable document).
    /// </summary>
    private bool TryVerifyVariant(
        JsonElement unsecuredDocument,
        DataIntegrityProof proofConfig,
        PublicKeyMaterial publicKey,
        byte[] signature,
        LegacyCanonicalization variant,
        out bool transformationFailed)
    {
        transformationFailed = false;

        // JCS cannot bind a document that still carries a "proof" member (a W3C proof chain the
        // pipeline injected): the convention nests only the current proof. Treat the JCS variant
        // as inapplicable so the RDFC fallback can run; if neither variant verifies, the overall
        // result is a fail-closed "the signature did not verify" (never a silent pass over the
        // unbound chain).
        if (variant == LegacyCanonicalization.Jcs && HasProofMember(unsecuredDocument))
        {
            transformationFailed = true;
            return false;
        }

        byte[] signingInput;
        try
        {
            signingInput = variant == LegacyCanonicalization.Rdfc
                ? BuildRdfcSigningInput(
                    unsecuredDocument, WithDocumentContext(proofConfig, unsecuredDocument), publicKey.KeyType)
                : BuildJcsSigningInput(unsecuredDocument, proofConfig);
        }
        catch (Exception ex) when (ex is JcsFormatException or RdfCanonicalizationException)
        {
            transformationFailed = true;
            return false;
        }

        return VerifySignature(publicKey, signingInput, signature);
    }

    /// <summary>
    /// Builds the JCS signing input: the document with the proof configuration (minus
    /// <c>proofValue</c>, minus <c>cryptosuite</c>) re-nested under a <c>proof</c> member,
    /// JCS-canonicalized. The UTF-8 bytes are signed directly (no explicit pre-hash).
    /// </summary>
    private static byte[] BuildJcsSigningInput(JsonElement unsecuredDocument, DataIntegrityProof proofConfig)
    {
        var docNode = JsonObject.Create(unsecuredDocument)!;
        docNode["proof"] = JsonSerializer.SerializeToNode(proofConfig, DataProofsJsonOptions.Default);
        var combined = JsonSerializer.SerializeToElement(docNode, DataProofsJsonOptions.Default);

        // Drop null object members (preserving null array elements) before canonicalizing, so a
        // JsonElement round-tripped from the wire canonicalizes identically to a WhenWritingNull-
        // serialized model. This mirrors zcap-dotnet's JsonCanonicalizer.StripNullMembers and is
        // load-bearing for cross-stack byte-identity on any document/proof carrying explicit nulls
        // (RFC 8785 itself keeps nulls; the legacy stacks strip object-member nulls before signing).
        var stripped = StripNullMembers(combined);
        return JcsCanonicalizer.Canonicalize(
            JsonSerializer.SerializeToElement(stripped, DataProofsJsonOptions.Default));
    }

    /// <summary>Whether <paramref name="document"/> already carries a top-level <c>proof</c> member.</summary>
    private static bool HasProofMember(JsonElement document)
        => document.ValueKind == JsonValueKind.Object && document.TryGetProperty("proof", out _);

    /// <summary>
    /// Rebuilds <paramref name="element"/> dropping every null-valued <em>object member</em> at any
    /// depth while preserving null <em>array elements</em> (RFC 8785 keeps those). Byte-for-byte
    /// equivalent to zcap-dotnet's <c>JsonCanonicalizer.StripNullMembers</c>.
    /// </summary>
    private static JsonNode? StripNullMembers(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                var obj = new JsonObject();
                foreach (var property in element.EnumerateObject())
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }

                    obj[property.Name] = StripNullMembers(property.Value);
                }

                return obj;

            case JsonValueKind.Array:
                var arr = new JsonArray();
                foreach (var item in element.EnumerateArray())
                {
                    arr.Add(item.ValueKind == JsonValueKind.Null ? null : StripNullMembers(item));
                }

                return arr;

            default:
                return JsonNode.Parse(element.GetRawText());
        }
    }

    /// <summary>
    /// Builds the RDFC signing input: <c>SHA-256(RDFC(proofOptions)) ‖ SHA-256(RDFC(document))</c>
    /// — proof-options hash FIRST. <paramref name="proofOptions"/> must already carry the
    /// document's <c>@context</c> for JSON-LD processing.
    /// </summary>
    private byte[] BuildRdfcSigningInput(
        JsonElement unsecuredDocument, DataIntegrityProof proofOptions, KeyType keyType)
    {
        var canonicalProofOptions = _rdfCanonicalizer!.CanonicalizeJsonLd(
            JsonSerializer.SerializeToElement(proofOptions, DataProofsJsonOptions.Default),
            RdfCanonicalizationHashAlgorithm.Sha256);
        var canonicalDocument = _rdfCanonicalizer.CanonicalizeJsonLd(
            unsecuredDocument, RdfCanonicalizationHashAlgorithm.Sha256);

        // The legacy 2019/2020 suites are P-256/Ed25519 only — SHA-256 for both the RDFC
        // internal blank-node hash and the message digest. Concat is proofOptions ‖ document.
        var proofOptionsHash = Hash.Sha256(canonicalProofOptions);
        var documentHash = Hash.Sha256(canonicalDocument);

        var signingInput = new byte[proofOptionsHash.Length + documentHash.Length];
        proofOptionsHash.CopyTo(signingInput, 0);
        documentHash.CopyTo(signingInput, proofOptionsHash.Length);
        return signingInput;
    }

    /// <summary>
    /// Returns the proof options carrying the document's <c>@context</c> (the RDFC proof
    /// options always do). When the document has no <c>@context</c>, the proof's own is kept.
    /// </summary>
    private static DataIntegrityProof WithDocumentContext(DataIntegrityProof proofOptions, JsonElement document)
        => document.TryGetProperty("@context", out var documentContext)
            ? proofOptions with { Context = documentContext.Clone() }
            : proofOptions;
}
