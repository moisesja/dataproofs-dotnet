using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Internal;
using NetCid;
using NetCrypto;

namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// Shared mechanics of the JCS cryptosuites (FR-5), implementing the conformant
/// transform → hash → serialize pipeline of VC Data Integrity 1.0:
/// <list type="number">
/// <item><description>Transformation: JCS (RFC 8785) canonicalization of the unsecured document via NetCid.</description></item>
/// <item><description>Proof configuration: the proof options with the document's <c>@context</c> and
/// without <c>proofValue</c>, JCS-canonicalized separately.</description></item>
/// <item><description>Hashing: <c>hashData = hash(canonicalProofConfig) ‖ hash(canonicalDocument)</c>
/// with the suite/curve-mandated hash via NetCrypto.</description></item>
/// <item><description>Serialization: signature over <c>hashData</c> via the NetCrypto
/// <see cref="ISigner"/>; <c>proofValue</c> is base58-btc multibase via NetCid.</description></item>
/// </list>
/// Note this deliberately does NOT use the 2020-era embedded-proof JCS convention
/// (signing the document with the proof nested inside it) — the 2022/2019 suites require
/// the separate-proof-config + hash-concat mechanic.
/// </summary>
internal abstract class JcsCryptosuite : ICryptosuite
{
    private protected static readonly DefaultCryptoProvider Crypto = new();

    /// <inheritdoc />
    public abstract string Name { get; }

    /// <summary>Whether the given key type is usable with this suite.</summary>
    protected abstract bool IsSupportedKeyType(KeyType keyType);

    /// <summary>The suite/curve-mandated hash of <paramref name="data"/> (NetCrypto).</summary>
    protected abstract byte[] ComputeHash(ReadOnlySpan<byte> data, KeyType keyType);

    /// <summary>
    /// Normalizes the signer's raw signature to the suite's wire form, or returns
    /// <c>null</c> when the signature encoding is unrecognized.
    /// </summary>
    protected abstract byte[]? NormalizeSignature(byte[] signature, KeyType keyType);

    /// <summary>Verifies the wire-form signature over <paramref name="hashData"/>.</summary>
    protected abstract bool VerifySignature(PublicKeyMaterial publicKey, ReadOnlySpan<byte> hashData, ReadOnlySpan<byte> signature);

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
            throw new ProofGenerationException($"Key type {signer.KeyType} is not supported by the {Name} cryptosuite.");
        }

        if (!string.Equals(proofOptions.Type, DataIntegrityProof.DataIntegrityProofType, StringComparison.Ordinal))
        {
            throw new ProofGenerationException($"Proof options type must be '{DataIntegrityProof.DataIntegrityProofType}'.");
        }

        var cryptosuite = proofOptions.Cryptosuite ?? Name;
        if (!string.Equals(cryptosuite, Name, StringComparison.Ordinal))
        {
            throw new ProofGenerationException($"Proof options cryptosuite '{cryptosuite}' does not match '{Name}'.");
        }

        if (string.IsNullOrEmpty(proofOptions.ProofPurpose))
        {
            throw new ProofGenerationException("Proof options must declare a proofPurpose.");
        }

        if (string.IsNullOrEmpty(proofOptions.VerificationMethod))
        {
            throw new ProofGenerationException("Proof options must declare a verificationMethod.");
        }

        if (proofOptions.Created is not null && !XmlDateTimeStamp.TryParse(proofOptions.Created, out _))
        {
            throw new ProofGenerationException("Proof options 'created' is not a valid dateTimeStamp.");
        }

        if (proofOptions.Expires is not null && !XmlDateTimeStamp.TryParse(proofOptions.Expires, out _))
        {
            throw new ProofGenerationException("Proof options 'expires' is not a valid dateTimeStamp.");
        }

        // Per the JCS suites' Create Proof algorithm: when the unsecured document has an
        // @context, the proof carries the same @context.
        var context = unsecuredDocument.TryGetProperty("@context", out var documentContext)
            ? documentContext.Clone()
            : proofOptions.Context;

        var proofConfig = proofOptions with
        {
            Cryptosuite = cryptosuite,
            Context = context,
            ProofValue = null,
        };

        byte[] canonicalProofConfig;
        byte[] canonicalDocument;
        try
        {
            canonicalProofConfig = JcsCanonicalizer.Canonicalize(
                JsonSerializer.SerializeToElement(proofConfig, DataProofsJsonOptions.Default));
            canonicalDocument = JcsCanonicalizer.Canonicalize(unsecuredDocument);
        }
        catch (JcsFormatException ex)
        {
            throw new ProofGenerationException("The document or proof configuration could not be JCS-canonicalized.", ex);
        }

        var hashData = ConcatenateHashes(canonicalProofConfig, canonicalDocument, signer.KeyType);

        var rawSignature = await signer.SignAsync(hashData, cancellationToken).ConfigureAwait(false);
        var signature = NormalizeSignature(rawSignature, signer.KeyType)
            ?? throw new ProofGenerationException("The signer returned a signature in an unrecognized encoding.");

        return proofConfig with
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

            if (!string.Equals(proof.Type, DataIntegrityProof.DataIntegrityProofType, StringComparison.Ordinal)
                || !string.Equals(proof.Cryptosuite, Name, StringComparison.Ordinal))
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError,
                    $"The proof type/cryptosuite is not supported by the {Name} cryptosuite.", proof);
            }

            if (!IsSupportedKeyType(publicKey.KeyType))
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError,
                    $"Key type {publicKey.KeyType} is not supported by the {Name} cryptosuite.", proof);
            }

            if (proof.Created is not null && !XmlDateTimeStamp.TryParse(proof.Created, out _))
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The proof 'created' is not a valid dateTimeStamp.", proof);
            }

            if (proof.Expires is not null && !XmlDateTimeStamp.TryParse(proof.Expires, out _))
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The proof 'expires' is not a valid dateTimeStamp.", proof);
            }

            if (string.IsNullOrEmpty(proof.ProofValue))
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The proof carries no proofValue.", proof);
            }

            // The 2022/2019 suites REQUIRE base58-btc multibase proofValues ('z' header).
            if (!Multibase.TryDecode(proof.ProofValue, out var signature, out var encoding)
                || encoding != MultibaseEncoding.Base58Btc)
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The proofValue is not base58-btc multibase.", proof);
            }

            // JCS suites: when the proof carries @context, the secured document's @context
            // must start with the proof's @context values (in order); the document is then
            // canonicalized under the proof's @context.
            var documentToCanonicalize = unsecuredDocument;
            JsonNode? rewrittenDocument = null;
            if (proof.Context is { } proofContext)
            {
                if (!ContextStartsWith(unsecuredDocument, proofContext))
                {
                    return ProofVerificationResult.Failure(
                        ProofProblemCodes.ProofVerificationError,
                        "The secured document's @context does not start with the proof's @context.", proof);
                }

                var documentNode = JsonObject.Create(unsecuredDocument)!;
                documentNode["@context"] = JsonNode.Parse(proofContext.GetRawText());
                rewrittenDocument = documentNode;
            }

            byte[] canonicalProofConfig;
            byte[] canonicalDocument;
            try
            {
                var proofConfig = proof with { ProofValue = null };
                canonicalProofConfig = JcsCanonicalizer.Canonicalize(
                    JsonSerializer.SerializeToElement(proofConfig, DataProofsJsonOptions.Default));
                canonicalDocument = rewrittenDocument is null
                    ? JcsCanonicalizer.Canonicalize(documentToCanonicalize)
                    : JcsCanonicalizer.Canonicalize(rewrittenDocument);
            }
            catch (JcsFormatException)
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofTransformationError,
                    "The document or proof configuration could not be JCS-canonicalized.", proof);
            }

            var hashData = ConcatenateHashes(canonicalProofConfig, canonicalDocument, publicKey.KeyType);

            return VerifySignature(publicKey, hashData, signature)
                ? ProofVerificationResult.Success(proof)
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
    /// Builds <c>hashData = hash(canonicalProofConfig) ‖ hash(canonicalDocument)</c> —
    /// proof-configuration hash FIRST, per the suites' hashing algorithms.
    /// </summary>
    private byte[] ConcatenateHashes(byte[] canonicalProofConfig, byte[] canonicalDocument, KeyType keyType)
    {
        var proofConfigHash = ComputeHash(canonicalProofConfig, keyType);
        var documentHash = ComputeHash(canonicalDocument, keyType);

        var hashData = new byte[proofConfigHash.Length + documentHash.Length];
        proofConfigHash.CopyTo(hashData, 0);
        documentHash.CopyTo(hashData, proofConfigHash.Length);
        return hashData;
    }

    /// <summary>
    /// Returns <c>true</c> when the document's <c>@context</c> starts with all values of
    /// the proof's <c>@context</c> in the same order (scalars treated as single-element
    /// sequences), per the JCS suites' verification algorithms.
    /// </summary>
    private static bool ContextStartsWith(JsonElement document, JsonElement proofContext)
    {
        if (!document.TryGetProperty("@context", out var documentContext))
        {
            return false;
        }

        var proofValues = AsContextSequence(proofContext);
        var documentValues = AsContextSequence(documentContext);

        if (proofValues.Count > documentValues.Count)
        {
            return false;
        }

        for (var i = 0; i < proofValues.Count; i++)
        {
            if (!JsonElement.DeepEquals(proofValues[i], documentValues[i]))
            {
                return false;
            }
        }

        return true;
    }

    private static List<JsonElement> AsContextSequence(JsonElement context)
        => context.ValueKind == JsonValueKind.Array
            ? [.. context.EnumerateArray()]
            : [context];
}
