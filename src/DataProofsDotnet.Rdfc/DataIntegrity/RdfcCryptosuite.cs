using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using NetCid;
using NetCrypto;

namespace DataProofsDotnet.Rdfc.DataIntegrity;

/// <summary>
/// Shared mechanics of the RDFC cryptosuites (FR-11), implementing the conformant
/// transform → hash → serialize pipeline of VC Data Integrity 1.0 with RDF Dataset
/// Canonicalization (RDFC-1.0) as the transformation:
/// <list type="number">
/// <item><description>Transformation: RDFC-1.0 canonicalization of the unsecured document.</description></item>
/// <item><description>Proof configuration: the proof options carrying the document's <c>@context</c>
/// and without <c>proofValue</c>, RDFC-1.0-canonicalized separately.</description></item>
/// <item><description>Hashing: <c>hashData = hash(canonicalProofConfig) ‖ hash(canonicalDocument)</c>
/// with the suite/curve-mandated hash via NetCrypto.</description></item>
/// <item><description>Serialization: signature over <c>hashData</c> via the NetCrypto
/// <see cref="ISigner"/>; <c>proofValue</c> is base58-btc multibase via NetCid.</description></item>
/// </list>
/// Ported from zcap-dotnet's RDFC hash-concat (already conformant), generalized to arbitrary
/// documents and rerouted to NetCrypto/NetCid. Immutable and thread-safe (NFR-4).
/// </summary>
internal abstract class RdfcCryptosuite : ICryptosuite
{
    private protected static readonly DefaultCryptoProvider Crypto = new();

    private readonly IRdfCanonicalizer _canonicalizer;

    protected RdfcCryptosuite(IRdfCanonicalizer canonicalizer)
    {
        ArgumentNullException.ThrowIfNull(canonicalizer);
        _canonicalizer = canonicalizer;
    }

    /// <inheritdoc />
    public abstract string Name { get; }

    /// <summary>Whether the given key type is usable with this suite.</summary>
    protected abstract bool IsSupportedKeyType(KeyType keyType);

    /// <summary>The RDFC-1.0 internal hash algorithm for the given key type.</summary>
    protected abstract RdfCanonicalizationHashAlgorithm CanonicalizationHash(KeyType keyType);

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

        // Per the RDFC suites' Create Proof algorithm: the proof configuration carries the
        // same @context as the unsecured document so JSON-LD processing of the config uses
        // the document's vocabulary.
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
            var hash = CanonicalizationHash(signer.KeyType);
            canonicalProofConfig = _canonicalizer.CanonicalizeJsonLd(
                JsonSerializer.SerializeToElement(proofConfig, DataProofsJsonOptions.Default), hash);
            canonicalDocument = _canonicalizer.CanonicalizeJsonLd(unsecuredDocument, hash);
        }
        catch (RdfCanonicalizationException ex)
        {
            throw new ProofGenerationException("The document or proof configuration could not be RDFC-canonicalized.", ex);
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

            if (string.IsNullOrEmpty(proof.ProofValue))
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The proof carries no proofValue.", proof);
            }

            // The 2022/2019 RDFC suites REQUIRE base58-btc multibase proofValues ('z' header).
            if (!Multibase.TryDecode(proof.ProofValue, out var signature, out var encoding)
                || encoding != MultibaseEncoding.Base58Btc)
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The proofValue is not base58-btc multibase.", proof);
            }

            // The proof configuration is the proof without proofValue. For RDFC the proof
            // config carries an @context for JSON-LD processing: prefer the proof's own, else
            // borrow the secured document's (proofs created here always carry @context).
            var proofConfig = proof with { ProofValue = null };
            if (proofConfig.Context is null && unsecuredDocument.TryGetProperty("@context", out var docContext))
            {
                proofConfig = proofConfig with { Context = docContext.Clone() };
            }

            byte[] canonicalProofConfig;
            byte[] canonicalDocument;
            try
            {
                var hash = CanonicalizationHash(publicKey.KeyType);
                canonicalProofConfig = _canonicalizer.CanonicalizeJsonLd(
                    JsonSerializer.SerializeToElement(proofConfig, DataProofsJsonOptions.Default), hash);
                canonicalDocument = _canonicalizer.CanonicalizeJsonLd(unsecuredDocument, hash);
            }
            catch (RdfCanonicalizationException)
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofTransformationError,
                    "The document or proof configuration could not be RDFC-canonicalized.", proof);
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
}
