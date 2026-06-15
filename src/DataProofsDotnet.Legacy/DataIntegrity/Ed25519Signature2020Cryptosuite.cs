using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc;
using NetCrypto;

namespace DataProofsDotnet.Legacy.DataIntegrity;

/// <summary>
/// The legacy <c>Ed25519Signature2020</c> Linked-Data-Signature suite, byte-compatible with
/// zcap-dotnet's 2020-era wire convention (FR — legacy embedded proofs). Ed25519 over a
/// signing input built by JCS (the default) or RDFC-1.0; the 64-byte signature is encoded
/// as a base58-btc multibase <c>proofValue</c>. The wire proof carries
/// <c>type:"Ed25519Signature2020"</c> and NO <c>cryptosuite</c>; dispatch is by <c>type</c>.
/// </summary>
/// <remarks>
/// Ed25519 signing is deterministic, so JCS proof creation is byte-reproducible. A verifier
/// cannot distinguish the JCS and RDFC variants from the proof alone, so this suite verifies
/// under the construction-time variant first and falls back to the other.
/// </remarks>
public sealed class Ed25519Signature2020Cryptosuite : ICryptosuite
{
    /// <summary>The legacy proof <c>type</c>, <c>Ed25519Signature2020</c>.</summary>
    public const string ProofType = "Ed25519Signature2020";

    private readonly Engine _engine;

    /// <summary>
    /// Creates the suite. <paramref name="canonicalization"/> selects the create-path
    /// mechanic (<see cref="LegacyCanonicalization.Jcs"/> is the back-compat default);
    /// <paramref name="rdfCanonicalizer"/> overrides the offline-default RDFC canonicalizer
    /// (used by the RDFC variant and the RDFC verify fallback).
    /// </summary>
    public Ed25519Signature2020Cryptosuite(
        LegacyCanonicalization canonicalization = LegacyCanonicalization.Jcs,
        IRdfCanonicalizer? rdfCanonicalizer = null)
    {
        _engine = new Engine(canonicalization, rdfCanonicalizer);
    }

    /// <inheritdoc />
    public string Name => ProofType;

    /// <inheritdoc />
    public IReadOnlyCollection<string> SupportedProofTypes => _engine.SupportedProofTypes;

    /// <inheritdoc />
    public Task<DataIntegrityProof> CreateProofAsync(
        System.Text.Json.JsonElement unsecuredDocument,
        DataIntegrityProof proofOptions,
        ISigner signer,
        CancellationToken cancellationToken = default)
        => _engine.CreateProofAsync(unsecuredDocument, proofOptions, signer, cancellationToken);

    /// <inheritdoc />
    public ProofVerificationResult VerifyProof(
        System.Text.Json.JsonElement unsecuredDocument,
        DataIntegrityProof proof,
        PublicKeyMaterial publicKey)
        => _engine.VerifyProof(unsecuredDocument, proof, publicKey);

    private sealed class Engine(LegacyCanonicalization canonicalization, IRdfCanonicalizer? rdfCanonicalizer)
        : LegacyCryptosuiteBase(canonicalization, rdfCanonicalizer)
    {
        protected override string LegacyProofType => ProofType;

        public override string Name => ProofType;

        protected override bool IsSupportedKeyType(KeyType keyType) => keyType == KeyType.Ed25519;

        protected override byte[]? NormalizeSignature(byte[] signature, KeyType keyType)
            => signature.Length == 64 ? signature : null;

        protected override bool VerifySignature(
            PublicKeyMaterial publicKey, ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature)
            => Crypto.Verify(publicKey.KeyType, publicKey.KeyBytes.Span, signingInput, signature);
    }
}
