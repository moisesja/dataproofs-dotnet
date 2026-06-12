using NetCrypto;

namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// The <c>eddsa-jcs-2022</c> cryptosuite of Data Integrity EdDSA Cryptosuites v1.0
/// (FR-5): JCS canonicalization, SHA-256 hashing,
/// <c>hashData = SHA-256(canonicalProofConfig) ‖ SHA-256(canonicalDocument)</c>, and a
/// 64-byte Ed25519 signature encoded as base58-btc multibase <c>proofValue</c>.
/// Ed25519 signing is deterministic, so proof creation is byte-reproducible.
/// </summary>
public sealed class EddsaJcs2022Cryptosuite : ICryptosuite
{
    /// <summary>The cryptosuite identifier, <c>eddsa-jcs-2022</c>.</summary>
    public const string CryptosuiteName = "eddsa-jcs-2022";

    private readonly Engine _engine = new();

    /// <inheritdoc />
    public string Name => CryptosuiteName;

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

    private sealed class Engine : JcsCryptosuite
    {
        public override string Name => CryptosuiteName;

        protected override bool IsSupportedKeyType(KeyType keyType) => keyType == KeyType.Ed25519;

        protected override byte[] ComputeHash(ReadOnlySpan<byte> data, KeyType keyType) => Hash.Sha256(data);

        protected override byte[]? NormalizeSignature(byte[] signature, KeyType keyType)
            => signature.Length == 64 ? signature : null;

        protected override bool VerifySignature(PublicKeyMaterial publicKey, ReadOnlySpan<byte> hashData, ReadOnlySpan<byte> signature)
            => Crypto.Verify(publicKey.KeyType, publicKey.KeyBytes.Span, hashData, signature);
    }
}
