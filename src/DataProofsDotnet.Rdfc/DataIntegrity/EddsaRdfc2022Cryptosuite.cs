using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using NetCrypto;

namespace DataProofsDotnet.Rdfc.DataIntegrity;

/// <summary>
/// The <c>eddsa-rdfc-2022</c> cryptosuite of Data Integrity EdDSA Cryptosuites v1.0
/// (FR-11): RDFC-1.0 canonicalization, SHA-256 hashing,
/// <c>hashData = SHA-256(canonicalProofConfig) ‖ SHA-256(canonicalDocument)</c>, and a
/// 64-byte Ed25519 signature encoded as base58-btc multibase <c>proofValue</c>.
/// Ed25519 signing is deterministic, so proof creation is byte-reproducible.
/// </summary>
public sealed class EddsaRdfc2022Cryptosuite : ICryptosuite
{
    /// <summary>The cryptosuite identifier, <c>eddsa-rdfc-2022</c>.</summary>
    public const string CryptosuiteName = "eddsa-rdfc-2022";

    private readonly Engine _engine;

    /// <summary>Creates the suite over the offline-default RDFC canonicalizer (FR-10).</summary>
    public EddsaRdfc2022Cryptosuite()
        : this(new RdfcDocumentCanonicalizer())
    {
    }

    /// <summary>Creates the suite over the given RDFC canonicalizer.</summary>
    public EddsaRdfc2022Cryptosuite(IRdfCanonicalizer canonicalizer)
    {
        _engine = new Engine(canonicalizer);
    }

    /// <inheritdoc />
    public string Name => CryptosuiteName;

    /// <inheritdoc />
    public Task<DataIntegrityProof> CreateProofAsync(
        JsonElement unsecuredDocument,
        DataIntegrityProof proofOptions,
        ISigner signer,
        CancellationToken cancellationToken = default)
        => _engine.CreateProofAsync(unsecuredDocument, proofOptions, signer, cancellationToken);

    /// <inheritdoc />
    public ProofVerificationResult VerifyProof(
        JsonElement unsecuredDocument,
        DataIntegrityProof proof,
        PublicKeyMaterial publicKey)
        => _engine.VerifyProof(unsecuredDocument, proof, publicKey);

    private sealed class Engine(IRdfCanonicalizer canonicalizer) : RdfcCryptosuite(canonicalizer)
    {
        public override string Name => CryptosuiteName;

        protected override bool IsSupportedKeyType(KeyType keyType) => keyType == KeyType.Ed25519;

        protected override RdfCanonicalizationHashAlgorithm CanonicalizationHash(KeyType keyType)
            => RdfCanonicalizationHashAlgorithm.Sha256;

        protected override byte[] ComputeHash(ReadOnlySpan<byte> data, KeyType keyType) => Hash.Sha256(data);

        protected override byte[]? NormalizeSignature(byte[] signature, KeyType keyType)
            => signature.Length == 64 ? signature : null;

        protected override bool VerifySignature(PublicKeyMaterial publicKey, ReadOnlySpan<byte> hashData, ReadOnlySpan<byte> signature)
            => Crypto.Verify(publicKey.KeyType, publicKey.KeyBytes.Span, hashData, signature);
    }
}
