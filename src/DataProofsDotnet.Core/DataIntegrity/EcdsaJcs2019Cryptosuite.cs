using DataProofsDotnet.Internal;
using NetCrypto;

namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// The <c>ecdsa-jcs-2019</c> cryptosuite of Data Integrity ECDSA Cryptosuites v1.0
/// (FR-5), supporting P-256 (SHA-256) and P-384 (SHA-384): JCS canonicalization,
/// <c>hashData = hash(canonicalProofConfig) ‖ hash(canonicalDocument)</c> with the
/// curve-mandated hash, and an IEEE P1363 fixed-width <c>r ‖ s</c> ECDSA signature —
/// the W3C-correct wire form — encoded as base58-btc multibase <c>proofValue</c>.
/// DER signatures returned by NetCrypto signers are transcoded to P1363 byte-level,
/// so a non-exporting key-store signer suffices (AC-8).
/// </summary>
public sealed class EcdsaJcs2019Cryptosuite : ICryptosuite
{
    /// <summary>The cryptosuite identifier, <c>ecdsa-jcs-2019</c>.</summary>
    public const string CryptosuiteName = "ecdsa-jcs-2019";

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

        protected override bool IsSupportedKeyType(KeyType keyType)
            => keyType is KeyType.P256 or KeyType.P384;

        protected override byte[] ComputeHash(ReadOnlySpan<byte> data, KeyType keyType)
            => keyType == KeyType.P384 ? Hash.Sha384(data) : Hash.Sha256(data);

        protected override byte[]? NormalizeSignature(byte[] signature, KeyType keyType)
            => EcdsaSignatureEncoding.TryNormalizeToP1363(signature, FieldWidth(keyType), out var p1363)
                ? p1363
                : null;

        protected override bool VerifySignature(PublicKeyMaterial publicKey, ReadOnlySpan<byte> hashData, ReadOnlySpan<byte> signature)
            => Crypto.Verify(publicKey.KeyType, publicKey.KeyBytes.Span, hashData, signature, EcdsaSignatureFormat.IeeeP1363);

        private static int FieldWidth(KeyType keyType) => keyType == KeyType.P384 ? 48 : 32;
    }
}
