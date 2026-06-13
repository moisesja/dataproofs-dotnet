using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.Internal;
using NetCrypto;

namespace DataProofsDotnet.Rdfc.DataIntegrity;

/// <summary>
/// The <c>ecdsa-rdfc-2019</c> cryptosuite of Data Integrity ECDSA Cryptosuites v1.0
/// (FR-11), supporting P-256 (SHA-256) and P-384 (SHA-384): RDFC-1.0 canonicalization
/// (with the curve-mandated RDFC internal hash), <c>hashData = hash(canonicalProofConfig)
/// ‖ hash(canonicalDocument)</c>, and an IEEE P1363 fixed-width <c>r ‖ s</c> ECDSA
/// signature — the W3C-correct wire form — encoded as base58-btc multibase <c>proofValue</c>.
/// DER signatures from NetCrypto signers are transcoded to P1363 byte-level, so a
/// non-exporting key-store signer suffices (AC-8).
/// </summary>
public sealed class EcdsaRdfc2019Cryptosuite : ICryptosuite
{
    /// <summary>The cryptosuite identifier, <c>ecdsa-rdfc-2019</c>.</summary>
    public const string CryptosuiteName = "ecdsa-rdfc-2019";

    private readonly Engine _engine;

    /// <summary>Creates the suite over the offline-default RDFC canonicalizer (FR-10).</summary>
    public EcdsaRdfc2019Cryptosuite()
        : this(new RdfcDocumentCanonicalizer())
    {
    }

    /// <summary>Creates the suite over the given RDFC canonicalizer.</summary>
    public EcdsaRdfc2019Cryptosuite(IRdfCanonicalizer canonicalizer)
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

        protected override bool IsSupportedKeyType(KeyType keyType)
            => keyType is KeyType.P256 or KeyType.P384;

        protected override RdfCanonicalizationHashAlgorithm CanonicalizationHash(KeyType keyType)
            => keyType == KeyType.P384 ? RdfCanonicalizationHashAlgorithm.Sha384 : RdfCanonicalizationHashAlgorithm.Sha256;

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
