using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.Internal;
using DataProofsDotnet.Rdfc;
using NetCrypto;

namespace DataProofsDotnet.Legacy.DataIntegrity;

/// <summary>
/// The legacy <c>EcdsaSecp256r1Signature2019</c> Linked-Data-Signature suite, byte-compatible
/// with zcap-dotnet's 2020-era wire convention (FR — legacy embedded proofs). P-256 ECDSA
/// (SHA-256) over a signing input built by JCS (the default) or RDFC-1.0; the IEEE P1363
/// fixed-width <c>r ‖ s</c> signature — the wire form zcap signs (<c>IeeeP1363</c>) — is
/// encoded as a base58-btc multibase <c>proofValue</c>. DER signatures returned by NetCrypto
/// signers are transcoded to P1363 byte-level, so a non-exporting key-store signer suffices.
/// The wire proof carries <c>type:"EcdsaSecp256r1Signature2019"</c> and NO <c>cryptosuite</c>;
/// dispatch is by <c>type</c>.
/// </summary>
/// <remarks>
/// <para>
/// P-256 ECDSA signing is non-deterministic (random <c>k</c>), so a freshly created
/// proofValue is NOT byte-reproducible across runs — only round-trip (create→verify) and
/// verify-of-fixed-vector are meaningful. A verifier cannot distinguish the JCS and RDFC
/// variants from the proof alone, so this suite verifies under the construction-time variant
/// first and falls back to the other.
/// </para>
/// <para>
/// <b>Signature malleability.</b> ECDSA signatures are inherently malleable: given a valid
/// <c>(r, s)</c> proof, <c>(r, n − s)</c> is a second, equally valid proof over the same
/// message. This suite does NOT enforce low-<c>s</c> canonicalization — doing so would reject
/// otherwise-valid proofs emitted by zcap-dotnet and other LD-Signature producers and break
/// byte-compatibility (the conformant <c>ecdsa-*</c> suites behave the same). Verification
/// authenticates the signer; a <c>proofValue</c> must therefore NOT be treated as a unique
/// identifier for a proof. Callers needing replay/dedup defenses must key off proof
/// <c>id</c>/<c>nonce</c>/<c>created</c>, not the signature bytes.
/// </para>
/// </remarks>
public sealed class EcdsaSecp256r1Signature2019Cryptosuite : ICryptosuite
{
    /// <summary>The legacy proof <c>type</c>, <c>EcdsaSecp256r1Signature2019</c>.</summary>
    public const string ProofType = "EcdsaSecp256r1Signature2019";

    /// <summary>The P-256 field width in bytes (the P1363 signature is <c>2 × FieldWidth</c>).</summary>
    private const int FieldWidth = 32;

    private readonly Engine _engine;

    /// <summary>
    /// Creates the suite. <paramref name="canonicalization"/> selects the create-path
    /// mechanic (<see cref="LegacyCanonicalization.Jcs"/> is the back-compat default);
    /// <paramref name="rdfCanonicalizer"/> overrides the offline-default RDFC canonicalizer
    /// (used by the RDFC variant and the RDFC verify fallback).
    /// </summary>
    public EcdsaSecp256r1Signature2019Cryptosuite(
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

        protected override bool IsSupportedKeyType(KeyType keyType) => keyType == KeyType.P256;

        protected override byte[]? NormalizeSignature(byte[] signature, KeyType keyType)
            => EcdsaSignatureEncoding.TryNormalizeToP1363(signature, FieldWidth, out var p1363)
                ? p1363
                : null;

        protected override bool VerifySignature(
            PublicKeyMaterial publicKey, ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature)
            => Crypto.Verify(
                publicKey.KeyType, publicKey.KeyBytes.Span, signingInput, signature, EcdsaSignatureFormat.IeeeP1363);
    }
}
