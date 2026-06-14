using System.Text.Json;
using NetCrypto;

namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// A Data Integrity cryptosuite (FR-4). A suite composes the spec's suite-specific
/// steps — transformation (canonicalization), hashing, and proof serialization — behind
/// the two operations the pipeline delegates to. Registering a new suite (including
/// future 1.1-track revisions or <c>ecdsa-sd-2023</c>-style selective-disclosure suites)
/// requires no pipeline changes.
/// </summary>
/// <remarks>
/// Implementations MUST be immutable and thread-safe after construction (NFR-4).
/// </remarks>
public interface ICryptosuite
{
    /// <summary>The cryptosuite identifier this suite registers under (e.g. <c>eddsa-jcs-2022</c>).</summary>
    string Name { get; }

    /// <summary>
    /// The proof <c>type</c> values this suite verifies. Defaults to the Data Integrity
    /// generation's single type (<see cref="DataIntegrityProof.DataIntegrityProofType"/>),
    /// so existing suites continue to be dispatched by <c>cryptosuite</c> name exactly as
    /// today. A legacy Linked-Data-Signature suite (e.g. <c>Ed25519Signature2020</c>,
    /// <c>EcdsaSecp256r1Signature2019</c>) overrides this to its <c>type</c> string and
    /// leaves its proofs' <c>cryptosuite</c> null — the verify pipeline then dispatches such
    /// proofs to it by <c>type</c>. The suite itself remains responsible for fully validating
    /// the proof's <c>type</c>/<c>cryptosuite</c>/key/encoding inside
    /// <see cref="VerifyProof"/>; this collection only declares which types it claims.
    /// </summary>
    IReadOnlyCollection<string> SupportedProofTypes => DefaultSupportedProofTypes;

    /// <summary>The default <see cref="SupportedProofTypes"/> value — the single
    /// Data Integrity proof type — shared so the common case allocates nothing per call.</summary>
    private static readonly IReadOnlyCollection<string> DefaultSupportedProofTypes =
        [DataIntegrityProof.DataIntegrityProofType];

    /// <summary>
    /// Creates a proof over <paramref name="unsecuredDocument"/> per this suite's
    /// transform → hash → serialize pipeline. For proof chains the pipeline passes a
    /// document that already embeds the matching previous proofs.
    /// </summary>
    /// <param name="unsecuredDocument">The JSON object to secure (without the proof being created).</param>
    /// <param name="proofOptions">The proof options (no <c>proofValue</c>).</param>
    /// <param name="signer">The NetCrypto signer; a non-exporting key-store-backed signer suffices.</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    /// <returns>The completed proof including <c>proofValue</c>.</returns>
    /// <exception cref="ProofGenerationException">The options, document, or signer are invalid for this suite.</exception>
    Task<DataIntegrityProof> CreateProofAsync(
        JsonElement unsecuredDocument,
        DataIntegrityProof proofOptions,
        ISigner signer,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifies <paramref name="proof"/> over <paramref name="unsecuredDocument"/> with
    /// the supplied public key. Invalid proofs produce failed results — never exceptions.
    /// </summary>
    /// <param name="unsecuredDocument">The secured document with its <c>proof</c> member removed
    /// (for chains: with the matching previous proofs re-embedded by the pipeline).</param>
    /// <param name="proof">The proof under verification.</param>
    /// <param name="publicKey">The verification key material.</param>
    ProofVerificationResult VerifyProof(
        JsonElement unsecuredDocument,
        DataIntegrityProof proof,
        PublicKeyMaterial publicKey);
}
