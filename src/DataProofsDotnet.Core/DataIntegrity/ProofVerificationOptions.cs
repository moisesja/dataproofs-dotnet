namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// Verifier-supplied expectations for proof verification (FR-3). Unset members are not
/// checked.
/// </summary>
public sealed record ProofVerificationOptions
{
    /// <summary>
    /// When set, every proof's <c>proofPurpose</c> must equal this value; a mismatch
    /// fails with <see cref="ProofProblemCodes.ProofVerificationError"/> (distinct from
    /// the controller-authorization failure, which is
    /// <see cref="ProofProblemCodes.InvalidVerificationMethod"/>).
    /// </summary>
    public string? ExpectedProofPurpose { get; init; }

    /// <summary>When set, every proof's <c>domain</c> must equal this value
    /// (<see cref="ProofProblemCodes.InvalidDomainError"/> otherwise).</summary>
    public string? ExpectedDomain { get; init; }

    /// <summary>When set, every proof's <c>challenge</c> must equal this value
    /// (<see cref="ProofProblemCodes.InvalidChallengeError"/> otherwise).</summary>
    public string? ExpectedChallenge { get; init; }

    /// <summary>
    /// The instant against which <c>expires</c> is evaluated. Defaults to the current
    /// UTC time; settable for deterministic testing.
    /// </summary>
    public DateTimeOffset? VerificationTime { get; init; }

    /// <summary>
    /// When set, every <c>@context</c> in the secured document, at any depth, must hold only these
    /// context IRIs (a URI allowlist supporting application context validation). A value that is not listed, an
    /// inline context object or a <c>null</c> fails the document with a document-level
    /// <see cref="ProofProblemCodes.ProofVerificationError"/>, and no proof is verified.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A proof over RDF binds the statements, not the JSON that compacted them, so a holder can
    /// present a verified document under a <c>@context</c> that reads its terms differently
    /// (<c>boards</c> as <c>sails</c>), at the root or on any nested node. The specification's
    /// answer is that applications MUST accept only known contexts. Unset, nothing is checked and
    /// that duty stays with the application; a document without <c>@context</c> passes.
    /// </para>
    /// <para>
    /// The check runs before the proofs. §2.4.1 orders it after them but allows a different ordering
    /// that gives the same protections, and this one means a context a document names loads only if
    /// listed. Listing a context also trusts what
    /// it references: its imports, scoped contexts and redirects load with it. A refused document has
    /// no per-proof results, so read <c>Verified</c>: a check over an empty <c>ProofResults</c> passes.
    /// </para>
    /// <para>
    /// The list is a set of accepted contexts: order is not compared, and a listed context may
    /// appear at any depth. §4.6 step 3 fails a nested <c>@context</c> outright, but the JCS suites
    /// copy <c>@context</c> into each proof and a presentation embeds credentials with their own;
    /// this option does not enforce that exact-context profile. Applications that require a fixed
    /// context sequence or nesting policy must validate those separately.
    /// </para>
    /// <para>
    /// This option does not authenticate context content and alone is not equivalent to §4.6.
    /// Use approved immutable context copies (as the default offline loader does for its bundle),
    /// or a loader that checks approved content hashes, including imported and scoped contexts.
    /// An allowlisted mutable network URL or first-fetch cache does not pin semantics.
    /// </para>
    /// <para>
    /// Every key named <c>@context</c> counts, including one inside a JSON literal, because telling
    /// a literal apart takes processing the contexts: a term's type can make one, and
    /// <c>@value</c> is a keyword only outside a container map. So a literal holding that key, as a
    /// JSON Schema under <c>credentials/v2</c>'s <c>jsonSchema</c> can, fails the document unless the
    /// key's value is a listed IRI.
    /// </para>
    /// </remarks>
    public IReadOnlyCollection<string>? KnownContexts { get; init; }
}
