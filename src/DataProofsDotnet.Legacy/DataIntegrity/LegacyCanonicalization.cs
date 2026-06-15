namespace DataProofsDotnet.Legacy.DataIntegrity;

/// <summary>
/// The canonicalization mechanic a legacy Linked-Data-Signature suite uses to build its
/// signing input. The 2020-era suites support two wire conventions that share the same
/// proof <c>type</c> but differ in how the document and proof are turned into bytes.
/// </summary>
/// <remarks>
/// A verifier cannot distinguish the two variants from the proof alone (both carry
/// <c>type:"Ed25519Signature2020"</c>/<c>"EcdsaSecp256r1Signature2019"</c> and no
/// <c>cryptosuite</c>), so a single suite instance verifies under <see cref="Jcs"/> first
/// and falls back to <see cref="Rdfc"/>. The create path is fixed to the variant chosen at
/// construction, with <see cref="Jcs"/> the back-compat default.
/// </remarks>
public enum LegacyCanonicalization
{
    /// <summary>
    /// JCS (RFC 8785) over the document with the proof (minus <c>proofValue</c>) nested back
    /// inside under a <c>proof</c> member — zcap-dotnet's 2020-era default. The canonical
    /// UTF-8 bytes are fed directly to the signer/verifier; the primitive hashes internally.
    /// </summary>
    Jcs = 0,

    /// <summary>
    /// RDFC-1.0: the document and the proof options (carrying the document's <c>@context</c>)
    /// are canonicalized separately, each SHA-256'd, and concatenated as
    /// <c>SHA-256(proofOptions) ‖ SHA-256(document)</c> — the 64-byte signing input.
    /// </summary>
    Rdfc = 1,
}
