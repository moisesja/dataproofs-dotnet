namespace DataProofsDotnet.Jose.Signing;

/// <summary>
/// Where <see cref="JwsBuilder"/> writes a signer's <c>kid</c>: the integrity-protected header, or
/// the per-signature unprotected <c>header</c> object of a JSON-serialized JWS.
/// </summary>
/// <remarks>
/// <para>
/// RFC 7515 imposes no placement requirement. <c>kid</c> is "a hint indicating which key was used
/// to secure the JWS" (§4.1.4) and §6 states it plainly: these parameters "MUST be integrity
/// protected if the information that they convey is to be utilized in a trust decision; however,
/// if the only information used in the trust decision is a key, these parameters need not be
/// integrity protected, since changing them in a way that causes a different key to be used will
/// cause the validation to fail." Both placements are therefore conformant — the choice is the
/// application profile's, which is why it is an option here rather than a hard-coded rule.
/// </para>
/// <para>
/// What is <em>not</em> optional is RFC 7515 §7.2.1: the protected and unprotected parameter-name
/// sets MUST be disjoint. The builder writes <c>kid</c> to exactly one of the two, never both
/// (issue #17), and <see cref="JwsParser"/> rejects any overlap on the verify side (issue #19).
/// </para>
/// <para>
/// Compact serialization (RFC 7515 §7.1) has no unprotected header at all, so <c>kid</c> can only
/// ever be protected there — the placement that JWT, SD-JWT, and VC-JOSE-COSE consequently use.
/// </para>
/// </remarks>
public enum JwsKidPlacement
{
    /// <summary>
    /// Choose the placement the declared media type calls for (the default). No specification
    /// mandates either placement — RFC 7515 §4.1.4 leaves it open and DIDComm v2.1 states no rule;
    /// what drives this choice is DIDComm's published examples and reference-implementation
    /// interoperability.
    /// <para>
    /// For a JSON serialization whose <c>typ</c> is the DIDComm signed media type
    /// (<c>application/didcomm-signed+json</c>, or the bare <c>didcomm-signed+json</c> — DIDComm
    /// v2.1 §Message Formats permits omitting the <c>application/</c> prefix), the <c>kid</c> goes
    /// in the per-signature unprotected <c>header</c>: that is the shape of every example in
    /// DIDComm v2.1 Appendix C.2, and both SICPA reference implementations reject a signed
    /// envelope that lacks it (issue #25).
    /// </para>
    /// <para>
    /// Every other media type keeps the <c>kid</c> in the integrity-protected header, and compact
    /// serialization always does — it has no other header to use.
    /// </para>
    /// </summary>
    Auto = 0,

    /// <summary>
    /// Always write <c>kid</c> to the integrity-protected header, so it is covered by the
    /// signature. Applies to every serialization.
    /// </summary>
    Protected = 1,

    /// <summary>
    /// Always write <c>kid</c> to the per-signature unprotected <c>header</c> object, whatever the
    /// media type. Valid only for the JSON serializations;
    /// <see cref="JwsBuilder.BuildCompactAsync"/> rejects a signer that requests it *and* carries a
    /// <c>kid</c>, because compact serialization has no unprotected header (RFC 7515 §7.1) and
    /// silently protecting the <c>kid</c> instead would change the signed bytes away from what the
    /// caller asked for. A kid-less signer has nothing to place, so compact accepts it unchanged.
    /// <para>
    /// <b>Choose this only when the <c>kid</c> feeds nothing but key selection.</b> RFC 7515 §6
    /// makes that the condition of its exemption — such parameters "MUST be integrity protected
    /// <em>if</em> the information that they convey is to be utilized in a trust decision". A
    /// verifier that derives anything beyond "which key" from the reported
    /// <see cref="JwsParseResult.SignerKid"/> — a proof purpose, a verification relationship, an
    /// authorization scope — is making a trust decision on an unsigned value, and an intermediary
    /// can rewrite it to any other identifier that resolves to the same key. Use
    /// <see cref="Protected"/> when the signer identity itself must be bound into the signature.
    /// </para>
    /// </summary>
    Unprotected = 2,
}
