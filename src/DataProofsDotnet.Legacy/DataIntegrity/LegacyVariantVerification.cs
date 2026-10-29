namespace DataProofsDotnet.Legacy.DataIntegrity;

/// <summary>
/// Which canonicalization variants a legacy Linked-Data-Signature suite accepts when it verifies.
/// </summary>
/// <remarks>
/// The JCS and RDFC variants share the proof <c>type</c> and carry no <c>cryptosuite</c>, so the
/// proof alone does not say which one signed it. <see cref="Both"/> keeps verification transparent
/// to that choice. A verifier whose profile allows one variant uses
/// <see cref="ConstructedVariantOnly"/>, so a proof made with the other variant does not verify.
/// </remarks>
public enum LegacyVariantVerification
{
    /// <summary>
    /// Try the variant the suite was constructed with, then the other one. This is the default.
    /// </summary>
    Both = 0,

    /// <summary>
    /// Accept only the variant the suite was constructed with. With
    /// <see cref="LegacyCanonicalization.Rdfc"/>, a document the canonicalizer would lose data from
    /// fails with <c>DATA_LOSS_DETECTION_ERROR</c>, as in the RDFC Data Integrity suites.
    /// </summary>
    ConstructedVariantOnly = 1,
}
