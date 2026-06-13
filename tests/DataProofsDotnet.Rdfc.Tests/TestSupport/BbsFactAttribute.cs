using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests.TestSupport;

/// <summary>
/// A <see cref="FactAttribute"/> for live <c>bbs-2023</c> tests: runs when the NetCrypto BBS
/// native library is present, and otherwise skips with a clear reason. Sibling convention:
/// when BBS is absent these are the live-BBS tests gated out, while the capability-behavior
/// tests (tagged <c>[Trait("Category","BbsAbsent")]</c>) still run and assert that
/// registration succeeds and use throws.
/// </summary>
public sealed class BbsFactAttribute : FactAttribute
{
    public BbsFactAttribute()
    {
        if (!BbsCapability.IsAvailable)
        {
            Skip = "BBS native library (zkryptium-ffi) is not available on this host; live bbs-2023 tests skipped.";
        }
    }
}

/// <summary>A <see cref="TheoryAttribute"/> variant of <see cref="BbsFactAttribute"/>.</summary>
public sealed class BbsTheoryAttribute : TheoryAttribute
{
    public BbsTheoryAttribute()
    {
        if (!BbsCapability.IsAvailable)
        {
            Skip = "BBS native library (zkryptium-ffi) is not available on this host; live bbs-2023 tests skipped.";
        }
    }
}

/// <summary>Probes the NetCrypto BBS capability once.</summary>
public static class BbsCapability
{
    public static bool IsAvailable { get; } = new DefaultBbsCryptoProvider(BbsCiphersuite.Bls12381Sha256).IsAvailable;
}
