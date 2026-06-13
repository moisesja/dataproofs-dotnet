using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// AC-6 capability behavior for <c>bbs-2023</c>: registration ALWAYS succeeds — even when the
/// BBS native binaries are absent — and the suite reports its capability without throwing. On
/// a host where BBS is unavailable, the lifecycle methods throw NetCrypto's documented
/// <c>BbsUnavailableException</c> on use; on a host where it is available, they work. These
/// tests are tagged <c>[Trait("Category","BbsAbsent")]</c> (sibling-repo convention) and run
/// regardless of native availability, carrying the capability contract when the live lifecycle
/// tests skip.
/// </summary>
public sealed class Bbs2023CapabilityTests
{
    [Fact]
    [Trait("Category", "BbsAbsent")]
    public void AddBbs2023_Registration_AlwaysSucceeds()
    {
        var registry = new CryptosuiteRegistry();
        var act = () => registry.AddBbs2023();

        act.Should().NotThrow();
        registry.GetByName(Bbs2023Cryptosuite.CryptosuiteName).Should().NotBeNull();
    }

    [Fact]
    [Trait("Category", "BbsAbsent")]
    public void CreateWithRdfcSuites_RegistersBbs2023AlongsideRdfcAndJcsSuites()
    {
        var registry = RdfcCryptosuiteRegistration.CreateWithRdfcSuites();

        registry.RegisteredNames.Should().Contain(new[]
        {
            "eddsa-jcs-2022", "ecdsa-jcs-2019", "eddsa-rdfc-2022", "ecdsa-rdfc-2019", "bbs-2023",
        });
    }

    [Fact]
    [Trait("Category", "BbsAbsent")]
    public void Bbs2023Cryptosuite_Construction_DoesNotThrow_AndReportsCapability()
    {
        var suite = new Bbs2023Cryptosuite();

        suite.Name.Should().Be("bbs-2023");
        // IsAvailable is a non-throwing capability flag (true here, false on a BBS-less host).
        var act = () => _ = suite.IsAvailable;
        act.Should().NotThrow();
    }
}
