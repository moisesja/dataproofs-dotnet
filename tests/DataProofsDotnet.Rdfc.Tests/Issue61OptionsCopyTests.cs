using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using DataProofsDotnet.Rdfc.Tests.TestSupport;
using DataProofsDotnet.Tests.Shared;
using NetCrypto;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>Issue #61: the shared options-copy matrix through <c>eddsa-rdfc-2022</c>. bbs-2023 has its own (issue #44).</summary>
public sealed class Issue61EddsaRdfcOptionsCopyTests : Issue61OptionsCopyTestsBase
{
    protected override ICryptosuite Suite { get; } = new EddsaRdfc2022Cryptosuite();

    protected override ISigner Signer { get; } =
        Fx.Signer(Fx.KeyGen.FromPrivateKey(KeyType.Ed25519, Enumerable.Repeat((byte)0x21, 32).ToArray()));

    protected override DataIntegrityProof Options() => new()
    {
        Cryptosuite = EddsaRdfc2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = "did:example:x#k",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };
}

/// <summary>Issue #61: the shared options-copy matrix through <c>ecdsa-rdfc-2019</c>.</summary>
public sealed class Issue61EcdsaRdfcOptionsCopyTests : Issue61OptionsCopyTestsBase
{
    protected override ICryptosuite Suite { get; } = new EcdsaRdfc2019Cryptosuite();

    protected override ISigner Signer { get; } =
        Fx.Signer(Fx.KeyGen.FromPrivateKey(KeyType.P256, Enumerable.Repeat((byte)0x21, 32).ToArray()));

    protected override DataIntegrityProof Options() => new()
    {
        Cryptosuite = EcdsaRdfc2019Cryptosuite.CryptosuiteName,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = "did:example:x#k",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };
}
