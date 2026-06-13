using DataProofsDotnet;
using DataProofsDotnet.Core.Tests.TestSupport;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Unit;

/// <summary>FR-7: the dictionary-backed resolver shipped by Core.</summary>
public class StaticVerificationMethodResolverTests
{
    private static ResolvedVerificationMethod Method(string id, params string[] relationships)
        => new()
        {
            Id = id,
            Controller = "did:example:alice",
            PublicKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, Fx.SeedKey(0x01).PublicKey),
            Relationships = new HashSet<string>(relationships, StringComparer.Ordinal),
        };

    [Fact]
    public async Task Resolves_ByExactOrdinalId()
    {
        var method = Method("did:example:alice#key-1", ProofPurposes.AssertionMethod);
        var resolver = new StaticVerificationMethodResolver([method]);

        var resolved = await resolver.ResolveAsync("did:example:alice#key-1");

        resolved.Should().BeSameAs(method);
        resolved!.Relationships.Should().BeEquivalentTo([ProofPurposes.AssertionMethod]);
        resolved.ControllerControlsMethod.Should().BeTrue("the default is true");
    }

    [Fact]
    public async Task UnknownPrefixOrSubstringIds_DoNotResolve()
    {
        var resolver = new StaticVerificationMethodResolver([Method("did:example:alice#key-1")]);

        (await resolver.ResolveAsync("did:example:alice#key")).Should().BeNull();
        (await resolver.ResolveAsync("did:example:alice#key-12")).Should().BeNull();
        (await resolver.ResolveAsync("did:example:alice")).Should().BeNull();
        (await resolver.ResolveAsync("DID:EXAMPLE:ALICE#KEY-1")).Should().BeNull();
    }

    [Fact]
    public void DuplicateIds_AreRejected()
    {
        var act = () => new StaticVerificationMethodResolver(
            [Method("did:example:alice#key-1"), Method("did:example:alice#key-1")]);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void NullArguments_AreRejected()
    {
        FluentActions.Invoking(() => new StaticVerificationMethodResolver(null!))
            .Should().Throw<ArgumentNullException>();

        var resolver = new StaticVerificationMethodResolver([]);
        FluentActions.Invoking(() => resolver.ResolveAsync(null!).GetAwaiter().GetResult())
            .Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public async Task Cancellation_IsObserved()
    {
        var resolver = new StaticVerificationMethodResolver([Method("did:example:alice#key-1")]);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = () => resolver.ResolveAsync("did:example:alice#key-1", cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public void RelationshipsSet_IsDefensivelyCopied_AndOrdinal()
    {
        var source = new HashSet<string> { ProofPurposes.AssertionMethod };
        var method = new ResolvedVerificationMethod
        {
            Id = "did:example:alice#key-1",
            Controller = "did:example:alice",
            PublicKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, Fx.SeedKey(0x01).PublicKey),
            Relationships = source,
        };

        source.Add(ProofPurposes.Authentication);

        method.Relationships.Should().BeEquivalentTo([ProofPurposes.AssertionMethod]);
        method.Relationships.Contains("ASSERTIONMETHOD").Should().BeFalse();
    }
}
