using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Rdfc;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// A consumer's host activates the legacy suites by reflection: <see cref="ActivatorUtilities"/>,
/// a <see cref="ServiceCollection"/> registration by type, or <see cref="Activator"/>. Each of them
/// picks a constructor by enumerating the public ones, so the public constructor set is part of the
/// contract even when every signature on its own is fine. The PR #39 review found that a second
/// public constructor made <c>CreateFactory</c> and <c>CreateInstance</c> throw "Multiple constructors
/// accepting all given argument types". These tests run each path on both suites: the ones that fill
/// defaults behave as in 1.5.0, and the exact-arity one shows what the migration note describes.
/// </summary>
public class ActivationCompatibilityTests
{
    public static TheoryData<Type> Suites() => new()
    {
        typeof(Ed25519Signature2020Cryptosuite),
        typeof(EcdsaSecp256r1Signature2019Cryptosuite),
    };

    [Theory]
    [MemberData(nameof(Suites))]
    public void CreateFactory_WithNoArgumentTypes(Type suite)
    {
        var factory = ActivatorUtilities.CreateFactory(suite, Type.EmptyTypes);

        factory(new ProviderWithoutIsService(), null).Should().BeOfType(suite);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void CreateFactory_WithAnExplicitCanonicalization(Type suite)
    {
        var factory = ActivatorUtilities.CreateFactory(suite, [typeof(LegacyCanonicalization)]);

        factory(new ProviderWithoutIsService(), [LegacyCanonicalization.Rdfc]).Should().BeOfType(suite);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void CreateInstance_WithAProviderThatIsNotIServiceProviderIsService(Type suite)
    {
        // Without IServiceProviderIsService, ActivatorUtilities cannot ask which parameters the
        // provider can supply and falls back to matching the given arguments against every public
        // constructor.
        ActivatorUtilities.CreateInstance(new ProviderWithoutIsService(), suite).Should().BeOfType(suite);
        ActivatorUtilities.CreateInstance(new ProviderWithoutIsService(), suite, LegacyCanonicalization.Rdfc)
            .Should().BeOfType(suite);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void CreateInstance_WithAProviderThatIsIServiceProviderIsService(Type suite)
    {
        // The real container implements IServiceProviderIsService, so ActivatorUtilities picks the
        // longest constructor it can satisfy instead of matching arguments against every public one.
        using var provider = new ServiceCollection().BuildServiceProvider();

        ActivatorUtilities.CreateInstance(provider, suite).Should().BeOfType(suite);
        ActivatorUtilities.CreateInstance(provider, suite, LegacyCanonicalization.Rdfc).Should().BeOfType(suite);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void ServiceCollection_RegistrationByType(Type suite)
    {
        using var provider = new ServiceCollection().AddSingleton(suite).BuildServiceProvider();

        provider.GetRequiredService(suite).Should().BeOfType(suite);
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void Activator_BindsTheFullSignature_NotThe150Arity(Type suite)
    {
        // Activator.CreateInstance matches the argument list against a constructor's exact arity and
        // does not fill defaults, so naming every parameter works and the 1.5.0 two-argument list no
        // longer binds. That is the same exact-signature binding an assembly compiled against 1.5.0
        // performs on `new`, and the CHANGELOG migration note covers both: rebuild, or name the third
        // parameter. ActivatorUtilities and Microsoft DI fill defaults and are unaffected (above).
        Activator.CreateInstance(suite, LegacyCanonicalization.Rdfc, null, LegacyVariantVerification.Both)
            .Should().BeOfType(suite);

        var oneFiveArity = () => Activator.CreateInstance(suite, LegacyCanonicalization.Rdfc, null);
        oneFiveArity.Should().Throw<MissingMethodException>();
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public void OnePublicConstructor_EveryParameterOptional(Type suite)
    {
        // 1.5.0 shipped one public constructor, (LegacyCanonicalization = Jcs, IRdfCanonicalizer? = null).
        // Keeping a single public constructor whose parameters all have defaults is what makes every
        // activation path above unambiguous.
        var constructor = suite.GetConstructors().Should().ContainSingle().Subject;
        var parameters = constructor.GetParameters();

        parameters.Select(p => p.ParameterType)
            .Should().Equal(typeof(LegacyCanonicalization), typeof(IRdfCanonicalizer), typeof(LegacyVariantVerification));
        parameters.Should().OnlyContain(p => p.HasDefaultValue);
        parameters[0].DefaultValue.Should().Be(LegacyCanonicalization.Jcs);
        parameters[1].DefaultValue.Should().BeNull();
        parameters[2].DefaultValue.Should().Be(LegacyVariantVerification.Both);
    }

    [Fact]
    public void The150CallShapes_StillCompileAndBind()
    {
        // Source compatibility: every way 1.5.0 code constructs a suite. Compiling is the test.
        IRdfCanonicalizer canonicalizer = new RdfcDocumentCanonicalizer();

        _ = new Ed25519Signature2020Cryptosuite();
        _ = new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Rdfc);
        _ = new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Rdfc, null);
        _ = new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Rdfc, canonicalizer);
        _ = new Ed25519Signature2020Cryptosuite(rdfCanonicalizer: canonicalizer);
        _ = new EcdsaSecp256r1Signature2019Cryptosuite();
        _ = new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Rdfc);
        _ = new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Rdfc, null);
        _ = new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Rdfc, canonicalizer);
        _ = new EcdsaSecp256r1Signature2019Cryptosuite(rdfCanonicalizer: canonicalizer);
    }

    /// <summary>A provider that answers nothing and, deliberately, is not <c>IServiceProviderIsService</c>.</summary>
    private sealed class ProviderWithoutIsService : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}
