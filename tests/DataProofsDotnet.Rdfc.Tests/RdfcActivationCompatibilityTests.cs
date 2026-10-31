using DataProofsDotnet.Rdfc.DataIntegrity;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// A consumer's host activates the canonicalizer and the RDFC suites by reflection:
/// <see cref="ActivatorUtilities"/>, a <see cref="ServiceCollection"/> registration by type, or
/// <see cref="Activator"/>. Each picks a constructor by enumerating the public ones, so the public
/// constructor set is part of the contract. Through 1.5.0 each of these types had two public
/// constructors, <c>()</c> and <c>(X)</c>, which made <c>CreateFactory</c> and <c>CreateInstance</c>
/// without an <c>IServiceProviderIsService</c> provider throw "Multiple constructors accepting all
/// given argument types" (the defect PR #39 fixed for the Legacy suites). Each type now has one
/// public constructor with a defaulted parameter, the shape PR #39 settled on.
/// </summary>
public class RdfcActivationCompatibilityTests
{
    public static TheoryData<Type, Type> Types() => new()
    {
        // type, its dependency's type
        { typeof(RdfcDocumentCanonicalizer), typeof(IDocumentLoader) },
        { typeof(EddsaRdfc2022Cryptosuite), typeof(IRdfCanonicalizer) },
        { typeof(EcdsaRdfc2019Cryptosuite), typeof(IRdfCanonicalizer) },
        { typeof(Bbs2023Cryptosuite), typeof(IRdfCanonicalizer) },
    };

    private static object Dependency(Type dependency)
        => dependency == typeof(IDocumentLoader) ? OfflineDocumentLoader.Instance : new RdfcDocumentCanonicalizer();

    [Theory]
    [MemberData(nameof(Types))]
    public void CreateFactory_WithNoArgumentTypes(Type type, Type dependency)
    {
        _ = dependency;
        var factory = ActivatorUtilities.CreateFactory(type, Type.EmptyTypes);

        factory(new ProviderWithoutIsService(), null).Should().BeOfType(type);
    }

    [Theory]
    [MemberData(nameof(Types))]
    public void CreateFactory_WithTheDependencyAsAnArgument(Type type, Type dependency)
    {
        var factory = ActivatorUtilities.CreateFactory(type, [dependency]);

        factory(new ProviderWithoutIsService(), [Dependency(dependency)]).Should().BeOfType(type);
    }

    [Theory]
    [MemberData(nameof(Types))]
    public void CreateInstance_WithAProviderThatIsNotIServiceProviderIsService(Type type, Type dependency)
    {
        // Without IServiceProviderIsService, ActivatorUtilities matches the given arguments against
        // every public constructor; one constructor means one candidate.
        ActivatorUtilities.CreateInstance(new ProviderWithoutIsService(), type).Should().BeOfType(type);
        ActivatorUtilities.CreateInstance(new ProviderWithoutIsService(), type, Dependency(dependency)).Should().BeOfType(type);
    }

    [Theory]
    [MemberData(nameof(Types))]
    public void CreateInstance_WithAProviderThatIsIServiceProviderIsService(Type type, Type dependency)
    {
        using var empty = new ServiceCollection().BuildServiceProvider();
        using var registered = new ServiceCollection().AddSingleton(dependency, Dependency(dependency)).BuildServiceProvider();

        ActivatorUtilities.CreateInstance(empty, type).Should().BeOfType(type);
        ActivatorUtilities.CreateInstance(registered, type).Should().BeOfType(type);
    }

    [Theory]
    [MemberData(nameof(Types))]
    public void ServiceCollection_RegistrationByType(Type type, Type dependency)
    {
        using var empty = new ServiceCollection().AddSingleton(type).BuildServiceProvider();
        using var registered = new ServiceCollection().AddSingleton(dependency, Dependency(dependency)).AddSingleton(type).BuildServiceProvider();

        empty.GetRequiredService(type).Should().BeOfType(type);
        registered.GetRequiredService(type).Should().BeOfType(type);
    }

    [Theory]
    [MemberData(nameof(Types))]
    public void OnePublicConstructor_WithADefaultedNullableDependency(Type type, Type dependency)
    {
        var constructor = type.GetConstructors().Should().ContainSingle().Subject;
        var parameter = constructor.GetParameters().Should().ContainSingle().Subject;

        parameter.ParameterType.Should().Be(dependency);
        parameter.HasDefaultValue.Should().BeTrue();
        parameter.DefaultValue.Should().BeNull();
    }

    [Theory]
    [MemberData(nameof(Types))]
    public void Activator_BindsTheFullSignature_NotTheParameterlessForm(Type type, Type dependency)
    {
        // Activator.CreateInstance matches the argument list against a constructor's exact arity and
        // does not fill defaults: the full signature binds, the 1.5.0 parameterless form no longer does.
        // That is the CHANGELOG's migration note; ActivatorUtilities and Microsoft DI are unaffected (above).
        Activator.CreateInstance(type, Dependency(dependency)).Should().BeOfType(type);
        Activator.CreateInstance(type, [null]).Should().BeOfType(type);

        var parameterless = () => Activator.CreateInstance(type);
        parameterless.Should().Throw<MissingMethodException>();
    }

    [Fact]
    public void The150CallShapes_StillCompileAndBind()
    {
        // Source compatibility: every way 1.5.0 code constructs these types. Compiling is the test.
        IRdfCanonicalizer canonicalizer = new RdfcDocumentCanonicalizer();
        _ = new RdfcDocumentCanonicalizer(OfflineDocumentLoader.Instance);
        _ = new EddsaRdfc2022Cryptosuite();
        _ = new EddsaRdfc2022Cryptosuite(canonicalizer);
        _ = new EcdsaRdfc2019Cryptosuite();
        _ = new EcdsaRdfc2019Cryptosuite(canonicalizer);
        _ = new Bbs2023Cryptosuite();
        _ = new Bbs2023Cryptosuite(canonicalizer);
    }

    /// <summary>A provider that answers nothing and, deliberately, is not <c>IServiceProviderIsService</c>.</summary>
    private sealed class ProviderWithoutIsService : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}
