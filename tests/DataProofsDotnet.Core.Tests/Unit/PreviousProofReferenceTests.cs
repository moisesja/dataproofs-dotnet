using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Unit;

public class PreviousProofReferenceTests
{
    [Fact]
    public void FromSingle_CreatesStringForm()
    {
        var reference = PreviousProofReference.FromSingle("urn:uuid:0");

        reference.IsArrayForm.Should().BeFalse();
        reference.Values.Should().Equal("urn:uuid:0");
    }

    [Fact]
    public void FromValues_CreatesArrayForm()
    {
        var reference = PreviousProofReference.FromValues(["urn:uuid:0", "urn:uuid:1"]);

        reference.IsArrayForm.Should().BeTrue();
        reference.Values.Should().Equal("urn:uuid:0", "urn:uuid:1");
    }

    [Fact]
    public void FromSingle_RejectsNullOrEmpty()
    {
        FluentActions.Invoking(() => PreviousProofReference.FromSingle("")).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => PreviousProofReference.FromSingle(null!)).Should().Throw<ArgumentException>();
    }

    [Fact]
    public void FromValues_RejectsEmptyAndInvalidSets()
    {
        FluentActions.Invoking(() => PreviousProofReference.FromValues([])).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => PreviousProofReference.FromValues(["a", ""])).Should().Throw<ArgumentException>();
        FluentActions.Invoking(() => PreviousProofReference.FromValues(null!)).Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ImplicitConversion_FromString_IsSingleForm()
    {
        PreviousProofReference reference = "urn:uuid:0";

        reference.Should().Be(PreviousProofReference.FromSingle("urn:uuid:0"));
    }

    [Fact]
    public void Equality_DistinguishesShapeAndValues()
    {
        PreviousProofReference.FromSingle("a").Should().Be(PreviousProofReference.FromSingle("a"));
        PreviousProofReference.FromSingle("a").Should().NotBe(PreviousProofReference.FromSingle("b"));
        // Same single value, different wire shape -> not equal (shape is signed).
        PreviousProofReference.FromSingle("a").Should().NotBe(PreviousProofReference.FromValues(["a"]));
        PreviousProofReference.FromValues(["a", "b"]).Should().Be(PreviousProofReference.FromValues(["a", "b"]));
        PreviousProofReference.FromValues(["a", "b"]).Should().NotBe(PreviousProofReference.FromValues(["b", "a"]));
        PreviousProofReference.FromSingle("a").Equals(null).Should().BeFalse();

        PreviousProofReference.FromSingle("a").GetHashCode()
            .Should().Be(PreviousProofReference.FromSingle("a").GetHashCode());
    }
}
