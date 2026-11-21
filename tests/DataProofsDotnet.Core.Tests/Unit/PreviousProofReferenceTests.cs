using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Tests.Shared;
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

    public static TheoryData<string> Forms() => ["FromSingle", "FromValues", "implicit", "JSON string", "JSON array"];

    private static PreviousProofReference Create(string form) => form switch
    {
        "FromSingle" => PreviousProofReference.FromSingle("urn:uuid:0"),
        "FromValues" => PreviousProofReference.FromValues(["urn:uuid:0"]),
        "implicit" => "urn:uuid:0",
        "JSON string" => Parsed("\"urn:uuid:0\""),
        _ => Parsed("[\"urn:uuid:0\"]"),
    };

    // Through the converter, as a parsed proof's previousProof is built.
    private static PreviousProofReference Parsed(string previousProof)
        => JsonSerializer.Deserialize<DataIntegrityProof>(
            "{\"previousProof\":" + previousProof + "}", DataProofsJsonOptions.Default)!.PreviousProof!;

    [Theory]
    [MemberData(nameof(Forms))]
    public void Values_CannotBeChangedThroughAnyPublicInterface(string form)
    {
        // Issue #61: proofs and their options share the reference, so a change would rewrite every one of them.
        var reference = Create(form);

        Issue61OptionsCopyTestsBase.TryToRewrite(reference);

        reference.Values.Should().Equal("urn:uuid:0");
    }

    [Theory]
    [MemberData(nameof(Forms))]
    public void Values_ImplementsOnlyTheReadOnlyListInterfaces(string form)
    {
        // Any further interface (ICollection's SyncRoot, a writable list) would need a reason; PR #62 review.
        var type = Create(form).Values.GetType();

        type.IsArray.Should().BeFalse();
        type.GetInterfaces().Should().BeEquivalentTo(
            [typeof(IReadOnlyList<string>), typeof(IReadOnlyCollection<string>), typeof(IEnumerable<string>), typeof(System.Collections.IEnumerable)]);
    }

    [Fact]
    public void FromValues_KeepsItsOwnCopyOfTheIds()
    {
        var ids = new[] { "urn:uuid:0", "urn:uuid:1" };
        var reference = PreviousProofReference.FromValues(ids);

        ids[0] = "urn:uuid:changed";

        reference.Values.Should().Equal("urn:uuid:0", "urn:uuid:1");
    }

    [Fact]
    public void FromValues_KeepsNoArrayTheCallersCollectionWasHanded()
    {
        // A string[]'s CopyTo is the runtime's, so the test above cannot see this: ToArray hands a collection that
        // implements ICollection<T> the very array it returns, and FromValues kept that array (PR #62 review).
        var ids = new CapturingIds("urn:uuid:0", "urn:uuid:1");
        var reference = PreviousProofReference.FromValues(ids);

        ids.WriteToHandedArray(0, "urn:uuid:changed");

        reference.Values.Should().Equal("urn:uuid:0", "urn:uuid:1");
    }
}
