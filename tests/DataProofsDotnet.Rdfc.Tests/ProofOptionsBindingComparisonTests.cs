using System.Text;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.Internal;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// <see cref="ProofOptionsBinding"/> on hand-written canonical N-Quads, so each rule is tested alone.
/// <see cref="ProofOptionsBindingTests"/> runs the same check through the suites.
/// </summary>
public class ProofOptionsBindingComparisonTests
{
    private const string Sec = "https://w3id.org/security#";
    private const string UndefinedTerm = "https://www.w3.org/ns/credentials/undefined-term#";
    private const string RdfType = "<http://www.w3.org/1999/02/22-rdf-syntax-ns#type>";
    private const string Root = "_:c14n0";
    private const string Created = "2026-10-30T00:00:00Z";
    private const string Method = "did:example:issuer#key-1";

    private static DataIntegrityProof Proof() => new()
    {
        Cryptosuite = "eddsa-rdfc-2022",
        Created = Created,
        VerificationMethod = Method,
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    private static string[] Signed(string subject = Root) =>
    [
        $"{subject} {RdfType} <{Sec}DataIntegrityProof> .",
        $"{subject} <{Sec}cryptosuite> \"eddsa-rdfc-2022\"^^<{Sec}cryptosuiteString> .",
        $"{subject} <http://purl.org/dc/terms/created> \"{Created}\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .",
        $"{subject} <{Sec}proofPurpose> <{Sec}assertionMethod> .",
        $"{subject} <{Sec}verificationMethod> <{Method}> .",
    ];

    // Against these statements and no others.
    private static string? Exactly(DataIntegrityProof proof, IEnumerable<string> statements)
        => ProofOptionsBinding.Mismatch(Encoding.UTF8.GetBytes(string.Concat(statements.Select(statement => statement + "\n"))), proof);

    // Against the statements of Proof(), plus these.
    private static string? Mismatch(DataIntegrityProof proof, params string[] extraStatements)
        => Exactly(proof, [.. Signed(), .. extraStatements]);

    private static DataIntegrityProof With(DataIntegrityProof proof, string member, string value) => member switch
    {
        "expires" => proof with { Expires = value },
        "domain" => proof with { Domain = value },
        "challenge" => proof with { Challenge = value },
        "nonce" => proof with { Nonce = value },
        "previousProof" => proof with { PreviousProof = PreviousProofReference.FromSingle(value) },
        _ => throw new ArgumentOutOfRangeException(nameof(member)),
    };

    public static TheoryData<string, string> OptionalMembers() => new()
    {
        { "expires", "<" + Sec + "expiration> \"2027-01-01T00:00:00Z\"^^<http://www.w3.org/2001/XMLSchema#dateTime>" },
        { "domain", "<" + Sec + "domain> \"2027-01-01T00:00:00Z\"" },
        { "challenge", "<" + Sec + "challenge> \"2027-01-01T00:00:00Z\"" },
        { "nonce", "<" + Sec + "nonce> \"2027-01-01T00:00:00Z\"" },
        { "previousProof", "<" + Sec + "previousProof> <2027-01-01T00:00:00Z>" },
    };

    private const string OptionalValue = "2027-01-01T00:00:00Z";

    [Fact]
    public void AProofThatAgreesHasNoMismatch() => Mismatch(Proof()).Should().BeNull();

    [Theory, MemberData(nameof(OptionalMembers))]
    public void AMemberAndItsStatementAgree(string member, string statement)
        => Mismatch(With(Proof(), member, OptionalValue), $"{Root} {statement} .").Should().BeNull();

    [Theory, MemberData(nameof(OptionalMembers))]
    public void ASignedStatementWithNoMemberIsRefused(string member, string statement)
        => Mismatch(Proof(), $"{Root} {statement} .").Should().Contain(member);

    [Theory, MemberData(nameof(OptionalMembers))]
    public void AMemberWithNoSignedStatementIsRefused(string member, string statement)
    {
        _ = statement;
        Mismatch(With(Proof(), member, OptionalValue)).Should().Contain(member);
    }

    [Theory, MemberData(nameof(OptionalMembers))]
    public void AMemberThatDiffersFromItsStatementIsRefused(string member, string statement)
        => Mismatch(With(Proof(), member, "2028-01-01T00:00:00Z"), $"{Root} {statement} .").Should().Contain(member);

    [Theory]
    [InlineData("created")]
    [InlineData("verificationMethod")]
    [InlineData("cryptosuite")]
    [InlineData("proofPurpose")]
    public void ARequiredMemberThatDiffersIsRefused(string member)
    {
        var proof = member switch
        {
            "created" => Proof() with { Created = "2026-10-31T00:00:00Z" },
            "verificationMethod" => Proof() with { VerificationMethod = "did:example:other#key-1" },
            "cryptosuite" => Proof() with { Cryptosuite = "ecdsa-rdfc-2019" },
            _ => Proof() with { ProofPurpose = ProofPurposes.Authentication },
        };

        Mismatch(proof).Should().Contain(member);
    }

    [Theory]
    [InlineData("<http://purl.org/dc/terms/created>", "created")]
    [InlineData("<" + Sec + "verificationMethod>", "verificationMethod")]
    [InlineData("<" + Sec + "cryptosuite>", "cryptosuite")]
    [InlineData("<" + Sec + "proofPurpose>", "proofPurpose")]
    public void ARequiredMemberWithNoStatementIsRefused(string predicate, string member)
        => Exactly(Proof(), Signed().Where(statement => !statement.Contains(predicate, StringComparison.Ordinal)))
            .Should().Contain(member);

    [Fact]
    public void ASecondSignedValueCannotHideBehindOneMember()
        => Mismatch(With(Proof(), "domain", "a.example"), $"{Root} <{Sec}domain> \"a.example\" .", $"{Root} <{Sec}domain> \"b.example\" .")
            .Should().Contain("domain");

    [Fact]
    public void EveryPreviousProofMustBeSigned()
    {
        var one = Proof() with { PreviousProof = PreviousProofReference.FromValues(["urn:a"]) };
        var two = Proof() with { PreviousProof = PreviousProofReference.FromValues(["urn:a", "urn:b"]) };
        string[] statements = [$"{Root} <{Sec}previousProof> <urn:a> .", $"{Root} <{Sec}previousProof> <urn:b> ."];

        Mismatch(two, statements).Should().BeNull();
        Mismatch(one, statements).Should().Contain("previousProof");
    }

    [Fact]
    public void ABlankNodeNeverMatchesAValue()
        => Mismatch(With(Proof(), "domain", "c14n1"), $"{Root} <{Sec}domain> _:c14n1 .").Should().Contain("domain");

    [Fact]
    public void AnIriSubjectIsTheProofsId()
    {
        const string id = "urn:uuid:46464646-0000-4000-8000-000000000042";
        Exactly(Proof() with { Id = id }, Signed("<" + id + ">")).Should().BeNull();
        Exactly(Proof(), Signed("<" + id + ">")).Should().Contain("id");
        Exactly(Proof() with { Id = "urn:other" }, Signed("<" + id + ">")).Should().Contain("id");
    }

    [Fact]
    public void ABlankSubjectMeansTheProofHasNoId()
        => Mismatch(Proof() with { Id = "urn:other" }).Should().Contain("id");

    [Fact]
    public void AProofWithNoTypeStatementIsRefused()
        => Exactly(Proof(), Signed().Skip(1)).Should().Contain("type");

    [Fact]
    public void AnotherTypeIsNotTheProof()
        => Mismatch(Proof() with { Type = "Ed25519Signature2020" }).Should().Contain("type");

    [Fact]
    public void TwoProofsInTheDefaultGraphAreRefused()
        => Mismatch(Proof(), $"_:c14n1 {RdfType} <{Sec}DataIntegrityProof> .").Should().Contain("type");

    [Fact]
    public void AnEmbeddedProofInANamedGraphIsNotTheProof()
        => Mismatch(
                Proof(),
                $"_:c14n1 {RdfType} <{Sec}DataIntegrityProof> _:c14n2 .",
                $"_:c14n1 <{Sec}expiration> \"2027-01-01T00:00:00Z\" _:c14n2 .")
            .Should().BeNull();

    [Fact]
    public void ANamedGraphDoesNotSpeakForTheProof()
        => Mismatch(With(Proof(), "domain", "a.example"), $"{Root} <{Sec}domain> \"a.example\" <urn:graph> .")
            .Should().Contain("domain");

    [Theory]
    [InlineData(ProofPurposes.AssertionMethod, "assertionMethod")]
    [InlineData(ProofPurposes.Authentication, "authenticationMethod")]
    [InlineData(ProofPurposes.CapabilityInvocation, "capabilityInvocationMethod")]
    [InlineData(ProofPurposes.CapabilityDelegation, "capabilityDelegationMethod")]
    [InlineData(ProofPurposes.KeyAgreement, "keyAgreementMethod")]
    public void ARegisteredPurposeCarriesItsOwnIri(string purpose, string fragment)
    {
        var statements = Signed().Where(statement => !statement.Contains(Sec + "proofPurpose", StringComparison.Ordinal))
            .Append($"{Root} <{Sec}proofPurpose> <{Sec}{fragment}> .");

        Exactly(Proof() with { ProofPurpose = purpose }, statements).Should().BeNull();
    }

    [Theory]
    [InlineData(ProofPurposes.Authentication, Sec + "assertionMethod")]
    [InlineData(ProofPurposes.Authentication, Sec + "authentication")]
    [InlineData(ProofPurposes.Authentication, "https://example.org/purposes#authentication")]
    [InlineData("assertionMethodX", Sec + "assertionMethod")]
    [InlineData("Method", Sec + "assertionMethod")]
    [InlineData("b/c", "https://example.org/a/b/c")]
    [InlineData("a#b", "https://example.org/a#b#a#b")]
    [InlineData("x:y", "https://example.org/x:y")]
    [InlineData("", "https://example.org/")]
    public void APurposeThatIsNotTheOneSignedIsRefused(string purpose, string iri)
    {
        var statements = Signed().Where(statement => !statement.Contains(Sec + "proofPurpose", StringComparison.Ordinal))
            .Append($"{Root} <{Sec}proofPurpose> <{iri}> .");

        Exactly(Proof() with { ProofPurpose = purpose }, statements).Should().Contain("proofPurpose");
    }

    [Theory]
    [InlineData("capabilityRevocation", "urn:zcap-dotnet:revocation:v1#capabilityRevocation")]
    [InlineData("myPurpose", "https://example.org/purposes/myPurpose")]
    [InlineData("https://example.org/purposes#mine", "https://example.org/purposes#mine")]
    public void AnApplicationsOwnPurposeEndsInItsName(string purpose, string iri)
    {
        var statements = Signed().Where(statement => !statement.Contains(Sec + "proofPurpose", StringComparison.Ordinal))
            .Append($"{Root} <{Sec}proofPurpose> <{iri}> .");

        Exactly(Proof() with { ProofPurpose = purpose }, statements).Should().BeNull();
    }

    // The pipeline requires a purpose, but a suite can be called directly.
    [Fact]
    public void ASignedPurposeWithNoMemberIsRefused()
        => Mismatch(Proof() with { ProofPurpose = null }).Should().Contain("proofPurpose");

    [Fact]
    public void AProofTypedUnderAVocabReadsItsMembersThere()
    {
        string[] statements =
        [
            $"{Root} {RdfType} <{UndefinedTerm}DataIntegrityProof> .",
            $"{Root} <{UndefinedTerm}cryptosuite> \"eddsa-rdfc-2022\" .",
            $"{Root} <{UndefinedTerm}created> \"{Created}\" .",
            $"{Root} <{UndefinedTerm}proofPurpose> \"assertionMethod\" .",
            $"{Root} <{UndefinedTerm}verificationMethod> \"{Method}\" .",
        ];

        Exactly(Proof(), statements).Should().BeNull();
        Exactly(With(Proof(), "expires", OptionalValue), [.. statements, $"{Root} <{UndefinedTerm}expires> \"{OptionalValue}\" ."]).Should().BeNull();
        Exactly(Proof(), [.. statements, $"{Root} <{UndefinedTerm}expires> \"{OptionalValue}\" ."]).Should().Contain("expires");
    }

    [Fact]
    public void AProofTypedUnderAVocabCannotHideAStandardStatement()
    {
        string[] statements =
        [
            $"{Root} {RdfType} <{UndefinedTerm}DataIntegrityProof> .",
            $"{Root} <{UndefinedTerm}cryptosuite> \"eddsa-rdfc-2022\" .",
            $"{Root} <{UndefinedTerm}created> \"{Created}\" .",
            $"{Root} <{UndefinedTerm}proofPurpose> \"assertionMethod\" .",
            $"{Root} <{UndefinedTerm}verificationMethod> \"{Method}\" .",
            $"{Root} <{Sec}expiration> \"{OptionalValue}\" .",
        ];

        Exactly(Proof(), statements).Should().Contain("expires");
    }

    [Fact]
    public void BothSpellingsOfOneMemberMustAgree()
        => Mismatch(
                With(Proof(), "domain", "a.example"),
                $"{Root} <{Sec}domain> \"a.example\" .",
                $"{Root} <{Sec}domain> \"a.example\"@en .")
            .Should().BeNull();

    [Theory]
    [InlineData("a\"b", "a\\\"b")]
    [InlineData("a\\b", "a\\\\b")]
    [InlineData("a'b", "a\\'b")]
    [InlineData("a\tb", "a\\tb")]
    [InlineData("a\nb", "a\\nb")]
    [InlineData("a\rb", "a\\rb")]
    [InlineData("a\bb", "a\\bb")]
    [InlineData("a\fb", "a\\fb")]
    [InlineData("a\u00e9b", "a\\u00E9b")]
    [InlineData("a\U0001F600b", "a\\U0001F600b")]
    [InlineData("a\U0001F600b", "a\U0001F600b")]
    [InlineData("e\u0301", "e\u0301")]
    [InlineData("x\" <urn:p> \"y\" .", "x\\\" <urn:p> \\\"y\\\" .")]
    public void EscapesAreDecodedBeforeComparing(string value, string escaped)
        => Mismatch(With(Proof(), "challenge", value), $"{Root} <{Sec}challenge> \"{escaped}\" .").Should().BeNull();

    [Fact]
    public void AnEscapedIriIsDecodedBeforeComparing()
    {
        var statements = Signed().Where(statement => !statement.Contains(Sec + "verificationMethod", StringComparison.Ordinal))
            .Append($"{Root} <{Sec}verificationMethod> <did:example:\\u0061#key-1> .");

        Exactly(Proof() with { VerificationMethod = "did:example:a#key-1" }, statements).Should().BeNull();
    }

    [Theory]
    [InlineData("_:c14n0 <urn:p> \"v\"")]
    [InlineData("_:c14n0 <urn:p> \"v\" ")]
    [InlineData("_:c14n0 <urn:p> \"v\" . ")]
    [InlineData("_:c14n0 <urn:p> \"v\" . x")]
    [InlineData("_:c14n0  <urn:p> \"v\" .")]
    [InlineData("_:c14n0 <urn:p> \"v .")]
    [InlineData("_:c14n0 <urn:p> \"v\\")]
    [InlineData("_:c14n0 <urn:p \"v\" .")]
    [InlineData("_:c14n0 <urn:p> \"v\"^^<urn:t .")]
    [InlineData("_:c14n0 <urn:p> \"v\"@en")]
    [InlineData("\"s\" <urn:p> \"v\" .")]
    [InlineData("_:c14n0 \"p\" \"v\" .")]
    [InlineData("_:c14n0 _:p \"v\" .")]
    [InlineData("_:c14n0 <urn:p> \"v\" \"g\" .")]
    [InlineData("_:c14n0 <urn:p> v .")]
    [InlineData("_ <urn:p> \"v\" .")]
    [InlineData("_:c14n0")]
    [InlineData("_:c14n0 <urn:p> \"\\q\" .")]
    [InlineData("_:c14n0 <urn:p> \"\\u12\" .")]
    [InlineData("_:c14n0 <urn:p> \"\\u12G4\" .")]
    [InlineData("_:c14n0 <urn:p> \"\\uD800\" .")]
    [InlineData("_:c14n0 <urn:p> \"\\U00110000\" .")]
    [InlineData("_:c14n0 <urn:p> \"\\U0000004\" .")]
    [InlineData("_:c14n0 <urn:p\\q> \"v\" .")]
    public void AnUnreadableStatementFailsClosed(string statement)
        => Mismatch(Proof(), statement).Should().Contain("could not be read");

    [Fact]
    public void NothingAtAllIsRefused()
        => ProofOptionsBinding.Mismatch(ReadOnlySpan<byte>.Empty, Proof()).Should().NotBeNull();

    [Fact]
    public void AMismatchNeverQuotesAValue()
        => Mismatch(With(Proof(), "challenge", "s3cret-value"), $"{Root} <{Sec}challenge> \"other-value\" .")
            .Should().NotContain("s3cret").And.NotContain("other-value");
}
