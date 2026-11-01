using System.Globalization;
using System.Text;
using DataProofsDotnet.DataIntegrity;

namespace DataProofsDotnet.Rdfc.Internal;

/// <summary>
/// Requires the proof options the library reads to be what was signed. Verification decides on JSON
/// members (<c>expires</c>, <c>domain</c>, <c>proofPurpose</c>, …), an RDFC signature covers the RDF
/// those members expand to, and <c>@context</c> is not signed, so the same RDF can be spelled with
/// other JSON: a member renamed away, or one added that means something already signed. Reading the
/// canonical N-Quads that were hashed, and comparing them with the members in both directions, leaves
/// a context nothing to change.
/// </summary>
/// <remarks>
/// <para>
/// Only the members this library acts on are compared. An unmodeled member
/// (<see cref="DataIntegrityProof.AdditionalProperties"/>) has no meaning here, so an application that
/// acts on one must pin its contexts, as with the claims of the document itself.
/// </para>
/// <para>
/// A member is read from two predicates: the one every published context gives it, and its name in
/// the vocabulary of the proof's own type. The second is how a proof reads under a <c>@vocab</c>, as
/// <c>credentials/undefined-terms/v2</c> supplies for a suite with no published context
/// (<c>EcdsaSecp256r1Signature2019</c>). Both are always read, so a proof cannot be typed under one
/// and hide a statement under the other. Datatype and language are not compared: the library reads
/// the value alone.
/// </para>
/// <para>
/// Compiled into the Legacy package as well (a linked file), so its RDFC variant runs this same check
/// and neither package widens <c>InternalsVisibleTo</c>. Pure functions.
/// </para>
/// </remarks>
internal static class ProofOptionsBinding
{
    private const string Security = "https://w3id.org/security#";
    private const string RdfType = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";

    // The IRIs the bundled contexts give the five registered purposes, under the proofPurpose term's
    // scoped context. Four of them are not the name: authentication is authenticationMethod.
    private static readonly Dictionary<string, string> RegisteredPurposes = new(StringComparer.Ordinal)
    {
        [Security + "assertionMethod"] = ProofPurposes.AssertionMethod,
        [Security + "authenticationMethod"] = ProofPurposes.Authentication,
        [Security + "capabilityInvocationMethod"] = ProofPurposes.CapabilityInvocation,
        [Security + "capabilityDelegationMethod"] = ProofPurposes.CapabilityDelegation,
        [Security + "keyAgreementMethod"] = ProofPurposes.KeyAgreement,
    };

    private enum TermKind
    {
        Iri,
        BlankNode,
        Literal,
    }

    private readonly record struct Term(TermKind Kind, string Value);

    private readonly record struct Statement(Term Subject, string Predicate, Term Object, bool InDefaultGraph);

    /// <summary>
    /// Compares <paramref name="proof"/> with the canonical N-Quads of its proof configuration.
    /// </summary>
    /// <returns>Why they differ, naming the member and never quoting a value (FR-23), or <c>null</c> when they agree.</returns>
    public static string? Mismatch(ReadOnlySpan<byte> canonicalProofConfig, DataIntegrityProof proof)
    {
        var text = Encoding.UTF8.GetString(canonicalProofConfig);
        var statements = new List<Statement>();
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!TryReadStatement(line, out var statement))
            {
                return "The proof configuration's canonical form could not be read.";
            }

            // A named graph is another node's: an embedded proof, such as a delegated capability's parent.
            if (statement.InDefaultGraph)
            {
                statements.Add(statement);
            }
        }

        // The proof is the one node nothing points at, which only the signed statements decide. The
        // presented JSON must not choose it: @reverse can turn a signed nested node into the outer
        // object without changing the dataset, and that node would then answer for the proof.
        var pointedAt = statements
            .Where(statement => statement.Object.Kind != TermKind.Literal)
            .Select(statement => statement.Object)
            .ToHashSet();
        var roots = statements.Select(statement => statement.Subject).Where(subject => !pointedAt.Contains(subject)).Distinct().ToList();
        if (roots.Count != 1)
        {
            return "The proof configuration's canonical form does not have one proof node.";
        }

        var root = roots[0];
        var typeStatements = statements
            .Where(statement => statement.Subject == root
                && statement.Predicate == RdfType
                && statement.Object.Kind == TermKind.Iri
                && EndsInName(statement.Object.Value, proof.Type))
            .ToList();
        if (typeStatements.Count != 1)
        {
            return MemberMismatch("type");
        }

        if (root.Kind == TermKind.Iri ? root.Value != proof.Id : proof.Id is not null)
        {
            return MemberMismatch("id");
        }

        var vocabulary = typeStatements[0].Object.Value[..^proof.Type.Length];
        var signed = statements.Where(statement => statement.Subject == root).ToLookup(statement => statement.Predicate, statement => statement.Object);
        List<Term> SignedValues(string member, string predicate)
            => [.. signed[predicate].Concat(signed[vocabulary + member]).Distinct()];

        (string Member, string Predicate, string? Value)[] members =
        [
            ("expires", Security + "expiration", proof.Expires),
            ("domain", Security + "domain", proof.Domain),
            ("challenge", Security + "challenge", proof.Challenge),
            ("nonce", Security + "nonce", proof.Nonce),
            ("cryptosuite", Security + "cryptosuite", proof.Cryptosuite),
            ("created", "http://purl.org/dc/terms/created", proof.Created),
            ("verificationMethod", Security + "verificationMethod", proof.VerificationMethod),
        ];
        foreach (var (member, predicate, value) in members)
        {
            if (!Agrees(SignedValues(member, predicate), value is null ? [] : [value]))
            {
                return MemberMismatch(member);
            }
        }

        if (!Agrees(SignedValues("previousProof", Security + "previousProof"), proof.PreviousProof?.Values ?? []))
        {
            return MemberMismatch("previousProof");
        }

        return PurposeAgrees(SignedValues("proofPurpose", Security + "proofPurpose"), proof.ProofPurpose)
            ? null
            : MemberMismatch("proofPurpose");
    }

    private static string MemberMismatch(string member) => $"The proof's {member} does not match its canonical form.";

    private static bool EndsInName(string iri, string name)
        => iri.EndsWith("#" + name, StringComparison.Ordinal) || iri.EndsWith("/" + name, StringComparison.Ordinal);

    // Every statement must have its member and the reverse, so a value renamed away and one the
    // issuer never signed both fail, and a second signed value cannot be hidden behind one member.
    private static bool Agrees(List<Term> signed, IReadOnlyList<string> members)
        => signed.TrueForAll(term => term.Kind != TermKind.BlankNode)
            && signed.Select(term => term.Value).ToHashSet(StringComparer.Ordinal).SetEquals(members);

    // Under a @vocab a purpose is a plain string, and otherwise an IRI with one name. The pipeline and
    // a resolver compare a purpose as a string, so two spellings of one signed IRI would each pass a
    // policy written for that spelling alone.
    private static bool PurposeAgrees(List<Term> signed, string? purpose)
    {
        if (purpose is null)
        {
            return signed.Count == 0;
        }

        return signed switch
        {
            [{ Kind: TermKind.Literal, Value: var literal }] => literal == purpose,
            [{ Kind: TermKind.Iri, Value: var iri }] => PurposeName(iri) == purpose,
            _ => false,
        };
    }

    // The one spelling of a signed purpose IRI: its registered name, or else the name it ends in,
    // which is how a term of the issuer's context reads. An IRI with no such name, or whose name is a
    // registered purpose it is not, is spelled whole.
    private static string PurposeName(string iri)
    {
        if (RegisteredPurposes.TryGetValue(iri, out var registered))
        {
            return registered;
        }

        var name = iri[(iri.LastIndexOfAny(['/', '#']) + 1)..];
        return name.Length > 0 && !name.Contains(':') && !RegisteredPurposes.ContainsValue(name) ? name : iri;
    }

    // subject predicate object [graph] . — anything else fails closed rather than being guessed at.
    private static bool TryReadStatement(string line, out Statement statement)
    {
        statement = default;
        var position = 0;
        if (!TryReadTerm(line, ref position, out var subject) || subject.Kind == TermKind.Literal
            || !TrySkipSpace(line, ref position)
            || !TryReadTerm(line, ref position, out var predicate) || predicate.Kind != TermKind.Iri
            || !TrySkipSpace(line, ref position)
            || !TryReadTerm(line, ref position, out var value)
            || !TrySkipSpace(line, ref position))
        {
            return false;
        }

        var inDefaultGraph = position < line.Length && line[position] == '.';
        if (!inDefaultGraph
            && (!TryReadTerm(line, ref position, out var graph) || graph.Kind == TermKind.Literal
                || !TrySkipSpace(line, ref position)))
        {
            return false;
        }

        if (position != line.Length - 1 || line[position] != '.')
        {
            return false;
        }

        statement = new Statement(subject, predicate.Value, value, inDefaultGraph);
        return true;
    }

    private static bool TrySkipSpace(string line, ref int position)
    {
        if (position >= line.Length || line[position] != ' ')
        {
            return false;
        }

        position++;
        return true;
    }

    private static bool TryReadTerm(string line, ref int position, out Term term)
    {
        term = default;
        if (position >= line.Length)
        {
            return false;
        }

        switch (line[position])
        {
            case '<':
                var close = line.IndexOf('>', position);
                if (close < 0 || !TryDecode(line.AsSpan(position + 1, close - position - 1), out var iri))
                {
                    return false;
                }

                term = new Term(TermKind.Iri, iri);
                position = close + 1;
                return true;

            case '_' when position + 1 < line.Length && line[position + 1] == ':':
                var end = line.IndexOf(' ', position);
                if (end < 0)
                {
                    return false;
                }

                term = new Term(TermKind.BlankNode, line[(position + 2)..end]);
                position = end;
                return true;

            case '"':
                return TryReadLiteral(line, ref position, out term);

            default:
                return false;
        }
    }

    private static bool TryReadLiteral(string line, ref int position, out Term term)
    {
        term = default;

        // A literal ends at the first quote not escaped by a backslash.
        var end = position + 1;
        while (end < line.Length && line[end] != '"')
        {
            end += line[end] == '\\' ? 2 : 1;
        }

        if (end >= line.Length || !TryDecode(line.AsSpan(position + 1, end - position - 1), out var value))
        {
            return false;
        }

        position = end + 1;
        term = new Term(TermKind.Literal, value);

        // The datatype or language follows with no space, and neither is compared.
        if (line.AsSpan(position).StartsWith("^^<", StringComparison.Ordinal))
        {
            var close = line.IndexOf('>', position);
            if (close < 0)
            {
                return false;
            }

            position = close + 1;
        }
        else if (position < line.Length && line[position] == '@')
        {
            var space = line.IndexOf(' ', position);
            if (space < 0)
            {
                return false;
            }

            position = space;
        }

        return true;
    }

    // Decodes the N-Quads escapes. An unknown one, or one past the Unicode range, fails closed.
    private static bool TryDecode(ReadOnlySpan<char> text, out string decoded)
    {
        var result = new StringBuilder(text.Length);
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] != '\\')
            {
                result.Append(text[i]);
                continue;
            }

            if (++i == text.Length)
            {
                decoded = string.Empty;
                return false;
            }

            switch (text[i])
            {
                case 't': result.Append('\t'); break;
                case 'b': result.Append('\b'); break;
                case 'n': result.Append('\n'); break;
                case 'r': result.Append('\r'); break;
                case 'f': result.Append('\f'); break;
                case '"': result.Append('"'); break;
                case '\'': result.Append('\''); break;
                case '\\': result.Append('\\'); break;
                case 'u' or 'U':
                    var digits = text[i] == 'u' ? 4 : 8;
                    if (i + digits >= text.Length
                        || !uint.TryParse(text.Slice(i + 1, digits), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var codePoint)
                        || !Rune.TryCreate(codePoint, out var rune))
                    {
                        decoded = string.Empty;
                        return false;
                    }

                    result.Append(rune.ToString());
                    i += digits;
                    break;
                default:
                    decoded = string.Empty;
                    return false;
            }
        }

        decoded = result.ToString();
        return true;
    }
}
