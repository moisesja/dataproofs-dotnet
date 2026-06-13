namespace DataProofsDotnet.Tools.ApiSurfaceScan;

/// <summary>
/// The AC-7 POSITIVE allowlist. A type reference appearing in any public signature is permitted
/// only if it belongs to one of the sanctioned origins (PRD §9 AC-7 / §2.2):
///
///   (i)   this library's own namespaces — DataProofsDotnet.*;
///   (ii)  the enumerated BCL subset in bcl-allowlist.txt (scalars/spans/STJ/async/collections/
///         date+URI) — NOT all of System.*;
///   (iii) Microsoft.Extensions.* abstractions (DI package only);
///   (iv)  NetCrypto.* and NetCid.* public namespaces;
///   (v)   the SINGLE type Microsoft.IdentityModel.Tokens.JsonWebKey.
///
/// Everything else fails — System.Formats.Cbor.*, System.Net.*, System.Security.Cryptography.*,
/// any other Microsoft.IdentityModel.* type, VDS.RDF.*, Newtonsoft.*, Jose.*, SdJwt.*, NSec.*,
/// NBitcoin.*, Nethermind.* — without enumerating them, because the rule is an allowlist.
/// </summary>
internal sealed class Allowlist
{
    // The single Microsoft.IdentityModel type permitted (the JWK boundary exception).
    private const string JsonWebKeyType = "Microsoft.IdentityModel.Tokens.JsonWebKey";

    // Library + sanctioned-dependency namespace prefixes (allow the namespace, every type under it).
    private static readonly string[] NamespacePrefixes =
    [
        "DataProofsDotnet.",          // (i) this library
        "Microsoft.Extensions.",      // (iii) DI abstractions (DI package only)
        "NetCrypto.",                 // (iv) NetCrypto public namespaces
        "NetCid.",                    // (iv) NetCid public namespaces
    ];

    // Exact System.* type names from bcl-allowlist.txt (lines without ".*").
    private readonly HashSet<string> _bclExactTypes;

    // System.* namespace prefixes from bcl-allowlist.txt (lines ending in ".*").
    private readonly List<string> _bclNamespacePrefixes;

    private Allowlist(HashSet<string> bclExactTypes, List<string> bclNamespacePrefixes)
    {
        _bclExactTypes = bclExactTypes;
        _bclNamespacePrefixes = bclNamespacePrefixes;
    }

    public static Allowlist Load(string bclAllowlistPath)
    {
        if (!File.Exists(bclAllowlistPath))
            throw new FileNotFoundException($"BCL allowlist not found: {bclAllowlistPath}", bclAllowlistPath);

        var exact = new HashSet<string>(StringComparer.Ordinal);
        var prefixes = new List<string>();

        foreach (var rawLine in File.ReadLines(bclAllowlistPath))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;

            if (line.EndsWith(".*", StringComparison.Ordinal))
                prefixes.Add(line[..^1]); // keep trailing '.' so "System.Text.Json." is the prefix
            else
                exact.Add(line);
        }

        return new Allowlist(exact, prefixes);
    }

    /// <summary>
    /// True if the given fully-qualified type reference is permitted in a public signature.
    /// A member-access path (e.g. "DataProofsDotnet.X.Y.Member.get") is permitted iff its leading
    /// namespace is one of the library/dependency prefixes; for System.* the rule is exact-type or
    /// enumerated-namespace, so a System member path is never accepted by accident.
    /// </summary>
    public bool IsAllowed(string typeReference)
    {
        // (v) the single JWK exception (exact).
        if (typeReference.Equals(JsonWebKeyType, StringComparison.Ordinal))
            return true;

        // (i)/(iii)/(iv) library + sanctioned-dependency namespaces.
        foreach (var prefix in NamespacePrefixes)
        {
            if (typeReference.StartsWith(prefix, StringComparison.Ordinal))
                return true;
        }

        // (ii) the enumerated BCL subset — exact types first.
        if (_bclExactTypes.Contains(typeReference))
            return true;

        // …then enumerated BCL namespace prefixes (System.Text.Json.*, System.Collections.Generic.*).
        foreach (var prefix in _bclNamespacePrefixes)
        {
            if (typeReference.StartsWith(prefix, StringComparison.Ordinal))
                return true;
        }

        // A member-access path on an allowed BCL type (e.g. an exact type's nested member) is rare
        // in PublicAPI output, but accept "<exact-type>.<member>" too so a property accessor on an
        // allowed scalar does not false-positive. Walk down the dotted path: if any prefix segment
        // is an allowed exact BCL type, the trailing segments are members of it.
        int dot = typeReference.LastIndexOf('.');
        while (dot > 0)
        {
            string head = typeReference[..dot];
            if (_bclExactTypes.Contains(head) || head.Equals(JsonWebKeyType, StringComparison.Ordinal))
                return true;
            dot = head.LastIndexOf('.');
        }

        return false;
    }
}
