// AC-7 (public-API surface discipline) — PRD §9 AC-7 / §2.2.
//
// Parses every src PublicAPI.Shipped.txt + PublicAPI.Unshipped.txt and enforces the AC-7 POSITIVE
// allowlist of types permitted in public signatures: DataProofsDotnet.*, the enumerated BCL subset
// (bcl-allowlist.txt), Microsoft.Extensions.* (DI package only), NetCrypto.* / NetCid.*, and the
// single type Microsoft.IdentityModel.Tokens.JsonWebKey. Anything else fails — System.Formats.Cbor,
// System.Net, System.Security.Cryptography, other Microsoft.IdentityModel.* types, VDS.RDF,
// Newtonsoft, Jose, SdJwt, NSec/NBitcoin/Nethermind, etc.
//
// Exit codes: 0 = clean, 1 = one or more forbidden type references, 2 = usage / environment error.

using DataProofsDotnet.Tools.ApiSurfaceScan;

const int ExitClean = 0;
const int ExitViolation = 1;
const int ExitUsage = 2;

string? srcRootArg = null;
string? allowlistArg = null;
for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--src-root":
            if (i + 1 >= args.Length) { Console.Error.WriteLine("ERROR: --src-root requires a directory argument."); return ExitUsage; }
            srcRootArg = args[++i];
            break;
        case "--allowlist":
            if (i + 1 >= args.Length) { Console.Error.WriteLine("ERROR: --allowlist requires a file argument."); return ExitUsage; }
            allowlistArg = args[++i];
            break;
        case "-h":
        case "--help":
            Console.WriteLine("Usage: ApiSurfaceScan [--src-root <dir>] [--allowlist <bcl-allowlist.txt>]");
            Console.WriteLine("  Enforces the PRD §9 AC-7 positive allowlist over every src PublicAPI.*.txt file.");
            Console.WriteLine("  Exit 0 = clean, 1 = forbidden type references, 2 = usage/environment error.");
            return ExitClean;
        default:
            Console.Error.WriteLine($"ERROR: unknown argument '{args[i]}'. Use --help.");
            return ExitUsage;
    }
}

string srcRoot = srcRootArg ?? LocateSrcRoot();
if (!Directory.Exists(srcRoot))
{
    Console.Error.WriteLine($"ERROR: src root not found: {srcRoot}");
    return ExitUsage;
}

string allowlistPath = allowlistArg ?? LocateAllowlist();
Allowlist allowlist;
try
{
    allowlist = Allowlist.Load(allowlistPath);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"ERROR: cannot load BCL allowlist: {ex.Message}");
    return ExitUsage;
}

var apiFiles = Directory
    .EnumerateFiles(srcRoot, "PublicAPI.*.txt", SearchOption.AllDirectories)
    .Where(p => p.EndsWith("PublicAPI.Shipped.txt", StringComparison.Ordinal)
             || p.EndsWith("PublicAPI.Unshipped.txt", StringComparison.Ordinal))
    .OrderBy(p => p, StringComparer.Ordinal)
    .ToList();

if (apiFiles.Count == 0)
{
    Console.Error.WriteLine($"ERROR: no PublicAPI.*.txt files found under {srcRoot}");
    return ExitUsage;
}

Console.WriteLine("=== AC-7 public-API surface scan ===");
Console.WriteLine($"src root:   {srcRoot}");
Console.WriteLine($"allowlist:  {allowlistPath}");
Console.WriteLine($"API files:  {apiFiles.Count}");
Console.WriteLine();

var violations = new List<string>();
int totalLines = 0;
int totalTypeRefs = 0;

foreach (var file in apiFiles)
{
    int fileViolations = 0;
    string display = RelativeTo(srcRoot, file);
    int lineNumber = 0;

    foreach (var line in File.ReadLines(file))
    {
        lineNumber++;
        totalLines++;
        var typeRefs = TypeReferenceExtractor.Extract(line);
        foreach (var typeRef in typeRefs)
        {
            totalTypeRefs++;
            if (!allowlist.IsAllowed(typeRef))
            {
                fileViolations++;
                violations.Add($"{display}:{lineNumber}: forbidden type '{typeRef}' in public signature");
                violations.Add($"    line: {line.Trim()}");
            }
        }
    }

    Console.WriteLine($"  {display,-58} {(fileViolations == 0 ? "ok" : $"{fileViolations} VIOLATION(S)")}");
}

Console.WriteLine();
Console.WriteLine($"scanned {totalLines} declaration lines, {totalTypeRefs} type references.");
Console.WriteLine();

if (violations.Count == 0)
{
    Console.WriteLine("RESULT: CLEAN — every public type reference is on the AC-7 allowlist.");
    return ExitClean;
}

Console.Error.WriteLine("RESULT: VIOLATION(S) (AC-7):");
foreach (var v in violations)
    Console.Error.WriteLine($"  {v}");
return ExitViolation;

// ----------------------------------------------------------------------------------------------

static string LocateSrcRoot()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null)
    {
        string candidate = Path.Combine(dir.FullName, "src");
        if (Directory.Exists(candidate) &&
            Directory.EnumerateFiles(candidate, "DataProofsDotnet.*.csproj", SearchOption.AllDirectories).Any())
        {
            return candidate;
        }
        dir = dir.Parent;
    }
    return Path.Combine(Directory.GetCurrentDirectory(), "src");
}

static string LocateAllowlist()
{
    // Prefer the copy next to the executing assembly (CopyToOutputDirectory), then the checked-in
    // source next to this tool's project, walking up for the tasks/api-surface-scan directory.
    string beside = Path.Combine(AppContext.BaseDirectory, "bcl-allowlist.txt");
    if (File.Exists(beside))
        return beside;

    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null)
    {
        string candidate = Path.Combine(dir.FullName, "tasks", "api-surface-scan", "bcl-allowlist.txt");
        if (File.Exists(candidate))
            return candidate;
        dir = dir.Parent;
    }
    return beside;
}

static string RelativeTo(string root, string path)
{
    string parent = Directory.GetParent(root)?.FullName ?? root;
    return Path.GetRelativePath(parent, path);
}
