// AC-5 (didcomm JWS/JWE behavior parity) — PRD §9 AC-5.
//
// For each ported→source pair recorded in tests/DataProofsDotnet.Jose.Tests/Parity/PARITY.md, this
// tool extracts the assertion statements from BOTH the ported file (read from disk) and its didcomm
// source file (read via `git show <sha>:<path>` from the read-only didcomm clone), normalizes
// identifiers per PARITY.md's recorded rename map, and fails on any difference in the asserted
// literals or structure. Sanctioned structural adaptations (rename-map entries whose RHS is prose,
// e.g. reading a JSON payload property) are reported transparently and excluded from the strict
// diff, per the PARITY.md "Sanctioned adaptations" section.
//
// Exit codes: 0 = zero assertion differences, 1 = one or more differences, 2 = usage/environment.

using System.Diagnostics;
using DataProofsDotnet.Tools.ParityDiff;

const int ExitClean = 0;
const int ExitViolation = 1;
const int ExitUsage = 2;

string? parityMdArg = null;
string? portedRootArg = null;
string? didcommRepoArg = null;
bool verbose = false;
for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--parity-md": parityMdArg = NextArg(args, ref i); break;
        case "--ported-root": portedRootArg = NextArg(args, ref i); break;
        case "--didcomm-repo": didcommRepoArg = NextArg(args, ref i); break;
        case "-v":
        case "--verbose": verbose = true; break;
        case "-h":
        case "--help":
            Console.WriteLine("Usage: ParityDiff [--parity-md <PARITY.md>] [--ported-root <dir>] [--didcomm-repo <dir>] [-v]");
            Console.WriteLine("  Diffs ported parity assertions against their didcomm source at the SHA in PARITY.md (AC-5).");
            Console.WriteLine("  Exit 0 = zero differences, 1 = differences, 2 = usage/environment error.");
            return ExitClean;
        default:
            Console.Error.WriteLine($"ERROR: unknown argument '{args[i]}'. Use --help.");
            return ExitUsage;
    }
}

string parityMd = parityMdArg ?? LocateParityMd();
if (!File.Exists(parityMd))
{
    Console.Error.WriteLine($"ERROR: PARITY.md not found: {parityMd}");
    return ExitUsage;
}
string portedRoot = portedRootArg ?? Path.GetDirectoryName(Path.GetFullPath(parityMd))!;
string didcommRepo = didcommRepoArg ?? "/Users/moises/Projects/didcomm-dotnet";

ParityManifest manifest;
try
{
    manifest = ParityManifest.Parse(parityMd);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"ERROR: cannot parse PARITY.md: {ex.Message}");
    return ExitUsage;
}

Console.WriteLine("=== AC-5 parity-diff ===");
Console.WriteLine($"PARITY.md:     {parityMd}");
Console.WriteLine($"ported root:   {portedRoot}");
Console.WriteLine($"didcomm repo:  {didcommRepo}");
Console.WriteLine($"source SHA:    {manifest.SourceSha}");
Console.WriteLine($"file pairs:    {manifest.Pairs.Count}");
Console.WriteLine($"rename rules:  {manifest.Renames.Count} ({manifest.Renames.Count(r => r.StructuralAdaptation)} structural)");
Console.WriteLine();

// Verify the source SHA exists in the didcomm repo before reading any file from it.
if (!GitObjectExists(didcommRepo, manifest.SourceSha))
{
    Console.Error.WriteLine($"ERROR: commit {manifest.SourceSha} not found in {didcommRepo} (cannot read parity source).");
    return ExitUsage;
}

var normalizer = new RenameNormalizer(manifest.Renames);
var differences = new List<string>();
int totalPorted = 0, totalSource = 0, totalAdapted = 0, totalOmitted = 0;

string sourceTestsPrefix = "tests/DidComm.Core.Tests/";

foreach (var pair in manifest.Pairs)
{
    string portedPath = Path.Combine(portedRoot, pair.PortedFile);
    if (!File.Exists(portedPath))
    {
        differences.Add($"[{pair.PortedFile}] ported file not found at {portedPath}");
        continue;
    }

    string sourceGitPath = sourceTestsPrefix + pair.SourcePath;
    string? sourceText = GitShow(didcommRepo, manifest.SourceSha, sourceGitPath);
    if (sourceText is null)
    {
        differences.Add($"[{pair.PortedFile}] didcomm source not found at {manifest.SourceSha}:{sourceGitPath}");
        continue;
    }

    var portedAssertions = AssertionExtractor.Extract(File.ReadAllText(portedPath));
    var sourceTagged = AssertionExtractor.ExtractTagged(sourceText);

    // Normalize the source toward the ported public API. Two sets are removed from the strict diff:
    //   * assertions in PARITY.md-sanctioned OMITTED source test methods (DIDComm-only tests not
    //     ported — reported as omitted, not a parity violation);
    //   * assertions whose raw text matches a structural-adaptation marker (a sanctioned shape
    //     change, reported as adapted).
    var sourceAdapted = new List<string>();
    var sourceOmitted = new List<string>();
    var sourceNormalized = new List<string>();
    foreach (var t in sourceTagged)
    {
        if (IsOmittedMethod(t.Method, manifest.OmittedTestMethods))
            sourceOmitted.Add(t.Statement);
        else if (normalizer.IsStructurallyAdapted(t.Statement))
            sourceAdapted.Add(t.Statement);
        else
            sourceNormalized.Add(normalizer.Normalize(t.Statement));
    }

    // The ported assertions already use the new public-API vocabulary, so they are NOT renamed —
    // renames only lift the SOURCE identifiers up to that vocabulary. The corresponding adapted
    // ported assertions (reading a JSON payload property) are set aside so they do not count as
    // "extra" ported assertions.
    var portedAdapted = new List<string>();
    var portedNormalized = new List<string>();
    foreach (var p in portedAssertions)
    {
        if (normalizer.IsPortedAdaptation(p))
            portedAdapted.Add(p);
        else
            portedNormalized.Add(p);
    }

    totalPorted += portedNormalized.Count;
    totalSource += sourceNormalized.Count;
    totalAdapted += sourceAdapted.Count;
    totalOmitted += sourceOmitted.Count;

    int before = differences.Count;
    DiffMultisets(pair.PortedFile, sourceNormalized, portedNormalized, differences);

    string status = differences.Count == before ? "ok" : $"{differences.Count - before} DIFF";
    string notes = string.Concat(
        sourceAdapted.Count > 0 ? $", {sourceAdapted.Count} adapted" : string.Empty,
        sourceOmitted.Count > 0 ? $", {sourceOmitted.Count} omitted" : string.Empty);
    Console.WriteLine($"  {pair.PortedFile,-30} src {sourceNormalized.Count,3} / ported {portedNormalized.Count,3}{notes}  ->  {status}");

    if (verbose)
    {
        foreach (var a in sourceAdapted)
            Console.WriteLine($"        adapted (sanctioned): {Truncate(a, 100)}");
        foreach (var o in sourceOmitted)
            Console.WriteLine($"        omitted (sanctioned): {Truncate(o, 100)}");
    }
}

Console.WriteLine();
Console.WriteLine($"compared {totalSource} source / {totalPorted} ported strict assertions; "
    + $"{totalAdapted} sanctioned adaptations + {totalOmitted} omitted-test assertions set aside.");
Console.WriteLine();

if (differences.Count == 0)
{
    Console.WriteLine("RESULT: ZERO assertion differences — parity holds (AC-5).");
    return ExitClean;
}

Console.Error.WriteLine($"RESULT: {differences.Count} ASSERTION DIFFERENCE(S) (AC-5):");
foreach (var d in differences)
    Console.Error.WriteLine($"  - {d}");
return ExitViolation;

// ----------------------------------------------------------------------------------------------

// Order-independent multiset diff: every normalized source assertion must appear (with equal
// multiplicity) on the ported side, and vice versa. Reordering of tests is an allowed modification;
// adding/removing/changing an assertion's literals or structure is not.
static void DiffMultisets(string file, List<string> source, List<string> ported, List<string> differences)
{
    var sourceCounts = ToCounts(source);
    var portedCounts = ToCounts(ported);

    foreach (var (assertion, count) in sourceCounts)
    {
        portedCounts.TryGetValue(assertion, out int portedCount);
        if (portedCount < count)
            differences.Add($"[{file}] source asserts (x{count - portedCount} more) but ported does not: {assertion}");
    }
    foreach (var (assertion, count) in portedCounts)
    {
        sourceCounts.TryGetValue(assertion, out int sourceCount);
        if (sourceCount < count)
            differences.Add($"[{file}] ported asserts (x{count - sourceCount} more) absent from source: {assertion}");
    }
}

// A source test method is omitted if its name exactly equals a PARITY.md omitted entry, or ends
// with one as a "_"-delimited tail. The suffix form covers the "…_passes_when_present"
// continuation, whose elided stem is the sibling of the preceding fully-named omitted method.
static bool IsOmittedMethod(string method, IReadOnlySet<string> omitted)
{
    if (method.Length == 0)
        return false;
    foreach (var o in omitted)
    {
        if (method.Equals(o, StringComparison.Ordinal)
            || method.EndsWith("_" + o, StringComparison.Ordinal))
        {
            return true;
        }
    }
    return false;
}

static Dictionary<string, int> ToCounts(List<string> items)
{
    var counts = new Dictionary<string, int>(StringComparer.Ordinal);
    foreach (var item in items)
        counts[item] = counts.TryGetValue(item, out int c) ? c + 1 : 1;
    return counts;
}

static string? NextArg(string[] args, ref int i)
{
    if (i + 1 >= args.Length)
        throw new ArgumentException($"option '{args[i]}' requires a value");
    return args[++i];
}

static string LocateParityMd()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null)
    {
        string candidate = Path.Combine(dir.FullName,
            "tests", "DataProofsDotnet.Jose.Tests", "Parity", "PARITY.md");
        if (File.Exists(candidate))
            return candidate;
        dir = dir.Parent;
    }
    return Path.Combine(Directory.GetCurrentDirectory(),
        "tests", "DataProofsDotnet.Jose.Tests", "Parity", "PARITY.md");
}

static bool GitObjectExists(string repo, string sha)
{
    var (exit, _, _) = RunGit(repo, $"cat-file -t {sha}");
    return exit == 0;
}

static string? GitShow(string repo, string sha, string path)
{
    var (exit, stdout, _) = RunGit(repo, $"show {sha}:{path}");
    return exit == 0 ? stdout : null;
}

static (int Exit, string Stdout, string Stderr) RunGit(string repo, string arguments)
{
    var psi = new ProcessStartInfo
    {
        FileName = "git",
        WorkingDirectory = repo,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
    };
    psi.ArgumentList.Add("-C");
    psi.ArgumentList.Add(repo);
    foreach (var part in SplitArgs(arguments))
        psi.ArgumentList.Add(part);

    using var process = Process.Start(psi) ?? throw new InvalidOperationException("failed to start git");
    string stdout = process.StandardOutput.ReadToEnd();
    string stderr = process.StandardError.ReadToEnd();
    process.WaitForExit();
    return (process.ExitCode, stdout, stderr);
}

// git args here never contain quoted spaces, so a simple whitespace split is sufficient.
static IEnumerable<string> SplitArgs(string s) =>
    s.Split(' ', StringSplitOptions.RemoveEmptyEntries);

static string Truncate(string value, int max) =>
    value.Length <= max ? value : value[..max] + "…";
