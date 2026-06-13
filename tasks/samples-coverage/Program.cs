// FR-21 / AC-9 — mechanical samples-coverage gate.
//
// Reflects over the public API surface of ALL FIVE DataProofsDotnet.* package assemblies and
// verifies that every public type / method / property / constructor NAME appears in at least one
// samples/**/*.cs source file. The check is a substring match against the concatenated sample
// source — the established NetCrypto precedent (tasks/research/conventions.md §7.2): the goal is
// "the name shows up in the learning path", not a parse of compiled references.
//
// An uncovered member can be excused only by an entry in tasks/samples-coverage/allowlist.txt,
// one fully-qualified member per line, EACH followed by a "# justification:" comment. A line
// without a justification fails the tool (exit 2) — exemptions must be reviewed and honest.
//
// Exit codes: 0 = every non-allowlisted public member is covered; 1 = uncovered members remain;
// 2 = usage / configuration error (bad args, missing dir, unjustified allowlist line).
//
// Emits samples-coverage-report.md (a CI artifact) with the per-member -> covered/allowlisted map.

using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;

// --- args: [0] samples dir (default "samples"), [1] allowlist path (default next to this tool). ---
string repoRoot = FindRepoRoot();
string samplesDir = args.Length > 0 ? args[0] : Path.Combine(repoRoot, "samples");
string allowlistPath = args.Length > 1
    ? args[1]
    : Path.Combine(repoRoot, "tasks", "samples-coverage", "allowlist.txt");
string reportPath = Path.Combine(repoRoot, "tasks", "samples-coverage", "samples-coverage-report.md");

if (!Directory.Exists(samplesDir))
{
    Console.Error.WriteLine($"ERROR: samples directory not found: {Path.GetFullPath(samplesDir)}");
    return 2;
}

// --- concatenate every sample source file (ordinal-ordered for determinism). ---
string samplesText = string.Concat(
    Directory.EnumerateFiles(samplesDir, "*.cs", SearchOption.AllDirectories)
        .Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                 && !p.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
        .OrderBy(p => p, StringComparer.Ordinal)
        .Select(File.ReadAllText));

// --- load the allowlist: "Fully.Qualified.Member # justification: …" per line. ---
var allowlist = new HashSet<string>(StringComparer.Ordinal);
if (File.Exists(allowlistPath))
{
    int lineNo = 0;
    foreach (string raw in File.ReadAllLines(allowlistPath))
    {
        lineNo++;
        string line = raw.Trim();
        if (line.Length == 0 || line.StartsWith('#'))
            continue; // blank or a pure comment line

        int hash = line.IndexOf('#');
        if (hash < 0)
        {
            Console.Error.WriteLine($"ERROR: allowlist line {lineNo} has no '# justification:' comment: {line}");
            return 2;
        }

        string member = line[..hash].Trim();
        string comment = line[(hash + 1)..].Trim();
        if (member.Length == 0)
        {
            Console.Error.WriteLine($"ERROR: allowlist line {lineNo} has no member before the comment.");
            return 2;
        }
        if (!comment.StartsWith("justification:", StringComparison.OrdinalIgnoreCase)
            || comment["justification:".Length..].Trim().Length == 0)
        {
            Console.Error.WriteLine($"ERROR: allowlist line {lineNo} ('{member}') needs a non-empty '# justification:' comment.");
            return 2;
        }
        allowlist.Add(member);
    }
}

// Member names inherited from System.Object / System.Enum / System.Delegate (and the serialization
// plumbing on System.Exception / records) never need a dedicated sample, even when a type overrides
// them — they are not part of the library's intentional surface.
string[] inheritedNames =
[
    "ToString", "Equals", "GetHashCode", "GetType", "ReferenceEquals", "MemberwiseClone",
    "CompareTo", "HasFlag", "GetTypeCode",                  // System.Enum
    "Invoke", "BeginInvoke", "EndInvoke", "DynamicInvoke",  // System.Delegate
    "GetObjectData", "GetBaseException",                    // System.Exception
    "Deconstruct", "Clone", "PrintMembers", "op_Equality", "op_Inequality", // record synthesized
];

// The five package assemblies, anchored by one exported type each.
Assembly[] assemblies =
[
    typeof(DataProofsDotnet.DataIntegrity.DataIntegrityProofPipeline).Assembly,        // Core
    typeof(DataProofsDotnet.Jose.Signing.JwsBuilder).Assembly,                         // Jose
    typeof(DataProofsDotnet.Cose.CoseSign1).Assembly,                                  // Cose
    typeof(DataProofsDotnet.Rdfc.RdfcDocumentCanonicalizer).Assembly,                  // Rdfc
    typeof(DataProofsDotnet.Extensions.DependencyInjection.DataProofsBuilder).Assembly, // DI
];

var uncovered = new List<string>();
var covered = new List<string>();
var allowlisted = new List<string>();
var usedAllowlistEntries = new HashSet<string>(StringComparer.Ordinal);
int memberCount = 0;

const BindingFlags DeclaredPublic =
    BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

foreach (Type type in assemblies
             .SelectMany(a => a.GetExportedTypes())
             .OrderBy(t => t.FullName, StringComparer.Ordinal))
{
    if (type.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false))
        continue;

    // Generic types reflect as e.g. "Foo`1"; the source-visible name is "Foo".
    string typeName = type.Name.Split('`')[0];
    Require($"{type.FullName} (type)", typeName);

    // Enums: only the type name needs to appear; the values are exercised by use of the type.
    // Delegates: only the type name; Invoke is synthesized.
    if (type.IsEnum || typeof(Delegate).IsAssignableFrom(type))
        continue;

    foreach (ConstructorInfo ctor in type.GetConstructors(DeclaredPublic))
    {
        if (ctor.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false))
            continue;
        // A constructor is source-visible as `new TypeName(...)`, so the type name is the signal.
        Require($"{type.FullName}..ctor({Parameters(ctor)})", typeName);
    }

    foreach (MethodInfo method in type.GetMethods(DeclaredPublic))
    {
        // IsSpecialName drops property/event accessors and operators; DeclaredOnly drops inherited.
        if (method.IsSpecialName) continue;
        if (method.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false)) continue;
        if (inheritedNames.Contains(method.Name)) continue;
        Require($"{type.FullName}.{method.Name}", method.Name);
    }

    foreach (PropertyInfo property in type.GetProperties(DeclaredPublic))
    {
        if (property.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false)) continue;
        if (inheritedNames.Contains(property.Name)) continue;
        Require($"{type.FullName}.{property.Name}", property.Name);
    }

    foreach (FieldInfo field in type.GetFields(DeclaredPublic))
    {
        if (field.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false)) continue;
        if (inheritedNames.Contains(field.Name)) continue;
        Require($"{type.FullName}.{field.Name}", field.Name);
    }
}

// An allowlist entry that no longer matches any uncovered member is stale — flag it (exit 2).
string[] staleAllowlist = allowlist.Where(a => !usedAllowlistEntries.Contains(a)).OrderBy(x => x, StringComparer.Ordinal).ToArray();

WriteReport();

if (staleAllowlist.Length > 0)
{
    Console.Error.WriteLine($"ERROR: {staleAllowlist.Length} allowlist entr(y/ies) no longer match any uncovered member (remove them):");
    foreach (string s in staleAllowlist)
        Console.Error.WriteLine($"  STALE: {s}");
    return 2;
}

if (uncovered.Count == 0)
{
    Console.WriteLine($"Samples coverage OK: {memberCount} public member(s) across 5 packages "
        + $"({covered.Count} covered by samples, {allowlisted.Count} allowlisted). Report: {reportPath}");
    return 0;
}

foreach (string entry in uncovered)
    Console.WriteLine($"UNCOVERED: {entry}");
Console.Error.WriteLine($"FAILED: {uncovered.Count} public member(s) referenced by no sample (FR-21 / AC-9). See {reportPath}.");
return 1;

// --- the core check: does `name` appear in the sample source, modulo the allowlist? ---
void Require(string label, string name)
{
    memberCount++;
    if (allowlist.Contains(label))
    {
        usedAllowlistEntries.Add(label);
        allowlisted.Add(label);
        return;
    }
    if (samplesText.Contains(name, StringComparison.Ordinal))
        covered.Add(label);
    else
        uncovered.Add(label);
}

static string Parameters(MethodBase m) => string.Join(",", m.GetParameters().Select(p => p.ParameterType.Name));

void WriteReport()
{
    var sb = new StringBuilder();
    sb.AppendLine("# Samples coverage report (FR-21 / AC-9)");
    sb.AppendLine();
    sb.AppendLine($"- Public members across 5 packages: **{memberCount}**");
    sb.AppendLine($"- Covered by at least one sample: **{covered.Count}**");
    sb.AppendLine($"- Allowlisted (excused, with justification): **{allowlisted.Count}**");
    sb.AppendLine($"- Uncovered: **{uncovered.Count}**");
    sb.AppendLine();
    sb.AppendLine($"Samples directory: `{samplesDir}` · Allowlist: `{allowlistPath}`");
    sb.AppendLine();

    if (uncovered.Count > 0)
    {
        sb.AppendLine("## Uncovered members");
        sb.AppendLine();
        foreach (string u in uncovered.OrderBy(x => x, StringComparer.Ordinal))
            sb.AppendLine($"- `{u}`");
        sb.AppendLine();
    }

    if (allowlisted.Count > 0)
    {
        sb.AppendLine("## Allowlisted members");
        sb.AppendLine();
        foreach (string a in allowlisted.OrderBy(x => x, StringComparer.Ordinal))
            sb.AppendLine($"- `{a}`");
        sb.AppendLine();
    }

    sb.AppendLine("## Covered members");
    sb.AppendLine();
    foreach (string c in covered.OrderBy(x => x, StringComparer.Ordinal))
        sb.AppendLine($"- `{c}`");

    File.WriteAllText(reportPath, sb.ToString());
}

// Walk up from the tool's base directory to the repo root (the folder holding DataProofsDotnet.sln).
static string FindRepoRoot()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "DataProofsDotnet.sln")))
        dir = dir.Parent;
    return dir?.FullName ?? Directory.GetCurrentDirectory();
}
