// AC-11 (package identity & publish readiness) — PRD §9 AC-11. Publish gate.
//
// For each of the five DataProofsDotnet.* IDs:
//   1. Query the nuget.org registration endpoint
//      https://api.nuget.org/v3/registration5-semver1/{id-lowercase}/index.json
//      — 404 means the ID is unregistered and CLAIMABLE; 200 means it already exists and must be
//        owned by --owner (asserted via the search API's owners list) else the gate fails.
//   2. Report the DataProofsDotnet ID-prefix reservation status (prefix reservation is a one-time
//      OWNER action — request it via the NuGet account — so the tool reports/advises, it cannot
//      perform it).
//   3. Assert each src csproj's <PackageId> matches its intended ID exactly.
//
// Network is required for steps 1–2 (allowed per the phase brief / AC-11 runs in publish.yml).
// --offline skips the network and runs only the local PackageId assertion (step 3), documenting
// that the registration/ownership/prefix checks run in CI.
//
// --prerelease relaxes ONLY the prefix-reservation check to a warning (a prerelease cannot precede
// the published ID that makes reservation grantable); a stable publish omits it so the prefix is a
// hard gate. ID claimable-or-owned and PackageId exactness stay hard gates in both modes.
//
// Exit codes: 0 = all IDs claimable-or-owned + prefix reserved (or warned under --prerelease) + IDs exact;
//             1 = a gate failed (foreign-owned ID, PackageId mismatch, prefix not reserved [stable]);
//             2 = usage / environment error.

using System.Text.Json;
using System.Xml.Linq;

const int ExitClean = 0;
const int ExitViolation = 1;
const int ExitUsage = 2;

string[] expectedIds =
[
    "DataProofsDotnet.Core",
    "DataProofsDotnet.Jose",
    "DataProofsDotnet.Cose",
    "DataProofsDotnet.Rdfc",
    "DataProofsDotnet.Extensions.DependencyInjection",
];
const string IdPrefix = "DataProofsDotnet";

string? owner = null;
string? srcRootArg = null;
bool offline = false;
bool prerelease = false;
for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--owner":
            if (i + 1 >= args.Length) { Console.Error.WriteLine("ERROR: --owner requires a nuget account name."); return ExitUsage; }
            owner = args[++i];
            break;
        case "--src-root":
            if (i + 1 >= args.Length) { Console.Error.WriteLine("ERROR: --src-root requires a directory."); return ExitUsage; }
            srcRootArg = args[++i];
            break;
        case "--offline":
            offline = true;
            break;
        case "--prerelease":
            prerelease = true;
            break;
        case "-h":
        case "--help":
            Console.WriteLine("Usage: PackageIdentity --owner <nugetAccount> [--src-root <dir>] [--offline] [--prerelease]");
            Console.WriteLine("  Checks the five DataProofsDotnet.* IDs are claimable-or-owned, the prefix is reserved,");
            Console.WriteLine("  and each src csproj PackageId is exact (AC-11). Exit 0 ok / 1 gate fail / 2 usage.");
            Console.WriteLine("  --prerelease: an unreserved ID prefix is a WARNING (not a failure) for a prerelease");
            Console.WriteLine("                publish; it stays a HARD failure for a stable release.");
            return ExitClean;
        default:
            Console.Error.WriteLine($"ERROR: unknown argument '{args[i]}'. Use --help.");
            return ExitUsage;
    }
}

if (owner is null && !offline)
{
    Console.Error.WriteLine("ERROR: --owner <nugetAccount> is required (or pass --offline to run only the PackageId assertion).");
    return ExitUsage;
}

string srcRoot = srcRootArg ?? LocateSrcRoot();
if (!Directory.Exists(srcRoot))
{
    Console.Error.WriteLine($"ERROR: src root not found: {srcRoot}");
    return ExitUsage;
}

Console.WriteLine("=== AC-11 package identity & publish readiness ===");
Console.WriteLine($"owner:     {owner ?? "(offline — ownership check deferred to CI)"}");
Console.WriteLine($"src root:  {srcRoot}");
Console.WriteLine($"mode:      {(offline ? "offline (local PackageId assertion only)" : "online (nuget.org registration + ownership + prefix)")}");
Console.WriteLine();

var failures = new List<string>();

// ---- 3. PackageId exactness (local, always runs) ---------------------------------------------
Console.WriteLine("--- PackageId assertion (src csproj <PackageId>) ---");
var declaredIds = new Dictionary<string, string>(StringComparer.Ordinal); // id -> csproj path
foreach (var id in expectedIds)
{
    string csprojDir = Path.Combine(srcRoot, id);
    string csproj = Path.Combine(csprojDir, id + ".csproj");
    if (!File.Exists(csproj))
    {
        failures.Add($"[PackageId] expected project file not found: {csproj}");
        Console.WriteLine($"  {id,-50} csproj MISSING");
        continue;
    }

    string? packageId = ReadPackageId(csproj);
    if (packageId is null)
    {
        failures.Add($"[PackageId] {id}: csproj has no <PackageId> element.");
        Console.WriteLine($"  {id,-50} <PackageId> MISSING");
    }
    else if (!packageId.Equals(id, StringComparison.Ordinal))
    {
        failures.Add($"[PackageId] {id}: csproj <PackageId>='{packageId}' does not match intended ID '{id}' (squat risk; AC-11).");
        Console.WriteLine($"  {id,-50} MISMATCH ('{packageId}')");
        declaredIds[packageId] = csproj;
    }
    else
    {
        Console.WriteLine($"  {id,-50} ok");
        declaredIds[packageId] = csproj;
    }
}
Console.WriteLine();

// ---- 1. registration + ownership; 2. prefix reservation (online) -----------------------------
if (offline)
{
    Console.WriteLine("--- nuget.org registration + ownership + prefix: SKIPPED (--offline) ---");
    Console.WriteLine("    These run in publish.yml before the push, where network is available. The");
    Console.WriteLine("    local PackageId assertion above is the offline-runnable portion of AC-11.");
    Console.WriteLine();
}
else
{
    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    http.DefaultRequestHeaders.UserAgent.ParseAdd("dataproofs-package-identity/1.0");

    Console.WriteLine("--- nuget.org registration (registration5-semver1) + ownership ---");
    foreach (var id in expectedIds)
    {
        string lower = id.ToLowerInvariant();
        string regUrl = $"https://api.nuget.org/v3/registration5-semver1/{lower}/index.json";

        int status;
        try
        {
            using var resp = await http.GetAsync(regUrl);
            status = (int)resp.StatusCode;
        }
        catch (Exception ex)
        {
            failures.Add($"[registration] {id}: query failed — {ex.Message}");
            Console.WriteLine($"  {id,-50} QUERY FAILED");
            continue;
        }

        if (status == 404)
        {
            Console.WriteLine($"  {id,-50} 404 CLAIMABLE (unregistered)");
        }
        else if (status == 200)
        {
            var owners = await GetOwnersAsync(http, id);
            bool ownedByUs = owners.Any(o => o.Equals(owner, StringComparison.OrdinalIgnoreCase));
            if (ownedByUs)
            {
                Console.WriteLine($"  {id,-50} 200 OWNED by '{owner}' (owners: {string.Join(", ", owners)})");
            }
            else
            {
                failures.Add($"[registration] {id}: exists on nuget.org but is NOT owned by '{owner}' "
                    + $"(owners: {(owners.Count == 0 ? "unknown" : string.Join(", ", owners))}) — AC-11 fails the publish.");
                Console.WriteLine($"  {id,-50} 200 FOREIGN-OWNED (owners: {(owners.Count == 0 ? "unknown" : string.Join(", ", owners))})");
            }
        }
        else
        {
            failures.Add($"[registration] {id}: unexpected HTTP {status} from {regUrl}.");
            Console.WriteLine($"  {id,-50} HTTP {status} (unexpected)");
        }
    }
    Console.WriteLine();

    // ---- 2. prefix reservation ----
    Console.WriteLine("--- ID-prefix reservation ---");
    bool prefixReserved = await IsPrefixReservedAsync(http, expectedIds, owner!);
    if (prefixReserved)
    {
        Console.WriteLine($"  '{IdPrefix}' prefix appears RESERVED to '{owner}' (a registered {IdPrefix}.* ID reports verified=true).");
    }
    else if (prerelease)
    {
        // Prefix reservation cannot precede the first published ID (the search service has nothing
        // to mark verified until a DataProofsDotnet.* package exists). For a PRERELEASE publish this
        // is a WARNING, not a gate failure: every ID is asserted claimable-or-owned above (so the
        // prerelease cannot squat a foreign ID), and publishing the prerelease is what makes prefix
        // reservation grantable. The stable release re-runs this gate WITHOUT --prerelease, where an
        // unreserved prefix is a hard failure.
        Console.WriteLine($"  '{IdPrefix}' prefix NOT reserved — WARNING (prerelease): request reservation at");
        Console.WriteLine("    https://learn.microsoft.com/nuget/nuget-org/id-prefix-reservation once the");
        Console.WriteLine("    prerelease packages are published; the stable release will hard-gate on it.");
    }
    else
    {
        // Per AC-11, prefix reservation is a one-time OWNER action and cannot be automated. If no
        // DataProofsDotnet.* ID is published yet, reservation cannot be in place — that is expected
        // pre-first-publish and the gate points at the owner action rather than asserting falsely.
        failures.Add(
            $"[prefix] The '{IdPrefix}' ID prefix is not yet reserved to '{owner}'. Prefix reservation is a "
            + "one-time OWNER action (request it via the NuGet account: https://learn.microsoft.com/nuget/nuget-org/id-prefix-reservation) "
            + "— it cannot be automated. Reserve it before a stable publish so the family cannot be squatted between releases.");
        Console.WriteLine($"  '{IdPrefix}' prefix NOT reserved (owner action required — see failure detail).");
    }
    Console.WriteLine();
}

// ---- report ----------------------------------------------------------------------------------
if (failures.Count == 0)
{
    Console.WriteLine("RESULT: OK — all five IDs claimable-or-owned, prefix reserved (or n/a offline), PackageIds exact (AC-11).");
    return ExitClean;
}

Console.Error.WriteLine($"RESULT: {failures.Count} AC-11 GATE ISSUE(S):");
foreach (var f in failures)
    Console.Error.WriteLine($"  - {f}");
return ExitViolation;

// ----------------------------------------------------------------------------------------------

static string? ReadPackageId(string csprojPath)
{
    try
    {
        var doc = XDocument.Load(csprojPath);
        // Project files here use no XML namespace (SDK-style); match the local element name.
        return doc.Descendants()
            .FirstOrDefault(e => e.Name.LocalName.Equals("PackageId", StringComparison.Ordinal))
            ?.Value.Trim();
    }
    catch
    {
        return null;
    }
}

static async Task<List<string>> GetOwnersAsync(HttpClient http, string id)
{
    // The registration endpoint does not carry owners; the search service does. Query by exact id.
    string[] searchHosts =
    [
        "https://azuresearch-usnc.nuget.org/query",
        "https://azuresearch-ussc.nuget.org/query",
    ];

    foreach (var host in searchHosts)
    {
        try
        {
            string url = $"{host}?q=packageid:{Uri.EscapeDataString(id)}&prerelease=true&semVerLevel=2.0.0";
            using var resp = await http.GetAsync(url);
            if (!resp.IsSuccessStatusCode)
                continue;
            await using var stream = await resp.Content.ReadAsStreamAsync();
            using var json = await JsonDocument.ParseAsync(stream);
            if (!json.RootElement.TryGetProperty("data", out var data))
                continue;
            foreach (var pkg in data.EnumerateArray())
            {
                if (pkg.TryGetProperty("id", out var pid)
                    && pid.GetString()?.Equals(id, StringComparison.OrdinalIgnoreCase) == true
                    && pkg.TryGetProperty("owners", out var ownersEl))
                {
                    return ownersEl.EnumerateArray()
                        .Select(o => o.GetString() ?? string.Empty)
                        .Where(o => o.Length > 0)
                        .ToList();
                }
            }
        }
        catch
        {
            // try the next host
        }
    }
    return [];
}

// Prefix reservation surfaces in the search service as "verified": true on packages whose id is
// under a reserved prefix owned by the searching owner. With no DataProofsDotnet.* package published
// yet there is nothing to inspect, so this returns false (reservation cannot precede a published id
// for the search service to report) and the caller advises the owner action.
static async Task<bool> IsPrefixReservedAsync(HttpClient http, string[] ids, string owner)
{
    foreach (var id in ids)
    {
        string[] searchHosts =
        [
            "https://azuresearch-usnc.nuget.org/query",
            "https://azuresearch-ussc.nuget.org/query",
        ];
        foreach (var host in searchHosts)
        {
            try
            {
                string url = $"{host}?q=packageid:{Uri.EscapeDataString(id)}&prerelease=true&semVerLevel=2.0.0";
                using var resp = await http.GetAsync(url);
                if (!resp.IsSuccessStatusCode)
                    continue;
                await using var stream = await resp.Content.ReadAsStreamAsync();
                using var json = await JsonDocument.ParseAsync(stream);
                if (!json.RootElement.TryGetProperty("data", out var data))
                    continue;
                foreach (var pkg in data.EnumerateArray())
                {
                    if (pkg.TryGetProperty("id", out var pid)
                        && pid.GetString()?.Equals(id, StringComparison.OrdinalIgnoreCase) == true
                        && pkg.TryGetProperty("verified", out var verified)
                        && verified.ValueKind == JsonValueKind.True)
                    {
                        var owners = await GetOwnersAsync(http, id);
                        if (owners.Any(o => o.Equals(owner, StringComparison.OrdinalIgnoreCase)))
                            return true;
                    }
                }
            }
            catch
            {
                // try next host
            }
        }
    }
    return false;
}

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
