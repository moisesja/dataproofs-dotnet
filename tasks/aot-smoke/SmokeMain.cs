// ============================================================
// AC-12 — native AOT publish and JIT parity (PRD NFR-7, issue #27)
// ============================================================
// Exercises every DataProofsDotnet package with fixed keys and timestamps and records what it
// produced, so the same program can be compared across runtimes:
//
//   AotSmoke emit <report.json>             run every path, self-verify, write the report
//   AotSmoke verify <report.json>           verify another run's outputs (signatures, envelopes, JWEs)
//   AotSmoke compare <a.json> <b.json> ...  the "deterministic" sections must be byte-identical
//
// CI runs it under JIT, under JIT with reflection-based serialization disabled, as a .NET 10
// file-based app and as a native-AOT binary; see tasks/aot-smoke/README.md. Every failed expectation
// prints "FAILED: …" and exits 1.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace DataProofsDotnet.Tools.AotSmoke;

/// <summary>
/// The tool's entry point. Public so the .NET 10 file-based app in <c>file-based-app/</c> can run the
/// same paths through a <c>#:project</c> reference.
/// </summary>
public static class SmokeMain
{
    /// <summary>Runs one mode (<c>emit</c>, <c>verify</c> or <c>compare</c>) and returns the exit code.</summary>
    public static async Task<int> RunAsync(string[] args)
    {
        IlCanary.Run();
        ISmokePath[] paths =
        [
            new ProofInputPath(),
            new JcsPath(),
            new RdfcPath(),
            new Bbs2023Path(),
            new LegacyPath(),
            new JosePath(),
            new SdJwtPath(),
            new CoseAndVcPath(),
            new JwkPath(),
            new CompositionPath(), // last: compares its DI-built output with the JCS path's
        ];

        switch (args)
        {
            case ["emit", var path]:
            {
                var report = Report.New();
                report.Runtime["isDynamicCodeSupported"] = RuntimeFeature.IsDynamicCodeSupported;
                report.Runtime["reflectionEnabled"] = JsonSerializer.IsReflectionEnabledByDefault;
                report.Runtime["rid"] = RuntimeInformation.RuntimeIdentifier;
                report.Runtime["framework"] = RuntimeInformation.FrameworkDescription;
                report.Runtime["bbsAvailable"] = Bbs2023Path.IsAvailable();
                PrintRuntime("this run", report);
                foreach (var smokePath in paths)
                {
                    Console.WriteLine($"=== {smokePath.Name} ===");
                    await Run(smokePath, () => smokePath.EmitAsync(report));
                }

                report.Save(path);
                Console.WriteLine($"OK — AotSmoke emit: {Gate.Verified} checks passed, {report.Deterministic.Count} deterministic values and {report.Artifacts.Count} artifacts written to {path}.");
                return 0;
            }

            case ["verify", var path]:
            {
                var report = Report.Load(path);
                PrintRuntime($"verifying {path}, produced by", report);
                PrintRuntime("verifier", Report.New());
                foreach (var smokePath in paths)
                {
                    Console.WriteLine($"=== {smokePath.Name} ===");
                    await Run(smokePath, () => smokePath.VerifyAsync(report));
                }

                Console.WriteLine($"OK — AotSmoke verify: {Gate.Verified} checks passed against {path}.");
                return 0;
            }

            case ["compare", var first, var second, .. var rest]:
                return Compare([first, second, .. rest]);

            default:
                Console.Error.WriteLine("usage: AotSmoke emit <report.json> | verify <report.json> | compare <a.json> <b.json> [...]");
                return 2;
        }
    }

    // Several library APIs throw by contract on a bad input (JweParser on a failed decryption, for one),
    // so an exception escaping a path is a failed expectation, reported like any other.
    private static async Task Run(ISmokePath smokePath, Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            Gate.Fail($"{smokePath.Name}: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static int Compare(string[] files)
    {
        var reports = files.Select(Report.Load).ToArray();
        for (var i = 0; i < files.Length; i++)
        {
            PrintRuntime(files[i], reports[i]);
        }

        var baseline = reports[0].Deterministic;
        var differences = 0;
        for (var i = 1; i < reports.Length; i++)
        {
            var other = reports[i].Deterministic;
            foreach (var key in baseline.Select(p => p.Key).Union(other.Select(p => p.Key)).Order(StringComparer.Ordinal))
            {
                var a = baseline[key]?.GetValue<string>();
                var b = other[key]?.GetValue<string>();
                if (!string.Equals(a, b, StringComparison.Ordinal))
                {
                    differences++;
                    Console.Error.WriteLine($"FAILED: deterministic '{key}' differs between {files[0]} and {files[i]}");
                    Console.Error.WriteLine($"  {files[0]}: {a ?? "<missing>"}");
                    Console.Error.WriteLine($"  {files[i]}: {b ?? "<missing>"}");
                }
            }
        }

        if (differences > 0)
        {
            Console.Error.WriteLine($"FAILED: {differences} deterministic value(s) differ.");
            return 1;
        }

        Console.WriteLine($"OK — AotSmoke compare: {baseline.Count} deterministic values identical across {files.Length} reports.");
        return 0;
    }

    private static void PrintRuntime(string label, Report report)
    {
        var runtime = report.Runtime.Count > 0
            ? report.Runtime
            : new System.Text.Json.Nodes.JsonObject
            {
                ["isDynamicCodeSupported"] = RuntimeFeature.IsDynamicCodeSupported,
                ["reflectionEnabled"] = JsonSerializer.IsReflectionEnabledByDefault,
                ["rid"] = RuntimeInformation.RuntimeIdentifier,
            };
        Console.WriteLine($"[{label}] {string.Join(", ", runtime.Select(p => $"{p.Key}={p.Value}"))}");
    }
}
