using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace DataProofsDotnet.Tools.AotSmoke;

/// <summary>
/// A deliberate trim and AOT warning, so the AC-12 scan can prove the ILCompiler's analysis ran and its
/// warnings reached the publish log. Without it, a publish with the analysis switched off
/// (<c>SuppressTrimAnalysisWarnings</c>, <c>SuppressAotAnalysisWarnings</c>) logs no IL warning at all
/// and passes any scan that only looks for bad lines. <c>scan-il-warnings.sh</c> requires both canary
/// lines (the <c>require</c> entries of <c>known-il-warnings.txt</c>).
/// </summary>
/// <remarks>
/// The <c>#pragma</c> silences only the Roslyn analyzers that build this tool (warnings-as-errors); the
/// ILCompiler does not read it, so it reports the call. The annotated method does nothing.
/// </remarks>
internal static class IlCanary
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void Run()
    {
#pragma warning disable IL2026, IL3050 // the canary: ILC must report exactly this call
        Annotated();
#pragma warning restore IL2026, IL3050
    }

    [RequiresUnreferencedCode("AC-12 canary: trim analysis ran and its warnings reach the publish log.")]
    [RequiresDynamicCode("AC-12 canary: AOT analysis ran and its warnings reach the publish log.")]
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Annotated()
    {
    }
}
