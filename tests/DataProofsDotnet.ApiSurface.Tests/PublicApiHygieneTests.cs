using System.Reflection;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.ApiSurface.Tests;

/// <summary>
/// AC-6/AC-7 reflection gate (the runtime complement to the text-file <c>api-surface-scan</c>):
/// walks the exported surface of all five <c>DataProofsDotnet.*</c> assemblies and asserts no
/// public signature exposes a forbidden type — neither a backend/native assembly
/// (dotNetRDF/VDS.RDF, Newtonsoft, Jose, SdJwt, NSec, NBitcoin, Nethermind) nor a forbidden
/// namespace (System.Formats.Cbor, System.Security.Cryptography, System.Net, and any
/// Microsoft.IdentityModel.* type OTHER than the single sanctioned <c>JsonWebKey</c>). PRD §2.2.
///
/// Ported from crypto-dotnet's <c>PublicApiHygieneTests</c> (research note §4): a blocklist sweep
/// over <c>GetExportedTypes()</c>, so the sanctioned origins (DataProofsDotnet.*, NetCrypto.*,
/// NetCid.*, the allowed BCL subset, Microsoft.Extensions.*, and JsonWebKey) pass automatically and
/// any public type added later is covered without touching this test.
/// </summary>
public class PublicApiHygieneTests
{
    // Backend/native assemblies that may never surface in a public signature of any package.
    // (dotNetRDF ships its types in assembly "dotNetRdf" under namespace "VDS.RDF"; both forms are
    // listed so a match on either the assembly simple name or the namespace fires.)
    private static readonly string[] ForbiddenAssemblyPrefixes =
        ["dotNetRdf", "VDS.RDF", "Newtonsoft", "Jose", "SdJwt", "Owf.Sd.Jwt", "NSec", "NBitcoin", "Nethermind"];

    // Backend/encoding/network namespaces excluded from public signatures (PRD §2.2 / AC-7).
    private static readonly string[] ForbiddenNamespacePrefixes =
        ["System.Formats.Cbor", "System.Security.Cryptography", "System.Net", "VDS.RDF"];

    // The single Microsoft.IdentityModel type permitted (the JWK boundary exception).
    private const string SanctionedJwk = "Microsoft.IdentityModel.Tokens.JsonWebKey";

    private const BindingFlags DeclaredPublic =
        BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    // One anchor type per package -> the assembly to scan. (Rdfc is anchored on a type that lives
    // in the Rdfc assembly; the DI package on its builder.)
    private static IEnumerable<Assembly> PackageAssemblies() =>
    [
        typeof(DataProofsDotnet.DataIntegrity.DataIntegrityProofPipeline).Assembly,                 // Core
        typeof(DataProofsDotnet.Jose.Signing.JwsBuilder).Assembly,                                  // Jose
        typeof(DataProofsDotnet.Cose.CoseSign1).Assembly,                                           // Cose
        typeof(DataProofsDotnet.Rdfc.RdfcDocumentCanonicalizer).Assembly,                           // Rdfc
        typeof(DataProofsDotnet.Extensions.DependencyInjection.DataProofsBuilder).Assembly,         // DI
    ];

    [Fact]
    public void ExportedSurface_ContainsNoForbiddenTypes()
    {
        var violations = new List<string>();

        foreach (var assembly in PackageAssemblies())
        {
            var exportedTypes = assembly.GetExportedTypes();
            exportedTypes.Should().NotBeEmpty(
                $"package {assembly.GetName().Name} must expose a public surface to scan");

            foreach (var type in exportedTypes)
            {
                CheckType(type, $"{type.FullName} (exported type)", violations);

                if (type.BaseType is not null)
                    CheckType(type.BaseType, $"{type.FullName} base type", violations);

                foreach (var iface in type.GetInterfaces())
                    CheckType(iface, $"{type.FullName} implemented interface", violations);

                foreach (var ctor in type.GetConstructors(DeclaredPublic))
                    foreach (var p in ctor.GetParameters())
                        CheckType(p.ParameterType, $"{type.FullName}..ctor parameter '{p.Name}'", violations);

                foreach (var method in type.GetMethods(DeclaredPublic))
                {
                    if (method.IsSpecialName && method.Name.StartsWith("get_", StringComparison.Ordinal))
                        continue; // property getters are covered via the property scan below
                    CheckType(method.ReturnType, $"{type.FullName}.{method.Name} return type", violations);
                    foreach (var p in method.GetParameters())
                        CheckType(p.ParameterType, $"{type.FullName}.{method.Name} parameter '{p.Name}'", violations);
                }

                foreach (var property in type.GetProperties(DeclaredPublic))
                {
                    CheckType(property.PropertyType, $"{type.FullName}.{property.Name} property type", violations);
                    foreach (var p in property.GetIndexParameters())
                        CheckType(p.ParameterType, $"{type.FullName}.{property.Name} index parameter '{p.Name}'", violations);
                }

                foreach (var field in type.GetFields(DeclaredPublic))
                    CheckType(field.FieldType, $"{type.FullName}.{field.Name} field type", violations);

                foreach (var evt in type.GetEvents(DeclaredPublic))
                    if (evt.EventHandlerType is not null)
                        CheckType(evt.EventHandlerType, $"{type.FullName}.{evt.Name} event handler type", violations);
            }
        }

        violations.Should().BeEmpty(
            "no public signature may expose a backend type (dotNetRDF/Newtonsoft/Jose/SdJwt/NSec/"
            + "NBitcoin/Nethermind) or a forbidden namespace (System.Formats.Cbor / "
            + "System.Security.Cryptography / System.Net), nor any Microsoft.IdentityModel type other "
            + "than JsonWebKey (PRD §2.2 / AC-7)");
    }

    [Fact]
    public void Detector_FlagsForbiddenTypes_PositiveControl()
    {
        // Positive control: prove the recursive detector actually fires — including nested inside
        // arrays, generic instantiations, and tuples — so the main sweep cannot pass vacuously.
        var fired = new List<string>();

        CheckType(typeof(System.Formats.Cbor.CborReader), "control: cbor", fired);             // forbidden namespace
        CheckType(typeof(System.Net.Http.HttpClient), "control: net", fired);                  // forbidden namespace
        CheckType(typeof(System.Security.Cryptography.SHA256[]), "control: crypto array", fired); // array element
        CheckType(typeof(Task<VDS.RDF.IGraph>), "control: rdf generic arg", fired);            // generic arg, backend
        CheckType(typeof(Microsoft.IdentityModel.Tokens.SigningCredentials),
            "control: non-JWK identitymodel", fired);                                          // IdentityModel != JWK

        fired.Should().HaveCount(5, "every forbidden control type must be flagged");

        // Sanctioned types must NOT be flagged.
        var clean = new List<string>();
        CheckType(typeof(Microsoft.IdentityModel.Tokens.JsonWebKey), "control: jwk", clean);   // the one exception
        CheckType(typeof(NetCrypto.ISigner), "control: netcrypto", clean);
        CheckType(typeof(NetCid.Cid), "control: netcid", clean);
        CheckType(typeof(System.Text.Json.JsonElement), "control: stj", clean);
        CheckType(typeof(byte[]), "control: bcl scalar", clean);
        CheckType(typeof(DataProofsDotnet.DataIntegrity.DataIntegrityProof), "control: own type", clean);

        clean.Should().BeEmpty("sanctioned JWK/NetCrypto/NetCid/STJ/BCL/own types are not forbidden");
    }

    [Fact]
    public void DotNetRdf_IsReachableOnlyFromTheRdfcAssembly()
    {
        // dotNetRDF (assembly "dotNetRdf") is the sole RDF backend and must not be referenced by any
        // package except Rdfc. Inspecting the referenced-assembly list of each package proves the
        // §2.2 split: Core/Jose/Cose/DI never link dotNetRDF.
        var rdfcAssembly = typeof(DataProofsDotnet.Rdfc.RdfcDocumentCanonicalizer).Assembly;

        foreach (var assembly in PackageAssemblies())
        {
            bool referencesDotNetRdf = assembly.GetReferencedAssemblies()
                .Any(a => (a.Name ?? string.Empty).StartsWith("dotNetRdf", StringComparison.OrdinalIgnoreCase)
                       || (a.Name ?? string.Empty).StartsWith("VDS.RDF", StringComparison.OrdinalIgnoreCase));

            bool isRdfc = assembly == rdfcAssembly;
            if (isRdfc)
            {
                referencesDotNetRdf.Should().BeTrue(
                    "the Rdfc assembly is the sole sanctioned dotNetRDF reference (PRD §2.2) and must actually link it, "
                    + "so this canary cannot be silently neutered by a backend rename");
            }
            else
            {
                referencesDotNetRdf.Should().BeFalse(
                    $"{assembly.GetName().Name} must not reference dotNetRDF — it is allowed only in DataProofsDotnet.Rdfc (PRD §2.2)");
            }
        }
    }

    /// <summary>
    /// Recursively unwraps arrays/by-ref/pointer element types and generic arguments, recording a
    /// violation for every constituent type from a forbidden backend assembly or forbidden namespace
    /// (with the single Microsoft.IdentityModel.Tokens.JsonWebKey exception).
    /// </summary>
    private static void CheckType(Type type, string location, List<string> violations)
    {
        if (type.IsGenericParameter)
            return;

        if (type.HasElementType)
        {
            CheckType(type.GetElementType()!, location, violations);
            return;
        }

        if (IsForbidden(type))
            violations.Add(
                $"{location} exposes forbidden type '{type.FullName}' from assembly '{type.Assembly.GetName().Name}'");

        if (type.IsGenericType)
            foreach (var argument in type.GetGenericArguments())
                CheckType(argument, location, violations);
    }

    private static bool IsForbidden(Type type)
    {
        // The single sanctioned Microsoft.IdentityModel type.
        if (type.FullName == SanctionedJwk)
            return false;

        string assemblyName = type.Assembly.GetName().Name ?? string.Empty;
        if (ForbiddenAssemblyPrefixes.Any(p => assemblyName.StartsWith(p, StringComparison.Ordinal)))
            return true;

        string ns = type.Namespace ?? string.Empty;
        if (ForbiddenNamespacePrefixes.Any(p => ns == p || ns.StartsWith(p + ".", StringComparison.Ordinal)))
            return true;

        // Any OTHER Microsoft.IdentityModel.* type (only JsonWebKey is allowed).
        if (ns == "Microsoft.IdentityModel"
            || ns.StartsWith("Microsoft.IdentityModel.", StringComparison.Ordinal))
            return true;

        return false;
    }
}
