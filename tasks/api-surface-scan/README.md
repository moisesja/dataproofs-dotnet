# api-surface-scan (AC-7)

Console tool enforcing the PRD §9 AC-7 **positive allowlist** over the public API surface, parsed
from the checked-in `PublicAPI.Shipped.txt` / `PublicAPI.Unshipped.txt` files of every `src/`
package.

```
dotnet run --project tasks/api-surface-scan/ApiSurfaceScan.csproj -c Release -- [--src-root <dir>] [--allowlist <bcl-allowlist.txt>]
```

## What it checks

A type reference appearing in any public signature is permitted **only** if it belongs to one of
the sanctioned origins (AC-7 is an allowlist, not a blocklist):

| # | Origin |
|---|---|
| (i) | this library — `DataProofsDotnet.*` |
| (ii) | the **enumerated** BCL subset in [`bcl-allowlist.txt`](bcl-allowlist.txt) — *not* all of `System.*` |
| (iii) | `Microsoft.Extensions.*` abstractions (DI package only) |
| (iv) | `NetCrypto.*` and `NetCid.*` public namespaces |
| (v) | the **single** type `Microsoft.IdentityModel.Tokens.JsonWebKey` |

Anything else fails — `System.Formats.Cbor.*`, `System.Net.*`, `System.Security.Cryptography.*`,
any *other* `Microsoft.IdentityModel.*` type, `VDS.RDF.*`, `Newtonsoft.*`, `Jose.*`, `SdJwt.*`,
`NSec.*`, `NBitcoin.*`, `Nethermind.*` — without enumerating the forbidden set.

## How it parses the PublicAPI line format

`TypeReferenceExtractor` tokenizes each declaration line: it drops const initializers, splits the
declaration and the post-`->` return type on the structural punctuation that delimits type tokens
(`< > [ ] ( ) ,` whitespace, the `->` arrow), strips the `!`/`?` nullability suffixes and the
declaration modifiers (`static`/`const`/`readonly`/`override`/`operator`/`implicit`/`get`/`init`/…),
maps the C# keyword aliases (`void`/`bool`/`int`/`string`/`byte`/`object`/…) to their `System.*`
types, and emits every **dotted fully-qualified name** plus every mapped alias. Bare single
identifiers are member/parameter/type-parameter names and are skipped — a forbidden backend type
can only appear here as a fully-qualified name, and every such name is checked, including those
nested inside generics, arrays, and tuples.

## `bcl-allowlist.txt`

Enumerates exactly AC-7's BCL subset: scalar/primitive + span types, `System.Text.Json.*`, the
async types (`Task`/`ValueTask`/`CancellationToken`), `System.Collections.Generic.*`, and the
date/URI/id scalars (`DateTimeOffset`/`TimeSpan`/`Uri`/`Guid`), plus the `Func`/`Action`/`Exception`/
`Nullable`/`ValueTuple` plumbing that appears in signatures (their type arguments are checked
independently). A line ending in `.*` is a namespace prefix; any other line is an exact type.
Additions require a justification comment on the preceding line.

## Exit codes

- `0` — clean
- `1` — one or more forbidden type references in public signatures
- `2` — usage / environment error

## Result against the current repo

CLEAN. 10 PublicAPI files, 632 declaration lines, 1756 type references — all on the allowlist. The
one historical finding (a public `System.Net.Http.HttpClient` constructor on
`CachingNetworkDocumentLoader` in `Rdfc`) was fixed upstream by making that ctor `internal` and
adding an `IDocumentLoader`-only public overload; the scan confirms `System.Net.*` no longer
surfaces.
