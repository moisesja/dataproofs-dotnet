#!/usr/bin/env bash
# AC-12 IL-warning gate (PRD NFR-7, issue #27).
#
#   scan-il-warnings.sh <publish.log>   fail unless ILC ran and every IL2xxx/IL3xxx line is a known one
#   scan-il-warnings.sh --self-test     prove the scan fails on each input class it must reject
#
# A warning is known when it contains an entry of known-il-warnings.txt (next to this script). Any
# other IL warning fails the gate, whichever assembly it names: hidden reflection in an unannotated
# dependency is reported by ILC as that dependency's warning, not as a DataProofs one.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
known="$here/known-il-warnings.txt"

scan() {
  local log="$1"
  [ -s "$log" ] || { echo "FAILED: publish log '$log' is missing or empty"; return 1; }
  # The ILCompiler target prints this line only when it actually compiles; a skipped (up-to-date)
  # publish leaves it out, and its log would otherwise pass with no warnings at all.
  grep -q 'Generating native code' "$log" || { echo "FAILED: '$log' shows no native compilation ('Generating native code')"; return 1; }
  local lines unknown=0 patterns
  patterns="$(mktemp)"
  { grep -vE '^[[:space:]]*(#|$)' "$known" || true; } > "$patterns"
  lines="$({ grep -E 'IL[23][0-9]{3}' "$log" || true; } | sed -E 's/ \[[^]]*\]$//; s/^.*(IL[23][0-9]{3}: )/\1/' | sort -u)"
  echo "--- IL warnings in $log: $( [ -n "$lines" ] && printf '%s\n' "$lines" | wc -l | tr -d ' ' || echo 0) unique ---"
  [ -z "$lines" ] && { echo "OK — no IL warnings"; return 0; }
  while IFS= read -r line; do
    if grep -qF -f "$patterns" <<<"$line"; then
      echo "known   $line"
    else
      echo "UNKNOWN $line"; unknown=$((unknown + 1))
    fi
  done <<<"$lines"
  rm -f "$patterns"
  if [ "$unknown" -gt 0 ]; then
    echo "FAILED: $unknown IL warning(s) not in $(basename "$known"). Fix the code path, or list the warning there with the reason it is unreachable."
    return 1
  fi
  echo "OK — every IL warning is a known, unreachable third-party one"
}

self_test() {
  local dir; dir="$(mktemp -d)"; trap 'rm -rf "$dir"' RETURN
  local marker='  Generating native code'
  local newtonsoft="ILC : Trim analysis warning IL2026: Newtonsoft.Json.Linq.JValue.GetMetaObject(Expression): Using member 'X' which has 'RequiresUnreferencedCodeAttribute' can break functionality. [/x/AotSmoke.csproj]"
  local ours="ILC : AOT analysis warning IL3050: DataProofsDotnet.Core.Planted(): control line [/x/AotSmoke.csproj]"
  local dependency="ILC : Trim analysis warning IL2026: NetCid.JcsCanonicalizer.Canonicalize(JsonNode,IBufferWriter\`1<Byte>,Int32): Using member 'JsonSerializer.SerializeToDocument<JsonNode>(JsonNode,JsonSerializerOptions)' which has 'RequiresUnreferencedCodeAttribute'. [/x/AotSmoke.csproj]"
  local failures=0
  expect() { # name expected(pass|fail) content...
    local name="$1" want="$2"; shift 2
    printf '%s\n' "$@" > "$dir/$name.log"
    if scan "$dir/$name.log" > "$dir/$name.out" 2>&1; then got=pass; else got=fail; fi
    if [ "$got" = "$want" ]; then echo "self-test ok    $name ($want)"; else echo "self-test WRONG $name: wanted $want, got $got"; cat "$dir/$name.out"; failures=$((failures + 1)); fi
  }
  expect known-only        pass "$marker" "$newtonsoft"
  expect no-warnings       pass "$marker"
  expect dataproofs        fail "$marker" "$newtonsoft" "$ours"
  expect hidden-dependency fail "$marker" "$dependency"
  expect no-native-compile fail "$newtonsoft"
  : > "$dir/empty.log"; if scan "$dir/empty.log" > /dev/null 2>&1; then echo "self-test WRONG empty: passed"; failures=$((failures + 1)); else echo "self-test ok    empty (fail)"; fi
  if scan "$dir/missing.log" > /dev/null 2>&1; then echo "self-test WRONG missing: passed"; failures=$((failures + 1)); else echo "self-test ok    missing (fail)"; fi
  [ "$failures" -eq 0 ] || { echo "FAILED: $failures self-test case(s) wrong"; return 1; }
  echo "OK — scan self-test"
}

case "${1:-}" in
  --self-test) self_test ;;
  "") echo "usage: $0 <publish.log> | --self-test" >&2; exit 2 ;;
  *) scan "$1" ;;
esac
