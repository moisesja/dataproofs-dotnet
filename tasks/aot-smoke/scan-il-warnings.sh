#!/usr/bin/env bash
# AC-12 IL-warning gate (PRD NFR-7, issue #27).
#
#   scan-il-warnings.sh <publish.log>   fail unless ILC ran, the canary is present, and every
#                                       IL2xxx/IL3xxx warning matches known-il-warnings.txt
#   scan-il-warnings.sh --self-test     prove the scan rejects each input class it must reject
#
# Every IL warning must match an entry of known-il-warnings.txt (next to this script) as a prefix,
# whichever assembly it names: hidden reflection in an unannotated dependency is reported by ILC as
# that dependency's warning, not as a DataProofs one. The `require` entries (the IlCanary warnings)
# must also appear, which proves the analysis ran and was not suppressed.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
known_file="$here/known-il-warnings.txt"

# Prints one normalized warning per line: "ILxxxx: <origin member>: <message>". The match starts at the
# FIRST "ILxxxx: " in a line (grep -o is leftmost), so text inside a message cannot shift it, and the
# trailing " [project path]" MSBuild appends is dropped.
normalize() {
  { grep -oE 'IL[23][0-9]{3}: .*' "$1" || true; } | sed -E 's/\r$//; s/ \[[^]]*\]$//' | sort -u
}

scan() {
  local log="$1"
  [ -s "$log" ] || { echo "FAILED: publish log '$log' is missing or empty"; return 1; }
  # The ILCompiler target prints this only when it actually compiles; a publish skipped as up to date
  # leaves it out.
  grep -q 'Generating native code' "$log" || { echo "FAILED: '$log' shows no native compilation ('Generating native code')"; return 1; }

  local -a allowed=() required=()
  local entry
  while IFS= read -r entry || [ -n "$entry" ]; do
    entry="${entry%$'\r'}"
    case "$entry" in
      ''|'#'*) ;;
      'require '*) required+=("${entry#require }"); allowed+=("${entry#require }") ;;
      *) allowed+=("$entry") ;;
    esac
  done < "$known_file"
  [ "${#allowed[@]}" -gt 0 ] || { echo "FAILED: $(basename "$known_file") has no entries"; return 1; }

  local lines line unknown=0 matched prefix
  lines="$(normalize "$log")"
  echo "--- IL warnings in $log: $( [ -n "$lines" ] && printf '%s\n' "$lines" | wc -l | tr -d ' ' || echo 0) unique ---"
  if [ -n "$lines" ]; then
    while IFS= read -r line; do
      matched=0
      for prefix in "${allowed[@]}"; do
        if [[ "$line" == "$prefix"* ]]; then matched=1; break; fi
      done
      if [ "$matched" -eq 1 ]; then echo "known   $line"; else echo "UNKNOWN $line"; unknown=$((unknown + 1)); fi
    done <<<"$lines"
  fi

  local missing=0
  for prefix in "${required[@]}"; do
    if ! printf '%s\n' "$lines" | while IFS= read -r line; do [[ "$line" == "$prefix"* ]] && exit 0; done; then
      echo "MISSING canary: $prefix"; missing=$((missing + 1))
    fi
  done

  if [ "$missing" -gt 0 ]; then
    echo "FAILED: $missing canary warning(s) absent — the trim/AOT analysis did not run or its warnings were suppressed."
    return 1
  fi
  if [ "$unknown" -gt 0 ]; then
    echo "FAILED: $unknown IL warning(s) not in $(basename "$known_file"). Fix the code path, or list the warning there with the reason it is unreachable."
    return 1
  fi
  echo "OK — the canary is present and every IL warning is a known one"
}

self_test() {
  local dir; dir="$(mktemp -d)"; trap 'rm -rf "$dir"' RETURN
  local marker='  Generating native code'
  local canary2026="/x/IlCanary.cs(23): Trim analysis warning IL2026: DataProofsDotnet.Tools.AotSmoke.IlCanary.Run(): Using member 'DataProofsDotnet.Tools.AotSmoke.IlCanary.Annotated()' which has 'RequiresUnreferencedCodeAttribute'. [/x/AotSmoke.csproj]"
  local canary3050="/x/IlCanary.cs(23): AOT analysis warning IL3050: DataProofsDotnet.Tools.AotSmoke.IlCanary.Run(): Using member 'DataProofsDotnet.Tools.AotSmoke.IlCanary.Annotated()' which has 'RequiresDynamicCodeAttribute'. [/x/AotSmoke.csproj]"
  local newtonsoft="ILC : Trim analysis warning IL2026: Newtonsoft.Json.Linq.JValue.GetMetaObject(Expression): Using member 'X' which has 'RequiresUnreferencedCodeAttribute'. [/x/AotSmoke.csproj]"
  local ours="ILC : AOT analysis warning IL3050: DataProofsDotnet.Core.Planted(): control line [/x/AotSmoke.csproj]"
  local dependency="ILC : Trim analysis warning IL2026: NetCid.JcsCanonicalizer.Canonicalize(JsonNode,IBufferWriter\`1<Byte>,Int32): Using member 'JsonSerializer.SerializeToDocument<JsonNode>(JsonNode,JsonSerializerOptions)'. [/x/AotSmoke.csproj]"
  # A message that quotes a known entry must not borrow its match.
  local smuggled="ILC : Trim analysis warning IL2026: NetCid.Evil(): Using member 'IL2026: Newtonsoft.Json.Linq.JValue.GetMetaObject(Expression): x'. [/x/AotSmoke.csproj]"
  local failures=0 got
  expect() { # name expected(pass|fail) lines...
    local name="$1" want="$2"; shift 2
    printf '%s\n' "$@" > "$dir/$name.log"
    if scan "$dir/$name.log" > "$dir/$name.out" 2>&1; then got=pass; else got=fail; fi
    if [ "$got" = "$want" ]; then echo "self-test ok    $name ($want)"; else echo "self-test WRONG $name: wanted $want, got $got"; cat "$dir/$name.out"; failures=$((failures + 1)); fi
  }
  expect canary-and-known  pass "$marker" "$canary2026" "$canary3050" "$newtonsoft"
  expect canary-only       pass "$marker" "$canary2026" "$canary3050"
  expect crlf              pass "$marker"$'\r' "$canary2026"$'\r' "$canary3050"$'\r' "$newtonsoft"$'\r'
  expect suppressed        fail "$marker"
  expect half-canary       fail "$marker" "$canary2026" "$newtonsoft"
  expect dataproofs        fail "$marker" "$canary2026" "$canary3050" "$ours"
  expect hidden-dependency fail "$marker" "$canary2026" "$canary3050" "$dependency"
  expect smuggled-entry    fail "$marker" "$canary2026" "$canary3050" "$smuggled"
  expect no-native-compile fail "$canary2026" "$canary3050"
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
