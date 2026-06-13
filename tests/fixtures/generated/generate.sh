#!/usr/bin/env bash
# Regenerates the frozen ES256K / XC20P vectors in this directory.
# The generator refuses to overwrite existing files unless --force is given —
# the vectors are regression pins, not derived artifacts (see PROVENANCE.md).
set -euo pipefail
cd "$(dirname "$0")/../../.."
exec dotnet run --project tasks/generate-jose-vectors/GenerateJoseVectors.csproj -- "$(pwd)/tests/fixtures/generated" "$@"
