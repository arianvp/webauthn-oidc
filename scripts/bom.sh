#!/usr/bin/env bash
set -euo pipefail

nix path-info . --derivation --json | jq -r '.[] | .references | .[]' | xargs nix path-info --recursive --json | jq .
