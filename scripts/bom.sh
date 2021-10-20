#!/usr/bin/env bash
nix path-info . --derivation --json | jq -r '.[] | .references | .[]' | xargs nix path-info --recursive --json | jq .
