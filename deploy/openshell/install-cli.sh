#!/usr/bin/env bash
set -euo pipefail

# Pin the release and verify the downloaded asset against its release checksum.
version=v0.0.116
asset=openshell-x86_64-unknown-linux-musl.tar.gz
base="https://github.com/NVIDIA/OpenShell/releases/download/${version}"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
curl -fsSL "$base/$asset" -o "$work_dir/$asset"
curl -fsSL "$base/openshell-checksums-sha256.txt" -o "$work_dir/checksums.txt"
(cd "$work_dir" && grep "  $asset$" checksums.txt | sha256sum -c -)
tar -xzf "$work_dir/$asset" -C "$work_dir"
mkdir -p "$HOME/.local/bin"
install -m 0755 "$work_dir/openshell" "$HOME/.local/bin/openshell"
"$HOME/.local/bin/openshell" --version
