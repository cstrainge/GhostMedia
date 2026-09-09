#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
scratch_path="$repo_root/.build"
dist_path="$repo_root/dist"
architecture="$(uname -m)"

case "$architecture" in
    arm64 | x86_64) ;;
    *)
        echo "unsupported macOS architecture: $architecture" >&2
        exit 1
        ;;
esac

mkdir -p "$scratch_path/module-cache" "$dist_path"
export CLANG_MODULE_CACHE_PATH="$scratch_path/module-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$scratch_path/module-cache"

xcrun swift test --package-path "$repo_root" --scratch-path "$scratch_path"
xcrun swift build --package-path "$repo_root" --scratch-path "$scratch_path" --product GhostMediaAppleHarness
xcrun swift build --package-path "$repo_root" --scratch-path "$scratch_path" --product GhostMediaMac
xcrun swift build --package-path "$repo_root" --scratch-path "$scratch_path" --product GhostMediaWinControlProbe
xcrun swift build --package-path "$repo_root" --scratch-path "$scratch_path" --product GhostMediaRuntimeTests

bin_path="$(xcrun swift build --package-path "$repo_root" --scratch-path "$scratch_path" --show-bin-path)"
stage_path="$(mktemp -d "$dist_path/.macos-stage.XXXXXX")"
trap 'rm -rf "$stage_path"' EXIT

copy_product() {
    local source_name="$1"
    local destination_name="$2"
    cp "$bin_path/$source_name" "$stage_path/$destination_name"
}

copy_product GhostMediaAppleHarness "GhostMediaAppleHarness-macos-$architecture"
copy_product GhostMediaWinControlProbe "GhostMediaWinControlProbe-macos-$architecture"
copy_product GhostMediaRuntimeTests "GhostMediaRuntimeTests-macos-$architecture"
copy_product GhostMediaMac "GhostMediaMac-macos-$architecture"

for artifact in "$stage_path"/*; do
    mv "$artifact" "$dist_path/$(basename "$artifact")"
done

echo "macOS build artifacts published to $dist_path"
