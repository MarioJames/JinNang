#!/usr/bin/env bash
set -euo pipefail

# Download a published binary; no compiler, root access, or vault changes needed.
main() {
    local repo='https://github.com/MarioJames/JinNang'
    local version="${JINNANG_VERSION:-latest}"
    local install_dir="${JINNANG_INSTALL_DIR:-$HOME/.local/bin}"
    local arch asset latest_url base

    fail() { printf 'jinnang install: %s\n' "$*" >&2; exit 1; }
    [[ "$(uname -s)" == Linux ]] || fail 'only Linux is supported'
    case "$(uname -m)" in
        x86_64) arch=x86_64 ;;
        aarch64|arm64) arch=aarch64 ;;
        *) fail 'supported architectures: x86_64, aarch64' ;;
    esac
    for tool in curl tar sha256sum awk mktemp mkdir cp chmod mv rm; do
        command -v "$tool" >/dev/null || fail "required command not found: $tool"
    done
    [[ "$install_dir" == /* ]] || fail 'JINNANG_INSTALL_DIR must be an absolute path'
    [[ ! -d "$install_dir/jinnang" ]] || fail "$install_dir/jinnang is a directory"

    if [[ "$version" == latest ]]; then
        # Resolve once so an intervening release cannot mix checksums and binaries.
        latest_url=$(curl --fail --silent --show-error --location --head \
            --output /dev/null --write-out '%{url_effective}' "$repo/releases/latest")
        case "$latest_url" in
            "$repo/releases/tag/"*) version=${latest_url#"$repo/releases/tag/"} ;;
            *) fail 'could not resolve the latest release' ;;
        esac
    fi
    [[ "$version" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]] || fail 'invalid release tag'
    base="$repo/releases/download/$version"
    asset="jinnang-$arch-unknown-linux-musl.tar.gz"

    # Global variables let the EXIT trap clean up after any download/check failure.
    tmp_dir=$(mktemp -d)
    staged=''
    trap 'rm -rf -- "$tmp_dir"; if [[ -n "$staged" ]]; then rm -f -- "$staged"; fi' EXIT
    curl --fail --silent --show-error --location "$base/SHA256SUMS" --output "$tmp_dir/SHA256SUMS"
    curl --fail --silent --show-error --location "$base/$asset" --output "$tmp_dir/$asset"
    awk -v file="$asset" '$2 == file { print }' "$tmp_dir/SHA256SUMS" > "$tmp_dir/checksum"
    [[ $(awk 'END { print NR }' "$tmp_dir/checksum") == 1 ]] || fail 'missing or duplicate checksum'
    (cd "$tmp_dir" && sha256sum --check --status checksum) || fail 'SHA-256 verification failed'
    tar -xzf "$tmp_dir/$asset" -C "$tmp_dir" jinnang
    [[ -f "$tmp_dir/jinnang" && ! -L "$tmp_dir/jinnang" ]] || fail 'archive must contain a regular jinnang binary'

    mkdir -p -- "$install_dir"
    staged=$(mktemp "$install_dir/.jinnang.XXXXXXXX")
    cp -- "$tmp_dir/jinnang" "$staged"
    chmod 755 "$staged"
    "$staged" --version
    mv -fT -- "$staged" "$install_dir/jinnang"
    staged=''
    printf 'Installed %s to %s/jinnang\n' "$version" "$install_dir"
    case ":$PATH:" in
        *":$install_dir:"*) ;;
        *) printf "Add this to your shell profile, then reopen your terminal:\n  export PATH=%q:\"\$PATH\"\n" "$install_dir" ;;
    esac
}

main "$@"
