#!/bin/bash
# Supply-chain checks for the Tor stack tarballs. Sourced by
# Scripts/build-xcframework.sh and Scripts/test-supply-chain.sh; bash 3.2 safe.
#
# Every function returns non-zero (and prints why) on any doubt. Callers run
# under `set -e`, so a failed check aborts the build: fail closed.
#
#   sc_fetch <url> <dest>   download (or reuse a cached copy) and verify it
#   sc_verify <file>        pinned SHA-256 + upstream OpenPGP signature
#   sc_verify_hash <file>   pinned SHA-256 only (used right before extraction)
#
# Overridable for tests: SC_DIR (directory holding sources.lock, keys/,
# signatures/). TORCLIENT_ALLOW_UNSIGNED=1 skips ONLY the signature check when
# gpg is not installed; the SHA-256 pin is never skippable.

SC_DIR="${SC_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

sc_err() { echo "SUPPLY-CHAIN ERROR: $*" >&2; }

# sc_lock_field <tarball-name> <field-index 2..5>
sc_lock_field() {
    awk -v f="$1" -v i="$2" '
        $0 ~ /^[[:space:]]*(#|$)/ { next }
        $1 == f { print $i; found = 1; exit }
        END { if (!found) exit 1 }' "$SC_DIR/sources.lock"
}

sc_sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

# sc_verify_hash <file> [pinned-name]   (pinned-name defaults to basename)
sc_verify_hash() {
    local file="$1" name="${2:-$(basename "$1")}" expected actual
    expected="$(sc_lock_field "$name" 2)" || { sc_err "$name is not pinned in $SC_DIR/sources.lock"; return 1; }
    if ! printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$'; then
        sc_err "malformed SHA-256 for $name in sources.lock"; return 1
    fi
    [ -f "$file" ] || { sc_err "$file does not exist"; return 1; }
    actual="$(sc_sha256 "$file")"
    if [ "$actual" != "$expected" ]; then
        sc_err "SHA-256 mismatch for $name"
        sc_err "  expected $expected (sources.lock)"
        sc_err "  actual   $actual ($file)"
        sc_err "  The file was tampered with or corrupted. Investigate, then delete it; it is never replaced automatically."
        return 1
    fi
    echo "  sha256 OK    $name"
}

sc_verify_signature() {
    local file="$1" name keyring sig trusted signed_obj gpg_home status fprs fpr listed ok=0
    name="$(basename "$file")"
    keyring="$(sc_lock_field "$name" 3)" || { sc_err "no keyring pinned for $name"; return 1; }
    sig="$(sc_lock_field "$name" 4)"      || { sc_err "no signature pinned for $name"; return 1; }
    trusted="$(sc_lock_field "$name" 5)"  || { sc_err "no trusted fingerprints pinned for $name"; return 1; }

    if ! command -v gpg >/dev/null 2>&1; then
        if [ "${TORCLIENT_ALLOW_UNSIGNED:-0}" = 1 ]; then
            echo "  signature SKIPPED for $name (gpg missing, TORCLIENT_ALLOW_UNSIGNED=1); SHA-256 pin still enforced"
            return 0
        fi
        sc_err "gpg not found; install it (brew install gnupg) or set TORCLIENT_ALLOW_UNSIGNED=1 to rely on the SHA-256 pin alone"
        return 1
    fi

    case "$sig" in
        *.sha256sum.asc)
            # Tor signs a checksum file; it must name exactly the pinned hash.
            signed_obj="$SC_DIR/signatures/${sig%.asc}"
            [ -f "$signed_obj" ] || { sc_err "missing $signed_obj"; return 1; }
            listed="$(awk -v f="$name" '{ n = $2; sub(/^\*/, "", n); if (n == f) print $1 }' "$signed_obj")"
            if [ "$listed" != "$(sc_lock_field "$name" 2)" ]; then
                sc_err "$(basename "$signed_obj") lists '${listed:-nothing}' for $name; sources.lock pins $(sc_lock_field "$name" 2)"
                return 1
            fi
            ;;
        *) signed_obj="$file" ;;
    esac
    [ -f "$SC_DIR/signatures/$sig" ] || { sc_err "missing signature $SC_DIR/signatures/$sig"; return 1; }
    [ -f "$SC_DIR/keys/$keyring" ]   || { sc_err "missing keyring $SC_DIR/keys/$keyring"; return 1; }

    # Throwaway keyring holding ONLY the pinned keys: the user's keyring and
    # keyservers are never consulted.
    gpg_home="$(mktemp -d "${TMPDIR:-/tmp}/torclient-gpg.XXXXXX")"
    chmod 700 "$gpg_home"
    if ! gpg --homedir "$gpg_home" --batch --quiet --import "$SC_DIR/keys/$keyring" >/dev/null 2>&1; then
        rm -rf "$gpg_home"; sc_err "cannot import keys/$keyring"; return 1
    fi
    status="$(gpg --homedir "$gpg_home" --batch --status-fd 1 --verify \
        "$SC_DIR/signatures/$sig" "$signed_obj" 2>/dev/null || true)"
    gpgconf --homedir "$gpg_home" --kill all >/dev/null 2>&1 || true
    rm -rf "$gpg_home"

    if printf '%s\n' "$status" | grep -q '^\[GNUPG:\] BADSIG'; then
        sc_err "BAD signature on $(basename "$signed_obj")"; return 1
    fi
    # VALIDSIG <sig-fpr> <date> <ts> <exp> <ver> <res> <pk-algo> <hash-algo> <class> <primary-fpr>
    # A signature made by a key that has since expired is still VALIDSIG (with
    # EXPKEYSIG): it was made while the key was valid, and the hash pin fixes
    # the content regardless.
    fprs="$(printf '%s\n' "$status" | awk '$2 == "VALIDSIG" { print $NF }')"
    for fpr in $fprs; do
        case ",$trusted," in
            *",$fpr,"*) ok=1; echo "  signature OK $(basename "$signed_obj") (primary key $fpr)" ;;
        esac
    done
    if [ "$ok" != 1 ]; then
        sc_err "no valid signature from a pinned key on $(basename "$signed_obj") (valid signers: ${fprs:-none})"
        return 1
    fi
}

sc_verify() {
    sc_verify_hash "$1" && sc_verify_signature "$1"
}

sc_fetch() {
    local url="$1" dest="$2" name got
    name="$(basename "$dest")"
    # Refuse unpinned files before touching the network.
    sc_lock_field "$name" 2 >/dev/null || {
        sc_err "$name is not pinned in sources.lock; refusing to download it"; return 1; }
    if [ -f "$dest" ]; then
        echo "  cached       $name"
    else
        echo "  downloading  $name"
        rm -f "$dest.part"
        curl -fL --proto '=https' --tlsv1.2 --retry 3 --progress-bar -o "$dest.part" "$url" || {
            rm -f "$dest.part"; sc_err "download failed: $url"; return 1; }
        # Verify before the file gets its final name, so a bad download can
        # never later be mistaken for a good cached copy.
        if ! sc_verify_hash "$dest.part" "$name" >/dev/null 2>&1; then
            got="$(sc_sha256 "$dest.part")"; rm -f "$dest.part"
            sc_err "downloaded $name has SHA-256 $got, not the pinned value"; return 1
        fi
        mv "$dest.part" "$dest"
    fi
    sc_verify "$dest"
}
