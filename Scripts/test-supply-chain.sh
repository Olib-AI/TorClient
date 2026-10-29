#!/bin/bash
# Proves the Tor-stack supply-chain checks fail closed.
#
#   ./Scripts/test-supply-chain.sh
#
# Needs the four pinned tarballs in .build-tor/ (run
# `./Scripts/build-xcframework.sh --sources-only` once) and gpg. Works on
# copies in a temporary directory; the real cache is never modified. Exits
# non-zero if any check that should reject something accepts it.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(dirname "$SCRIPT_DIR")"
CACHE="${TORCLIENT_BUILD_DIR:-${PACKAGE_DIR}/.build-tor}"
REAL_SC="${SCRIPT_DIR}/supply-chain"

TARBALLS="zlib-1.3.2.tar.gz openssl-4.1.0.tar.gz libevent-2.1.13-stable.tar.gz tor-0.4.9.15.tar.gz"
for t in $TARBALLS; do
    [ -f "$CACHE/$t" ] || { echo "missing $CACHE/$t; run Scripts/build-xcframework.sh --sources-only first"; exit 2; }
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/torclient-sc-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0 FAIL=0
pass() { PASS=$((PASS + 1)); echo "PASS  $1"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL  $1"; }

# expect_ok / expect_reject <description> <command...>: each case runs in a
# subshell so a sourced `exit` cannot end the test run.
expect_ok()     { local d="$1"; shift; if ( "$@" ) >"$WORK/out" 2>&1; then pass "$d"; else fail "$d"; sed 's/^/      /' "$WORK/out"; fi; }
expect_reject() { local d="$1"; shift; if ( "$@" ) >"$WORK/out" 2>&1; then fail "$d (was ACCEPTED)"; sed 's/^/      /' "$WORK/out"; else pass "$d"; fi; }

# A private copy of the pinned metadata that individual cases can corrupt.
fresh_sc() {
    rm -rf "$WORK/sc"; cp -R "$REAL_SC" "$WORK/sc"
}
fresh_file() {  # <tarball> -> copy in $WORK/files (APFS clone when possible)
    mkdir -p "$WORK/files"; rm -f "$WORK/files/$1"
    cp -c "$CACHE/$1" "$WORK/files/$1" 2>/dev/null || cp "$CACHE/$1" "$WORK/files/$1"
}
# shellcheck disable=SC2034  # SC_DIR is read by the sourced verify.sh
lib() { SC_DIR="$WORK/sc"; . "$REAL_SC/verify.sh"; "$@"; }

echo "== library checks"
fresh_sc
for t in $TARBALLS; do
    fresh_file "$t"
    expect_ok "pinned, signed $t is accepted" lib sc_verify "$WORK/files/$t"
done

fresh_file zlib-1.3.2.tar.gz
printf 'x' >> "$WORK/files/zlib-1.3.2.tar.gz"
expect_reject "tarball with one appended byte is rejected" lib sc_verify "$WORK/files/zlib-1.3.2.tar.gz"
expect_reject "tampered CACHED tarball is rejected by sc_fetch (no re-download)" \
    lib sc_fetch "https://invalid.example/zlib-1.3.2.tar.gz" "$WORK/files/zlib-1.3.2.tar.gz"
if [ -f "$WORK/files/zlib-1.3.2.tar.gz" ] && [ "$(shasum -a 256 < "$WORK/files/zlib-1.3.2.tar.gz")" != "$(shasum -a 256 < "$CACHE/zlib-1.3.2.tar.gz")" ]; then
    pass "tampered cached tarball is left in place for inspection, not silently replaced"
else
    fail "tampered cached tarball was modified or removed"
fi

fresh_file openssl-4.1.0.tar.gz
cp "$WORK/files/openssl-4.1.0.tar.gz" "$WORK/files/openssl-4.1.1.tar.gz"
expect_reject "tarball that is not pinned is rejected" lib sc_verify "$WORK/files/openssl-4.1.1.tar.gz"
expect_reject "download of a tarball that is not pinned is refused" \
    lib sc_fetch "https://invalid.example/openssl-4.1.1.tar.gz" "$WORK/files/new/openssl-4.1.1.tar.gz"

fresh_sc
sed -i '' -E 's/^(libevent-2\.1\.13-stable\.tar\.gz[[:space:]]+)f/\10/' "$WORK/sc/sources.lock"
fresh_file libevent-2.1.13-stable.tar.gz
expect_reject "pin edited in sources.lock (content no longer matches) is rejected" \
    lib sc_verify "$WORK/files/libevent-2.1.13-stable.tar.gz"

fresh_sc
# Flip one character inside the base64 body of the detached signature.
awk 'NR==4 { c = substr($0, 10, 1); r = (c == "A") ? "B" : "A"; $0 = substr($0, 1, 9) r substr($0, 11) } { print }' \
    "$REAL_SC/signatures/zlib-1.3.2.tar.gz.asc" > "$WORK/sc/signatures/zlib-1.3.2.tar.gz.asc"
fresh_file zlib-1.3.2.tar.gz
expect_reject "corrupted upstream signature is rejected" lib sc_verify "$WORK/files/zlib-1.3.2.tar.gz"

fresh_sc
cp "$REAL_SC/keys/openssl.asc" "$WORK/sc/keys/zlib.asc"
expect_reject "signature checked against the wrong project's key is rejected" \
    lib sc_verify "$WORK/files/zlib-1.3.2.tar.gz"

fresh_sc
sed -i '' -E 's/^(zlib-1\.3\.2\.tar\.gz.*[[:space:]])5ED46A6721D365587791E2AA783FCD8E58BCAFBA$/\1B146647E45A7B33947AB226B2A2C87D161692D40/' "$WORK/sc/sources.lock"
expect_reject "valid signature from a key that is not pinned for this file is rejected" \
    lib sc_verify "$WORK/files/zlib-1.3.2.tar.gz"

fresh_sc
sed -i '' -E 's/^1/2/' "$WORK/sc/signatures/tor-0.4.9.15.tar.gz.sha256sum"
fresh_file tor-0.4.9.15.tar.gz
expect_reject "Tor .sha256sum altered (hash no longer matches pin or signature) is rejected" \
    lib sc_verify "$WORK/files/tor-0.4.9.15.tar.gz"

fresh_sc
sed -i '' -E 's/^(tor-0\.4\.9\.15\.tar\.gz[[:space:]]+)1/\12/' "$WORK/sc/sources.lock"
TORSHA_FAKE="$(awk '$1 == "tor-0.4.9.15.tar.gz" { print $2 }' "$WORK/sc/sources.lock")"
printf '%s  tor-0.4.9.15.tar.gz\n' "$TORSHA_FAKE" > "$WORK/sc/signatures/tor-0.4.9.15.tar.gz.sha256sum"
# Tarball rewritten to match the forged pin: hash check is bypassed by
# construction, so only the signature over the .sha256sum stands in the way.
expect_reject "forged pin + forged .sha256sum without a matching signature is rejected" \
    lib sc_verify_signature "$WORK/files/tor-0.4.9.15.tar.gz"

echo "== end to end: build-xcframework.sh --sources-only"
E2E="$WORK/e2e"; mkdir -p "$E2E"
for t in $TARBALLS; do cp -c "$CACHE/$t" "$E2E/$t" 2>/dev/null || cp "$CACHE/$t" "$E2E/$t"; done
expect_ok "build accepts the pristine pinned tarballs" \
    env TORCLIENT_BUILD_DIR="$E2E" "$SCRIPT_DIR/build-xcframework.sh" --sources-only

printf 'x' >> "$E2E/openssl-4.1.0.tar.gz"
expect_reject "build ABORTS on a tampered cached openssl tarball" \
    env TORCLIENT_BUILD_DIR="$E2E" "$SCRIPT_DIR/build-xcframework.sh" --sources-only
if grep -q 'SHA-256 mismatch for openssl-4.1.0.tar.gz' "$WORK/out" \
   && ! grep -q 'All sources verified' "$WORK/out"; then
    pass "abort names the tampered file and no later step ran"
else
    fail "abort message missing or build continued"; sed 's/^/      /' "$WORK/out"
fi
if [ ! -d "$E2E/openssl-4.1.0" ] && [ ! -d "$E2E/output" ]; then
    pass "nothing was extracted or built from the tampered tarball"
else
    fail "build directory shows extraction/build after tamper"
fi

echo ""
echo "supply-chain tests: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
