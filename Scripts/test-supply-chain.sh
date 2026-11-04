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

TARBALLS="zlib-1.3.2.tar.gz openssl-4.1.0.tar.gz libevent-2.1.13-stable.tar.gz tor-0.4.9.16.tar.gz"
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

# A first hex digit that differs from the pinned Tor hash. Derived, because a
# fixed `s/^1/2/` changes nothing once a new release's hash starts with another
# digit: the case then hands the checks a pristine file and fails as "ACCEPTED".
TOR_OTHER_DIGIT="$(awk '$1 == "tor-0.4.9.16.tar.gz" { print (substr($2, 1, 1) == "0") ? "1" : "0" }' "$REAL_SC/sources.lock")"

fresh_sc
sed -i '' -E "s/^./$TOR_OTHER_DIGIT/" "$WORK/sc/signatures/tor-0.4.9.16.tar.gz.sha256sum"
fresh_file tor-0.4.9.16.tar.gz
expect_reject "Tor .sha256sum altered (hash no longer matches pin or signature) is rejected" \
    lib sc_verify "$WORK/files/tor-0.4.9.16.tar.gz"

fresh_sc
sed -i '' -E "s/^(tor-0\.4\.9\.16\.tar\.gz[[:space:]]+)./\1$TOR_OTHER_DIGIT/" "$WORK/sc/sources.lock"
TORSHA_FAKE="$(awk '$1 == "tor-0.4.9.16.tar.gz" { print $2 }' "$WORK/sc/sources.lock")"
printf '%s  tor-0.4.9.16.tar.gz\n' "$TORSHA_FAKE" > "$WORK/sc/signatures/tor-0.4.9.16.tar.gz.sha256sum"
# Tarball rewritten to match the forged pin: hash check is bypassed by
# construction, so only the signature over the .sha256sum stands in the way.
expect_reject "forged pin + forged .sha256sum without a matching signature is rejected" \
    lib sc_verify_signature "$WORK/files/tor-0.4.9.16.tar.gz"

echo "== signature made after the signing key expired"
# Real case: David Goulet signed 0.4.9.16 after our pinned copy of his key
# expired, and Alexander Faeroy signed it inside his key's life.
AHF_FPR=1C1BC007A9F607AA8152C040BEA7B180B1491921
DGOULET_FPR=B74417EDDF22AC9F9E90F49142E86A2A11F48D36
TOR_TGZ=tor-0.4.9.16.tar.gz
trust_only() {  # <fingerprint>: pin $TOR_TGZ to this signer alone
    fresh_sc
    awk -v f="$TOR_TGZ" -v k="$1" '$1 == f { $5 = k } { print }' "$REAL_SC/sources.lock" > "$WORK/sc/sources.lock"
}
fresh_file "$TOR_TGZ"
trust_only "$AHF_FPR"
expect_ok "Tor tarball passes on the signature made while the signer's key was valid" \
    lib sc_verify "$WORK/files/$TOR_TGZ"
trust_only "$DGOULET_FPR"
expect_reject "Tor tarball with only the signature made after the key expired is rejected" \
    lib sc_verify "$WORK/files/$TOR_TGZ"
if grep -q 'made after that key expired' "$WORK/out"; then
    pass "that rejection says the signature came after the key expired"
else
    fail "that rejection does not name the reason"; sed 's/^/      /' "$WORK/out"
fi

# Synthetic keys, so both sides of the boundary are covered for a primary key
# and for a signing subkey. gpg will not sign with an expired key, so the
# pinned copy is exported while the key expires, then the expiry is lifted in
# the signer's own keyring and the late signature made with that. This is the
# shape of the real case: the pinned copy has an expiry that the signer later
# extended.
GEN="$WORK/gen"; mkdir -p "$GEN"; chmod 700 "$GEN"
T0=1600000000 T_EARLY=$((T0 + 86400)) T_EXP=$((T0 + 10 * 86400)) T_LATE=$((T0 + 20 * 86400))
kgpg() { local at="$1"; shift; gpg --homedir "$GEN" --batch --yes --quiet --pinentry-mode loopback --passphrase '' \
    --faked-system-time "$at!" --ignore-time-conflict "$@" 2>/dev/null; }
echo "payload" > "$WORK/payload.tar.gz"
PAYLOAD_SHA="$(shasum -a 256 "$WORK/payload.tar.gz" | awk '{print $1}')"
new_key() {  # <uid> <primary expiry "seconds=N" or "never">; primary fingerprint lands in $NEWFPR
    kgpg "$T0" --quick-generate-key "$1" ed25519 cert "$2"
    NEWFPR="$(gpg --homedir "$GEN" --batch --with-colons --fixed-list-mode --list-keys "$1" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')"
}
synthetic_sc() {  # <pubkey file> <signature file> <primary fpr>
    fresh_sc
    cp "$1" "$WORK/sc/keys/synthetic.asc"
    cp "$2" "$WORK/sc/signatures/payload.tar.gz.asc"
    printf 'payload.tar.gz %s synthetic.asc payload.tar.gz.asc %s\n' "$PAYLOAD_SHA" "$3" >> "$WORK/sc/sources.lock"
}

# Primary key and signing subkey both expire.
new_key "primary@test.invalid" "seconds=$((T_EXP - T0))"
PRIMARY_FPR="$NEWFPR"
kgpg "$T0" --quick-add-key "$PRIMARY_FPR" ed25519 sign "seconds=$((T_EXP - T0))"
kgpg "$T0" --armor --export "$PRIMARY_FPR" > "$WORK/primary-pinned.asc"
SIGNING_SUB="$(gpg --homedir "$GEN" --batch --with-colons --fixed-list-mode --list-keys "$PRIMARY_FPR" 2>/dev/null | awk -F: '$1 == "sub" { s = 1; next } $1 == "fpr" && s { print $10; exit }')"
kgpg "$T_EARLY" --armor --detach-sign --local-user "${SIGNING_SUB}!" -o "$WORK/in-life.asc" "$WORK/payload.tar.gz"
kgpg "$((T0 + 3600))" --quick-set-expire "$PRIMARY_FPR" never
kgpg "$((T0 + 3600))" --quick-set-expire "$PRIMARY_FPR" never '*'
kgpg "$T_LATE" --armor --detach-sign --local-user "${SIGNING_SUB}!" -o "$WORK/after-life.asc" "$WORK/payload.tar.gz"
synthetic_sc "$WORK/primary-pinned.asc" "$WORK/in-life.asc" "$PRIMARY_FPR"
expect_ok "signature from before the key expired still counts, though the key has expired now" \
    lib sc_verify_signature "$WORK/payload.tar.gz"
synthetic_sc "$WORK/primary-pinned.asc" "$WORK/after-life.asc" "$PRIMARY_FPR"
expect_reject "signature made after the pinned key expired is rejected" \
    lib sc_verify_signature "$WORK/payload.tar.gz"

# Only the signing subkey expires; the primary key never does.
new_key "subkey@test.invalid" never
SUBONLY_FPR="$NEWFPR"
kgpg "$T0" --quick-add-key "$SUBONLY_FPR" ed25519 sign "seconds=$((T_EXP - T0))"
kgpg "$T0" --armor --export "$SUBONLY_FPR" > "$WORK/subonly-pinned.asc"
SUBONLY_SUB="$(gpg --homedir "$GEN" --batch --with-colons --fixed-list-mode --list-keys "$SUBONLY_FPR" 2>/dev/null | awk -F: '$1 == "sub" { s = 1; next } $1 == "fpr" && s { print $10; exit }')"
kgpg "$T_EARLY" --armor --detach-sign --local-user "${SUBONLY_SUB}!" -o "$WORK/sub-in-life.asc" "$WORK/payload.tar.gz"
kgpg "$((T0 + 3600))" --quick-set-expire "$SUBONLY_FPR" never '*'
kgpg "$T_LATE" --armor --detach-sign --local-user "${SUBONLY_SUB}!" -o "$WORK/sub-after-life.asc" "$WORK/payload.tar.gz"
synthetic_sc "$WORK/subonly-pinned.asc" "$WORK/sub-in-life.asc" "$SUBONLY_FPR"
expect_ok "signature from before the signing subkey expired counts" \
    lib sc_verify_signature "$WORK/payload.tar.gz"
synthetic_sc "$WORK/subonly-pinned.asc" "$WORK/sub-after-life.asc" "$SUBONLY_FPR"
expect_reject "signature made after only the signing subkey expired is rejected" \
    lib sc_verify_signature "$WORK/payload.tar.gz"
gpgconf --homedir "$GEN" --kill all >/dev/null 2>&1 || true

# Fail closed when a date cannot be read. A gpg wrapper changes only the output
# named by $STUB_MODE; the signature that it reports is otherwise a good one.
REAL_GPG="$(command -v gpg)"
STUB="$WORK/stub"; mkdir -p "$STUB"
{
    echo '#!/bin/bash'
    echo 'case " $* " in'
    echo '  *" --list-keys "*)'
    echo '    case "$STUB_MODE" in'
    echo "      nolist) exit 0 ;;"
    echo "      badexp) exec \"$REAL_GPG\" \"\$@\" | awk -F: -v OFS=: '\$1 == \"pub\" || \$1 == \"sub\" { \$7 = \"soon\" } { print }' ;;"
    echo '    esac ;;'
    echo '  *" --verify "*)'
    echo '    case "$STUB_MODE" in'
    echo "      badts) \"$REAL_GPG\" \"\$@\" | awk '\$2 == \"VALIDSIG\" { \$5 = \"yesterday\" } { print }'; exit 0 ;;"
    echo '    esac ;;'
    echo 'esac'
    echo "exec \"$REAL_GPG\" \"\$@\""
} > "$STUB/gpg"
chmod +x "$STUB/gpg"
stubbed() { local mode="$1"; shift; PATH="$STUB:$PATH" STUB_MODE="$mode" lib "$@"; }
trust_only "$AHF_FPR"
expect_ok "a gpg wrapper that changes nothing still passes (the cases below test what they say)" \
    stubbed none sc_verify_signature "$WORK/files/$TOR_TGZ"
expect_reject "key expiry that cannot be listed is rejected" \
    stubbed nolist sc_verify_signature "$WORK/files/$TOR_TGZ"
expect_reject "key expiry that is not a number is rejected" \
    stubbed badexp sc_verify_signature "$WORK/files/$TOR_TGZ"
expect_reject "signature time that is not a number is rejected" \
    stubbed badts sc_verify_signature "$WORK/files/$TOR_TGZ"

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
