#!/bin/bash
# build-xcframework.sh - Build Tor and dependencies from source for iOS
#
# Builds zlib, OpenSSL, libevent, and Tor as static libraries, then packages
# them into a single TorClientC.xcframework for use with Swift Package Manager.
#
# Usage:
#   ./Scripts/build-xcframework.sh                 # device arm64 + arm64e, simulator arm64
#   ./Scripts/build-xcframework.sh --clean         # clean and rebuild from scratch
#   ./Scripts/build-xcframework.sh --sources-only  # download + verify tarballs, then stop
#
# Slices:
#   ios-arm64_arm64e            one fat static library: arm64 (A11-A13) and
#                               arm64e (pointer authentication, A12+ when the
#                               app itself is built arm64e)
#   ios-arm64_x86_64-simulator  arm64 + an x86_64 link stub that aborts at runtime
#
# Supply chain: every tarball is pinned by SHA-256 and checked against its
# upstream OpenPGP signature (Scripts/supply-chain/) before it is extracted,
# cached copies included. Any mismatch aborts the build.
#
# Hardening (all slices, all four libraries): -ftrivial-auto-var-init=zero,
# typed allocator support (-ftyped-memory-operations), Apple's security
# warning set (Xcode's ENABLE_SECURITY_COMPILER_WARNINGS plus -Wshadow
# -Wempty-body). Warnings are counted per library and listed in
# .build-tor/logs/warnings-summary.txt. -fbounds-safety is NOT used: it
# requires source annotations upstream C does not have.
#
# Reproducibility: fixed SOURCE_DATE_EPOCH, ZERO_AR_DATE, -ffile-prefix-map
# and neutral --prefix values, so no build-machine path ends up in the binary.
# The SHA-256 of every slice is written to TorClientC.xcframework.sha256 next
# to the xcframework; StealthOS's Scripts/verify-release.sh checks it.
#
# Env:
#   TORCLIENT_BUILD_DIR   build directory (default: <package>/.build-tor)
#   TORCLIENT_OUTPUT_DIR  where the xcframework + .sha256 go (default: <package>);
#                         build twice into two dirs and diff the .sha256 files
#                         to check reproducibility
#
# Requirements:
#   - macOS with Xcode (command line tools)
#   - Homebrew packages: autoconf automake libtool pkg-config gnupg
#   - ~3GB disk space for build artifacts
#   - ~15-45 minutes depending on CPU
#
# Output:
#   TorClientC.xcframework/         - Ready-to-use XCFramework
#   TorClientC.xcframework.sha256   - Per-slice checksums of this build

set -e
set -o pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

ZLIB_VERSION="1.3.2"
OPENSSL_VERSION="4.1.0"
LIBEVENT_VERSION="2.1.13-stable"
TOR_VERSION="0.4.9.15"
MIN_IOS="18.0"

ZLIB_URL="https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
LIBEVENT_URL="https://github.com/libevent/libevent/releases/download/release-${LIBEVENT_VERSION}/libevent-${LIBEVENT_VERSION}.tar.gz"
TOR_URL="https://dist.torproject.org/tor-${TOR_VERSION}.tar.gz"

# Resolve paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(dirname "$SCRIPT_DIR")"
PATCH_DIR="${SCRIPT_DIR}/patches"
BUILD_DIR="${TORCLIENT_BUILD_DIR:-${PACKAGE_DIR}/.build-tor}"
OUTPUT_DIR="${BUILD_DIR}/output"
LOG_DIR="${BUILD_DIR}/logs"
XCFRAMEWORK_DIR="${TORCLIENT_OUTPUT_DIR:-$PACKAGE_DIR}/TorClientC.xcframework"
CHECKSUM_FILE="${TORCLIENT_OUTPUT_DIR:-$PACKAGE_DIR}/TorClientC.xcframework.sha256"

# shellcheck source=supply-chain/verify.sh
. "${SCRIPT_DIR}/supply-chain/verify.sh"

# Build matrix: <sdk>:<arch>:<output subdir>
SLICES="iphoneos:arm64:arm64-ios iphoneos:arm64e:arm64e-ios iphonesimulator:arm64:arm64-sim"

# Compiler hardening applied to every C file of every library.
#   -ftrivial-auto-var-init=zero  Xcode CLANG_ENABLE_STACK_ZERO_INIT
#   -ftyped-memory-operations     Xcode CLANG_ENABLE_C_TYPED_ALLOCATOR_SUPPORT
#                                 (malloc -> malloc_type_malloc, iOS 17+)
HARDEN_CFLAGS="-ftrivial-auto-var-init=zero -ftyped-memory-operations"
# Xcode ENABLE_SECURITY_COMPILER_WARNINGS (Clang.xcspec) + GCC_WARN_SHADOW +
# CLANG_WARN_EMPTY_BODY. Diagnostics only; counted, never fatal for upstream.
SECURITY_WARNINGS="-Wbuiltin-memcpy-chk-size -Wformat-nonliteral -Warray-bounds"
SECURITY_WARNINGS="$SECURITY_WARNINGS -Warray-bounds-pointer-arithmetic -Wsuspicious-memaccess"
SECURITY_WARNINGS="$SECURITY_WARNINGS -Wsizeof-array-div -Wsizeof-pointer-div -Wreturn-stack-address"
SECURITY_WARNINGS="$SECURITY_WARNINGS -Wshadow -Wempty-body"
# Reproducibility: strip the build directory from __FILE__ / debug info.
REPRO_CFLAGS="-ffile-prefix-map=${BUILD_DIR}=/torclient-build"
COMMON_CFLAGS="$HARDEN_CFLAGS $SECURITY_WARNINGS $REPRO_CFLAGS"

# Deterministic archives and build dates (Tor 0.4.9.15 release day).
export ZERO_AR_DATE=1
export SOURCE_DATE_EPOCH=1793232000

# Auto-detect toolchain paths
IOS_SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
SIM_SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"
CC="$(xcrun --find clang)"
AR="$(xcrun --find ar)"
RANLIB="$(xcrun --find ranlib)"
LD="$(xcrun --find ld)"
JOBS="$(sysctl -n hw.ncpu)"

# =============================================================================
# PREREQUISITES CHECK
# =============================================================================

check_prerequisites() {
    local missing=0

    if ! command -v xcodebuild &>/dev/null; then
        echo "ERROR: Xcode command line tools not found"
        echo "  Install with: xcode-select --install"
        missing=1
    fi

    for tool in autoconf automake pkg-config; do
        if ! command -v "$tool" &>/dev/null; then
            echo "ERROR: $tool not found"
            echo "  Install with: brew install $tool"
            missing=1
        fi
    done

    if ! command -v gpg &>/dev/null && [ "${TORCLIENT_ALLOW_UNSIGNED:-0}" != 1 ]; then
        echo "ERROR: gpg not found (needed to verify upstream release signatures)"
        echo "  Install with: brew install gnupg"
        echo "  (or set TORCLIENT_ALLOW_UNSIGNED=1 to rely on the SHA-256 pins alone)"
        missing=1
    fi

    if ! command -v libtoolize &>/dev/null && ! command -v glibtoolize &>/dev/null; then
        echo "ERROR: libtool not found"
        echo "  Install with: brew install libtool"
        missing=1
    fi

    if [ ! -d "$IOS_SDK" ]; then
        echo "ERROR: iOS SDK not found at: $IOS_SDK"
        missing=1
    fi

    if [ ! -d "$SIM_SDK" ]; then
        echo "ERROR: iOS Simulator SDK not found at: $SIM_SDK"
        missing=1
    fi

    if [ $missing -eq 1 ]; then
        echo ""
        echo "Install all requirements with:"
        echo "  xcode-select --install"
        echo "  brew install autoconf automake libtool pkg-config gnupg"
        exit 1
    fi
}

# =============================================================================
# CROSS-COMPILE CACHE VARIABLES
# =============================================================================
# When cross-compiling for iOS, configure scripts try to run test programs
# to detect platform features. These fail because iOS binaries can't run on
# macOS. We pre-set the results to skip these tests.

setup_cross_compile_cache() {
    # libevent feature detection
    export ac_cv_func_clock_gettime=yes
    export ac_cv_func_epoll_create=no  # Linux only
    export ac_cv_func_epoll_ctl=no
    export ac_cv_func_eventfd=no
    export ac_cv_func_kqueue=yes       # BSD/macOS/iOS
    export ac_cv_func_poll=yes
    export ac_cv_func_select=yes
    export ac_cv_func_sigaction=yes
    export ac_cv_func_signal=yes
    export ac_cv_func_strlcpy=yes
    export ac_cv_func_strtok_r=yes
    export ac_cv_func_vasprintf=yes
    export ac_cv_func_getaddrinfo=yes
    export ac_cv_func_getnameinfo=yes
    export ac_cv_func_getprotobynumber=yes
    export ac_cv_func_getservbyname=yes
    export ac_cv_func_gettimeofday=yes
    export ac_cv_func_inet_ntop=yes
    export ac_cv_func_inet_pton=yes
    export ac_cv_func_mmap=yes
    export ac_cv_func_pipe=yes
    export ac_cv_func_pipe2=no         # Linux only
    export ac_cv_func_sendfile=no
    export ac_cv_func_splice=no        # Linux only
    export ac_cv_func_usleep=yes
    export ac_cv_func_nanosleep=yes
    export ac_cv_func_accept4=no       # Linux only
    export ac_cv_func_arc4random=yes
    export ac_cv_func_arc4random_buf=yes
    export ac_cv_func_fcntl=yes
    export ac_cv_func_getegid=yes
    export ac_cv_func_geteuid=yes
    export ac_cv_func_issetugid=yes
    export ac_cv_func_mach_absolute_time=yes
    export ac_cv_func_setenv=yes
    export ac_cv_func_setrlimit=yes
    export ac_cv_func_sysctl=yes
    export ac_cv_func_timerfd_create=no
    export ac_cv_func_umask=yes
    export ac_cv_func_unsetenv=yes

    # Tor feature detection
    export ac_cv_func_getentropy=no          # iOS getentropy behaves differently (per iCepa research)
    export ac_cv_func_mprotect=yes
    export ac_cv_func_mlockall=yes
    export ac_cv_func_malloc=yes
    export ac_cv_func_realloc=yes
    export ac_cv_func_strlcat=yes
    export ac_cv_func_explicit_bzero=no      # iOS SDK doesn't declare properly; uses memset_s fallback
    export ac_cv_func_timingsafe_memcmp=no   # iOS has timingsafe_bcmp, not timingsafe_memcmp
    export tor_cv_cflags__fstack_protector_all=no
    export tor_cv_cflags__Wstack_protector=no
    export tor_cv_cflags__fPIE=yes
    export tor_cv_ldflags__pie=yes
    export tor_cv_twos_complement=yes
    export tor_cv_sign_extend=yes
    export tor_cv_time_t_signed=yes
    export tor_cv_null_is_zero=yes
    export tor_cv_unaligned_ok=yes
}

# =============================================================================
# LOGGING
# =============================================================================

log()     { echo "[$(date '+%H:%M:%S')] $1"; }
log_ok()  { echo "[$(date '+%H:%M:%S')] OK: $1"; }
log_err() { echo "[$(date '+%H:%M:%S')] ERROR: $1" >&2; }
step()    { echo ""; echo "=== [$1/$TOTAL_STEPS] $2 ==="; }

# =============================================================================
# DOWNLOAD
# =============================================================================

# Extract a tarball only after re-checking its pinned SHA-256: the copy on
# disk is what gets built, whatever happened since the download step.
extract_verified() {
    local tarball="$1"
    sc_verify_hash "$tarball" >/dev/null || exit 1
    tar xzf "$tarball"
}

# Run a build command with its full output in a per-library log (warnings are
# counted from these logs). On failure, show the tail and abort.
run_logged() {
    local logfile="$1"; shift
    if ! "$@" >>"$logfile" 2>&1; then
        log_err "command failed: $* (log: $logfile)"
        tail -40 "$logfile" >&2
        exit 1
    fi
}

# =============================================================================
# GET PLATFORM-SPECIFIC FLAGS
# =============================================================================

get_platform_flags() {
    local sdk_type="$1"  # iphoneos or iphonesimulator
    local sdk_path min_flag
    if [ "$sdk_type" = "iphoneos" ]; then
        sdk_path="$IOS_SDK"
        min_flag="-mios-version-min"
    else
        sdk_path="$SIM_SDK"
        min_flag="-mios-simulator-version-min"
    fi
    echo "$sdk_path" "$min_flag"
}

# =============================================================================
# BUILD CACHE STAMPS
# =============================================================================
# A cached library is reused only if it was built from the same versions,
# flags, toolchain and inputs. Anything else (e.g. adding a hardening flag)
# rebuilds it, so a stale non-hardened object can never be repackaged.

toolchain_id() {
    xcrun clang --version | head -1
    xcrun --sdk iphoneos --show-sdk-build-version
    xcrun --sdk iphonesimulator --show-sdk-build-version
}

# build_stamp <component> <version> <arch> [extra inputs...]
build_stamp() {
    { printf '%s\n' "stamp-v2" "$@" "$COMMON_CFLAGS" "$MIN_IOS"; toolchain_id; } | shasum -a 256 | cut -c1-64
}

is_built() {  # <out-dir> <stamp> <artifact>
    [ -f "$1/$3" ] && [ "$(cat "$1/.stamp" 2>/dev/null)" = "$2" ]
}

# =============================================================================
# BUILD: ZLIB
# =============================================================================
# zlib's configure tries to run test binaries, which fails during
# cross-compilation. We compile the source files directly instead.

build_zlib() {
    local sdk_type="$1" arch="$2" subdir="$3"
    local out="${OUTPUT_DIR}/zlib/${subdir}"
    local stamp; stamp="$(build_stamp zlib "$ZLIB_VERSION" "$arch" "$sdk_type")"
    local logfile="${LOG_DIR}/zlib-${subdir}.log"

    if is_built "$out" "$stamp" lib/libz.a; then
        log "zlib ${subdir}: already built"
        return
    fi
    rm -rf "$out"; : > "$logfile"

    log "Building zlib for ${subdir}..."

    read -r sdk_path min_flag <<< "$(get_platform_flags "$sdk_type")"
    local cflags="-arch $arch -isysroot $sdk_path ${min_flag}=${MIN_IOS} -O2 -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN $COMMON_CFLAGS"

    rm -rf "zlib-${ZLIB_VERSION}"
    extract_verified "zlib-${ZLIB_VERSION}.tar.gz"
    cd "zlib-${ZLIB_VERSION}"

    mkdir -p "$out/lib" "$out/include"

    local srcs="adler32.c crc32.c deflate.c infback.c inffast.c inflate.c inftrees.c trees.c zutil.c compress.c uncompr.c gzclose.c gzlib.c gzread.c gzwrite.c"
    for src in $srcs; do
        # shellcheck disable=SC2086
        run_logged "$logfile" $CC $cflags -c "$src" -o "${src%.c}.o"
    done

    $AR rcs "$out/lib/libz.a" *.o
    $RANLIB "$out/lib/libz.a"
    cp zlib.h zconf.h "$out/include/"
    echo "$stamp" > "$out/.stamp"

    cd ..
    rm -rf "zlib-${ZLIB_VERSION}"
    log_ok "zlib ${subdir}"
}

# =============================================================================
# BUILD: OPENSSL
# =============================================================================
# OpenSSL is configured with minimal features needed for Tor client operation.
# Many cipher suites and protocols are disabled to reduce binary size.

build_openssl() {
    local sdk_type="$1" arch="$2" subdir="$3"
    local out="${OUTPUT_DIR}/openssl/${subdir}"
    local conf="${SCRIPT_DIR}/openssl/ios64e.conf"
    local stamp; stamp="$(build_stamp openssl "$OPENSSL_VERSION" "$arch" "$sdk_type" "$(shasum -a 256 < "$conf")" \
        "flags: $HARDEN_CFLAGS $SECURITY_WARNINGS (no prefix map)")"
    local logfile="${LOG_DIR}/openssl-${subdir}.log"

    if is_built "$out" "$stamp" lib/libssl.a; then
        log "OpenSSL ${subdir}: already built"
        return
    fi
    rm -rf "$out"; : > "$logfile"

    log "Building OpenSSL for ${subdir} (this is the longest step)..."

    rm -rf "openssl-${OPENSSL_VERSION}"
    extract_verified "openssl-${OPENSSL_VERSION}.tar.gz"
    cd "openssl-${OPENSSL_VERSION}"

    # Minimal feature set for Tor client
    local opts="no-shared no-dso no-hw no-engine no-async no-tests"
    opts="$opts no-apps no-docs no-ui-console"
    opts="$opts no-ssl2 no-ssl3 no-comp no-dtls no-dtls1 no-dtls1-method"
    opts="$opts no-weak-ssl-ciphers no-sctp no-srp no-psk no-srtp"
    opts="$opts no-gost no-idea no-md2 no-md4 no-mdc2 no-rc2 no-rc4 no-rc5"
    opts="$opts no-seed no-bf no-cast no-camellia no-aria no-des"
    opts="$opts no-sm2 no-sm3 no-sm4 no-whirlpool no-rmd160 no-siphash"
    opts="$opts no-ct no-ocsp no-ts no-cms no-cmp no-ocb"
    opts="$opts enable-ec_nistp_64_gcc_128"

    local target min_flag config_arg=""
    if [ "$sdk_type" = "iphoneos" ] && [ "$arch" = "arm64e" ]; then
        target="ios64e-xcrun"
        config_arg="--config=${conf}"
        min_flag="-mios-version-min=${MIN_IOS}"
    elif [ "$sdk_type" = "iphoneos" ]; then
        target="ios64-xcrun"
        min_flag="-mios-version-min=${MIN_IOS}"
    else
        target="iossimulator-xcrun"
        min_flag="-mios-simulator-version-min=${MIN_IOS}"
    fi

    # Neutral prefix + DESTDIR staging: OPENSSLDIR / MODULESDIR are compiled
    # into libcrypto, and must not carry this machine's paths (privacy and
    # reproducibility). Nothing is ever loaded from them on iOS (no-shared,
    # no-dso; a missing openssl.cnf is ignored), same as before.
    local stage="${BUILD_DIR}/stage-openssl-${subdir}"
    rm -rf "$stage"
    # No $REPRO_CFLAGS here: OpenSSL embeds its whole compiler command line in
    # libcrypto (OpenSSL_version(OPENSSL_CFLAGS)), so a -ffile-prefix-map
    # would itself leak the build path. Its sources compile with relative
    # paths, so __FILE__ carries no machine path anyway.
    # shellcheck disable=SC2086
    run_logged "$logfile" ./Configure $config_arg $target $opts -Os $min_flag $HARDEN_CFLAGS $SECURITY_WARNINGS \
        --prefix=/torclient/openssl \
        --openssldir=/torclient/openssl/ssl

    run_logged "$logfile" make -j"${JOBS}"
    run_logged "$logfile" make install_sw DESTDIR="$stage"
    mkdir -p "$out"
    cp -R "$stage/torclient/openssl/lib" "$stage/torclient/openssl/include" "$out/"
    rm -rf "$stage"
    echo "$stamp" > "$out/.stamp"

    cd ..
    rm -rf "openssl-${OPENSSL_VERSION}"
    log_ok "OpenSSL ${subdir}"
}

# =============================================================================
# BUILD: LIBEVENT
# =============================================================================
# libevent provides the async I/O event loop that Tor uses for networking.
# OpenSSL support in libevent is disabled because Tor handles TLS directly.

build_libevent() {
    local sdk_type="$1" arch="$2" subdir="$3"
    local out="${OUTPUT_DIR}/libevent/${subdir}"
    local stamp; stamp="$(build_stamp libevent "$LIBEVENT_VERSION" "$arch" "$sdk_type")"
    local logfile="${LOG_DIR}/libevent-${subdir}.log"

    if is_built "$out" "$stamp" lib/libevent.a; then
        log "libevent ${subdir}: already built"
        return
    fi
    rm -rf "$out"; : > "$logfile"

    log "Building libevent for ${subdir}..."

    read -r sdk_path min_flag <<< "$(get_platform_flags "$sdk_type")"
    local cflags="-arch $arch -isysroot $sdk_path ${min_flag}=${MIN_IOS} -Os $COMMON_CFLAGS"
    local ldflags="-arch $arch -isysroot $sdk_path ${min_flag}=${MIN_IOS}"

    rm -rf "libevent-${LIBEVENT_VERSION}"
    extract_verified "libevent-${LIBEVENT_VERSION}.tar.gz"
    cd "libevent-${LIBEVENT_VERSION}"

    run_logged "$logfile" ./configure \
        --host=arm-apple-darwin \
        --prefix="$out" \
        --disable-shared --enable-static \
        --disable-samples --disable-libevent-regress \
        --disable-debug-mode --disable-malloc-replacement \
        --disable-openssl \
        CC="$CC" AR="$AR" RANLIB="$RANLIB" \
        CFLAGS="$cflags" LDFLAGS="$ldflags"

    run_logged "$logfile" make -j"${JOBS}"
    run_logged "$logfile" make install
    echo "$stamp" > "$out/.stamp"

    cd ..
    rm -rf "libevent-${LIBEVENT_VERSION}"
    log_ok "libevent ${subdir}"
}

# =============================================================================
# BUILD: TOR
# =============================================================================
# Tor is built in client-only mode with relay and directory authority modules
# disabled. This produces a smaller binary suitable for embedded use.
#
# A stub implementation is injected for ext_or_cmd functions that are
# referenced by the protocol code but only implemented in the relay module.

# Local patches applied on top of the pristine Tor tarball (see
# Scripts/patches/*.patch; each file's header explains the bug and its
# upstream status). The fingerprint is stored next to each libtor.a so a
# cached build is redone whenever the patch set changes.
tor_patches_fingerprint() {
    local files=("${PATCH_DIR}"/*.patch)
    if [ ! -e "${files[0]}" ]; then
        echo "none"
        return
    fi
    cat "${files[@]}" | shasum -a 256 | cut -d' ' -f1
}

apply_tor_patches() {
    local files=("${PATCH_DIR}"/*.patch)
    [ -e "${files[0]}" ] || return 0
    for p in "${files[@]}"; do
        log "  Applying $(basename "$p")"
        patch -p1 --forward --silent < "$p" || {
            log_err "Patch failed: $(basename "$p")"
            return 1
        }
    done
}

build_tor() {
    local sdk_type="$1" arch="$2" subdir="$3"
    local out="${OUTPUT_DIR}/tor/${subdir}"
    local fingerprint
    fingerprint="$(tor_patches_fingerprint)"

    local openssl_dir="${OUTPUT_DIR}/openssl/${subdir}"
    local libevent_dir="${OUTPUT_DIR}/libevent/${subdir}"
    local zlib_dir="${OUTPUT_DIR}/zlib/${subdir}"

    # Rebuilt whenever the patch set or any dependency build changes.
    local stamp; stamp="$(build_stamp tor "$TOR_VERSION" "$arch" "$sdk_type" "$fingerprint" \
        "$(cat "$openssl_dir/.stamp" "$libevent_dir/.stamp" "$zlib_dir/.stamp")")"
    local logfile="${LOG_DIR}/tor-${subdir}.log"

    if is_built "$out" "$stamp" lib/libtor.a; then
        log "Tor ${subdir}: already built (patch set ${fingerprint:0:12})"
        return
    fi
    rm -rf "$out"; : > "$logfile"

    log "Building Tor for ${subdir}..."

    read -r sdk_path min_flag <<< "$(get_platform_flags "$sdk_type")"

    local cflags="-arch $arch -isysroot $sdk_path ${min_flag}=${MIN_IOS} -O2 -DTOR_UNIT_TESTS=0 $COMMON_CFLAGS"
    local cppflags="-I${openssl_dir}/include -I${libevent_dir}/include -I${zlib_dir}/include"
    local ldflags="-arch $arch -isysroot $sdk_path ${min_flag}=${MIN_IOS}"
    ldflags="$ldflags -L${openssl_dir}/lib -L${libevent_dir}/lib -L${zlib_dir}/lib"

    rm -rf "tor-${TOR_VERSION}"
    extract_verified "tor-${TOR_VERSION}.tar.gz"
    cd "tor-${TOR_VERSION}"
    apply_tor_patches

    # Neutral --prefix: Tor compiles its DATADIR/CONFDIR into the binary; the
    # app passes every path it uses explicitly, so these only must not leak
    # this machine's directory layout.
    run_logged "$logfile" ./configure \
        --host=arm-apple-darwin \
        --prefix=/torclient/tor \
        --disable-tool-name-check \
        --disable-asciidoc --disable-manpage --disable-html-manual \
        --disable-module-dirauth --disable-module-relay \
        --disable-libscrypt --disable-unittests \
        --disable-lzma --disable-zstd --disable-seccomp \
        --disable-systemd --disable-system-torrc \
        --disable-linker-hardening \
        --disable-gcc-warnings-advisory \
        --enable-static-tor --enable-pic \
        --enable-static-openssl --enable-static-libevent \
        --with-openssl-dir="${openssl_dir}" \
        --with-libevent-dir="${libevent_dir}" \
        --with-zlib-dir="${zlib_dir}" \
        CC="$CC" AR="$AR" RANLIB="$RANLIB" LD="$LD" \
        CFLAGS="$cflags $cppflags" LDFLAGS="$ldflags" CPPFLAGS="$cppflags"

    # Create stub for ext_or_cmd functions.
    # When the relay module is disabled, proto_ext_or.c still references
    # ext_or_cmd_new/ext_or_cmd_free_ but the implementations live in
    # ext_orport.c (relay module). We provide minimal stubs.
    cat > src/feature/relay/ext_or_cmd_stub.c << 'STUB_EOF'
#include "orconfig.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "lib/malloc/malloc.h"

struct ext_or_cmd_t {
  uint16_t cmd;
  uint16_t len;
  char body[];
};

struct ext_or_cmd_t *
ext_or_cmd_new(uint16_t len)
{
  size_t size = offsetof(struct ext_or_cmd_t, body) + len;
  struct ext_or_cmd_t *cmd = tor_malloc(size);
  memset(cmd, 0, size);
  cmd->len = len;
  return cmd;
}

void
ext_or_cmd_free_(struct ext_or_cmd_t *cmd)
{
  tor_free(cmd);
}
STUB_EOF
    # shellcheck disable=SC2086
    run_logged "$logfile" $CC $cflags $cppflags -I. -Isrc -c src/feature/relay/ext_or_cmd_stub.c \
        -o src/feature/relay/ext_or_cmd_stub.o

    # Build the combined libtor.a (all internal Tor libraries merged)
    run_logged "$logfile" make -j"${JOBS}" libtor.a

    if [ ! -f "libtor.a" ]; then
        log_err "libtor.a not found after build"
        cd ..
        return 1
    fi

    # Add the ext_or_cmd stub to libtor.a
    $AR rs libtor.a src/feature/relay/ext_or_cmd_stub.o 2>/dev/null
    $RANLIB libtor.a

    # Install
    mkdir -p "$out/lib" "$out/include"
    cp libtor.a "$out/lib/libtor.a"
    $RANLIB "$out/lib/libtor.a"

    # Copy the public API header
    if [ -f "src/feature/api/tor_api.h" ]; then
        cp src/feature/api/tor_api.h "$out/include/tor_api.h"
    fi
    echo "$fingerprint" > "$out/patches.sha256"
    echo "$stamp" > "$out/.stamp"

    cd ..
    rm -rf "tor-${TOR_VERSION}"
    log_ok "Tor ${subdir}"
}

# =============================================================================
# WARNING SUMMARY
# =============================================================================
# Upstream C is not patched for warnings; they are counted and reported so a
# version bump that adds new ones is visible. Counts are unique diagnostics
# (file:line:col + message), per library, summed over all slices.

summarize_warnings() {
    local summary="${LOG_DIR}/warnings-summary.txt"
    {
        echo "Compiler warnings (unique file:line:col diagnostics) with:"
        echo "  $SECURITY_WARNINGS"
        echo ""
        local lib
        for lib in zlib openssl libevent tor; do
            local uniq_file="${LOG_DIR}/${lib}-warnings.txt"
            cat "${LOG_DIR}/${lib}-"*.log 2>/dev/null \
                | grep -E '^[^ ].*:[0-9]+:[0-9]+: warning: ' \
                | sed -E "s|^${BUILD_DIR}/||; s|^\.\./||" \
                | sort -u > "$uniq_file" || true
            printf '%-9s %6s warnings\n' "$lib" "$(wc -l < "$uniq_file" | tr -d ' ')"
            grep -oE '\[-W[a-zA-Z0-9_=-]+' "$uniq_file" | tr -d '[' | sort | uniq -c | sort -rn \
                | awk '{ printf "            %6d  %s\n", $1, $2 }' || true
        done
    } > "$summary"
    cat "$summary"
}


# =============================================================================
# CREATE XCFRAMEWORK
# =============================================================================

# combine_slice <subdir> <dest-dir>: one libTorClient.a + headers for a slice.
combine_slice() {
    local subdir="$1" pdir="$2"
    mkdir -p "$pdir/lib" "$pdir/include"

    local all_libs=""
    all_libs="$all_libs ${OUTPUT_DIR}/zlib/${subdir}/lib/libz.a"
    all_libs="$all_libs ${OUTPUT_DIR}/openssl/${subdir}/lib/libssl.a"
    all_libs="$all_libs ${OUTPUT_DIR}/openssl/${subdir}/lib/libcrypto.a"

    # Use individual libevent libs to avoid duplicates (libevent.a is a convenience archive)
    for lib in libevent_core.a libevent_extra.a libevent_openssl.a libevent_pthreads.a; do
        [ -f "${OUTPUT_DIR}/libevent/${subdir}/lib/$lib" ] && \
            all_libs="$all_libs ${OUTPUT_DIR}/libevent/${subdir}/lib/$lib"
    done

    all_libs="$all_libs ${OUTPUT_DIR}/tor/${subdir}/lib/libtor.a"

    # shellcheck disable=SC2086
    /usr/bin/libtool -static -no_warning_for_no_symbols -o "$pdir/lib/libTorClient.a" $all_libs
    log "  ${subdir}: $(du -h "$pdir/lib/libTorClient.a" | cut -f1)"

    # Copy headers
    mkdir -p "$pdir/include/openssl" "$pdir/include/event2"
    cp -r "${OUTPUT_DIR}/openssl/${subdir}/include/openssl/"* "$pdir/include/openssl/"
    cp "${OUTPUT_DIR}/libevent/${subdir}/include/"*.h "$pdir/include/"
    cp -r "${OUTPUT_DIR}/libevent/${subdir}/include/event2/"* "$pdir/include/event2/"
    cp "${OUTPUT_DIR}/tor/${subdir}/include/tor_api.h" "$pdir/include/"

    # Module map for Swift interop. Deliberately no `link "TorClient"`:
    # an autolink directive is copied into every object file of every
    # module that (even transitively) imports TorClientC, so each of those
    # images would ask for libTorClient.a again. SwiftPM links the binary
    # target explicitly, into the TorClientWrapper product only.
    cat > "$pdir/include/module.modulemap" << 'MAPEOF'
module TorClientC {
    header "tor_api.h"
    export *
}
MAPEOF
}

create_xcframework() {
    log "Creating XCFramework..."

    local combined_dir="${BUILD_DIR}/combined"
    rm -rf "$combined_dir" "$XCFRAMEWORK_DIR"
    mkdir -p "$combined_dir"

    combine_slice arm64-ios  "${combined_dir}/arm64-ios"
    combine_slice arm64e-ios "${combined_dir}/arm64e-ios"
    combine_slice arm64-sim  "${combined_dir}/arm64-sim"

    # An xcframework holds one library per platform variant, so both device
    # architectures go into ONE fat archive (identifier ios-arm64_arm64e).
    # Their public headers must be identical for that to be sound.
    if ! diff -r "${combined_dir}/arm64-ios/include" "${combined_dir}/arm64e-ios/include" >/dev/null; then
        diff -r "${combined_dir}/arm64-ios/include" "${combined_dir}/arm64e-ios/include" | head -20 >&2
        log_err "arm64 and arm64e public headers differ; cannot share one device slice"
        exit 1
    fi
    local device_dir="${combined_dir}/ios-device"
    mkdir -p "$device_dir/lib"
    cp -R "${combined_dir}/arm64-ios/include" "$device_dir/include"
    lipo -create "${combined_dir}/arm64-ios/lib/libTorClient.a" "${combined_dir}/arm64e-ios/lib/libTorClient.a" \
        -output "$device_dir/lib/libTorClient.a"

    # Create x86_64 simulator stub for Intel Mac linker compatibility.
    # Xcode links both arm64 and x86_64 for simulator targets even on Apple Silicon.
    # These stubs satisfy the linker but abort() at runtime on Intel.
    log "Creating x86_64 simulator stub..."

    local stub_dir="${BUILD_DIR}/x86_64_stub"
    rm -rf "$stub_dir"
    mkdir -p "$stub_dir"

    cat > "$stub_dir/tor_stub_x86_64.c" << 'STUBEOF'
#include <stdio.h>
#include <stdlib.h>

static void x86_64_stub_abort(const char* func) {
    fprintf(stderr, "FATAL: %s called on x86_64. Tor requires arm64 simulator (Apple Silicon).\n", func);
    abort();
}

typedef struct tor_main_configuration_t { int _; } tor_main_configuration_t;

tor_main_configuration_t* tor_main_configuration_new(void) {
    x86_64_stub_abort("tor_main_configuration_new"); return NULL;
}
void tor_main_configuration_free(tor_main_configuration_t* c) {
    (void)c; x86_64_stub_abort("tor_main_configuration_free");
}
int tor_main_configuration_set_command_line(tor_main_configuration_t* c, int argc, char** argv) {
    (void)c; (void)argc; (void)argv; x86_64_stub_abort("tor_main_configuration_set_command_line"); return -1;
}
int tor_main_configuration_setup_control_socket(tor_main_configuration_t* c) {
    (void)c; x86_64_stub_abort("tor_main_configuration_setup_control_socket"); return -1;
}
int tor_run_main(const tor_main_configuration_t* c) {
    (void)c; x86_64_stub_abort("tor_run_main"); return -1;
}
const char* tor_api_get_provider_version(void) {
    x86_64_stub_abort("tor_api_get_provider_version"); return NULL;
}
int tor_main(int argc, char** argv) {
    (void)argc; (void)argv; x86_64_stub_abort("tor_main"); return -1;
}
STUBEOF

    # shellcheck disable=SC2086
    $CC -arch x86_64 -isysroot "$SIM_SDK" -mios-simulator-version-min=${MIN_IOS} -Os \
        $HARDEN_CFLAGS -ffile-prefix-map="${stub_dir}=/torclient-build" \
        -c "$stub_dir/tor_stub_x86_64.c" -o "$stub_dir/tor_stub_x86_64.o"
    $AR rcs "$stub_dir/libTorClient_x86_64.a" "$stub_dir/tor_stub_x86_64.o"
    $RANLIB "$stub_dir/libTorClient_x86_64.a"

    # Create universal (fat) simulator library: arm64 + x86_64
    local sim_dir="${combined_dir}/ios-simulator"
    mkdir -p "$sim_dir/lib"
    cp -R "${combined_dir}/arm64-sim/include" "$sim_dir/include"
    lipo -create "${combined_dir}/arm64-sim/lib/libTorClient.a" "$stub_dir/libTorClient_x86_64.a" \
        -output "$sim_dir/lib/libTorClient.a"

    # Create the XCFramework. xcodebuild derives the identifiers from the
    # architectures: ios-arm64_arm64e and ios-arm64_x86_64-simulator.
    xcodebuild -create-xcframework \
        -library "$device_dir/lib/libTorClient.a" -headers "$device_dir/include" \
        -library "$sim_dir/lib/libTorClient.a" -headers "$sim_dir/include" \
        -output "$XCFRAMEWORK_DIR" >/dev/null

    local id
    for id in ios-arm64_arm64e ios-arm64_x86_64-simulator; do
        if [ ! -f "${XCFRAMEWORK_DIR}/${id}/libTorClient.a" ]; then
            log_err "expected slice ${id} missing from the xcframework"
            exit 1
        fi
    done
    if [ "$(lipo -archs "${XCFRAMEWORK_DIR}/ios-arm64_arm64e/libTorClient.a")" != "arm64 arm64e" ]; then
        log_err "device slice is not arm64 + arm64e: $(lipo -archs "${XCFRAMEWORK_DIR}/ios-arm64_arm64e/libTorClient.a")"
        exit 1
    fi

    log_ok "XCFramework created at: $XCFRAMEWORK_DIR"
}

# Per-slice SHA-256 of this build. StealthOS's Scripts/verify-release.sh
# checks the xcframework the app links against this file.
write_checksums() {
    {
        echo "# TorClientC.xcframework - Tor ${TOR_VERSION}, OpenSSL ${OPENSSL_VERSION}, libevent ${LIBEVENT_VERSION}, zlib ${ZLIB_VERSION}"
        echo "# toolchain: $(xcrun clang --version | head -1), iphoneos SDK $(xcrun --sdk iphoneos --show-sdk-build-version)"
        echo "# tor patch set: $(tor_patches_fingerprint)"
        echo "# Check: (cd TorClientC.xcframework && grep -v '^#' ../TorClientC.xcframework.sha256 | shasum -a 256 -c)"
        (cd "$XCFRAMEWORK_DIR" && find . -type f ! -name '.DS_Store' | sed 's|^\./||' | LC_ALL=C sort \
            | while read -r f; do shasum -a 256 "$f"; done)
    } > "$CHECKSUM_FILE"
    log_ok "Checksums written to $CHECKSUM_FILE"
}

# =============================================================================
# MAIN
# =============================================================================

TOTAL_STEPS=6

echo ""
echo "=========================================="
echo "  TorClient Build Script"
echo "  Tor ${TOR_VERSION} | OpenSSL ${OPENSSL_VERSION}"
echo "  libevent ${LIBEVENT_VERSION} | zlib ${ZLIB_VERSION}"
echo "=========================================="
echo ""
echo "  iOS SDK:    $IOS_SDK"
echo "  Sim SDK:    $SIM_SDK"
echo "  Compiler:   $CC"
echo "  Jobs:       $JOBS"
echo "  Min iOS:    $MIN_IOS"
echo "  Slices:     $SLICES"
echo "  Hardening:  $HARDEN_CFLAGS"
echo ""

SOURCES_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --clean)
            log "Cleaning build directory..."
            rm -rf "$BUILD_DIR" "$XCFRAMEWORK_DIR" "$CHECKSUM_FILE"
            log_ok "Clean complete"
            ;;
        --sources-only) SOURCES_ONLY=1 ;;
        *) log_err "unknown argument: $arg"; exit 2 ;;
    esac
done

step 1 "Checking prerequisites"
check_prerequisites
log_ok "All prerequisites satisfied"

step 2 "Downloading and verifying sources (pinned SHA-256 + OpenPGP)"
mkdir -p "$BUILD_DIR" "$LOG_DIR"
cd "$BUILD_DIR"
setup_cross_compile_cache
sc_fetch "$ZLIB_URL" "zlib-${ZLIB_VERSION}.tar.gz"
sc_fetch "$OPENSSL_URL" "openssl-${OPENSSL_VERSION}.tar.gz"
sc_fetch "$LIBEVENT_URL" "libevent-${LIBEVENT_VERSION}.tar.gz"
sc_fetch "$TOR_URL" "tor-${TOR_VERSION}.tar.gz"
log_ok "All sources verified"

if [ "$SOURCES_ONLY" = 1 ]; then
    exit 0
fi

step 3 "Building zlib ${ZLIB_VERSION}"
for s in $SLICES; do IFS=: read -r sdk arch sub <<< "$s"; build_zlib "$sdk" "$arch" "$sub"; done

step 4 "Building OpenSSL ${OPENSSL_VERSION}"
for s in $SLICES; do IFS=: read -r sdk arch sub <<< "$s"; build_openssl "$sdk" "$arch" "$sub"; done

step 5 "Building libevent ${LIBEVENT_VERSION}"
for s in $SLICES; do IFS=: read -r sdk arch sub <<< "$s"; build_libevent "$sdk" "$arch" "$sub"; done

step 6 "Building Tor ${TOR_VERSION}"
for s in $SLICES; do IFS=: read -r sdk arch sub <<< "$s"; build_tor "$sdk" "$arch" "$sub"; done

echo ""
echo "=== Creating XCFramework ==="
create_xcframework
write_checksums

echo ""
echo "=== Compiler warnings (upstream code, not patched) ==="
summarize_warnings

# Summary
echo ""
echo "=========================================="
echo "  Build Complete"
echo "=========================================="
echo ""
echo "  Output: $XCFRAMEWORK_DIR"
echo ""
echo "  Contents:"
for dir in "$XCFRAMEWORK_DIR"/*/; do
    [ -d "$dir" ] || continue
    local_name="$(basename "$dir")"
    if [ -f "$dir/libTorClient.a" ]; then
        echo "    ${local_name}: $(du -h "$dir/libTorClient.a" | cut -f1) ($(lipo -archs "$dir/libTorClient.a"))"
    fi
done
echo ""
echo "  Verify with: lipo -info TorClientC.xcframework/ios-arm64_arm64e/libTorClient.a"
echo ""
