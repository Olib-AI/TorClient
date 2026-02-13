#!/bin/bash
# build-xcframework.sh - Build Tor and dependencies from source for iOS
#
# Builds zlib, OpenSSL, libevent, and Tor as static libraries, then packages
# them into a single TorClientC.xcframework for use with Swift Package Manager.
#
# Usage:
#   ./Scripts/build-xcframework.sh           # Build for arm64 (device + simulator)
#   ./Scripts/build-xcframework.sh --clean   # Clean and rebuild from scratch
#
# Requirements:
#   - macOS with Xcode (command line tools)
#   - Homebrew packages: autoconf automake libtool pkg-config
#   - ~2GB disk space for build artifacts
#   - ~10-30 minutes depending on CPU
#
# Output:
#   TorClientC.xcframework/   - Ready-to-use XCFramework

set -e

# =============================================================================
# CONFIGURATION
# =============================================================================

ZLIB_VERSION="1.3.1"
OPENSSL_VERSION="3.6.1"
LIBEVENT_VERSION="2.1.12-stable"
TOR_VERSION="0.4.9.5"
MIN_IOS="18.0"

ZLIB_URL="https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz"
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
LIBEVENT_URL="https://github.com/libevent/libevent/releases/download/release-${LIBEVENT_VERSION}/libevent-${LIBEVENT_VERSION}.tar.gz"
TOR_URL="https://dist.torproject.org/tor-${TOR_VERSION}.tar.gz"

# Resolve paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PACKAGE_DIR}/.build-tor"
OUTPUT_DIR="${BUILD_DIR}/output"
XCFRAMEWORK_DIR="${PACKAGE_DIR}/TorClientC.xcframework"

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
        echo "  brew install autoconf automake libtool pkg-config"
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

download() {
    local url="$1" file="$2"
    if [ -f "$file" ]; then
        log "Cached: $(basename "$file")"
    else
        log "Downloading $(basename "$file")..."
        curl -L --progress-bar -o "$file" "$url"
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
# BUILD: ZLIB
# =============================================================================
# zlib's configure tries to run test binaries, which fails during
# cross-compilation. We compile the source files directly instead.

build_zlib() {
    local sdk_type="$1" subdir="$2"
    local out="${OUTPUT_DIR}/zlib/${subdir}"

    if [ -f "$out/lib/libz.a" ]; then
        log "zlib ${subdir}: already built"
        return
    fi

    log "Building zlib for ${subdir}..."

    read -r sdk_path min_flag <<< "$(get_platform_flags "$sdk_type")"
    local cflags="-arch arm64 -isysroot $sdk_path ${min_flag}=${MIN_IOS} -O2 -D_LARGEFILE64_SOURCE=1 -DHAVE_HIDDEN"

    rm -rf "zlib-${ZLIB_VERSION}"
    tar xzf "zlib-${ZLIB_VERSION}.tar.gz"
    cd "zlib-${ZLIB_VERSION}"

    mkdir -p "$out/lib" "$out/include"

    local srcs="adler32.c crc32.c deflate.c infback.c inffast.c inflate.c inftrees.c trees.c zutil.c compress.c uncompr.c gzclose.c gzlib.c gzread.c gzwrite.c"
    for src in $srcs; do
        $CC $cflags -c "$src" -o "${src%.c}.o"
    done

    $AR rcs "$out/lib/libz.a" *.o
    $RANLIB "$out/lib/libz.a"
    cp zlib.h zconf.h "$out/include/"

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
    local sdk_type="$1" subdir="$2"
    local out="${OUTPUT_DIR}/openssl/${subdir}"

    if [ -f "$out/lib/libssl.a" ]; then
        log "OpenSSL ${subdir}: already built"
        return
    fi

    log "Building OpenSSL for ${subdir} (this is the longest step)..."

    rm -rf "openssl-${OPENSSL_VERSION}"
    tar xzf "openssl-${OPENSSL_VERSION}.tar.gz"
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

    local target min_flag
    if [ "$sdk_type" = "iphoneos" ]; then
        target="ios64-xcrun"
        min_flag="-mios-version-min=${MIN_IOS}"
    else
        target="iossimulator-xcrun"
        min_flag="-mios-simulator-version-min=${MIN_IOS}"
    fi

    ./Configure $target $opts -Os $min_flag \
        --prefix="$out" \
        --openssldir="$out/ssl"

    make -j${JOBS} 2>&1 | tail -1
    make install_sw 2>&1 | tail -1

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
    local sdk_type="$1" subdir="$2"
    local out="${OUTPUT_DIR}/libevent/${subdir}"

    if [ -f "$out/lib/libevent.a" ]; then
        log "libevent ${subdir}: already built"
        return
    fi

    log "Building libevent for ${subdir}..."

    read -r sdk_path min_flag <<< "$(get_platform_flags "$sdk_type")"
    local cflags="-arch arm64 -isysroot $sdk_path ${min_flag}=${MIN_IOS} -Os"
    local ldflags="-arch arm64 -isysroot $sdk_path ${min_flag}=${MIN_IOS}"

    rm -rf "libevent-${LIBEVENT_VERSION}"
    tar xzf "libevent-${LIBEVENT_VERSION}.tar.gz"
    cd "libevent-${LIBEVENT_VERSION}"

    ./configure \
        --host=arm-apple-darwin \
        --prefix="$out" \
        --disable-shared --enable-static \
        --disable-samples --disable-libevent-regress \
        --disable-debug-mode --disable-malloc-replacement \
        --disable-openssl \
        CC="$CC" AR="$AR" RANLIB="$RANLIB" \
        CFLAGS="$cflags" LDFLAGS="$ldflags" \
        2>&1 | tail -1

    make -j${JOBS} 2>&1 | tail -1
    make install 2>&1 | tail -1

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

build_tor() {
    local sdk_type="$1" subdir="$2"
    local out="${OUTPUT_DIR}/tor/${subdir}"

    if [ -f "$out/lib/libtor.a" ]; then
        log "Tor ${subdir}: already built"
        return
    fi

    log "Building Tor for ${subdir}..."

    read -r sdk_path min_flag <<< "$(get_platform_flags "$sdk_type")"

    local openssl_dir="${OUTPUT_DIR}/openssl/${subdir}"
    local libevent_dir="${OUTPUT_DIR}/libevent/${subdir}"
    local zlib_dir="${OUTPUT_DIR}/zlib/${subdir}"

    local cflags="-arch arm64 -isysroot $sdk_path ${min_flag}=${MIN_IOS} -O2 -DTOR_UNIT_TESTS=0"
    local cppflags="-I${openssl_dir}/include -I${libevent_dir}/include -I${zlib_dir}/include"
    local ldflags="-arch arm64 -isysroot $sdk_path ${min_flag}=${MIN_IOS}"
    ldflags="$ldflags -L${openssl_dir}/lib -L${libevent_dir}/lib -L${zlib_dir}/lib"

    rm -rf "tor-${TOR_VERSION}"
    tar xzf "tor-${TOR_VERSION}.tar.gz"
    cd "tor-${TOR_VERSION}"

    ./configure \
        --host=arm-apple-darwin \
        --prefix="$out" \
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
        CFLAGS="$cflags $cppflags" LDFLAGS="$ldflags" CPPFLAGS="$cppflags" \
        2>&1 | tail -1

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
    $CC $cflags $cppflags -I. -Isrc -c src/feature/relay/ext_or_cmd_stub.c \
        -o src/feature/relay/ext_or_cmd_stub.o

    # Build the combined libtor.a (all internal Tor libraries merged)
    make -j${JOBS} libtor.a 2>&1 | tail -1

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

    cd ..
    rm -rf "tor-${TOR_VERSION}"
    log_ok "Tor ${subdir}"
}

# =============================================================================
# CREATE XCFRAMEWORK
# =============================================================================

create_xcframework() {
    log "Creating XCFramework..."

    local combined_dir="${BUILD_DIR}/combined"
    rm -rf "$combined_dir" "$XCFRAMEWORK_DIR"
    mkdir -p "$combined_dir"

    # Combine all static libraries per platform using Apple's libtool
    for platform_info in "ios-arm64:arm64-ios" "ios-arm64-simulator:arm64-sim"; do
        local platform="${platform_info%%:*}"
        local subdir="${platform_info##*:}"
        local pdir="${combined_dir}/${platform}"
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

        /usr/bin/libtool -static -o "$pdir/lib/libTorClient.a" $all_libs
        log "  ${platform}: $(du -h "$pdir/lib/libTorClient.a" | cut -f1)"

        # Copy headers
        mkdir -p "$pdir/include/openssl" "$pdir/include/event2"
        cp -r "${OUTPUT_DIR}/openssl/${subdir}/include/openssl/"* "$pdir/include/openssl/" 2>/dev/null || true
        cp "${OUTPUT_DIR}/libevent/${subdir}/include/"*.h "$pdir/include/" 2>/dev/null || true
        cp -r "${OUTPUT_DIR}/libevent/${subdir}/include/event2/"* "$pdir/include/event2/" 2>/dev/null || true

        # Tor API header
        if [ -f "${OUTPUT_DIR}/tor/${subdir}/include/tor_api.h" ]; then
            cp "${OUTPUT_DIR}/tor/${subdir}/include/tor_api.h" "$pdir/include/"
        fi

        # Module map for Swift interop
        cat > "$pdir/include/module.modulemap" << 'MAPEOF'
module TorClientC {
    header "tor_api.h"
    export *
    link "TorClient"
}
MAPEOF
    done

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

    $CC -arch x86_64 -isysroot "$SIM_SDK" -mios-simulator-version-min=${MIN_IOS} \
        -c "$stub_dir/tor_stub_x86_64.c" -o "$stub_dir/tor_stub_x86_64.o"
    $AR rcs "$stub_dir/libTorClient_x86_64.a" "$stub_dir/tor_stub_x86_64.o"
    $RANLIB "$stub_dir/libTorClient_x86_64.a"

    # Create universal (fat) simulator library: arm64 + x86_64
    local sim_lib="${combined_dir}/ios-arm64-simulator/lib/libTorClient.a"
    lipo -create "$sim_lib" "$stub_dir/libTorClient_x86_64.a" \
        -output "$stub_dir/libTorClient_universal.a"
    cp "$stub_dir/libTorClient_universal.a" "$sim_lib"

    # Create the XCFramework
    xcodebuild -create-xcframework \
        -library "${combined_dir}/ios-arm64/lib/libTorClient.a" \
        -headers "${combined_dir}/ios-arm64/include" \
        -library "${combined_dir}/ios-arm64-simulator/lib/libTorClient.a" \
        -headers "${combined_dir}/ios-arm64-simulator/include" \
        -output "$XCFRAMEWORK_DIR"

    # Update Info.plist to declare x86_64 support in the simulator slice
    cat > "${XCFRAMEWORK_DIR}/Info.plist" << 'PLISTEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AvailableLibraries</key>
	<array>
		<dict>
			<key>BinaryPath</key>
			<string>libTorClient.a</string>
			<key>HeadersPath</key>
			<string>Headers</string>
			<key>LibraryIdentifier</key>
			<string>ios-arm64</string>
			<key>LibraryPath</key>
			<string>libTorClient.a</string>
			<key>SupportedArchitectures</key>
			<array>
				<string>arm64</string>
			</array>
			<key>SupportedPlatform</key>
			<string>ios</string>
		</dict>
		<dict>
			<key>BinaryPath</key>
			<string>libTorClient.a</string>
			<key>HeadersPath</key>
			<string>Headers</string>
			<key>LibraryIdentifier</key>
			<string>ios-arm64_x86_64-simulator</string>
			<key>LibraryPath</key>
			<string>libTorClient.a</string>
			<key>SupportedArchitectures</key>
			<array>
				<string>arm64</string>
				<string>x86_64</string>
			</array>
			<key>SupportedPlatform</key>
			<string>ios</string>
			<key>SupportedPlatformVariant</key>
			<string>simulator</string>
		</dict>
	</array>
	<key>CFBundlePackageType</key>
	<string>XFWK</string>
	<key>XCFrameworkFormatVersion</key>
	<string>1.0</string>
</dict>
</plist>
PLISTEOF

    # Rename simulator directory to match the declared LibraryIdentifier
    if [ -d "${XCFRAMEWORK_DIR}/ios-arm64-simulator" ]; then
        mv "${XCFRAMEWORK_DIR}/ios-arm64-simulator" "${XCFRAMEWORK_DIR}/ios-arm64_x86_64-simulator"
    fi

    log_ok "XCFramework created at: $XCFRAMEWORK_DIR"
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
echo ""

# Clean if requested
if [ "$1" = "--clean" ]; then
    log "Cleaning build directory..."
    rm -rf "$BUILD_DIR" "$XCFRAMEWORK_DIR"
    log_ok "Clean complete"
fi

step 1 "Checking prerequisites"
check_prerequisites
log_ok "All prerequisites satisfied"

step 2 "Downloading sources"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
setup_cross_compile_cache
download "$ZLIB_URL" "zlib-${ZLIB_VERSION}.tar.gz"
download "$OPENSSL_URL" "openssl-${OPENSSL_VERSION}.tar.gz"
download "$LIBEVENT_URL" "libevent-${LIBEVENT_VERSION}.tar.gz"
download "$TOR_URL" "tor-${TOR_VERSION}.tar.gz"
log_ok "All sources ready"

step 3 "Building zlib ${ZLIB_VERSION}"
build_zlib iphoneos arm64-ios
build_zlib iphonesimulator arm64-sim

step 4 "Building OpenSSL ${OPENSSL_VERSION}"
build_openssl iphoneos arm64-ios
build_openssl iphonesimulator arm64-sim

step 5 "Building libevent ${LIBEVENT_VERSION}"
build_libevent iphoneos arm64-ios
build_libevent iphonesimulator arm64-sim

step 6 "Building Tor ${TOR_VERSION}"
build_tor iphoneos arm64-ios
build_tor iphonesimulator arm64-sim

echo ""
echo "=== Creating XCFramework ==="
create_xcframework

# Summary
BUILD_END=$(date +%s)
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
        echo "    ${local_name}: $(du -h "$dir/libTorClient.a" | cut -f1)"
    fi
done
echo ""
echo "  Verify with: file TorClientC.xcframework/ios-arm64/libTorClient.a"
echo ""
