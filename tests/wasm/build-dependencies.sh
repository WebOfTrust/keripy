#!/usr/bin/env bash
# Run with the Pyodide cross-build environment active.
set -euo pipefail
recipes=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$recipes/../.." && pwd)
if [[ -e "$root/wheels/dependencies" ]]; then
    echo "$root/wheels/dependencies already exists." >&2
    exit 1
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
out="$work/dependencies"
mkdir "$out"

fetch() {
    local url=$1 checksum=$2 file=${1##*/}
    curl --fail --location --retry 3 --silent --show-error "$url" --output "$file"
    printf '%s  %s\n' "$checksum" "$file" | shasum -a 256 --check -
    tar -xzf "$file"
}

MSGPACK_PUREPYTHON=1 python -m pip wheel --no-deps --no-build-isolation --require-hashes \
    --only-binary=:all: --no-binary=hio,msgpack -r "$recipes/requirements.txt" -w "$out"

fetch https://files.pythonhosted.org/packages/source/b/blake3/blake3-1.0.9.tar.gz \
    5fa374fa5070ca084368776c19b420157eb0f2d3f091343d6bc59189929d62e2
fetch https://files.pythonhosted.org/packages/source/c/cbor2/cbor2-6.1.4.tar.gz \
    01ecc79a28f33d17331943ce508fc1e21f4b06553c73f874f4c77120d72b2ef9
fetch https://files.pythonhosted.org/packages/source/c/cryptography/cryptography-50.0.1.tar.gz \
    5dd9bda1c12b4162f6ff568eeb5e0ff956c28d14406e875cfe8a63a2d414ff20
fetch https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz \
    603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

# Pyodide 314 does not provide an OpenSSL installation for linking wheels.
export OPENSSL_DIR="$work/opt/keripy/openssl" OPENSSL_STATIC=1 OPENSSL_NO_VENDOR=1
(
    cd openssl-3.5.9
    CFLAGS='-O3 -fPIC -fwasm-exceptions -sSUPPORT_LONGJMP=wasm' \
    LDFLAGS='-fwasm-exceptions -sSUPPORT_LONGJMP=wasm' \
        emconfigure ./Configure gcc no-shared --prefix=/opt/keripy/openssl --libdir=lib \
            --cross-compile-prefix= CC=emcc AR=emar RANLIB=emranlib
    emmake make -j"${PYODIDE_JOBS:-4}" DESTDIR="$work" install_dev
)

export CARGO_TARGET_WASM32_UNKNOWN_EMSCRIPTEN_RUSTFLAGS='-C link-arg=-sSIDE_MODULE=2'
build_rust_wheel() {
    local source=$1 manifest=$2
    cargo fetch --locked --manifest-path "$source/$manifest"
    CARGO_NET_OFFLINE=true pyodide build "$source" --outdir "$out" \
        --no-isolation --skip-emscripten-install --exports pyinit
}
build_rust_wheel blake3-1.0.9 Cargo.toml
build_rust_wheel cbor2-6.1.4 rust/Cargo.toml
build_rust_wheel cryptography-50.0.1 Cargo.toml

fetch https://download.libsodium.org/libsodium/releases/libsodium-1.0.22.tar.gz \
    adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349
fetch https://files.pythonhosted.org/packages/source/p/pysodium/pysodium-0.7.18.tar.gz \
    781ada024456ac74c411193b82d94018c85c94130ea01a22dbec48b8ff458b07

(
    cd libsodium-1.0.22
    emconfigure env -u EMSCRIPTEN ./configure --host=wasm32-unknown-emscripten --disable-shared \
        --without-pthreads --disable-ssp --disable-asm --disable-pie \
        --disable-dependency-tracking CFLAGS='-O2 -fPIC'
    # Use Pyodide's secure /dev/urandom. The standalone JS backend requires eval.
    emmake make -C src/libsodium randombytes/libsodium_la-randombytes.lo CPPFLAGS=-U__EMSCRIPTEN__
    emmake make -C src/libsodium -j"${PYODIDE_JOBS:-4}"
    emcc -O2 -sSIDE_MODULE=1 -Wl,--whole-archive src/libsodium/.libs/libsodium.a \
        -Wl,--no-whole-archive -o ../pysodium-0.7.18/pysodium/libsodium.so
)
(
    cd pysodium-0.7.18
    patch -p1 < "$recipes/pysodium-emscripten.patch"
    cp ../libsodium-1.0.22/LICENSE LICENSE-libsodium
    python -m build --wheel --no-isolation --outdir "$out" \
        -C--build-option=--plat-name=pyemscripten_2026_0_wasm32
)

mkdir -p "$root/wheels"
mv "$out" "$root/wheels/"
