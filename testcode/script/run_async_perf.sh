#!/usr/bin/env bash
# This file is part of the openHiTLS project.
# Licensed under the Mulan PSL v2: http://license.coscl.org.cn/MulanPSL2
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$script_dir/../.." && pwd)
build_dir="$repo/build-async-perf"
out_dir="$repo/testcode/output/async_perf"
repeat=5
jobs=8
smoke=false
pin=()
extra=()

usage() {
    echo "Usage: $0 [--smoke] [--build-dir DIR] [--out DIR]"
    echo "       [--repeat N] [--jobs N] [--pin-cpu CPU] [--cmake-option=-DNAME=VALUE]"
}

while (($#)); do
    case "$1" in
        --smoke) smoke=true; shift ;;
        --build-dir|--out|--repeat|--jobs|--pin-cpu)
            (($# >= 2)) || { usage >&2; exit 2; }
            case "$1" in
                --build-dir) build_dir=$2 ;;
                --out) out_dir=$2 ;;
                --repeat) repeat=$2 ;;
                --jobs) jobs=$2 ;;
                --pin-cpu) pin=(--pin-cpu "$2") ;;
            esac
            shift 2 ;;
        --cmake-option=-D*)
            option=${1#--cmake-option=}
            case "$option" in
                *ASYNC*|*PROVIDER*|*BUILD_SHARED*|*BUILD_BENCHMARK*)
                    echo "Reserved build option: $option" >&2; exit 2 ;;
            esac
            extra+=("$option"); shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[[ $repeat =~ ^[1-9][0-9]*$ && $jobs =~ ^[1-9][0-9]*$ ]] || { usage >&2; exit 2; }
mkdir -p -- "$build_dir" "$out_dir"
build_dir=$(cd -- "$build_dir" && pwd)
out_dir=$(cd -- "$out_dir" && pwd)

common=(-DHITLS_BUILD_PROFILE=full -DCMAKE_BUILD_TYPE=Debug
        -DHITLS_BUILD_SHARED=ON -DHITLS_BUILD_STATIC=OFF -DHITLS_BUILD_BENCHMARK=ON
        -DHITLS_CRYPTO_PROVIDER=ON -DHITLS_TLS_FEATURE_PROVIDER=ON
        -DHITLS_TLS_FEATURE_PROVIDER_DYNAMIC=ON)
case "$(uname -m)" in
    x86_64) common+=(-DHITLS_ASM_X8664=ON) ;;
    aarch64|arm64) common+=(-DHITLS_ASM_ARMV8=ON) ;;
esac

build_variant() {
    local tag=$1 bsl_async=$2
    local variant="$build_dir/$tag"
    cmake -S "$repo" -B "$variant" "${common[@]}" "${extra[@]}" \
        -DHITLS_BSL_ASYNC="$bsl_async" -DHITLS_TLS_FEATURE_MODE_ASYNC="$bsl_async"
    cmake --build "$variant" -j "$jobs"
    cmake -S "$repo/testcode/framework/async/provider" -B "$variant/sim-provider" \
        -DOPENHITLS_BUILD_DIR="$variant" -DSIM_PROV_OUTPUT_DIR="$variant/provider" -DSIM_PROV_ASYNC="$bsl_async"
    cmake --build "$variant/sim-provider" -j "$jobs"
}

run_variant() {
    local tag=$1
    local variant="$build_dir/$tag"
    local args=(--repeat "$repeat" -a 'hs-sync-*')
    if [[ $tag == on ]]; then
        args=(--repeat "$repeat" -a '*')
    fi
    if $smoke; then
        args=(--repeat 1 -c 1 -w 4 --device-mode inline)
    fi
    LD_LIBRARY_PATH="$variant${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    DYLD_LIBRARY_PATH="$variant${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
        python3 "$repo/testcode/benchmark/async_perf/run_async_perf.py" \
        --server "$variant/testcode/benchmark/async_perf/openhitls_async_benchmark" \
        --client "$variant/testcode/benchmark/async_perf/openhitls_async_client" \
        "${args[@]}" "${pin[@]}" --provider-path "$variant/provider" \
        --cert-dir "$repo/testcode/testdata/tls/certificate/der" --out "$out_dir/$tag"
}

build_variant off OFF
run_variant off
build_variant on ON
run_variant on
