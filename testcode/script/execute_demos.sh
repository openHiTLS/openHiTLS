#!/usr/bin/env bash
# This file is part of the openHiTLS project, licensed under the Mulan PSL v2.
# Run every demo from the current source tree, including client/server pairs.
set -u

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
HITLS_ROOT_DIR=$(cd "${SCRIPT_DIR}/../.." && pwd)
DEMO_DIR="${HITLS_ROOT_DIR}/testcode/demo"

if [[ ${1:-} == "--help" || ${1:-} == "help" ]]; then
    echo "Usage: bash $0 [build-directory]"
    exit 0
fi
if (( $# > 1 )); then
    echo "Expected at most one build directory" >&2
    exit 1
fi
BUILD_DIR=${1:-${DEMO_DIR}/build}
if [[ $# == 0 && ! -d ${BUILD_DIR} ]]; then
    BUILD_DIR="${HITLS_ROOT_DIR}/testcode/build/demo"
fi
BUILD_DIR=$(cd "${BUILD_DIR}" && pwd) || exit 1

# Source inventory detects incomplete builds and ignores stale executables.
shopt -s nullglob
sources=("${DEMO_DIR}"/*.c)
if (( ${#sources[@]} == 0 )); then
    echo "No demo sources found" >&2
    exit 1
fi
missing=0
for source in "${sources[@]}"; do
    name=$(basename "${source}" .c)
    if [[ ! -x ${BUILD_DIR}/${name} ]]; then
        echo "[FAIL] Missing executable: ${BUILD_DIR}/${name}" >&2
        missing=$((missing + 1))
    fi
done
if (( missing > 0 )); then
    echo "Build demos first: bash testcode/script/build_sdv.sh asan demos" >&2
    exit 1
fi

LOG_DIR=$(mktemp -d "${BUILD_DIR}/demo-logs.XXXXXX") || exit 1
WORK_DIR="${LOG_DIR}/work"
mkdir "${WORK_DIR}" || exit 1
ln -s "${DEMO_DIR}/assets" "${WORK_DIR}/assets" || exit 1
export LD_LIBRARY_PATH="${HITLS_ROOT_DIR}/build${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
if [[ $(uname) == Darwin ]]; then
    export DYLD_LIBRARY_PATH="${HITLS_ROOT_DIR}/build${DYLD_LIBRARY_PATH:+:${DYLD_LIBRARY_PATH}}"
fi
# A sanitizer diagnostic must produce a failing process exit status.
ASAN_BASE="${ASAN_OPTIONS:-}:detect_stack_use_after_return=1:strict_string_checks=1:detect_leaks=1:halt_on_error=1:exitcode=1"
active_pids=()
cleanup()
{
    local pid
    for pid in "${active_pids[@]}"; do
        kill "${pid}" 2>/dev/null || true
    done
    for pid in "${active_pids[@]}"; do
        wait "${pid}" 2>/dev/null || true
    done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
passed=0
failed=0

record_result()
{
    local name=$1 rc=$2 diagnostic
    if (( rc == 0 )); then
        echo "[PASS] ${name}"
        passed=$((passed + 1))
    else
        echo "[FAIL] ${name} (exit ${rc}; log: ${LOG_DIR}/${name}.log)"
        tail -n 20 "${LOG_DIR}/${name}.log"
        for diagnostic in "${LOG_DIR}/${name}.asan"*; do
            echo "Sanitizer report: ${diagnostic}"
            head -n 20 "${diagnostic}"
        done
        failed=$((failed + 1))
    fi
}

start_demo()
{
    local name=$1 work_dir=$2
    shift 2
    (
        cd "${work_dir}" || exit 1
        export ASAN_OPTIONS="${ASAN_BASE}:log_path=${LOG_DIR}/${name}.asan"
        exec "$@"
    ) >"${LOG_DIR}/${name}.log" 2>&1 &
    demo_pid=$!
    active_pids+=("${demo_pid}")
}

run_demo()
{
    local name=$1 work_dir=$2 rc
    shift 2
    start_demo "${name}" "${work_dir}" "$@"
    wait "${demo_pid}"
    rc=$?
    active_pids=()
    record_result "${name}" "${rc}"
}

run_pair()
{
    local server=$1 client=$2 work_dir=$3 server_pid client_pid server_rc client_rc
    start_demo "${server}" "${work_dir}" "${BUILD_DIR}/${server}"
    server_pid=${demo_pid}
    # These one-connection servers must not be probed with an extra connection.
    sleep 1
    start_demo "${client}" "${work_dir}" "${BUILD_DIR}/${client}"
    client_pid=${demo_pid}
    wait "${client_pid}"
    client_rc=$?
    if (( client_rc != 0 )); then
        kill "${server_pid}" 2>/dev/null || true
    fi
    wait "${server_pid}"
    server_rc=$?
    active_pids=()
    record_result "${server}" "${server_rc}"
    record_result "${client}" "${client_rc}"
}

echo "Demo logs: ${LOG_DIR}"
for source in "${sources[@]}"; do
    name=$(basename "${source}" .c)
    case "${name}" in
        example_tlcp_client|example_dtls13_udp_client|example_tls13_rfc9973_client)
            # Accounted for by run_pair, including both exit statuses.
            ;;
        example_tlcp_server)
            run_pair "${name}" example_tlcp_client "${WORK_DIR}"
            ;;
        example_dtls13_udp_server)
            run_pair "${name}" example_dtls13_udp_client "${BUILD_DIR}"
            ;;
        example_tls13_rfc9973_server)
            run_pair "${name}" example_tls13_rfc9973_client "${BUILD_DIR}"
            ;;
        example_es_raw_dump)
            noise_sources=()
            if grep -qx -- '-DHITLS_CRYPTO_ENTROPY_NS_CPUJITTER' "${HITLS_ROOT_DIR}/build/macros.txt"; then
                noise_sources+=(jitter)
            fi
            if grep -qx -- '-DHITLS_CRYPTO_ENTROPY_NS_HASHLOOP' "${HITLS_ROOT_DIR}/build/macros.txt"; then
                noise_sources+=(hashloop)
            fi
            if (( ${#noise_sources[@]} == 0 )); then
                echo "No built-in noise source enabled" >"${LOG_DIR}/${name}.log"
                record_result "${name}" 1
            fi
            for noise in "${noise_sources[@]}"; do
                run_demo "${name}_${noise}" "${WORK_DIR}" "${BUILD_DIR}/${name}" \
                    "${noise}" seq "${WORK_DIR}/${noise}.raw" 1000 lsb8
            done
            ;;
        example_entropy_dump)
            conditioner=sha3_256_df
            if grep -qx -- '-DHITLS_CRYPTO_ENTROPY_GM_CF' "${HITLS_ROOT_DIR}/build/macros.txt"; then
                conditioner=sm3_df
            fi
            run_demo "${name}" "${WORK_DIR}" "${BUILD_DIR}/${name}" \
                "${WORK_DIR}/entropy.bin" 1 "${conditioner}" drbg
            ;;
        *)
            run_demo "${name}" "${WORK_DIR}" "${BUILD_DIR}/${name}"
            ;;
    esac
done
echo "Demo summary: Pass=${passed} Fail=${failed}; logs: ${LOG_DIR}"
(( failed == 0 ))
