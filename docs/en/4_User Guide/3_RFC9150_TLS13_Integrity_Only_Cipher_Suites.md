# RFC 9150: TLS 1.3 Integrity-Only Cipher Suites (TLS_SHA256_SHA256 / TLS_SHA384_SHA384)

This guide explains how to **build, configure, and verify** the RFC 9150 integrity-only TLS 1.3 cipher suites in openHiTLS, and points to **automated tests** and **demo programs** in the tree.

## 1. CMake options

Record protection uses **HMAC** under **TLS 1.3**. Enable the feature with:

- `HITLS_TLS_SUITE_CIPHER_TLS13_INTEGRITY=ON`
- Plus: `HITLS_TLS_SUITE_KX_ECDHE`, at least one of `HITLS_TLS_SUITE_AUTH_*` (e.g. RSA/ECDSA/PSK), and `HITLS_TLS_PROTO_TLS13`.

Example (full profile + integrity):

```bash
cd openHiTLS
git submodule update --init platform/Secure_C
mkdir -p build && cd build
cmake .. -DHITLS_BUILD_PROFILE=full -DHITLS_TLS_SUITE_CIPHER_TLS13_INTEGRITY=ON -DHITLS_BUILD_GEN_INFO=ON
make -j
```

After configuration, `build/macros.txt` should contain `-DHITLS_TLS_SUITE_TLS_SHA256_SHA256` and related macros.

## 2. SDV tests

With the main library built and `build/macros.txt` present:

```bash
cd testcode
bash script/build_sdv.sh 'run-tests=test_suite_sdv_tls_rfc9150|test_suite_sdv_frame_tls_rfc9150' no-demos
cd output
./test_suite_sdv_tls_rfc9150
./test_suite_sdv_frame_tls_rfc9150
```

The frame suite covers handshake + application data for both suites and a **negative test** that flips a MAC byte and expects `bad_record_mac`.

## 3. Demo programs

Sources: [testcode/demo/rfc9150_server.c](../../../testcode/demo/rfc9150_server.c), [testcode/demo/rfc9150_client.c](../../../testcode/demo/rfc9150_client.c). They use TLS 1.3 config and only `HITLS_TLS_SHA256_SHA256`, listening on **127.0.0.1:12346**.

Build (pass the same `CUSTOM_CFLAGS` as the main library, e.g. from `build/macros.txt`):

```bash
cd testcode/demo
rm -rf build && mkdir build && cd build
CUSTOM_CFLAGS=$(tr '\n' ' ' < ../../../build/macros.txt)
cmake -DCUSTOM_CFLAGS="$CUSTOM_CFLAGS -D__FILENAME__=__FILE__" ..
make -j rfc9150_server rfc9150_client
```

Run the server first, then the client. Test certificates are under `testcode/testdata/tls/certificate/der/ecdsa_sha256/`, same as the stock `client.c` / `server.c` demos.

## 4. Security note

These suites provide **no confidentiality**. Use only where the threat model explicitly allows plaintext on the wire.

## 5. References

- [RFC 9150](https://www.rfc-editor.org/rfc/rfc9150.html)  
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) (TLS 1.3)  
- [RFC 6234](https://www.rfc-editor.org/rfc/rfc6234.html) (SHA/HMAC)  
