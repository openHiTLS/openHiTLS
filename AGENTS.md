# openHiTLS

openHiTLS is a C cryptographic and TLS library licensed under Mulan PSL v2. It provides symmetric/asymmetric cryptography, hash, KDF, TLS 1.2/1.3, X.509 PKI, and post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA, McEliece, FrodoKEM).

This file is for agents modifying openHiTLS source code. Key references: `LICENSE` (Mulan PSL v2), `CONTRIBUTING-zh.md`, `SECURITY.md` (vulnerability reporting). New source files start with the project license header — copy it from any existing `.c` file in the target module.

## Project Structure

| Directory | Description |
|-----------|-------------|
| `crypto/` | Symmetric/asymmetric crypto, hash, MAC, KDF, DRBG, post-quantum (ML-KEM, ML-DSA, FrodoKEM, McEliece, etc.) |
| `crypto/eal/` | Crypto Engine Abstraction Layer — unified API dispatching to algorithm implementations |
| `tls/` | TLS protocol: handshake, record layer, alert, CCS, certificate handling, connection management |
| `pki/` | X.509 certificates, CRL, CSR, PKCS#12, CMS |
| `bsl/` | Base Support Library: ASN.1, Base64, PEM, error stack, logging, buffer, linked list, params |
| `auth/` | Authentication protocols: PAKE (SPAKE2+), OTP, Privacy Pass tokens |
| `codecs/` | Encoding/decoding utilities |
| `apps/` | CLI application (similar to `openssl` command) |
| `include/` | Public API headers, organized by module (`include/crypto/`, `include/tls/`, `include/bsl/`, `include/pki/`, `include/auth/`) |
| `config/` | Provider-config include redirect (`macro_config/hitls_build.h`); build presets live in `cmake/presets/` |
| `testcode/` | SDV tests, benchmarks, build scripts |

## Security

- Suspected vulnerabilities — crypto flaws, memory-safety bugs, timing side channels — must be reported through `SECURITY.md`; never opened as public issues, and PoCs / exploit details must not be pasted into issues, PRs, or test descriptions
- Follow the Constant-Time Guidelines below for production code that handles keys, MACs, or decrypted data; a passing test suite does not prove absence of side channels

## Definition of Done

A task is only complete when **all** of the following hold:

1. **Library builds clean**: `(cd build && make -j)` succeeds with no new warnings — compare the build log against a pre-change baseline, and never silence a warning with `-Wno...` or `#pragma` to satisfy this. Rebuild also whenever source changes out-of-band from your edits (notably after `git stash` / `git stash pop`) — do this before running any test.
2. **Affected SDV suite passes**: relevant `execute_sdv.sh` invocation reports PASS for every case you touched (SKIP is acceptable only when guarded by `SKIP_TEST()` for a genuinely unrelated disabled feature; FAIL is never acceptable).
3. **Secret-data hygiene** (in production code touching crypto / key / MAC / password paths): no `memcmp` on secret-derived data, no secret-dependent early exits, no secret-dependent array indices (see Constant-Time Guidelines).
4. **Error-stack discipline**: push each failure once. If a callee already pushed the returned error, use `GOTO_ERR_IF_EX`; if it did not, push the error at the caller.
5. **No unauthorized commits**: do not `git add` / `git commit` / `git push` or open a PR unless the user explicitly asks. When asked, follow the commit-message conventions linked in `CONTRIBUTING-zh.md`; PRs enter review only after the CI pipeline passes.

If any step is blocked (e.g. test infrastructure unavailable), surface the blocker to the user instead of silently skipping it.

## Build & Test Commands

Default to the helper-script debug build for normal source changes. Use direct CMake only when the user requests specific CMake options or the task requires fine-grained feature selection.

### Full Build (via helper script)
```bash
cd testcode/script && bash build_hitls.sh debug
```

### CMake Build (direct, with fine-grained control)
See `docs/en/4_User Guide/1_Build and Installation Guide.md#31-cmake-build` for full direct-CMake usage, common options, installation, and cross-compilation details.

```bash
mkdir -p build && cd build
cmake .. [options]
make -j
```
Key CMake options:
| Option | Description |
|--------|-------------|
| `-DHITLS_BUILD_PROFILE=full/iso19790/none` | `full` enables all features (default); `none` starts from explicitly supplied feature flags |
| `-DHITLS_CRYPTO_<ALG>=ON/OFF` | Enable/disable specific algorithm (e.g. `HITLS_CRYPTO_RSA`, `HITLS_CRYPTO_SM4`) |
| `-DHITLS_ASM_<ARCH>=ON` | Enable assembly for one architecture: `HITLS_ASM_ARMV8` / `HITLS_ASM_ARMV7` / `HITLS_ASM_X8664` / `HITLS_ASM_X8664_AVX512` / `HITLS_ASM_RISCV64`. No auto-detect switch exists; `build_hitls.sh` sets the matching switch per target |

See `cmake/hitls_options.cmake` for the exhaustive option list. To add a new feature macro, edit that file; CMake then generates the runtime build header at `${CMAKE_BINARY_DIR}/config/hitls_build_config.h` from `cmake/config.h.in` (`config/macro_config/hitls_build.h` is only a static redirect for provider configuration).

### Cross-compile / Incremental Build
- Cross-compile: `cd testcode/script && bash build_hitls.sh armv8_le`
- Incremental (after source changes): `cd build && make -j`

### Full SDV Test Suite
```bash
cd testcode/script && bash build_hitls.sh debug && bash build_sdv.sh && bash execute_sdv.sh
```

### Test Scope Selection
- For narrow changes, rebuild the library and run the most relevant single SDV suite first.
- For public API changes, shared crypto/TLS logic, or cross-module behavior changes, run the affected suites and consider the full SDV suite.
- For build-system, feature-macro, or platform-specific changes, verify the corresponding build profile or cross-compile target.

### Single SDV Test Suite
`run-tests` accepts the `.data` filename stem (without path or extension). Use `|` to specify multiple suites.
```bash
# Step 1: rebuild library if source changed
(cd build && make -j)
# Step 2: build & run one suite (use | in run-tests to add more; drop the no-<comp> flags you don't need)
(cd testcode/script && bash build_sdv.sh no-demos no-tls no-pki run-tests="test_suite_sdv_pake" && bash execute_sdv.sh test_suite_sdv_pake)
```
Use `no-crypto`, `no-tls`, `no-pki`, `no-auth`, and `no-bsl` to omit tests for untouched components; `no-demos` omits demo programs. See `bash build_sdv.sh --help` for details. Use `no-*` flags only for components outside the change scope; do not copy the example blindly.

### Single Test Case (faster iteration)
Pass the case name (the `@test` ID, e.g. `SDV_CRYPT_EAL_SPAKE2PLUS_TC001`) to `execute_sdv.sh`; it locates the owning suite automatically.
```bash
(cd testcode/script && bash execute_sdv.sh SDV_CRYPT_EAL_SPAKE2PLUS_TC001)
```

### Discovering Available Suites
Test suites are discovered from `.data` files under `testcode/sdv/testcase/`. List them portably (works on both Linux and macOS):
```bash
find testcode/sdv/testcase -name "*.data" | sed 's|.*/||; s|\.data$||'
```

### Performance Tests
Build & run benchmarks (see `testcode/benchmark/README.md` for full selector syntax):
```bash
cmake -B build-benchmark -DHITLS_BUILD_BENCHMARK=ON && make -C build-benchmark -j openhitls_benchmark
./build-benchmark/testcode/benchmark/openhitls_benchmark -a 'sm2*'   # -a <glob>, -t N iters, -s N secs
```

## Error Handling

- Most operation-style APIs return `int32_t`: `CRYPT_SUCCESS` (0) or `HITLS_SUCCESS` (0) on success, and a specific error code on failure. Constructor/new APIs commonly return pointers and use `NULL` for failure; free/deinit callbacks commonly return `void`.
- Error codes: `include/crypto/crypt_errno.h` (crypto), `include/tls/hitls_error.h` (TLS)
- `GOTO_ERR_IF` pushes the returned error; `GOTO_ERR_IF_EX` skips the push when the callee already pushed it. Both jump to `ERR` on failure.
- Use `goto ERR` cleanup pattern for functions that allocate resources:
  ```c
  int32_t ret;
  Foo *a = NULL;
  Bar *b = NULL;
  a = Create(...);
  GOTO_ERR_IF(SomeOp(a), ret);       // use when SomeOp returns failure without pushing it
  GOTO_ERR_IF_EX(OtherOp(a), ret);   // use when OtherOp already pushed its failure
  // ... success path ...
  ERR:
      Destroy(a);
      Destroy(b);
      return ret;
  ```
- Helper macros (defined in `crypto/include/crypt_utils.h`): `GOTO_ERR_IF` / `GOTO_ERR_IF_EX` (as in the example above), plus `RETURN_RET_IF(cond, ret)` and `RETURN_RET_IF_ERR(func, ret)` for the push-then-return variants.

## Memory Management

- In library code (`crypto/`, `tls/`, `bsl/`, `pki/`, `auth/`, `codecs/`, `apps/`): use `BSL_SAL_Malloc(size)` / `BSL_SAL_Calloc(num, size)` — never raw `malloc`/`calloc`. SDV test code under `testcode/` may use plain `malloc`/`free`
- Use `BSL_SAL_FREE(ptr)` macro to free (calls `BSL_SAL_Free` + sets pointer to NULL)
- For sensitive data: call `BSL_SAL_CleanseData(ptr, size)` before freeing, or use `BSL_SAL_ClearFree(ptr, size)` which combines both
- All declared in `include/bsl/bsl_sal.h`

## Naming Conventions

| Scope | Prefix | Example |
|-------|--------|---------|
| Public crypto API | `CRYPT_EAL_` | `CRYPT_EAL_CipherNewCtx` |
| Internal crypto | `CRYPT_` + module | `CRYPT_RSA_PubEnc`, `CRYPT_SM2_Sign` |
| Public TLS API | `HITLS_` | `HITLS_Connect`, `HITLS_Accept` |
| BSL utilities | `BSL_` | `BSL_SAL_Malloc`, `BSL_ERR_PUSH_ERROR` |
| BigNum | `BN_` | `BN_Create`, `BN_MontExp` |
| PKI | `HITLS_X509_` / `HITLS_CMS_` | `HITLS_X509_CertVerify` |
| Auth | `HITLS_AUTH_` | `HITLS_AUTH_PakeNewCtx` |
| Error codes (crypto) | `CRYPT_` | `CRYPT_NULL_INPUT`, `CRYPT_MEM_ALLOC_FAIL` |
| Error codes (TLS) | `HITLS_` | `HITLS_NULL_INPUT` |
| Feature macros | `HITLS_CRYPTO_` / `HITLS_TLS_` | `HITLS_CRYPTO_RSA`, `HITLS_TLS_FEATURE_PSK` |

- Files: `module_purpose.c` (e.g. `rsa_encdec.c`, `rsa_keygen.c`, `sm2_crypt.c`)
- New source files should follow the surrounding module's structure: the project license header first, then `#include "hitls_build.h"`, then the matching module or feature guard (for example `HITLS_CRYPTO_XXX`, `HITLS_TLS_FEATURE_XXX`, `HITLS_PKI_XXX`, or `HITLS_AUTH_XXX`).

## Code Style

- Avoid new comments unless they clarify non-obvious logic or are explicitly requested
- Follow existing conventions in each file
- Use `ALIGN32` / `ALIGN64` for stack-allocated field element arrays, sized to the algorithm's worst case rather than the input length
- Always close `#if` / `#ifdef` with `#endif` at end of file; ensure file ends with a newline
- Documentation changes in `docs/en/` must be mirrored in `docs/zh/` (localized filenames), and vice versa
- `.clang-format` exists at project root — all code should conform to it; new files must be formatted with `clang-format -i` before committing

## Common Pitfalls / Anti-patterns

- **Public ABI leaks**: do not add fields to public structs (e.g. `CRYPT_EAL_LibCtx`, `HITLS_Ctx`) or change signatures of `HITLS_*` / `CRYPT_EAL_*` functions. The public API surface is stable.
- **Silent test skip**: a test that does `if (disabled) return;` is reported as PASS. Always call `SKIP_TEST()` so the report distinguishes pass / skip / fail.

## Constant-Time Guidelines

- Apply these rules to production code when values may depend on private keys, plaintext, MACs, passwords, shared secrets, decapsulation results, or other secret-derived data; these rules do not prescribe comparison APIs for test code
- In production code, use `ConstTimeMemcmp` (from `bsl_bytes.h`) instead of `memcmp` for comparisons involving secret-derived data. Use ordinary comparisons for public or non-sensitive data, and normal assertions or comparisons in `testcode/`
- `ConstTimeMemcmp` returns `0xffffffff` on match, `0` on mismatch (inverted vs `memcmp`)
- Use `Uint32ConstTimeIsZero`, `Uint32ConstTimeEqual`, `Uint32ConstTimeSelect`, `Uint8ConstTimeSelect` (from `bsl_bytes.h`) for secret-dependent conditionals
- Loop bounds touching secret data must use public upper bounds (e.g. `params->t`) with masked accumulation rather than secret-dependent early exit
- Memory access addresses must be independent of secret values — replace secret-keyed table indexing with the library's constant-time selection/gather patterns (`Uint32ConstTimeSelect` in `crypto/rsa/src/rsa_padding.c`, `ECP256_Gatherw5` in `crypto/ecc/src/asm_ecp_nistp256.c`, `MASK_LOW32` in `crypto/curve25519/src/curve25519_op.c`)

## SDV Test Data Format

Test cases live in `.data` files under `testcode/sdv/testcase/`. Each case is two lines — a free-form description followed by `TEST_FUNCTION_NAME:param1:param2:"hex_string":integer` (strings hex-encoded in double quotes, integers/enums bare, blank line between cases). The function name must match a `/* BEGIN_CASE */` function in the suite's `.c`. Test framework overview: `docs/en/4_User Guide/2_Test Guide.md`.

## Adding a New Test

Each SDV suite has a `.base.c`, a group `.c`, and a `.data` file under `testcode/sdv/testcase/<component>/<module>/`. The group file includes its base with `/* INCLUDE_BASE <suite> */`.

1. Add a function wrapped in `/* BEGIN_CASE */ ... /* END_CASE */`. Its name **must match** the first field in `.data`; otherwise, the test is not found. Use the `@brief`, `@expect`, and `@precon` fields. See `testcode/sdv/testcase/crypto/hkdf/test_suite_sdv_eal_kdf_hkdf.c` for a working example.
   ```c
   /* BEGIN_CASE */
   void TEST_NAME(...)
   {
       if (featureDisabled) {
           SKIP_TEST();
       }
       /* Run operation and assert result. */
   }
   /* END_CASE */
   ```
2. Add matching rows to `.data`. Use assertions from `testcode/framework/include/test.h`; use `SKIP_TEST()` instead of bare `return` for disabled features.
3. Build and run: `(cd testcode/script && bash build_sdv.sh run-tests="<suite_stem>" && bash execute_sdv.sh <suite_stem>)`. Confirm PASS or guarded SKIP in `testcode/output/result.log`. For a new suite, copy an existing triple, e.g. `testcode/sdv/testcase/crypto/rsa/`.
