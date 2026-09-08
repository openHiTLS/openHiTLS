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
- Follow the Constant-Time Guidelines below on any path touching keys, MACs, or decrypted data; a passing test suite does not prove absence of side channels

## Definition of Done

A task is only complete when **all** of the following hold:

1. **Library builds clean**: `(cd build && make -j)` succeeds with no new warnings — compare the build log against a pre-change baseline, and never silence a warning with `-Wno...` or `#pragma` to satisfy this. Rebuild also whenever source changes out-of-band from your edits (notably after `git stash` / `git stash pop`) — do this before running any test.
2. **Affected SDV suite passes**: relevant `execute_sdv.sh` invocation reports PASS for every case you touched (SKIP is acceptable only when guarded by `SKIP_TEST()` for a genuinely unrelated disabled feature; FAIL is never acceptable).
3. **Formatting is stable**: `clang-format --dry-run --Werror <changed files>` reports no errors (non-mutating; `git diff` cannot verify this while edits are unstaged).
4. **Secret-data hygiene** (whenever touching crypto / key / MAC / password paths): no `memcmp` on secret-derived data, no secret-dependent early exits, no secret-dependent array indices (see Constant-Time Guidelines).
5. **Error-stack discipline**: errors are pushed exactly once at the first production site; callees that already pushed must be wrapped with `GOTO_ERR_IF_EX`, not `GOTO_ERR_IF`.
6. **No unauthorized commits**: do not `git add` / `git commit` / `git push` or open a PR unless the user explicitly asks. When asked, follow the commit-message conventions linked in `CONTRIBUTING-zh.md`; PRs enter review only after the CI pipeline passes.

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
The `no-<component>` flags disable building that component's tests to save time — pick them to match what you are **not** touching:

| Flag | Effect |
|------|--------|
| `no-crypto` | Skip crypto tests |
| `no-tls` | Skip TLS tests |
| `no-pki` | Skip PKI tests |
| `no-auth` | Skip auth tests |
| `no-bsl` | Skip BSL tests |
| `no-demos` | Do not build demo programs |

So `no-tls no-pki no-demos` is right for a PAKE (auth) fix; for an RSA (crypto) fix use `no-tls no-pki no-auth no-demos` instead. Blindly copying the example flags without checking the component will silently skip the suite you need.

### Single Test Case (faster iteration)
Pass the case name (the `@test` ID, e.g. `SDV_CRYPT_EAL_SPAKE2PLUS_TC001`) to `execute_sdv.sh` — it locates the owning suite automatically — or run the suite binary directly with the case name as its argument:
```bash
(cd testcode/script && bash execute_sdv.sh SDV_CRYPT_EAL_SPAKE2PLUS_TC001)
# or
(cd testcode/output && ./test_suite_sdv_pake SDV_CRYPT_EAL_SPAKE2PLUS_TC001)
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
- Push errors to the BSL error stack at the point where the error is first produced; avoid duplicate pushes when the callee already pushed the error
- Use `goto ERR` cleanup pattern for functions that allocate resources:
  ```c
  int32_t ret;
  Foo *a = NULL;
  Bar *b = NULL;
  a = Create(...);
  GOTO_ERR_IF(SomeOp(a), ret);       // pushes error + goto ERR
  GOTO_ERR_IF_EX(OtherOp(a), ret);   // goto ERR without pushing (callee already pushed)
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

- Apply these rules whenever values may depend on private keys, plaintext, MACs, passwords, shared secrets, decapsulation results, or other secret-derived data
- Use `ConstTimeMemcmp` (from `bsl_bytes.h`) instead of `memcmp` for any comparison involving secret-derived data (MAC tags, decrypted plaintext, password-derived keys)
- `ConstTimeMemcmp` returns `0xffffffff` on match, `0` on mismatch (inverted vs `memcmp`)
- Use `Uint32ConstTimeIsZero`, `Uint32ConstTimeEqual`, `Uint32ConstTimeSelect`, `Uint8ConstTimeSelect` (from `bsl_bytes.h`) for secret-dependent conditionals
- Loop bounds touching secret data must use public upper bounds (e.g. `params->t`) with masked accumulation rather than secret-dependent early exit
- Memory access addresses must be independent of secret values — replace secret-keyed table indexing with the library's constant-time selection/gather patterns (`Uint32ConstTimeSelect` in `crypto/rsa/src/rsa_padding.c`, `ECP256_Gatherw5` in `crypto/ecc/src/asm_ecp_nistp256.c`, `MASK_LOW32` in `crypto/curve25519/src/curve25519_op.c`)

## Architecture Notes

- `HITLS_CRYPTO_RSA_BLINDING` is a CMake compile-time option (default OFF); SDV tests inherit whether it is enabled from the library build
- `CRYPT_RSA_BLINDING` is a runtime flag on `CRYPT_RSA_Ctx->flags`; blinding needs a public exponent — `RSA_InitBlind` (`crypto/rsa/src/rsa_encdec.c`) derives `e` from `d`, `p`, `q` via `RSA_GetPublicExp` when `prvKey->e` is unset, so pre-set `e` (via `SetRsaPrvKeyEx`) only when derivation fails
- RSA SDV tests that enable blinding need deterministic test RNG setup before the operation
- `MontMulBin` / `MontMulBinCore` use `mont->t` internally as scratch buffer; never pass `mont->t` as output parameter to `MontMulBin`

## SDV Test Data Format

Test cases live in `.data` files under `testcode/sdv/testcase/`. Each case is two lines — a free-form description followed by `TEST_FUNCTION_NAME:param1:param2:"hex_string":integer` (strings hex-encoded in double quotes, integers/enums bare, blank line between cases). The function name must match a `/* BEGIN_CASE */` function in the suite's `.c`. Test framework overview: `docs/en/4_User Guide/2_Test Guide.md`.

## Adding a New Test

Each SDV suite is a triple under `testcode/sdv/testcase/<component>/<module>/`: `<suite>.base.c` (`main()` + framework init + shared stubs), `<suite>_<group>.c` (test functions for one group), `<suite>_<group>.data` (rows driving the matching `.c`). A group `.c` declares its base via `/* INCLUDE_BASE <suite> */` immediately after the license header. To add a case:

1. **Write the test function** in the group `.c`, wrapped in `/* BEGIN_CASE */ ... /* END_CASE */`. The function name **must equal** the first field of the `.data` row. Header style: `@brief` describes the main test flow + test point in 1–3 sentences (not every ASSERT, not routine plumbing); `@expect` is a one-line outcome; `@precon` writes `nan` if nothing special. Shape (copy the full working example from `testcode/sdv/testcase/crypto/hkdf/test_suite_sdv_eal_kdf_hkdf.c`, case `SDV_CRYPT_EAL_KDF_HKDF_FUN_TC001`):
   ```c
   /* BEGIN_CASE */
   void SDV_CRYPT_EAL_KDF_HKDF_FUN_TC001(int algId, Hex *key, Hex *salt, Hex *info, Hex *result)
   {
       if (IsHmacAlgDisabled(algId)) {
           SKIP_TEST();
       }
       CRYPT_EAL_KdfCtx *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
       ASSERT_TRUE(ctx != NULL);
       /* set params via BSL_PARAM_InitValue + CRYPT_EAL_KdfSetParam, derive,
          then ASSERT_COMPARE against the expected vector — see the reference file */
   EXIT:
       CRYPT_EAL_KdfFreeCtx(ctx);
   }
   /* END_CASE */
   ```
2. **Add one or more rows** to the matching `.data` file (format above). The first field **must** match the function name from step 1 — a typo produces a silent "function not found" at run time.
3. **ASSERT macros** (`testcode/framework/include/test.h`): `ASSERT_TRUE` / `ASSERT_EQ` / `ASSERT_NE` / `ASSERT_LT` (value checks, `goto EXIT` on failure); `ASSERT_COMPARE` (byte-buffer diff); `SKIP_TEST()` (mark skipped — **must** replace bare `return` when a feature is disabled, else it is misreported as PASS).
4. **Build & run**: rebuild library, then `(cd testcode/script && bash build_sdv.sh run-tests="<suite_stem>" && bash execute_sdv.sh <suite_stem>)`; verify PASS (or guarded SKIP) in `testcode/output/result.log`. For a brand-new suite, copy an existing triple (e.g. `testcode/sdv/testcase/crypto/rsa/`).
