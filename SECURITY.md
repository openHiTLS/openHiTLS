# openHiTLS Security Policy

Canonical URL: https://gitcode.com/openHiTLS/openhitls/blob/main/SECURITY.md

This document defines openHiTLS's **security scope** (§1) and **side-channel
commitments** (§2). Vulnerability reporting, severity assessment, and
coordinated disclosure are outside its scope; see the project's official
[vulnerability management page](https://www.openhitls.net/zh/support/vulnerability-management.html)
(in Chinese).

> **Note:** A Chinese translation is available at
> [`SECURITY_zh.md`](SECURITY_zh.md) for convenience. If the two versions
> diverge, this English version is authoritative.

---

## 1. Scope

### 1.1 Components in scope

This policy covers **all production code shipped in this repository** —
including the cryptographic engine (`crypto/`), protocol implementations
(`tls/`), PKI processing (`pki/`), base support library (`bsl/`),
authentication protocols (`auth/`), public headers (`include/`), and the
`openhitls` command-line tool (`apps/`, subject to §1.3). Modules added
to this repository in the future are automatically in scope.

### 1.2 Vulnerability classes in scope

We will treat the following as candidate vulnerabilities:

- **Memory safety** in any code path reachable from attacker-controlled input:
  buffer overflow, underflow, out-of-bounds read/write, use-after-free,
  double-free, null-pointer dereference, uninitialized read, type confusion.
- **Cryptographic correctness flaws**: broken signature verification, MAC
  forgery, weak key generation, nonce reuse, KEM decapsulation failure
  handling.
- **Protocol-level flaws** in TLS 1.2 / 1.3 / TLCP / DTLCP: state machine
  confusion, cross-protocol attack, downgrade, certificate verification
  bypass, premature handshake completion, misuse of extensions.
- **PKI processing flaws**: X.509 / CSR / CRL / PKCS#12 / CMS parsers
  crashing, looping, leaking memory, or accepting malformed structures that
  should be rejected.
- **Side channels** in code that handles secret-derived data, as detailed in
  §2.
- **Input validation** failures that let attacker-supplied data corrupt
  internal state.

### 1.3 Out-of-scope impacts

The following impact classes are **outside our threat model** and will not
receive a CVE, although we may still fix them as ordinary bugs:

1. **Denial of service that affects only the `openhitls` CLI tool itself**
   — for example, crashing any CLI subcommand via an unhandled signal,
   exhausting memory in the CLI front-end, hanging on a malformed input
   file, or printing incorrect output to stdout without cryptographic
   consequence. The CLI is intended for interoperability testing, key
   generation, and operator use; it is not a production server or a
   long-running service. A vulnerability that affects both the CLI and the
   libraries is in scope for the library impact; only the impact that is
   exclusive to the CLI itself is excluded.
2. **API misuse** where the application calls a function in a way that the
   API contract explicitly forbids, or where the API is not designed to
   receive attacker-controlled input. Documented preconditions in headers
   and docstrings are part of the contract.
3. **Same-system timing side channels** where the attacker must already run
   code on the same physical host (see §2 for the granularity we do cover).
4. **Physical attacks** — power analysis, EM emission, fault injection,
   glitching, etc. — require platform-level mitigations.
5. **CPU / microarchitecture / hardware flaws** (e.g. Spectre-class, Rowhammer,
   unreliable DRAM, broken RNG sources). We will respond to such reports as
   hardening requests, not as openHiTLS CVEs.
6. **Attacks that require prior code execution on the host**, kernel-level
   compromise, arbitrary memory write, or a compromised trust anchor (lying CA,
   misbehaving HSM, or malicious third-party crypto module). A wrong trust
   decision caused by a broken trust anchor is the expected consequence of a
   broken trust anchor, not a vulnerability in openHiTLS.
7. **Denial of service achievable by simply killing the process** (e.g.
   `kill -9`, OOM killer, exhausting file descriptors without memory
   corruption), and other attacks whose impact is no greater than what the
   operator could already do to themselves.
8. **Resource exhaustion from spec-compliant inputs** where the upstream
   specification defines no maximum for the parameter in question (e.g., KDF
   iteration count, recursion depth). The impact is platform-dependent;
   deployers handling untrusted input must enforce their own upper bounds.
9. **Vulnerabilities introduced by a downstream patch** that is not present
   in this repository (e.g. a distro-specific patch). Report those to the
   downstream vendor.

A report whose only impact falls into §1.3 will be acknowledged, classified
as out-of-scope or as a regular bug, and may still be fixed publicly — just
not via the CVE / embargo track.

---

## 2. Side-channel commitment

openHiTLS handles secret-derived data (private keys, plaintext, MAC tags,
session keys, KEM decapsulation results, PAKE transcripts) and is committed
to **constant-time programming** for those code paths.

### 2.1 What we promise

- **No secret-dependent control flow** in cryptographic primitives: loop
  bounds and branch conditions do not depend on secret data.
- **No secret-dependent memory access**: array indices and table lookups do
  not depend on secret data in a way that could leak it.
- **Constant-time comparison** for any secret-derived buffer, with no
  early exit on the first mismatched byte.
- **Network-observable timing**: we treat exploitable timing variations
  visible to a remote attacker, on common compilers at common optimization
  levels (`-O2`, `-Os`), as a vulnerability. The same applies to physical
  timing observation that the platform cannot reasonably mitigate.

### 2.2 What we do not promise

- **Same-process microarchitectural side channels** (L1/L2/L3 cache, BTB,
  TLB, memory bus contention, port contention) exploitable only by an
  attacker running code on the same physical core / socket. These require
  OS / hypervisor / hardware mitigations.
- **Power, EM, acoustic, thermal emissions** as observed via physical
  sensors. Use a TEE, HSM, or shielded environment if your threat model
  includes them.
- **Fault injection** — glitching the clock, voltage, laser, etc. Hardening
  may be added over time but its absence is not a vulnerability.
- **Timing variations visible only under uncommon compiler / compiler-option
  combinations** (`-O3`, `-Oz`, LTO, auto-vectorization enabled at unusual
  flags, proprietary compilers). We recommend compiling with `-O2` or `-Os`
  for security-sensitive builds.
- **Side channels in third-party modules** that the deployer chooses to
  load at runtime.

### 2.3 Post-quantum caveat

Post-quantum algorithms are implementations of relatively recent NIST
standards / candidates. Their side-channel analysis literature is still
maturing. While we apply our standard constant-time rules to their code,
we cannot guarantee that no future, currently-undocumented attack
technique will apply. We will treat any **publicly documented**
side-channel technique against these algorithms as a vulnerability and
respond accordingly.

---

## 3. Policy versioning

This policy may be updated. Material changes to the scope or side-channel
commitments will be announced through the project's official channels.
The latest version is always the one on the `main` branch of this repository.
