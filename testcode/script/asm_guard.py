#!/usr/bin/env python3
# This file is part of the openHiTLS project.
#
# openHiTLS is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#     http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
"""Conservative source and object checks for hand-written assembly.

Usage:
    python3 testcode/script/asm_guard.py              scan sources and build/ objects
    python3 testcode/script/asm_guard.py --verbose    also print WARN, INFO, and a summary
    python3 testcode/script/asm_guard.py --source-only  skip object inspection (incomplete checks)
    python3 testcode/script/asm_guard.py --objects DIR  inspect given object files or directories
    python3 testcode/script/asm_guard.py --pp         scan clang-preprocessed sources

The exit code is 1 when any ERROR finding exists, 0 otherwise. WARN and INFO
never change it. Without --verbose only ERROR findings print. An assembly
object set is required unless --source-only is given, so a source-only scan
cannot look like a complete section and symbol check.

Checks:

1. Source scan (.S, .s, .asm): section placement of functions and data,
   local branch targets, function label and size boundaries, CFI directive
   pairing, dot-label hygiene, and data fall-through before function ends.
   ERROR: ASM-SOURCE-READ, ASM-FUNC-NONEXEC, ASM-BRANCH-TARGET.
   WARN: ASM-FUNC-LABEL, ASM-FUNC-SIZE, ASM-CODE-DATA-FALLTHROUGH,
   ASM-LOCAL-LABEL, ASM-CFI-BOUNDARY, ASM-BRANCH-LOCAL-CONVENTION
   (branch target resolves to a bare file-local label instead of a .L
   label or a declared local function).

2. File-level heuristics (first occurrence per kind, WARN):
   ASM-ABI-HEURISTIC (manual ABI review), ASM-STACK-BOUNDS-HEURISTIC (large
   negative stack offset), ASM-ALIGNMENT-HEURISTIC (aligned vector op),
   ASM-CODE-DATA-HEURISTIC (data directive in executable section),
   ASM-CT-BRANCH-HEURISTIC and ASM-CT-ADDRESS-HEURISTIC (possible secret
   dependence; data flow is not analyzed).

3. Per-function control-flow analysis (labels and branch mnemonics):
   ASM-STACK-IMBALANCE (every return or tail branch must restore the entry
   stack depth), ASM-PAC-HEURISTIC (PACIASP/AUTIASP pairing per path),
   ASM-CALLEE-SAVED-HEURISTIC (unsaved writes to callee-saved registers;
   INFO for local bl-only helpers and included files), ASM-STACK-SKIPPED
   (INFO; the analysis could not be completed and says why).

4. Object scan (actual ELF and Mach-O flags and symbols; llvm-readobj
   preferred, readelf ELF-only fallback):
   ERROR: ASM-OBJECT-READ, ASM-OBJECT-FORMAT, ASM-OBJECT-PARSE,
   ASM-FUNC-NONEXEC, ASM-OBJECT-EXEC, ASM-EXEC-STACK, ASM-DUPLICATE-SYMBOL.
   WARN: ASM-FUNC-SIZE, ASM-FUNC-TYPE-MISSING, ASM-LEAKED-LABEL,
   ASM-WRITABLE-OBJECT, ASM-DUPLICATE-WEAK, ASM-STACK-NOTE-MISSING,
   ASM-STACK-HEADER-MISSING. INFO: ASM-SYMBOL-VISIBILITY,
   ASM-UNRESOLVED-EXTERNAL (WARN with --strict-unresolved),
   ASM-MACHO-FUNCTION-METADATA, ASM-STACK-POLICY.

5. Preprocessed scan (--pp, needs clang): ASM-PP-FAIL, ASM-PP-CC-TARGET,
   ASM-PP-CONFIG report preprocessing problems; ASM-OBJECTS-MISSING reports
   a missing object set. Targets come from the file name (aarch64, armv7,
   x86_64, riscv64); override with --pp-targets, --pp-cc, --pp-flag. gcc has
   no --target option; use --pp-cc <cross-gcc> --pp-targets host instead.

Limits: stack, PAC, callee-saved, alignment, fall-through, and constant-time
findings are conservative heuristics, not proofs. Assembler-level .macro
bodies are never expanded. Mach-O lacks ELF-style symbol metadata. COFF/PE
objects are rejected. No ISA-extension or cross-architecture instruction
validation is performed. An assembly build and expert review remain
necessary. Run the regression tests with --self-test.
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable


ASM_SUFFIXES = {".s", ".asm"}
READONLY_NAMES = (
    ".rodata", ".rdata", ".const", ".srodata", ".gnu.linkonce.r.",
    "__const", "__cstring", "__literal4", "__literal8", "__literal16",
    "__ustring", "__gcc_except_tab", "__eh_frame",
)
EXEC_MACH_SECTIONS = {"__text", "__stubs", "__stub_helper", "__auth_stubs"}
RISCV_BRANCH_MNEMONICS = {
    "beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez", "bltz", "bgez",
    "blez", "bgtz", "bgt", "ble", "bgtu", "bleu", "tail",
}
OBJECT_BATCH_SIZE = 64


@dataclasses.dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    path: str
    line: int | None
    message: str

    def render(self) -> str:
        location = self.path
        if self.line is not None:
            location += f":{self.line}"
        return f"{self.severity}: {location}: {self.code}: {self.message}"


@dataclasses.dataclass
class Section:
    name: str
    executable: bool
    writable: bool


@dataclasses.dataclass
class ObjSymbol:
    name: str
    value: int
    size: int
    binding: str
    kind: str
    visibility: str
    section: str
    undefined: bool


@dataclasses.dataclass
class ObjectInfo:
    path: str
    fmt: str
    arch: str
    file_type: str
    sections: dict[str, Section]
    symbols: list[ObjSymbol]
    stack_note: Section | None
    gnu_stack_flags: str


def _blank_dead_if_zero_regions(lines: list[str]) -> list[str]:
    """Blank lines excluded by '#if 0'. An '#else' or '#elif' branch may be live, so scan it."""
    result: list[str] = []
    depth: int | None = None
    for line in lines:
        stripped = line.strip()
        directive = re.match(r"#\s*(if|ifdef|ifndef|elif|else|endif)\b", stripped)
        if depth is None:
            if directive and re.fullmatch(r"#\s*if\s+0+\s*", stripped):
                depth = 0
                result.append("")
            else:
                result.append(line)
            continue
        if directive:
            keyword = directive.group(1)
            if keyword in {"if", "ifdef", "ifndef"}:
                depth += 1
            elif keyword == "endif" and depth == 0:
                depth = None
            elif keyword == "endif":
                depth -= 1
            elif depth == 0:
                depth = None
        result.append("")
    return result


def _strip_comments(lines: list[str]) -> list[str]:
    output = []
    in_block = False
    for line in lines:
        cleaned = []
        i = 0
        while i < len(line):
            if in_block:
                end = line.find("*/", i)
                if end < 0:
                    i = len(line)
                    continue
                in_block = False
                i = end + 2
            elif line.startswith("/*", i):
                in_block = True
                i += 2
            elif line.startswith("//", i):
                break
            else:
                cleaned.append(line[i])
                i += 1
        output.append("".join(cleaned))
    return output


def _split_commas(text: str) -> list[str]:
    result = []
    start = 0
    quoted = False
    for index, char in enumerate(text):
        if char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            result.append(text[start:index].strip())
            start = index + 1
    result.append(text[start:].strip())
    return result


def _section_from_directive(line: str, current: Section) -> Section:
    stripped = line.strip()
    if stripped == "CRYPT_AARCH64_RODATA_SECTION":
        return Section("CRYPT_AARCH64_RODATA_SECTION", False, False)
    if re.match(r"\.text(?:\s|$)", stripped):
        return Section(".text", True, False)
    if re.match(r"\.(?:data|bss)(?:\s|$)", stripped):
        return Section(stripped.split()[0], False, True)
    if re.match(r"\.rodata(?:\s|$)", stripped):
        return Section(".rodata", False, False)

    match = re.match(r"\.(?:pushsection|section)\s+(.+)$", stripped)
    if not match:
        return current
    fields = _split_commas(match.group(1))
    first = fields[0].strip().strip('"') if fields else ""
    second = fields[1].strip().strip('"') if len(fields) > 1 else ""
    if first.startswith("__") and second.startswith("__"):
        name = f"{first},{second}"
        executable = first == "__TEXT" and second in EXEC_MACH_SECTIONS
        writable = first.startswith("__DATA") and not first.startswith("__DATA_CONST")
        return Section(name, executable, writable)

    name = first
    flags = second if second and not second.startswith("@") else ""
    executable = "x" in flags or name == ".text" or name.startswith((".text.", ".init", ".fini"))
    writable = "w" in flags or name in {".data", ".bss"} or name.startswith((".data.", ".bss."))
    if not flags and any(
        name == item or name.startswith(item if item.endswith(".") else item + ".")
        for item in READONLY_NAMES
    ):
        writable = False
    return Section(name, executable, writable)


def _is_local_branch_target(target: str) -> bool:
    return target.startswith(".L") or target.startswith("LBB") or target.startswith("Ltmp")


def _branch_target(line: str) -> str | None:
    text = line.strip()
    if not text or text.startswith((".", "#")) or ":" in text.split()[0]:
        return None
    match = re.match(r"([A-Za-z][A-Za-z0-9_.]*)\s+(.+)$", text)
    if not match:
        return None
    mnemonic, operands = match.groups()
    lower = mnemonic.lower()
    is_branch = (
        lower.startswith("j") or lower.startswith("loop") or lower in {"call", "callq", "bl", "blr"}
        or lower in RISCV_BRANCH_MNEMONICS
        or lower in {"b", "cbz", "cbnz", "tbz", "tbnz"} or bool(re.fullmatch(r"b\.[a-z]+", lower))
        or (re.fullmatch(r"b[a-z]+", lower) and lower[1:] in ARM_CONDS)
    )
    if not is_branch:
        return None
    target = _split_commas(operands)[-1].strip().split()[0].rstrip(",")
    target = target.lstrip("$")
    return target if _is_local_branch_target(target) else None


def _symbolic_branch_target(line: str) -> str | None:
    """Return the symbolic target of a branch or call in any label form."""
    text = line.strip()
    if not text or text.startswith((".", "#")) or ":" in text.split()[0]:
        return None
    match = re.match(r"([A-Za-z][A-Za-z0-9_.]*)\s+(.+)$", text)
    if not match:
        return None
    mnemonic, operands = match.groups()
    lower = mnemonic.lower()
    is_branch = (
        lower.startswith("j") or lower.startswith("loop") or lower in {"call", "callq", "bl", "b"}
        or lower in RISCV_BRANCH_MNEMONICS
        or lower in {"cbz", "cbnz", "tbz", "tbnz"} or bool(re.fullmatch(r"b\.[a-z]+", lower))
        or (re.fullmatch(r"b[a-z]+", lower) and lower[1:] in ARM_CONDS)
    )
    if not is_branch:
        return None
    target = _split_commas(operands)[-1].strip().split()[0].rstrip(",")
    target = target.lstrip("$*")
    return target if re.fullmatch(r"[A-Za-z_.$@][\w.$@]*|\d+[fb]?", target) else None


def included_asm_sources(sources: list[Path]) -> set[Path]:
    """Assembly files pulled into another translation unit by #include."""
    included: set[Path] = set()
    for source in sources:
        try:
            text = source.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in re.finditer(r'^\s*#\s*include\s+"([^"]+\.sS?)"', text, re.MULTILINE | re.IGNORECASE):
            target = (source.parent / match.group(1)).resolve()
            if target != source.resolve():
                included.add(target)
    return included


def audit_source(path: Path, root: Path, may_be_included: bool = False) -> list[Finding]:
    try:
        original = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        return [Finding("ERROR", "ASM-SOURCE-READ", str(path), None, str(error))]
    lines = _blank_dead_if_zero_regions(_strip_comments(original))
    origins = [(str(path), number) for number in range(1, len(lines) + 1)]
    return _scan_assembly(lines, origins, root, may_be_included=may_be_included)


def _relative(path: str, root: Path) -> str:
    try:
        return str(Path(path).relative_to(root))
    except ValueError:
        return path


def _scan_assembly(
    lines: list[str],
    origins: list[tuple[str, int | None]],
    root: Path,
    extra_functions: set[str] | None = None,
    ended_lines: dict[str, int] | None = None,
    extra_local_names: set[str] | None = None,
    may_be_included: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    current = Section(".text", True, False)
    section_stack: list[tuple[Section, Section | None]] = []
    previous_section: Section | None = None
    labels: set[str] = set()
    declared_functions: dict[str, int] = {}
    function_sites: list[tuple[str, int, Section]] = []
    active_functions: dict[str, int] = {}
    size_markers: set[str] = set()
    end_markers: set[str] = set()
    cfi_start = 0
    cfi_end = 0
    branch_targets: list[tuple[int, str]] = []
    symbol_branch_targets: list[tuple[int, str]] = []
    suspicious_ct_branch: int | None = None
    suspicious_ct_index: int | None = None
    abi_signal: int | None = None
    bad_stack_access: int | None = None
    alignment_signal: int | None = None
    embedded_data: int | None = None
    nonlocal_dot_label: tuple[str, int] | None = None
    nonlocal_dot_label_count = 0
    local_function_names: set[str] = set(extra_local_names or [])
    globl_names: set[str] = set()

    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == ".previous":
            if previous_section is not None:
                updated = previous_section
                if current.executable and not updated.executable and active_functions:
                    origin_file, origin_line = origins[number - 1] if number <= len(origins) else ("", None)
                    live = _live_functions(active_functions, ended_lines, origin_line)
                    if live:
                        names = ", ".join(live)
                        findings.append(Finding(
                            "WARN", "ASM-CODE-DATA-FALLTHROUGH", _relative(origin_file, root), origin_line,
                            f"section changes to {updated.name} before source-visible function boundary for {names}; fall-through is not proven",
                        ))
                previous_section, current = current, updated
            continue
        if re.match(r"\.pushsection\b", stripped):
            section_stack.append((current, previous_section))
        if stripped.startswith(".popsection"):
            if section_stack:
                current, previous_section = section_stack.pop()
            continue
        updated = _section_from_directive(stripped, current)
        if updated is not current:
            if current.executable and not updated.executable and active_functions:
                origin_file, origin_line = origins[number - 1] if number <= len(origins) else ("", None)
                live = _live_functions(active_functions, ended_lines, origin_line)
                if live:
                    names = ", ".join(live)
                    findings.append(Finding(
                        "WARN", "ASM-CODE-DATA-FALLTHROUGH", _relative(origin_file, root), origin_line,
                        f"section changes to {updated.name} before source-visible function boundary for {names}; fall-through is not proven",
                    ))
            previous_section, current = current, updated
            continue

        function_type = re.match(r"\.type\s+([^,\s]+)\s*,\s*[%@]?function\b", stripped, re.IGNORECASE)
        if function_type:
            declared_functions[function_type.group(1)] = number
        for macro in ("CRYPT_AARCH64_FUNC_START", "CRYPT_AARCH64_LOCAL_FUNC_START"):
            macro_match = re.search(rf"\b{macro}\s*\(\s*([A-Za-z_.$][\w.$]*)\s*\)", stripped)
            if macro_match:
                name = macro_match.group(1)
                declared_functions[name] = number
                function_sites.append((name, number, current))
                active_functions.clear()
                active_functions[name] = number
                if "LOCAL" in macro:
                    local_function_names.add(name)

        function_end = re.search(r"\bCRYPT_AARCH64_(?:LOCAL_)?FUNC_END\s*\(\s*([A-Za-z_.$][\w.$]*)\s*\)", stripped)
        if function_end:
            end_name = function_end.group(1)
            end_markers.add(end_name)
            active_functions.pop(end_name, None)
        globl_match = re.match(r"\.globl\s+([^\s]+)", stripped)
        if globl_match:
            globl_names.add(globl_match.group(1))
        size_match = re.match(r"\.size\s+([^,\s]+)", stripped)
        if size_match:
            size_name = size_match.group(1)
            size_markers.add(size_name)
            active_functions.pop(size_name, None)
        if re.match(r"\.cfi_startproc\b", stripped):
            cfi_start += 1
        if re.match(r"\.cfi_endproc\b", stripped):
            cfi_end += 1
        end_directive = re.match(r"\.end(?:p|func)\s+([^\s,]+)", stripped)
        if end_directive:
            end_markers.add(end_directive.group(1))
        elif re.match(r"\.endfunc\b", stripped) and len(active_functions) == 1:
            end_markers.update(active_functions)

        label = re.match(r"([A-Za-z_.$][\w.$\\@]*|[0-9]+)\s*:", stripped)
        if label:
            name = label.group(1)
            labels.add(name)
            if name.startswith(".") and not name.startswith(".L"):
                nonlocal_dot_label_count += 1
                if nonlocal_dot_label is None:
                    nonlocal_dot_label = (name, number)
            if name in declared_functions or (extra_functions and name in extra_functions):
                function_sites.append((name, number, current))
                active_functions.clear()
                active_functions[name] = number
            elif name.startswith("_") and (
                name[1:] in declared_functions or (extra_functions and name[1:] in extra_functions)
            ):
                function_sites.append((name, number, current))
                active_functions.clear()
                active_functions[name] = number

        target = _branch_target(stripped)
        if target:
            branch_targets.append((number, target))
        symbolic_target = _symbolic_branch_target(stripped)
        if symbolic_target is not None:
            symbol_branch_targets.append((number, symbolic_target))
        if embedded_data is None and current.executable and re.match(
            r"\.(?:byte|2byte|short|hword|half|word|long|quad|8byte|zero|space|ascii|asciz|string)\b",
            stripped,
            re.IGNORECASE,
        ):
            embedded_data = number

        lower = stripped.lower()
        if suspicious_ct_branch is None and re.match(
            r"(?:j(?!mp)[a-z]+|loop[a-z]*|b\.(?:eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)|cbz|cbnz|tbz|tbnz)\b",
            lower,
        ):
            suspicious_ct_branch = number
        if suspicious_ct_index is None and (
            re.search(r"\([^)]*,\s*%?r?(?:ax|bx|cx|dx|si|di|[0-9]+)[^)]*\)", stripped, re.IGNORECASE)
            or re.search(r"\[(?:x|w|v|q|d|s|h|b)?\d+\s*,\s*(?:x|w)\d+", stripped, re.IGNORECASE)
        ):
            suspicious_ct_index = number
        if abi_signal is None and re.search(
            r"(?:\b(?:push|pop|callq?|bl|blr|ret)\b|%rsp|\bsp\b|\bx(?:19|2[0-9])\b|\b(?:d|q)(?:[89]|1[0-5])\b)",
            stripped,
            re.IGNORECASE,
        ):
            abi_signal = number
        if bad_stack_access is None and (
            re.search(r"-(?:1[3-9]\d|[2-9]\d\d+)\(%rsp\)", stripped, re.IGNORECASE)
            or re.search(r"\[sp\s*,\s*#-\d+\]", stripped, re.IGNORECASE)
        ):
            bad_stack_access = number
        if alignment_signal is None and re.search(r"\b(?:v?movaps|vmovdqa|movdqa)\b", stripped, re.IGNORECASE):
            alignment_signal = number

    def origin(index: int) -> tuple[str, int | None]:
        return origins[index - 1] if 1 <= index <= len(origins) else ("", None)

    def locate(index: int) -> tuple[str, int | None]:
        file_name, line_number = origin(index)
        return (_relative(file_name, root) if file_name else "", line_number)

    for name, number, section in function_sites:
        if not section.executable:
            site, line = locate(number)
            findings.append(Finding(
                "ERROR", "ASM-FUNC-NONEXEC", site, line,
                f"function {name} is declared in non-executable section {section.name}; section state is checked after directives and function macros",
            ))
    for name, number in declared_functions.items():
        site, line = locate(number)
        if name not in labels and not any(site_name == name for site_name, _, _ in function_sites):
            findings.append(Finding(
                "WARN", "ASM-FUNC-LABEL", site, line,
                f"function {name} has no source-visible label; macro expansion may define it",
            ))
        if name not in size_markers and name not in end_markers:
            findings.append(Finding(
                "WARN", "ASM-FUNC-SIZE", site, line,
                f"no source-visible .size or project function-end macro for {name}; macro expansion may supply the boundary",
            ))

    for number, target in branch_targets:
        if target not in labels:
            site, line = locate(number)
            findings.append(Finding(
                "ERROR", "ASM-BRANCH-TARGET", site, line,
                f"local branch target {target} is not defined in this source file",
            ))
    for number, target in symbol_branch_targets:
        if re.fullmatch(r"\d+[fb]?", target) or target.startswith((".", "LBB", "Ltmp")):
            continue
        if target not in labels:
            continue
        bare = target.lstrip("_")
        if target in declared_functions or bare in declared_functions:
            continue
        if extra_functions and (target in extra_functions or bare in extra_functions):
            continue
        if target in globl_names or bare in globl_names:
            continue
        site, line = locate(number)
        findings.append(Finding(
            "WARN", "ASM-BRANCH-LOCAL-CONVENTION", site, line,
            f"branch target {target} is a bare file-local label; use a .L-prefixed label inside a function "
            "or declare the subroutine with CRYPT_AARCH64_LOCAL_FUNC_START",
        ))
    report_file = _relative(origins[0][0], root) if origins else ""
    if cfi_start != cfi_end:
        findings.append(Finding(
            "WARN", "ASM-CFI-BOUNDARY", report_file, None,
            f"CFI start/end directive counts differ ({cfi_start}/{cfi_end}); control-flow paths are not validated",
        ))
    if nonlocal_dot_label is not None:
        site, line = locate(nonlocal_dot_label[1])
        findings.append(Finding(
            "WARN", "ASM-LOCAL-LABEL", site, line,
            f"dot-prefixed label {nonlocal_dot_label[0]} is not .L-prefixed ({nonlocal_dot_label_count} occurrence(s)); "
            "the assembler emits it as a local symbol instead of discarding it",
        ))
    heuristic_findings = (
        (abi_signal, "ASM-ABI-HEURISTIC", "stack balance, return-address recovery, and callee-saved registers need manual ABI review; this scan does not prove all control-flow paths"),
        (bad_stack_access, "ASM-STACK-BOUNDS-HEURISTIC", "large negative stack offset may exceed the allocated frame; frame-pointer changes, red zones, and path conditions are not modeled"),
        (alignment_signal, "ASM-ALIGNMENT-HEURISTIC", "aligned vector operation found; operand alignment is not proven"),
        (embedded_data, "ASM-CODE-DATA-HEURISTIC", "data directive appears in an executable section; verify control flow cannot fall through into it"),
        (suspicious_ct_branch, "ASM-CT-BRANCH-HEURISTIC", "conditional control flow may depend on secret data; data dependence is not analyzed and public loop branches also match"),
        (suspicious_ct_index, "ASM-CT-ADDRESS-HEURISTIC", "indexed memory access may depend on secret data; address provenance is not analyzed and public indices also match"),
    )
    for signal, code, message in heuristic_findings:
        if signal is not None:
            site, line = locate(signal)
            findings.append(Finding("WARN", code, site, line, message))
    findings.extend(_function_control_findings(
        lines, origins, root, function_sites,
        None if extra_functions is None else declared_functions, local_function_names, globl_names,
        may_be_included,
    ))
    return findings


ARM_CONDS = {
    "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al",
}
RISCV_CONDS = RISCV_BRANCH_MNEMONICS - {"tail"}


def _split_operands(text: str) -> list[str]:
    """Split operands on commas, keeping bracketed groups such as [sp, #-16]! intact."""
    result = []
    start = 0
    depth = 0
    for index, char in enumerate(text):
        if char in "[{(":
            depth += 1
        elif char in "]})":
            depth -= 1
        elif char == "," and depth == 0:
            result.append(text[start:index].strip())
            start = index + 1
    result.append(text[start:].strip())
    return [item for item in result if item]


_ARITH_RE = re.compile(r"[-+*/()<> 0-9a-fA-FxX]+")


def _parse_number(token: str) -> int | None:
    value = token.strip().lstrip("#$")
    try:
        return int(value, 0)
    except ValueError:
        pass
    if value and _ARITH_RE.fullmatch(value) and re.search(r"\d", value):
        try:
            return int(eval(value, {"__builtins__": {}}, {}))  # charset-whitelisted constant expression
        except (ArithmeticError, SyntaxError, ValueError, TypeError, NameError):
            return None
    return None


def _reg(token: str) -> str:
    return token.strip().lstrip("%$").lower()


def _count_reglist(text: str) -> int:
    inner = text.strip()
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1]
    count = 0
    for item in inner.lower().split(","):
        item = item.strip()
        if not item:
            continue
        span = re.fullmatch(r"([a-z0-9]+)-([a-z0-9]+)", item)
        if span and item[0].isdigit():
            count += int(span.group(2)) - int(span.group(1)) + 1
        elif span:
            first = re.sub(r"\D", "", span.group(1))
            second = re.sub(r"\D", "", span.group(2))
            count += int(second) - int(first) + 1 if first and second else 1
        else:
            count += 1
    return count


def _aarch64_writeback_delta(operands: str) -> int | None | str:
    pre = re.search(r"\[\s*(?:sp|wsp)\s*,\s*(#[-+*/()<> 0-9a-fA-FxX]+?)\s*\]\s*!", operands)
    if pre:
        offset = _parse_number(pre.group(1))
        return -offset if offset is not None else "opaque"
    post = re.search(r"\[\s*(?:sp|wsp)\s*\]\s*,\s*(#[-+*/()<> 0-9a-fA-FxX]+)", operands)
    if post:
        offset = _parse_number(post.group(1))
        return -offset if offset is not None else "opaque"
    return None


def _is_sp(token: str) -> bool:
    return _reg(token) in {"sp", "rsp", "wsp", "x31"}


def _is_fp(token: str) -> bool:
    return _reg(token) in {"x29", "rbp", "fp"}


def _stack_instruction(mnemonic: str, operands: str) -> tuple[str, object]:
    """Return (kind, data) for one instruction; kind in delta/ret/popret/branch/call/indirect/setfp/fromfp/leave/plain."""
    lower = mnemonic.lower()
    operand_list = _split_operands(operands)
    att = "%" in operands
    last = operand_list[-1] if operand_list else ""
    labelish = re.compile(r"^[A-Za-z_.$@][\w.$@]*$|^\d+[fb]$|^\w+\(\w+\)$")

    if lower in {"paciasp", "pacibsp", "aarch64_paciasp"} or (lower == "hint" and re.search(r"#25\b", operands)):
        return "pacsig", None
    if lower in {"autiasp", "autibsp", "aarch64_autiasp"} or (lower == "hint" and re.search(r"#29\b", operands)):
        return "pacauth", None
    if lower == "retab":
        return "retab", None
    if lower in {"ret", "retq"}:
        imm = _parse_number(operand_list[0]) if operand_list else None
        return "ret", imm
    if lower == "jr" and operand_list and _reg(operand_list[0]) in {"ra", "lr", "x30"}:
        return "ret", None
    if lower == "bx" and operand_list and _reg(operand_list[0]) in {"lr", "x30"}:
        return "ret", None
    if lower in {"br", "bra", "blr", "jalr", "ret", "jr"}:
        return "indirect", None
    if lower == "jmp" or lower == "j":
        if last.startswith("*") or not labelish.match(last):
            return "indirect", None
        return "branch", ("uncond", last)
    if lower == "jal":
        first = operand_list[0] if operand_list else ""
        if _reg(first) in {"zero", "x0"}:
            if not labelish.match(last):
                return "indirect", None
            return "branch", ("uncond", last)
        return "call", None
    if lower.startswith("j") and len(lower) > 1 or lower.startswith("loop"):
        if not labelish.match(last):
            return "indirect", None
        return "branch", ("cond", last)
    if lower == "b":
        return "branch", ("uncond", last)
    if re.fullmatch(r"b\.[a-z]+", lower) or (re.fullmatch(r"b[a-z]+", lower) and lower[1:] in ARM_CONDS):
        return "branch", ("cond", last)
    if lower in {"cbz", "cbnz", "tbz", "tbnz"} or lower in RISCV_CONDS:
        return "branch", ("cond", last)
    if lower == "tail":
        return "branch", ("uncond", last)
    if lower in {"bl", "blx", "call", "callq"}:
        return "call", None

    writeback = _aarch64_writeback_delta(operands)
    if writeback is not None:
        return ("delta", writeback) if writeback != "opaque" else ("indirect", None)

    if lower.startswith("ld") and re.search(r"\b(?:x30|lr)\b", operands):
        return "reloadlr", None

    if lower in {"push", "pop", "vpush", "vpop"}:
        if "{" not in operands:
            width = 4 if lower.endswith("l") else 8
            return "delta", width if lower.startswith("push") else -width
        count = _count_reglist(",".join(operand_list))
        if lower.startswith("v"):
            width = 16 if re.search(r"\bq\d+", operands) else 8
        else:
            width = 4
        if lower.startswith("push") or lower == "vpush":
            return "delta", width * count
        if "pc" in operands:
            return "popret", -width * count
        return "delta", -width * count
    if lower in {"pushq", "pushl"}:
        return "delta", 4 if lower.endswith("l") else 8
    if lower in {"popq", "popl"}:
        return "delta", -4 if lower.endswith("l") else -8
    if re.fullmatch(r"(?:st|ld)m[a-z]*", lower) and operand_list and _is_sp(operand_list[0]):
        base = operand_list[0].replace(" ", "")
        if not base.endswith("!"):
            return "plain", None
        count = _count_reglist(",".join(operand_list[1:]))
        if lower.startswith("ldm") and "pc" in operands:
            return "popret", -4 * count
        return "delta", (4 if lower.startswith("st") else -4) * count

    regs = [_reg(item) for item in operand_list]

    if lower.startswith("lea") and len(operand_list) == 2 and any(_is_sp(item) for item in operand_list):
        destination = operand_list[-1] if att else operand_list[0]
        source = operand_list[0] if att else operand_list[-1]
        if _is_sp(destination):
            att_offset = re.search(r"^([^()]*)\(%rsp\)$", source.replace(" ", "")) if att else None
            intel_offset = re.search(r"^\[rsp([+-][^\]]+)\]$", source.replace(" ", "")) if not att else None
            if att_offset and (att_offset.group(1) == "" or _parse_number(att_offset.group(1)) is not None):
                offset = _parse_number(att_offset.group(1)) if att_offset.group(1) else 0
                return "delta", -offset
            if intel_offset and _parse_number(intel_offset.group(1)) is not None:
                return "delta", -_parse_number(intel_offset.group(1))
        return "indirect", None
    if lower.startswith(("add", "sub")) and any(_is_sp(item) for item in operand_list):
        destination = operand_list[-1] if att else operand_list[0]
        if not _is_sp(destination):
            return "plain", None
        numbers = [value for value in (_parse_number(item) for item in operand_list) if value is not None]
        sources = [item for item in operand_list[1:] if _is_sp(item)] if not att else [item for item in operand_list[:-1] if _is_sp(item)]
        if len(numbers) != 1 or (len(operand_list) > 2 and not sources):
            others = [item for item in operand_list if not _is_sp(item) and _parse_number(item) is None]
            if len(numbers) == 1 and len(others) == 1 and _is_fp(others[0]):
                return "fromfp", -numbers[0] if lower.startswith("sub") else numbers[0]
            return "indirect", None
        value = numbers[0]
        return "delta", value if lower.startswith("sub") else -value
    if lower == "addi" and operand_list and _is_sp(operand_list[0]):
        if len(operand_list) == 3 and _is_sp(operand_list[1]):
            value = _parse_number(operand_list[2])
            if value is None:
                return "indirect", None
            return "delta", -value
        return "indirect", None

    if lower.startswith("mov") and len(operand_list) == 2:
        first, second = operand_list
        pair_is_frame = (_is_sp(first) and _is_fp(second)) or (_is_sp(second) and _is_fp(first))
        if pair_is_frame:
            destination = second if att else first
            return ("fromfp", None) if _is_sp(destination) else ("setfp", None)
        destination = second if att else first
        source = first if att else second
        if _is_sp(source) and not _is_sp(destination):
            return "savesp", destination.lstrip("%$")
        if _is_sp(destination) and not _is_sp(source):
            return "restoresp", source.lstrip("%$")

    if lower == "leave":
        return "leave", None
    if operand_list:
        destination = operand_list[-1] if att else operand_list[0]
        if _is_sp(destination):
            return "indirect", None
    return "plain", None


MACRO_NAME_RE = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9_]+)+")
CALLEE_ARCH_LR = {"aarch64": "x30", "arm32": "lr", "riscv": "ra"}
READ_FIRST_MNEMONICS = {"cmp", "cmn", "tst", "teq", "ccmp", "cbz", "cbnz", "tbz", "tbnz", "prfm", "mrs"}


def _detect_arch(entries: list[tuple[int, str, str]]) -> str | None:
    tokens: list[str] = []
    for _, mnemonic, operands in entries:
        tokens.append(mnemonic.lower())
        tokens.extend(op.lower() for op in _split_operands(operands))
    joined = " ".join(tokens)
    if "%" in joined:
        return "x86"
    if re.search(r"\b(?:x|w)\d\d?\b", joined) or re.search(r"\bsp\b", joined) and re.search(r"\b(?:x|q|v|d)\d+", joined):
        return "aarch64"
    if re.search(r"\bra\b|\bs\d+\b|\ba\d+\b|\bt[0-6]\b", joined):
        return "riscv"
    if re.search(r"\br\d\d?\b|\blr\b|\bpc\b|\bip\b", joined):
        return "arm32"
    if re.search(r"\bblx?\b", joined):
        return "arm32" if re.search(r"\br\d\b", joined) else "aarch64"
    return None


def _canonical_reg(token: str, arch: str) -> str | None:
    value = token.strip().lstrip("%$").lower().split(".")[0].strip("[]{")
    match = re.fullmatch(r"([a-z]+)(\d+)", value)
    prefix, number = (match.group(1), int(match.group(2))) if match else (value, None)
    if arch == "aarch64":
        if prefix in {"x", "w"} and 19 <= number <= 30:
            return f"x{number}"
        if prefix in {"v", "q", "d", "s", "h", "b"} and 8 <= number <= 15:
            return f"v{number}"
        return None
    if arch == "arm32":
        apcs = {"a1": "r0", "a2": "r1", "a3": "r2", "a4": "r3", "v1": "r4", "v2": "r5", "v3": "r6", "v4": "r7",
                "v5": "r8", "v6": "r9", "v7": "r10", "v8": "r11", "sb": "r9", "sl": "r10", "fp": "r11", "ip": "r12"}
        if value in apcs:
            reg = apcs[value]
            return reg if 4 <= int(reg[1:]) <= 11 else None
        if value == "lr":
            return "lr"
        if prefix == "r" and 4 <= number <= 11:
            return f"r{number}"
        if prefix in {"d", "q"} and 8 <= number <= 15:
            return f"v{number}"
        return None
    if arch == "x86":
        base = {"rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bl": "rbx", "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp"}
        if value in base:
            return base[value]
        if re.fullmatch(r"r1[2-5](d|w|b)?", value):
            return f"r{value[1:3]}"
        return None
    if arch == "riscv":
        if prefix == "s" and 0 <= number <= 11:
            return f"s{number}"
        if value == "ra":
            return "ra"
        return None
    return None


def _callee_saved_set(arch: str) -> set[str]:
    if arch == "aarch64":
        return {f"x{n}" for n in range(19, 30)} | {f"v{n}" for n in range(8, 16)}
    if arch == "arm32":
        return {f"r{n}" for n in range(4, 12)} | {f"v{n}" for n in range(8, 16)}
    if arch == "x86":
        return {"rbx", "rbp"} | {f"r{n}" for n in range(12, 16)}
    if arch == "riscv":
        return {f"s{n}" for n in range(12)} | {"ra"}
    return set()


APCS_ORDER = ["a1", "a2", "a3", "a4", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "sb", "sl", "fp", "ip", "sp", "lr", "pc"]


def _expand_reglist(operands: str) -> list[str]:
    inner = operands.strip()
    match = re.search(r"\{([^}]*)\}", inner)
    if not match:
        return [inner.split(",")[0].strip()] if inner else []
    result: list[str] = []
    for item in match.group(1).split(","):
        item = item.strip()
        span = re.fullmatch(r"([a-z]+)(\d+)-([a-z]+)(\d+)", item)
        if span and span.group(1) == span.group(3):
            result.extend(f"{span.group(1)}{n}" for n in range(int(span.group(2)), int(span.group(4)) + 1))
            continue
        named = re.fullmatch(r"([a-z][a-z0-9]*)-([a-z][a-z0-9]*)", item)
        if named and named.group(1) in APCS_ORDER and named.group(2) in APCS_ORDER:
            first, last = APCS_ORDER.index(named.group(1)), APCS_ORDER.index(named.group(2))
            if first <= last:
                result.extend(APCS_ORDER[first:last + 1])
                continue
        if item:
            result.append(item)
    return result


def _saved_registers(mnemonic: str, operands: str, arch: str) -> set[str]:
    lower = mnemonic.lower()
    ops = _split_operands(operands)
    canonical: set[str] = set()
    if arch == "x86":
        if lower in {"push", "pushq", "pushl"} and ops:
            reg = _canonical_reg(ops[0], arch)
            if reg:
                canonical.add(reg)
        if lower in {"mov", "movq", "movl"} and len(ops) == 2 and re.search(r"\((?:%rsp|%rbp)\)$", ops[1]):
            reg = _canonical_reg(ops[0], arch)
            if reg:
                canonical.add(reg)
        return canonical
    if lower in {"push", "vpush"} or re.fullmatch(r"stm[a-z]*", lower) or lower in {"sq", "sd", "sw", "sh", "sb", "fsd", "fsw"}:
        for token in _expand_reglist(operands):
            reg = _canonical_reg(token, arch)
            if reg:
                canonical.add(reg)
        return canonical
    if lower in {"stp", "str", "stur", "stnp"}:
        for op in ops:
            if "[" in op:
                break
            reg = _canonical_reg(op, arch)
            if reg:
                canonical.add(reg)
        return canonical
    return canonical


def _destination_registers(mnemonic: str, operands: str, arch: str) -> set[str]:
    """Registers written by one instruction; destination-position heuristic."""
    lower = mnemonic.lower()
    if lower in READ_FIRST_MNEMONICS or lower.startswith(("cmp", "test", "ucomis", "vucomis", "bt", "st")):
        return set()
    if lower == "push" or lower.startswith("vpush"):
        return set()
    ops = _split_operands(operands)
    if not ops:
        return set()
    att = arch == "x86"
    canonical: set[str] = set()

    def add(token: str) -> None:
        reg = _canonical_reg(token, arch)
        if reg:
            canonical.add(reg)

    if lower.startswith("ld") or lower in {"pop", "vpop"} or re.fullmatch(r"ldm[a-z]*", lower) or lower in {"lq", "ld", "lw", "lh", "lb", "fld", "flw"}:
        memory = next((op for op in ops if "[" in op or "(" in op), "")
        base = re.search(r"[\[(]\s*%?([a-z0-9]+)", memory)
        if base and base.group(1) in ("sp", "x29", "wsp", "rbp", "fp"):
            return set()  # frame restore
        for op in ops:
            if "[" in op or "(" in op:
                break
            add(op)
        return canonical
    if att:
        candidate = ops[-1]
        if "(" in candidate or candidate.startswith("*"):
            return set()
        if lower in {"mov", "movq", "movl"} and len(ops) == 2 and re.search(r"\((?:%rsp|%rbp)\)", ops[0]):
            return set()  # frame restore
        add(candidate)
    else:
        add(ops[0])
    return canonical


def _callee_saved_findings(
    name: str, entries: list[tuple[int, str, str]], classified: list,
    resolve: Callable[[str, int], int | None], arch_hint: str | None = None,
) -> list[tuple[int, list[str]]]:
    """Return (line, unsaved-register-list) entries for callee-saved writes without saves."""
    for (_, kind, _), (_, mnemonic, _) in zip(classified, entries):
        if kind == "indirect" and re.fullmatch(r"[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9_]+)+", mnemonic):
            return []  # saves or writes may hide inside assembler macros
    arch = _detect_arch(entries) or arch_hint
    if arch is None:
        return []
    callee = _callee_saved_set(arch)
    lr = CALLEE_ARCH_LR.get(arch)
    states: dict[int, set[str]] = {}
    worklist: list[tuple[int, set[str]]] = [(0, set())]
    written: dict[str, int] = {}
    while worklist:
        index, saved = worklist.pop()
        if index >= len(entries):
            continue
        if index in states:
            saved = states[index] & saved
            if saved == states[index]:
                continue
        states[index] = saved.copy()
        line_no, mnemonic, operands = entries[index]
        _, kind, data = classified[index]
        lower = mnemonic.lower()
        saved = saved | _saved_registers(lower, operands, arch)
        if kind == "call" and lr and lr not in saved:
            written.setdefault(lr, line_no)
        for reg in _destination_registers(lower, operands, arch):
            if reg in callee and reg not in saved:
                written.setdefault(reg, line_no)
        if kind == "branch":
            mode, target = data
            resolved = resolve(target, index)
            if resolved is not None:
                worklist.append((resolved, saved))
            if mode == "cond":
                worklist.append((index + 1, saved))
        elif kind not in {"ret", "retab", "popret", "indirect"}:
            worklist.append((index + 1, saved))
    if not written:
        return []
    first = min(written.values())
    return [(first, sorted(written))]


def _analyze_function_body(
    name: str, body: list[tuple[int, str]], expanded: bool,
    function_names: set[str] | None = None, arch_hint: str | None = None,
) -> tuple[list[tuple[str, str, int, str]], dict]:
    """Per-function PAC pairing and stack-depth analysis.

    Returns (findings, edges). Depth counts bytes pushed below the entry stack
    pointer; every return or tail branch must restore it to zero. Control flow
    is modeled from labels and branch mnemonics only. Edges record tail-branch
    and call targets with the PAC-sign state for cross-function checks.
    """
    entries: list[tuple[int, str, str]] = []
    labels: dict[str, int] = {}
    numeric_defs: dict[int, list[int]] = {}
    pending: list[str] = []
    in_macro = False
    for line_no, raw in body:
        for statement in _split_statements(raw):
            stripped = statement.strip()
            while True:
                label_match = re.match(r"([A-Za-z_.$@][\w.$@]*|\d+)\s*:\s*", stripped)
                if not label_match:
                    break
                pending.append(label_match.group(1))
                stripped = stripped[label_match.end():]
            if not stripped:
                continue
            if in_macro:
                if re.match(r"\.endm\b", stripped):
                    in_macro = False
                continue
            if re.match(r"\.macro\b", stripped):
                in_macro = True
                continue
            if re.match(
                r"CRYPT_AARCH64_(?:(?:LOCAL_)?FUNC_(?:START|END)|(?:GET_RELA|GET_GOTSYM|EXTERN|ARCH_[A-Z_]+|RODATA_SECTION)\b)",
                stripped,
            ):
                continue
            if stripped.startswith(".") or stripped.startswith("#"):
                continue
            instruction = re.match(r"([A-Za-z][A-Za-z0-9_.]*)\s*(.*)$", stripped)
            if not instruction:
                continue
            index = len(entries)
            for label in pending:
                if label.isdigit():
                    numeric_defs.setdefault(int(label), []).append(index)
                else:
                    labels.setdefault(label, index)
            pending = []
            entries.append((line_no, instruction.group(1), instruction.group(2).strip()))
    for label in pending:
        if label.isdigit():
            numeric_defs.setdefault(int(label), []).append(len(entries))
        else:
            labels.setdefault(label, len(entries))

    if not entries:
        return [], {}

    findings: list[tuple[str, str, int, str]] = []
    edges: dict = {"tail": {}, "call": set()}

    def classify(mnemonic: str, operands: str) -> tuple[str, object]:
        kind, data = _stack_instruction(mnemonic, operands)
        if kind == "plain" and re.fullmatch(r"[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9_]+)+", mnemonic):
            return "indirect", None
        return kind, data

    classified = [(line_no, *classify(mnemonic, operands)) for line_no, mnemonic, operands in entries]

    def normalize_target(target: str) -> str:
        inner = re.search(r"\w+\((\w+)\)", target)
        return (inner.group(1) if inner else target).lstrip("_")

    def resolve(target: str, at: int) -> int | None:
        numeric = re.fullmatch(r"(\d+)([fb])", target)
        if numeric:
            number, direction = int(numeric.group(1)), numeric.group(2)
            defs = numeric_defs.get(number, [])
            if direction == "f":
                later = [index for index in defs if index > at]
                return later[0] if later else None
            earlier = [index for index in defs if index < at]
            return earlier[-1] if earlier else None
        return labels.get(target)

    callee_sites = _callee_saved_findings(name, entries, classified, resolve, arch_hint)
    if callee_sites:
        edges["callee_saved"] = callee_sites
    if not any(kind in {"delta", "ret", "retab", "popret", "setfp", "fromfp", "leave", "pacsig", "pacauth", "reloadlr"} for _, kind, _ in classified):
        return findings, edges

    for (_, kind, _), (_, mnemonic, operands) in zip(classified, entries):
        if kind == "call":
            parts = _split_operands(operands)
            edges["call"].add(normalize_target(parts[-1] if parts else ""))

    pac_in_use = any(kind in {"pacsig", "pacauth", "retab"} for _, kind, _ in classified)
    states: dict[int, tuple[int, int | None, bool]] = {}
    sp_regs: dict[str, int] = {}
    worklist: list[tuple[int, int, int | None, bool]] = [(0, 0, None, False)]
    exit_depths: list[tuple[int, int, str]] = []
    auth_without_sign: list[int] = []

    def abort(reason: str, line_no: int) -> tuple[list, dict]:
        findings.append(("INFO", "ASM-STACK-SKIPPED", line_no, f"stack analysis for {name} skipped: {reason}"))
        edges["incomplete"] = True
        return findings, edges

    while worklist:
        index, depth, fp, signed = worklist.pop()
        if index >= len(entries):
            exit_depths.append((entries[-1][0], depth, "control flow falls off the analyzed function body"))
            continue
        line_no, kind, data = classified[index]
        if index in states:
            if states[index] != (depth, fp, signed):
                return abort("control-flow paths reach one point with different stack states", line_no)
            continue
        states[index] = (depth, fp, signed)
        successors: list[tuple[int, int, int | None, bool]] = []
        if kind == "delta":
            reloaded = (
                pac_in_use
                and entries[index][1].lower().startswith("ld")
                and re.search(r"\b(?:x30|lr)\b", entries[index][2], re.IGNORECASE)
            )
            successors.append((index + 1, depth + int(data), fp, True if reloaded else signed))
        elif kind in {"ret", "retab"}:
            if kind == "retab" and not signed:
                auth_without_sign.append(line_no)
            elif kind == "ret" and signed:
                findings.append((
                    "WARN", "ASM-PAC-HEURISTIC", line_no,
                    f"return in {name} executes with a signed return address; an AUTIASP is missing on this path",
                ))
            imm = data if isinstance(data, int) else 0
            exit_depths.append((line_no, depth, "return path" if not imm else "return path with immediate cleanup"))
        elif kind == "popret":
            if signed:
                findings.append((
                    "WARN", "ASM-PAC-HEURISTIC", line_no,
                    f"return in {name} executes with a signed return address; an AUTIASP is missing on this path",
                ))
            exit_depths.append((line_no, depth + int(data), "return path"))
        elif kind == "pacsig":
            successors.append((index + 1, depth, fp, True))
        elif kind == "reloadlr":
            successors.append((index + 1, depth, fp, True if pac_in_use else signed))
        elif kind == "pacauth":
            if not signed:
                auth_without_sign.append(line_no)
            successors.append((index + 1, depth, fp, False))
        elif kind == "branch":
            mode, target = data
            resolved = resolve(target, index)
            if resolved is None:
                target_name = normalize_target(target)
                edges["tail"].setdefault(target_name, set()).add(signed)
                if function_names is None or target_name in function_names:
                    exit_depths.append((line_no, depth, "tail branch to a function entry"))
                if mode == "cond":
                    successors.append((index + 1, depth, fp, signed))
            elif mode == "uncond":
                successors.append((resolved, depth, fp, signed))
            else:
                successors.append((resolved, depth, fp, signed))
                successors.append((index + 1, depth, fp, signed))
        elif kind == "call":
            parts = _split_operands(entries[index][2])
            edges["call"].add(normalize_target(parts[-1] if parts else ""))
            successors.append((index + 1, depth, fp, False))
        elif kind == "savesp":
            sp_regs[str(data)] = depth
            successors.append((index + 1, depth, fp, signed))
        elif kind == "restoresp":
            if str(data) not in sp_regs:
                return abort(f"stack pointer restored from {data} without a recorded save", line_no)
            successors.append((index + 1, sp_regs[str(data)], fp, signed))
        elif kind == "setfp":
            successors.append((index + 1, depth, depth, signed))
        elif kind == "fromfp":
            if fp is None:
                return abort("stack pointer restored from frame pointer without a recorded value", line_no)
            new_depth = fp - int(data or 0)
            successors.append((index + 1, new_depth, fp, signed))
        elif kind == "leave":
            if fp is None:
                return abort("leave without a recorded frame pointer", line_no)
            successors.append((index + 1, fp - 8, fp, signed))
        elif kind == "indirect":
            mnemonic = entries[index][1]
            if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", mnemonic):
                reason = f"macro call {mnemonic} may adjust the stack; run with --pp to analyze its expansion"
            else:
                reason = f"indirect branch or unrecognized stack-pointer change ({mnemonic} {entries[index][2]})"
            return abort(reason, line_no)
        else:
            successors.append((index + 1, depth, fp, signed))
        worklist.extend(successors)

    for line_no, depth, description in exit_depths:
        if depth != 0:
            findings.append((
                "WARN", "ASM-STACK-IMBALANCE", line_no,
                f"{description} in {name} leaves the stack {depth} byte(s) off the entry depth; "
                "frame restore may be incomplete (heuristic; macro expansion may hide instructions)",
            ))
            break
    if auth_without_sign:
        edges["auth_sites"] = auth_without_sign
    return findings, edges


def _function_control_findings(
    lines: list[str],
    origins: list[tuple[str, int | None]],
    root: Path,
    function_sites: list[tuple[str, int, Section]],
    declared_functions: dict[str, int] | None = None,
    local_function_names: set[str] | None = None,
    globl_names: set[str] | None = None,
    may_be_included: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    ordered = sorted(function_sites, key=lambda item: item[1])
    skips: list[tuple[int, str, str, str]] = []
    tail_edges: dict[str, set] = {}
    call_edges: set[str] = set()
    pending_auth: list[tuple[str, int]] = []
    pending_callee: list[tuple[str, int, list[str]]] = []
    incomplete_functions: set[str] = set()
    shadowed_entries: set[str] = set()
    file_arch: str | None = None
    file_name = ""
    for position, (name, number, section) in enumerate(ordered):
        if not section.executable:
            continue
        end = ordered[position + 1][1] - 1 if position + 1 < len(ordered) else len(lines)
        body = [(index, lines[index - 1]) for index in range(number, max(number, end) + 1)]
        expanded = declared_functions is not None
        names = ({name for name, _, _ in function_sites} | set(declared_functions or {})) if expanded else None
        if file_arch is None:
            file_arch = _detect_arch([(0, "", line) for _, line in body])
        items, edges = _analyze_function_body(name, body, expanded, names, file_arch)
        for severity, code, line_no, message in items:
            if 1 <= line_no <= len(origins):
                file_name, origin_line = origins[line_no - 1]
                if code == "ASM-STACK-SKIPPED":
                    reason = message.split("skipped: ", 1)[-1]
                    skips.append((origin_line or line_no, file_name, reason, name))
                else:
                    findings.append(Finding(severity, code, _relative(file_name, root), origin_line or line_no, message))
        for target, states in edges.get("tail", {}).items():
            tail_edges.setdefault(target, set()).update(states)
        call_edges.update(edges.get("call", set()))
        if edges.get("incomplete"):
            incomplete_functions.add(name)
            shadowed_entries.update(edges.get("tail", {}))
            shadowed_entries.update(edges.get("call", set()))
        for line_no in edges.get("auth_sites", []):
            pending_auth.append((name, line_no))
        for line_no, regs in edges.get("callee_saved", []):
            pending_callee.append((name, line_no, regs))

    for name, line_no in pending_auth:
        if not (1 <= line_no <= len(origins)):
            continue
        if name in incomplete_functions or name in shadowed_entries:
            continue
        file_name, origin_line = origins[line_no - 1]
        if name in call_edges:
            findings.append(Finding(
                "WARN", "ASM-PAC-HEURISTIC", _relative(file_name, root), origin_line or line_no,
                f"AUTIASP in {name} executes with an unsigned return address; a call (bl) entry resets LR",
            ))
        elif name in tail_edges and False in tail_edges[name]:
            findings.append(Finding(
                "WARN", "ASM-PAC-HEURISTIC", _relative(file_name, root), origin_line or line_no,
                f"AUTIASP in {name} is reachable from a tail branch on a path without PACIASP",
            ))
        elif name not in tail_edges:
            bare = name.lstrip("_")
            public = (
                local_function_names is not None and bare not in local_function_names
                and (globl_names is None or bare in globl_names or f"_{bare}" in globl_names)
            )
            findings.append(Finding(
                "WARN" if public else "INFO", "ASM-PAC-HEURISTIC", _relative(file_name, root), origin_line or line_no,
                f"AUTIASP in {name} has no in-file PACIASP or tail-branch entry; "
                + ("a public entry is reached by call (bl), which resets LR to unsigned" if public
                   else "verify the caller signs LR"),
            ))

    for name, line_no, regs in pending_callee:
        if not (1 <= line_no <= len(origins)):
            continue
        bare = name.lstrip("_")
        local_names = (local_function_names or set())
        is_local = bare in local_names or (globl_names is not None and bare not in globl_names and f"_{bare}" not in globl_names)
        tail_only_local = is_local and bare in tail_edges and bare not in call_edges
        if tail_only_local:
            continue
        file_name, origin_line = origins[line_no - 1]
        local_bl_entry = is_local and (bare in call_edges or may_be_included)
        severity = "INFO" if local_bl_entry else "WARN"
        detail = (
            "its in-file callers may save these registers before the call; verify"
            if local_bl_entry
            else "the caller expects them preserved"
        )
        findings.append(Finding(
            severity, "ASM-CALLEE-SAVED-HEURISTIC", _relative(file_name, root), origin_line or line_no,
            f"{name} writes callee-saved register(s) {', '.join(regs)} without saving them; {detail} "
            "(heuristic; writes inside assembler macros are not visible)",
        ))

    grouped: dict[str, tuple[int, str, list[str]]] = {}
    for line_no, file_name, reason, name in skips:
        first_line, group_file, names = grouped.get(reason, (line_no, file_name, []))
        names.append(name)
        grouped[reason] = (first_line, group_file or file_name, names)
    for reason, (line_no, file_name, names) in grouped.items():
        shown = ", ".join(dict.fromkeys(names[:6]))
        extra = f" (+{len(set(names)) - 6} more)" if len(set(names)) > 6 else ""
        findings.append(Finding(
            "INFO", "ASM-STACK-SKIPPED", _relative(file_name, root) if file_name else "", line_no,
            f"stack analysis skipped: {reason}; affected function(s): {shown}{extra}",
        ))
    return findings



def _live_functions(
    active_functions: dict[str, int],
    ended_lines: dict[str, int] | None,
    origin_line: int | None,
) -> dict[str, int]:
    if not ended_lines or origin_line is None:
        return dict(active_functions)
    live: dict[str, int] = {}
    for name, declared_line in active_functions.items():
        end_line = ended_lines.get(name, ended_lines.get(name.lstrip("_")))
        if end_line is None or end_line >= origin_line:
            live[name] = declared_line
    return live


def _split_statements(line: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    index = 0
    quoted = False
    while index < len(line):
        if line[index] == '"':
            quoted = not quoted
        if not quoted and any(line.startswith(sep, index) for sep in ("%%", ";")):
            statements.append("".join(current))
            current = []
            index += 2 if line.startswith("%%", index) else 1
            continue
        current.append(line[index])
        index += 1
    statements.append("".join(current))
    return [item.strip() for item in statements if item.strip()]


def _pp_targets_for(filename: str) -> list[str | None]:
    name = filename.lower()
    if "armv8" in name or "aarch64" in name or "arm64" in name:
        return ["aarch64-linux-gnu", "arm64-apple-darwin"]
    if "armv7" in name or "arm" in name:
        return ["armv7-linux-gnueabi"]
    if "x86_64" in name or "x8664" in name or "avx" in name:
        return ["x86_64-linux-gnu"]
    if "riscv" in name:
        return ["riscv64-linux-gnu"]
    return [None]


def _collect_function_names(path: Path) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return set()
    names: set[str] = set()
    for stripped in (line.strip() for line in _blank_dead_if_zero_regions(_strip_comments(text))):
        type_match = re.match(r"\.type\s+([^,\s]+)\s*,\s*[%@]?function\b", stripped, re.IGNORECASE)
        if type_match:
            names.add(type_match.group(1))
        for macro in ("CRYPT_AARCH64_FUNC_START", "CRYPT_AARCH64_LOCAL_FUNC_START"):
            macro_match = re.search(rf"\b{macro}\s*\(\s*([A-Za-z_.$][\w.$]*)\s*\)", stripped)
            if macro_match:
                names.add(macro_match.group(1))
    return names


def _collect_local_function_names(path: Path) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return set()
    names: set[str] = set()
    for stripped in (line.strip() for line in _blank_dead_if_zero_regions(_strip_comments(text))):
        local_match = re.search(r"\bCRYPT_AARCH64_LOCAL_FUNC_START\s*\(\s*([A-Za-z_.$][\w.$]*)\s*\)", stripped)
        if local_match:
            names.add(local_match.group(1))
    return names


def _collect_function_end_lines(path: Path) -> dict[str, int]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    ends: dict[str, int] = {}
    for number, stripped in enumerate((line.strip() for line in _blank_dead_if_zero_regions(_strip_comments(text))), 1):
        end_match = re.search(r"\bCRYPT_AARCH64_(?:LOCAL_)?FUNC_END\s*\(\s*([A-Za-z_.$][\w.$]*)\s*\)", stripped)
        if end_match:
            ends[end_match.group(1)] = number
            continue
        size_match = re.match(r"\.size\s+([^,\s]+)", stripped)
        if size_match:
            ends[size_match.group(1)] = number
            continue
        named_end = re.match(r"\.end(?:p|func)\s+([^\s,]+)", stripped)
        if named_end:
            ends[named_end.group(1)] = number
    return ends


def _cc_supports_target(cc: str) -> bool:
    """Only clang-family drivers accept --target for cross-platform preprocessing."""
    try:
        result = subprocess.run([cc, "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return False
    return "clang" in result.stdout.lower() or "clang" in result.stderr.lower()


def _preprocess(path: Path, cc: str, target: str | None, flags: list[str]) -> tuple[tuple[list[str], list[tuple[str, int | None]]] | None, str | None]:
    command = [cc, "-E", "-x", "assembler-with-cpp"]
    if target:
        command.append(f"--target={target}")
    command += flags + [str(path)]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        detail = (result.stderr.strip().splitlines() or ["preprocessor failed"])[-1]
        return None, detail
    lines: list[str] = []
    origins: list[tuple[str, int | None]] = []
    current_file = str(path)
    current_line = 0
    marker = re.compile(r'^#\s*(\d+)\s+"([^"]+)"')
    for raw in result.stdout.splitlines():
        marker_match = marker.match(raw)
        if marker_match:
            current_file = marker_match.group(2)
            current_line = int(marker_match.group(1))
            continue
        for statement in _split_statements(raw):
            lines.append(statement)
            origins.append((current_file, current_line))
        current_line += 1
    return (lines, origins), None


def audit_preprocessed(
    path: Path,
    root: Path,
    cc: str,
    target: str | None,
    flags: list[str],
    function_names: set[str],
    ended_lines: dict[str, int] | None = None,
    local_names: set[str] | None = None,
) -> list[Finding]:
    label = target or "host"
    scanned, error = _preprocess(path, cc, target, flags)
    if scanned is None:
        return [Finding("ERROR", "ASM-PP-FAIL", _relative(str(path), root), None, f"preprocessing for {label} failed: {error}")]
    lines, origins = scanned
    findings = _scan_assembly(
        lines, origins, root, extra_functions=function_names,
        ended_lines=ended_lines, extra_local_names=local_names,
    )
    return [
        dataclasses.replace(item, message=f"{item.message} [preprocessed for {label}]")
        if item.code != "ASM-SOURCE-READ" else item
        for item in findings
    ]


def _pp_config_flags(build_dir: Path, pp_flag: list[str]) -> tuple[list[str], Finding | None]:
    """Return generated-config defines plus a finding when no config is available."""
    config_header = (build_dir / "config" / "hitls_build_config.h").resolve()
    if config_header.is_file():
        return [f'-DHITLS_CONFIG_FILE="{config_header}"', "-DHITLS_CRYPTO_PROVIDER"], None
    custom = any("HITLS_CONFIG_FILE" in flag for flag in pp_flag)
    action = "using the config supplied via --pp-flag" if custom \
        else "build the library or pass the config include via --pp-flag"
    return [], Finding("WARN" if custom else "ERROR", "ASM-PP-CONFIG", str(config_header), None,
                       f"generated build config header not found; {action}")


def _blocks(text: str, section_name: str, block_prefix: str) -> list[str]:
    section_start = text.find(section_name)
    if section_start < 0:
        return []
    result = []
    cursor = section_start + len(section_name)
    while True:
        start = text.find(block_prefix, cursor)
        if start < 0:
            break
        brace = text.find("{", start)
        if brace < 0:
            break
        depth = 0
        end = brace
        while end < len(text):
            if text[end] == "{":
                depth += 1
            elif text[end] == "}":
                depth -= 1
                if depth == 0:
                    end += 1
                    result.append(text[start:end])
                    cursor = end
                    break
            end += 1
        else:
            break
    return result


def _field(block: str, name: str) -> str:
    match = re.search(rf"^\s*{re.escape(name)}:\s*(.*?)\s*$", block, re.MULTILINE)
    return match.group(1) if match else ""


def _clean_field(value: str) -> str:
    return re.sub(r"\s*\([^)]*\)\s*$", "", value).strip()


def _number(value: str) -> int:
    match = re.search(r"(?:0x[0-9a-fA-F]+|\d+)", value)
    if not match:
        return 0
    return int(match.group(0), 0)


def _macho_section_ordinal(value: str) -> int:
    match = re.search(r"\((0x[0-9a-fA-F]+|\d+)\)\s*$", value)
    if not match:
        return 0
    return int(match.group(1), 0)


def _tool_command() -> list[str] | None:
    for tool in ("llvm-readobj", "llvm-readobj-23", "llvm-readobj-22", "llvm-readobj-21", "llvm-readobj-20", "llvm-readobj-19", "llvm-readobj-18", "llvm-readobj-17", "llvm-readobj-16", "llvm-readobj-15"):
        path = shutil.which(tool)
        if path:
            return [path]
    return None


def _inspector_command() -> tuple[str, list[str]] | None:
    """Prefer llvm-readobj (ELF and Mach-O); fall back to GNU-style readelf (ELF only)."""
    llvm = _tool_command()
    if llvm:
        return "llvm", llvm
    for tool in ("readelf", "llvm-readelf", "llvm-readelf-23", "llvm-readelf-22", "llvm-readelf-21", "llvm-readelf-20", "llvm-readelf-19", "llvm-readelf-18", "llvm-readelf-17", "llvm-readelf-16", "llvm-readelf-15"):
        path = shutil.which(tool)
        if path:
            return "gnu", [path]
    return None


def _parse_object_blocks(path: str, block_text: str) -> ObjectInfo:
    fmt_match = re.search(r"^Format:\s*(.+)$", block_text, re.MULTILINE)
    arch_match = re.search(r"^Arch:\s*(.+)$", block_text, re.MULTILINE)
    fmt = fmt_match.group(1).strip() if fmt_match else "unknown"
    arch = arch_match.group(1).strip() if arch_match else "unknown"
    file_type_match = re.search(r"^\s*FileType:\s*(.+)$", block_text, re.MULTILINE)
    if not file_type_match:
        file_type_match = re.search(r"^\s*Type:\s*(.+)$", block_text, re.MULTILINE)
    file_type = _clean_field(file_type_match.group(1)) if file_type_match else "unknown"
    is_macho = "Mach-O" in fmt
    sections: dict[str, Section] = {}
    macho_section_ordinals: dict[int, str] = {}
    for block in _blocks(block_text, "Sections [", "Section {"):
        name = _clean_field(_field(block, "Name"))
        segment = _clean_field(_field(block, "Segment"))
        flags = block
        attrs = block
        if is_macho:
            executable = segment == "__TEXT" and (
                name in EXEC_MACH_SECTIONS or ("PureInstructions" in attrs and name not in READONLY_NAMES)
            )
            writable = segment.startswith("__DATA") and not segment.startswith("__DATA_CONST")
            full_name = f"{segment},{name}" if segment else name
        else:
            executable = "SHF_EXECINSTR" in flags
            writable = "SHF_WRITE" in flags
            full_name = name
        section_key = full_name if is_macho else name
        sections[section_key] = Section(full_name, executable, writable)
        if is_macho:
            macho_section_ordinals[_number(_field(block, "Index")) + 1] = section_key

    symbols: list[ObjSymbol] = []
    for block in _blocks(block_text, "Symbols [", "Symbol {"):
        name = _clean_field(_field(block, "Name"))
        if not name:
            continue
        section_raw = _field(block, "Section")
        section_text = _clean_field(section_raw)
        binding = _clean_field(_field(block, "Binding")) or ("Global" if re.search(r"^\s*Extern\s*$", block, re.MULTILINE) else "Local")
        kind = _clean_field(_field(block, "Type")) or "unknown"
        undefined = section_text.startswith("Undefined") or (is_macho and kind.lower() == "undef")
        if undefined or section_text.startswith("Common"):
            section = ""
        elif is_macho:
            section = macho_section_ordinals.get(_macho_section_ordinal(section_raw), "")
        else:
            section = section_text
        other = _field(block, "Other")
        visibility_match = re.search(r"STV_(DEFAULT|INTERNAL|HIDDEN|PROTECTED)", block)
        if visibility_match:
            visibility = visibility_match.group(1).lower()
        elif "N_PEXT" in block or "PrivateExtern" in block:
            visibility = "private"
        else:
            visibility = "default" if _number(other) == 0 else f"other-{_number(other)}"
        symbols.append(ObjSymbol(
            name=name,
            value=_number(_field(block, "Value")),
            size=_number(_field(block, "Size")),
            binding=binding,
            kind=kind,
            visibility=visibility,
            section=section,
            undefined=undefined,
        ))

    stack_note = sections.get(".note.GNU-stack")
    stack_block = next((b for b in _blocks(block_text, "ProgramHeaders [", "ProgramHeader {") if _field(b, "Type").startswith("PT_GNU_STACK")), "")
    return ObjectInfo(path, fmt, arch, file_type, sections, symbols, stack_note, stack_block)


READELF_KINDS = {
    "FUNC": "Function", "OBJECT": "Object", "SECTION": "Section", "NOTYPE": "None",
    "FILE": "File", "COMMON": "Common", "TLS": "TLS", "IFUNC": "Function",
}


def _parse_readelf(path: str, text: str) -> ObjectInfo | None:
    if "ELF Header:" not in text:
        return None
    file_type_map = {"REL": "Relocatable", "EXEC": "Executable", "DYN": "SharedObject", "CORE": "CoreFile"}
    type_match = re.search(r"^\s*Type:\s*(\w+)", text, re.MULTILINE)
    file_type = file_type_map.get(type_match.group(1), "unknown") if type_match else "unknown"
    machine_match = re.search(r"^\s*Machine:\s*(.+)$", text, re.MULTILINE)
    arch = machine_match.group(1).strip() if machine_match else "unknown"
    class_match = re.search(r"^\s*Class:\s*(\S+)", text, re.MULTILINE)
    fmt = "elf" + (class_match.group(1).lower() if class_match else "")

    sections: dict[str, Section] = {}
    section_names: dict[int, str] = {}
    in_section_headers = False
    for line in text.splitlines():
        if line.startswith("Section Headers:"):
            in_section_headers = True
            continue
        if in_section_headers:
            if not line.strip() or line.lstrip().startswith("Key to Flags"):
                in_section_headers = False
                continue
            index_match = re.match(r"\s*\[\s*(\d+)\]", line)
            if not index_match:
                continue
            tokens = line[line.index("]") + 1:].split()
            if len(tokens) < 9:
                continue
            index, name = int(index_match.group(1)), tokens[0]
            flags = tokens[6] if len(tokens) >= 10 else ""
            if flags and not re.fullmatch(r"[WAXMSILOGTCREPTxn]+", flags):
                flags = ""
            section_names[index] = name
            sections[name] = Section(name, "X" in flags, "W" in flags)

    symbols: list[ObjSymbol] = []
    seen_symbols: set[tuple] = set()  # readelf lists .dynsym and .symtab; keep one entry per symbol
    in_symbols = False
    for line in text.splitlines():
        if line.startswith("Symbol table"):
            in_symbols = True
            continue
        if in_symbols:
            if not line.strip():
                in_symbols = False
                continue
            entry = re.match(
                r"\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$",
                line,
            )
            if not entry:
                continue
            name = entry.group(8).strip().split(" ")[0]
            if not name:
                continue
            bind_map = {"LOCAL": "Local", "GLOBAL": "Global", "WEAK": "Weak", "UNIQUE": "Global", "GNU_UNIQUE": "Global"}
            kind_raw = entry.group(4)
            ndx = entry.group(7)
            undefined = ndx == "UND"
            if undefined or ndx == "COM":
                section = ""
            elif ndx.isdigit():
                section = section_names.get(int(ndx), "")
            else:
                section = ""
            entry_key = (name, entry.group(2), entry.group(3), kind_raw, entry.group(5), entry.group(6), entry.group(7))
            if entry_key in seen_symbols:
                continue
            seen_symbols.add(entry_key)
            symbols.append(ObjSymbol(
                name=name,
                value=int(entry.group(2), 16),
                size=int(entry.group(3)),
                binding=bind_map.get(entry.group(5), entry.group(5)),
                kind=READELF_KINDS.get(kind_raw, kind_raw.title()),
                visibility=entry.group(6).lower(),
                section=section,
                undefined=undefined,
            ))

    stack_note = sections.get(".note.GNU-stack")
    gnu_stack_flags = ""
    for line in text.splitlines():
        if "GNU_STACK" in line:
            flag_tokens = [token for token in line.split() if re.fullmatch(r"[RWE]+", token)]
            gnu_stack_flags = "PF_X" if flag_tokens and "E" in flag_tokens[-1] else "RW"
    return ObjectInfo(path, fmt, arch, file_type, sections, symbols, stack_note, gnu_stack_flags)


def inspect_objects(paths: list[Path], inspector: tuple[str, list[str]]) -> tuple[list[ObjectInfo], list[Finding]]:
    findings: list[Finding] = []
    objects: list[ObjectInfo] = []
    kind, command = inspector
    if kind == "gnu":
        for path in paths:
            result = subprocess.run(
                command + ["-W", "-h", "-S", "-l", "-s", str(path)],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            detail = ""
            if result.returncode:
                detail = (result.stderr.strip().splitlines() or ["readelf failed"])[-1]
            obj = _parse_readelf(str(path), result.stdout) if result.returncode == 0 else None
            if obj is None:
                findings.append(Finding(
                    "ERROR", "ASM-OBJECT-READ", str(path), None,
                    f"{detail or 'not an ELF object'}; the readelf backend supports ELF objects only; install llvm-readobj to inspect Mach-O or other formats",
                ))
                continue
            objects.append(obj)
        return objects, findings
    for offset in range(0, len(paths), OBJECT_BATCH_SIZE):
        batch = paths[offset:offset + OBJECT_BATCH_SIZE]
        command2 = command + ["--file-headers", "--sections", "--symbols", "--program-headers"] + [str(path) for path in batch]
        result = subprocess.run(command2, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        path_list = ", ".join(str(path) for path in batch)
        if result.returncode:
            return [], [Finding("ERROR", "ASM-OBJECT-READ", path_list, None, result.stderr.strip() or "llvm-readobj failed")]
        starts = list(re.finditer(r"^File:\s*(.+)$", result.stdout, re.MULTILINE))
        if len(starts) != len(batch):
            return [], [Finding("ERROR", "ASM-OBJECT-PARSE", path_list, None, "could not map llvm-readobj output to each input object")]
        for index, match in enumerate(starts):
            end = starts[index + 1].start() if index + 1 < len(starts) else len(result.stdout)
            obj = _parse_object_blocks(match.group(1).strip(), result.stdout[match.end():end])
            if not (obj.fmt.startswith("elf") or "Mach-O" in obj.fmt):
                findings.append(Finding(
                    "ERROR", "ASM-OBJECT-FORMAT", obj.path, None,
                    f"unsupported object format {obj.fmt}; only ELF and Mach-O are checked",
                ))
                continue
            objects.append(obj)
    return objects, findings


def audit_objects(objects: list[ObjectInfo], strict_unresolved: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    definitions: dict[str, list[tuple[ObjectInfo, ObjSymbol]]] = {}
    undefined: dict[str, list[tuple[ObjectInfo, ObjSymbol]]] = {}
    for obj in objects:
        for symbol in obj.symbols:
            if symbol.undefined:
                if symbol.binding in {"Global", "Weak"}:
                    undefined.setdefault(symbol.name, []).append((obj, symbol))
                continue
            if symbol.binding in {"Global", "Weak"}:
                definitions.setdefault(symbol.name, []).append((obj, symbol))
            section = obj.sections.get(symbol.section)
            if symbol.kind.lower() in {"function", "stt_func"}:
                if section is None or not section.executable:
                    findings.append(Finding(
                        "ERROR", "ASM-FUNC-NONEXEC", obj.path, None,
                        f"function symbol {symbol.name} is in non-executable or unknown section {symbol.section or '<none>'}",
                    ))
                if symbol.size == 0:
                    findings.append(Finding(
                        "WARN", "ASM-FUNC-SIZE", obj.path, None,
                        f"function symbol {symbol.name} has zero or unavailable size",
                    ))
            elif symbol.kind.lower() in {"none", "stt_notype", "unknown"} and symbol.binding == "Global" and section is not None and section.executable:
                findings.append(Finding(
                    "WARN", "ASM-FUNC-TYPE-MISSING", obj.path, None,
                    f"global symbol {symbol.name} is in executable section {section.name} but has no function type",
                ))
            is_elf_section_symbol = symbol.kind.lower() in {"section", "stt_section"} and "Mach-O" not in obj.fmt
            if symbol.binding == "Local" and symbol.name.startswith(".") and not symbol.name.startswith(".L") \
                    and not is_elf_section_symbol:
                findings.append(Finding(
                    "WARN", "ASM-LEAKED-LABEL", obj.path, None,
                    f"local symbol {symbol.name} is dot-prefixed but not .L-prefixed; hidden labels must use the .L prefix to stay out of the symbol table",
                ))
            if symbol.kind.lower() in {"object", "stt_object"} and section is not None:
                if section.executable:
                    findings.append(Finding(
                        "ERROR", "ASM-OBJECT-EXEC", obj.path, None,
                        f"object symbol {symbol.name} is in executable section {section.name}",
                    ))
                if section.writable:
                    findings.append(Finding(
                        "WARN", "ASM-WRITABLE-OBJECT", obj.path, None,
                        f"object symbol {symbol.name} is in writable section {section.name}; confirm it is mutable by design",
                    ))

        visible_functions = [
            symbol.name for symbol in obj.symbols
            if not symbol.undefined and symbol.binding in {"Global", "Weak"}
            and symbol.kind.lower() in {"function", "stt_func"} and symbol.visibility == "default"
        ]
        if visible_functions:
            findings.append(Finding(
                "INFO", "ASM-SYMBOL-VISIBILITY", obj.path, None,
                f"{len(visible_functions)} default-visible function symbol(s); confirm intended exports: "
                + ", ".join(visible_functions[:12]) + (" ..." if len(visible_functions) > 12 else ""),
            ))
        if "Mach-O" in obj.fmt:
            findings.append(Finding(
                "INFO", "ASM-MACHO-FUNCTION-METADATA", obj.path, None,
                "Mach-O symbols do not encode ELF function/object kinds or symbol sizes; source macro checks provide partial boundary coverage",
            ))

        if obj.fmt.startswith("elf"):
            if obj.file_type.startswith("Relocatable"):
                if obj.stack_note is None:
                    findings.append(Finding(
                        "WARN", "ASM-STACK-NOTE-MISSING", obj.path, None,
                        "ELF object has no .note.GNU-stack section; final linker stack policy may be toolchain-dependent",
                    ))
                elif obj.stack_note.executable:
                    findings.append(Finding(
                        "ERROR", "ASM-EXEC-STACK", obj.path, None,
                        ".note.GNU-stack has executable flags",
                    ))
            if obj.gnu_stack_flags and "PF_X" in obj.gnu_stack_flags:
                findings.append(Finding("ERROR", "ASM-EXEC-STACK", obj.path, None, "ELF PT_GNU_STACK is executable"))
            elif obj.file_type in {"Executable", "SharedObject"} and not obj.gnu_stack_flags:
                findings.append(Finding(
                    "WARN", "ASM-STACK-HEADER-MISSING", obj.path, None,
                    "ELF executable has no PT_GNU_STACK header; stack policy is not explicit",
                ))
        elif "Mach-O" in obj.fmt:
            findings.append(Finding(
                "INFO", "ASM-STACK-POLICY", obj.path, None,
                "Mach-O object has no ELF GNU-stack marker; platform stack policy is not checked",
            ))

        # Symbol names and visibility are kept in the object model for inspection.
        # Mach-O does not encode ELF-style function type or symbol size metadata.

    for name, entries in definitions.items():
        strong = [(obj, symbol) for obj, symbol in entries if symbol.binding == "Global"]
        if len(strong) > 1:
            locations = ", ".join(obj.path for obj, _ in strong)
            findings.append(Finding("ERROR", "ASM-DUPLICATE-SYMBOL", locations, None, f"multiple strong definitions of {name}"))
        elif len(entries) > 1:
            locations = ", ".join(obj.path for obj, _ in entries)
            findings.append(Finding("WARN", "ASM-DUPLICATE-WEAK", locations, None, f"multiple weak definitions of {name}"))
    unresolved_names = sorted(name for name in undefined if name not in definitions)
    if unresolved_names:
        severity = "WARN" if strict_unresolved else "INFO"
        findings.append(Finding(
            severity, "ASM-UNRESOLVED-EXTERNAL", ", ".join(obj.path for name in unresolved_names for obj, _ in undefined[name]), None,
            f"{len(unresolved_names)} undefined external symbol(s) are not defined by the supplied objects; these may be normal library imports: "
            + ", ".join(unresolved_names[:12]) + (" ..." if len(unresolved_names) > 12 else ""),
        ))
    return findings


def discover_sources(root: Path) -> list[Path]:
    excluded = {".git", "build", "build-debug", "build-release", "output", "node_modules"}
    sources = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in ASM_SUFFIXES | {".S"}:
            continue
        if any(part in excluded for part in path.relative_to(root).parts):
            continue
        sources.append(path)
    return sorted(sources)


def discover_asm_objects(root: Path) -> list[Path]:
    if not root.exists():
        return []
    suffixes = (".S.o", ".s.o", ".S.obj", ".s.obj")
    return sorted(path for path in root.rglob("*") if path.is_file() and path.name.endswith(suffixes))


def expand_object_paths(paths: Iterable[Path]) -> list[Path]:
    found = []
    suffixes = (".o", ".obj", ".lo")
    for path in paths:
        if path.is_dir():
            found.extend(candidate for candidate in path.rglob("*") if candidate.is_file() and candidate.name.endswith(suffixes))
        elif path.is_file():
            found.append(path)
        else:
            raise FileNotFoundError(path)
    return sorted(set(found))


def run_self_test(script_dir: Path) -> int:
    command = [sys.executable, "-m", "unittest", "discover", "-s", str(script_dir / "tests"), "-v"]
    return subprocess.run(command, cwd=script_dir.parent.parent).returncode


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--root", type=Path, default=script_dir.parent.parent, help="repository root (default: script parent)")
    parser.add_argument("--objects", nargs="+", type=Path, help="object files or directories to inspect")
    parser.add_argument("--build-dir", type=Path, default=None, help="build directory for automatic assembly-object discovery")
    parser.add_argument("--source-only", action="store_true", help="skip object inspection; section and symbol checks are incomplete")
    parser.add_argument("--strict-unresolved", action="store_true", help="report unresolved symbols outside the supplied object set as warnings")
    parser.add_argument("--verbose", action="store_true", help="print warnings, information, and scan summary")
    parser.add_argument("--pp", action="store_true", help="scan macro-expanded sources instead of raw sources (requires clang)")
    parser.add_argument("--pp-cc", default=None, help="preprocessor driver (default: clang)")
    parser.add_argument("--pp-targets", default=None, help="comma-separated targets overriding per-file defaults; use 'host' for the compiler default target")
    parser.add_argument("--pp-flag", action="append", default=[], metavar="FLAG", help="extra preprocessor flag, repeatable (for example -I or -D)")
    parser.add_argument("--self-test", action="store_true", help="run the regression test suite")
    args = parser.parse_args()
    if args.self_test:
        return run_self_test(script_dir)
    if args.source_only and args.objects:
        parser.error("--source-only cannot be combined with --objects")

    root = args.root.resolve()
    build_dir = (args.build_dir or (root / "build")).resolve()
    findings: list[Finding] = []
    sources = discover_sources(root)
    if not args.pp:
        included = included_asm_sources(sources)
        for source in sources:
            findings.extend(audit_source(source, root, may_be_included=source.resolve() in included))
        if args.verbose:
            print(f"Scanned {len(sources)} assembly source file(s) under {root}")

    if args.pp:
        cc = args.pp_cc or shutil.which("clang")
        if not cc:
            print("ERROR: clang is required for preprocessed scanning", file=sys.stderr)
            return 2
        explicit_targets = None
        if args.pp_targets:
            explicit_targets = [None if item == "host" else item for item in args.pp_targets.split(",")]
        needs_target = any(
            target is not None
            for target in (explicit_targets or [target for source in sources for target in _pp_targets_for(source.name)])
        )
        if needs_target and not _cc_supports_target(cc):
            findings.append(Finding(
                "ERROR", "ASM-PP-CC-TARGET", cc, None,
                "preprocessor driver is not clang-based and cannot preprocess for non-host targets; "
                "install clang or restrict scanning with --pp-targets host",
            ))
        else:
            pp_flags = ["-D__ASSEMBLER__"] + list(args.pp_flag)
            for include in (root / "config" / "macro_config", root / "crypto" / "include"):
                if include.is_dir():
                    pp_flags += ["-I", str(include)]
            config_flags, config_finding = _pp_config_flags(build_dir, args.pp_flag)
            if config_finding:
                findings.append(config_finding)
            pp_flags += config_flags
            pp_count = 0
            for source in sources:
                names = _collect_function_names(source)
                ends = _collect_function_end_lines(source)
                locals_ = _collect_local_function_names(source)
                for target in explicit_targets or _pp_targets_for(source.name):
                    findings.extend(audit_preprocessed(source, root, cc, target, pp_flags, names, ends, locals_))
                    pp_count += 1
            if args.verbose:
                print(f"Preprocessed {pp_count} source/target pair(s) with {cc}")
            deduplicated: list[Finding] = []
            seen: set[tuple[str, str, int | None]] = set()
            for item in findings:
                key = (item.code, item.path, item.line)
                if key in seen:
                    continue
                seen.add(key)
                deduplicated.append(item)
            findings = deduplicated

    if args.source_only:
        object_paths = []
        if args.verbose:
            print("INFO: source-only mode; actual section flags and symbol tables are not inspected")
    elif args.objects:
        try:
            object_paths = expand_object_paths(args.objects)
        except FileNotFoundError as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 2
    else:
        object_paths = discover_asm_objects(build_dir)
    if not args.source_only and object_paths:
        inspector = _inspector_command()
        if inspector is None:
            print("ERROR: no object inspector found; install llvm (llvm-readobj) or binutils (readelf)", file=sys.stderr)
            return 2
        objects, read_findings = inspect_objects(object_paths, inspector)
        findings.extend(read_findings)
        findings.extend(audit_objects(objects, args.strict_unresolved))
        if args.verbose:
            print(f"Inspected {len(objects)} object file(s) with {inspector[1][0]} ({inspector[0]} backend)")
    elif not args.source_only:
        findings.append(Finding(
            "ERROR", "ASM-OBJECTS-MISSING", str(build_dir), None,
            "no assembly object files found; build the library or pass --objects, or use --source-only to accept incomplete checks",
        ))

    for finding in findings:
        if (
            args.verbose
            or finding.severity == "ERROR"
            or (args.strict_unresolved and finding.code == "ASM-UNRESOLVED-EXTERNAL")
        ):
            print(finding.render())
    error_count = sum(item.severity == "ERROR" for item in findings)
    if args.verbose:
        counts = {severity: sum(item.severity == severity for item in findings) for severity in ("ERROR", "WARN", "INFO")}
        print(f"Result: {counts['ERROR']} error(s), {counts['WARN']} warning(s), {counts['INFO']} info message(s)")
        print("Constant-time findings are heuristics. Data dependence and address provenance are not analyzed.")
        print("ABI, stack bounds, and fall-through need manual review where the scan reports warnings.")
        print("No ISA-extension checking or cross-architecture instruction validation is performed.")
    return 1 if error_count else 0


if __name__ == "__main__":
    sys.exit(main())
