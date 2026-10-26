import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asm_guard  # noqa: E402


ELF_GOOD = r"""
.section .rodata,"a",@progbits
.globl fixture_constants
.type fixture_constants,@object
fixture_constants:
    .quad 0x1234
.size fixture_constants,.-fixture_constants
.section .text,"ax",@progbits
.globl fixture_function
.hidden fixture_function
.type fixture_function,@function
fixture_function:
    ret
.size fixture_function,.-fixture_function
.section .note.GNU-stack,"",@progbits
"""


ELF_READONLY_FUNCTION = r"""
#define CRYPT_AARCH64_RODATA_SECTION .section .rodata,"a",@progbits
CRYPT_AARCH64_RODATA_SECTION
.globl misplaced_function
.type misplaced_function,@function
misplaced_function:
    ret
.size misplaced_function,.-misplaced_function
.section .note.GNU-stack,"",@progbits
"""


ELF_EXEC_STACK = r"""
.text
.globl stack_fixture
.type stack_fixture,@function
stack_fixture:
    ret
.size stack_fixture,.-stack_fixture
.section .note.GNU-stack,"x",@progbits
"""


ELF_WRITABLE_OBJECT = r"""
.data
.globl mutable_or_constant
.type mutable_or_constant,@object
mutable_or_constant:
    .quad 0x1234
.size mutable_or_constant,.-mutable_or_constant
.section .note.GNU-stack,"",@progbits
"""


ELF_UNRESOLVED = r"""
.text
.globl caller_fixture
.type caller_fixture,@function
caller_fixture:
    call missing_fixture
    ret
.size caller_fixture,.-caller_fixture
.section .note.GNU-stack,"",@progbits
"""


MACHO_GOOD = r"""
.section __TEXT,__const
.globl _fixture_constants
_fixture_constants:
    .quad 0x1234
.section __TEXT,__literal16
.globl _fixture_literal16
_fixture_literal16:
    .quad 0x9abc
.section __DATA,__const
.globl _fixture_writable
_fixture_writable:
    .quad 0x5678
.section __TEXT,__text,regular,pure_instructions
.globl _fixture_function
_fixture_function:
    ret
"""


MACHO_READONLY_FUNCTION = r"""
.section __TEXT,__const
.globl _misplaced_function
_misplaced_function:
    ret
"""


class AssemblyGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clang = shutil.which("clang")
        if not cls.clang:
            raise RuntimeError("clang is required for asm guard tests")
        cls.readobj = asm_guard._inspector_command()
        if not cls.readobj:
            raise RuntimeError("an object inspector (llvm-readobj or readelf) is required for asm guard tests")
        cls.temp = tempfile.TemporaryDirectory(prefix="asm-guard-")
        cls.tmpdir = Path(cls.temp.name)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def assemble(self, name, source, target):
        source_path = self.tmpdir / f"{name}.S"
        object_path = self.tmpdir / f"{name}.o"
        source_path.write_text(source)
        command = [self.clang, f"--target={target}", "-c", str(source_path), "-o", str(object_path)]
        result = subprocess.run(command, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return source_path, object_path

    def inspect(self, object_path):
        objects, findings = asm_guard.inspect_objects([object_path], self.readobj)
        self.assertEqual(findings, [])
        self.assertEqual(len(objects), 1)
        return objects[0]

    def test_elf_actual_flags_types_and_readonly_constants(self):
        _, object_path = self.assemble("good-elf", ELF_GOOD, "x86_64-unknown-linux-gnu")
        obj = self.inspect(object_path)
        self.assertTrue(obj.sections[".text"].executable)
        self.assertFalse(obj.sections[".rodata"].executable)
        self.assertFalse(obj.sections[".rodata"].writable)
        findings = asm_guard.audit_objects([obj])
        self.assertFalse(any(item.severity == "ERROR" for item in findings), findings)
        self.assertFalse(any(item.code == "ASM-WRITABLE-OBJECT" for item in findings), findings)
        function = next(item for item in obj.symbols if item.name == "fixture_function")
        self.assertEqual(function.kind, "Function")
        self.assertEqual(function.visibility, "hidden")
        self.assertGreater(function.size, 0)

    def test_regression_function_stays_in_rodata_when_text_is_omitted(self):
        source_path, object_path = self.assemble(
            "readonly-function", ELF_READONLY_FUNCTION, "x86_64-unknown-linux-gnu"
        )
        obj = self.inspect(object_path)
        findings = asm_guard.audit_objects([obj])
        self.assertTrue(any(item.code == "ASM-FUNC-NONEXEC" for item in findings), findings)
        source_findings = asm_guard.audit_source(source_path, self.tmpdir)
        self.assertTrue(any(item.code == "ASM-FUNC-NONEXEC" for item in source_findings), source_findings)

    def test_executable_stack_is_rejected(self):
        _, object_path = self.assemble("exec-stack", ELF_EXEC_STACK, "x86_64-unknown-linux-gnu")
        obj = self.inspect(object_path)
        findings = asm_guard.audit_objects([obj])
        self.assertTrue(any(item.code == "ASM-EXEC-STACK" for item in findings), findings)

    def test_writable_object_and_unresolved_import_are_reported(self):
        _, data_object = self.assemble("writable-object", ELF_WRITABLE_OBJECT, "x86_64-unknown-linux-gnu")
        data = self.inspect(data_object)
        self.assertTrue(any(item.code == "ASM-WRITABLE-OBJECT" for item in asm_guard.audit_objects([data])))

        _, caller_object = self.assemble("unresolved", ELF_UNRESOLVED, "x86_64-unknown-linux-gnu")
        caller = self.inspect(caller_object)
        findings = asm_guard.audit_objects([caller], strict_unresolved=True)
        self.assertTrue(any(item.code == "ASM-UNRESOLVED-EXTERNAL" and item.severity == "WARN" for item in findings), findings)

    def test_macho_sections_with_same_name_keep_segment_flags(self):
        _, good_object = self.assemble("good-macho", MACHO_GOOD, "arm64-apple-darwin")
        good = self.inspect(good_object)
        self.assertTrue(good.sections["__TEXT,__text"].executable)
        self.assertFalse(good.sections["__TEXT,__const"].executable)
        self.assertFalse(good.sections["__TEXT,__const"].writable)
        self.assertTrue(good.sections["__DATA,__const"].writable)
        readonly_symbol = next(item for item in good.symbols if item.name == "_fixture_constants")
        writable_symbol = next(item for item in good.symbols if item.name == "_fixture_writable")
        self.assertEqual(readonly_symbol.section, "__TEXT,__const")
        self.assertEqual(writable_symbol.section, "__DATA,__const")
        literal_symbol = next(item for item in good.symbols if item.name == "_fixture_literal16")
        self.assertEqual(literal_symbol.section, "__TEXT,__literal16")

        _, bad_object = self.assemble(
            "readonly-macho", MACHO_READONLY_FUNCTION, "arm64-apple-darwin"
        )
        bad = self.inspect(bad_object)
        findings = asm_guard.audit_objects([bad])
        self.assertFalse(any(item.code == "ASM-FUNC-NONEXEC" for item in findings), findings)

    def test_unsupported_object_format_fails_closed(self):
        output = """File: fixture.obj
Format: COFF-x86-64
Arch: x86_64
Sections [
]
Symbols [
]
ProgramHeaders [
]
"""
        with patch.object(asm_guard.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = output
            run.return_value.stderr = ""
            objects, findings = asm_guard.inspect_objects([Path("fixture.obj")], ("llvm", ["llvm-readobj"]))
        self.assertEqual(objects, [])
        self.assertTrue(any(item.code == "ASM-OBJECT-FORMAT" for item in findings), findings)

    def test_gnu_backend_parses_elf_and_reports_findings(self):
        gnu = shutil.which("readelf") or shutil.which("llvm-readelf")
        if not gnu:
            self.skipTest("no GNU-style readelf available")
        source = r"""
.section .rodata,"a",@progbits
.globl fixture_constants
.type fixture_constants,@object
fixture_constants:
    .quad 0x1234
.size fixture_constants,.-fixture_constants
.section .text,"ax",@progbits
.globl fixture_function
.type fixture_function,@function
fixture_function:
.abc:
    ret
.size fixture_function,.-fixture_function
.section .note.GNU-stack,"x",@progbits
"""
        _, object_path = self.assemble("gnu-backend", source, "x86_64-unknown-linux-gnu")
        objects, findings = asm_guard.inspect_objects([object_path], ("gnu", [gnu]))
        self.assertEqual(findings, [])
        obj = objects[0]
        self.assertTrue(obj.fmt.startswith("elf"))
        self.assertEqual(obj.file_type, "Relocatable")
        self.assertTrue(obj.sections[".text"].executable)
        self.assertFalse(obj.sections[".rodata"].executable)
        self.assertFalse(obj.sections[".rodata"].writable)
        self.assertTrue(obj.sections[".note.GNU-stack"].executable)
        audit = asm_guard.audit_objects([obj])
        self.assertTrue(any(item.code == "ASM-LEAKED-LABEL" and ".abc" in item.message for item in audit), audit)
        self.assertTrue(any(item.code == "ASM-EXEC-STACK" for item in audit), audit)
        self.assertFalse(any(item.code == "ASM-LEAKED-LABEL" and ".text" in item.message for item in audit), audit)
        function = next(item for item in obj.symbols if item.name == "fixture_function")
        self.assertEqual(function.kind, "Function")
        self.assertGreater(function.size, 0)

    def test_gnu_backend_rejects_macho_with_hint(self):
        gnu = shutil.which("readelf") or shutil.which("llvm-readelf")
        if not gnu:
            self.skipTest("no GNU-style readelf available")
        _, object_path = self.assemble("gnu-macho", MACHO_GOOD, "arm64-apple-darwin")
        objects, findings = asm_guard.inspect_objects([object_path], ("gnu", [gnu]))
        self.assertEqual(objects, [])
        self.assertTrue(any(item.code == "ASM-OBJECT-READ" and "llvm-readobj" in item.message for item in findings), findings)

    def scan_source(self, name, source):
        path = self.tmpdir / name
        path.write_text(source)
        return asm_guard.audit_source(path, self.tmpdir)

    def test_pac_pairing_mismatch_warns(self):
        findings = self.scan_source("pac-mismatch.S", """\
.text
.type f,@function
f:
    paciasp
    ret
.size f,.-f
""")
        self.assertTrue(any(item.code == "ASM-PAC-HEURISTIC" for item in findings), findings)

    def test_pac_pairing_balanced_syntaxes_are_clean(self):
        findings = self.scan_source("pac-ok.S", """\
.text
.type f,@function
f:
    AARCH64_PACIASP
    AARCH64_AUTIASP
    ret
.size f,.-f
.type g,@function
g:
    paciasp
    hint #29
    ret
.size g,.-g
.type h,@function
h:
    hint #25
    autiasp
    ret
.size h,.-h
""")
        self.assertFalse(any(item.code == "ASM-PAC-HEURISTIC" for item in findings), findings)

    def test_pac_multi_exit_sign_once_auth_each_is_clean(self):
        findings = self.scan_source("pac-multi.S", """\
.text
.type f,@function
f:
    paciasp
    cbz x0, .La
    autiasp
    ret
.La:
    autiasp
    ret
.size f,.-f
""")
        self.assertFalse(any(item.code == "ASM-PAC-HEURISTIC" for item in findings), findings)

    def test_pac_dispatch_tail_entry_auth_is_clean(self):
        findings = self.scan_source("pac-dispatch.S", """\
.text
.type dispatch,@function
dispatch:
    paciasp
    b.eq helper
.size dispatch,.-dispatch
.type helper,@function
helper:
    autiasp
    ret
.size helper,.-helper
""")
        self.assertFalse(any(item.code == "ASM-PAC-HEURISTIC" for item in findings), findings)

    def test_pac_bl_entry_auth_warns(self):
        findings = self.scan_source("pac-bl.S", """\
.text
.type caller,@function
caller:
    paciasp
    bl helper
    autiasp
    ret
.size caller,.-caller
.type helper,@function
helper:
    autiasp
    ret
.size helper,.-helper
""")
        self.assertTrue(any(item.code == "ASM-PAC-HEURISTIC" and "call" in item.message for item in findings), findings)

    def test_pac_auth_on_unsigned_tail_path_warns(self):
        findings = self.scan_source("pac-tail-bad.S", """\
.text
.type dispatch,@function
dispatch:
    cbz x0, helper
    paciasp
    autiasp
    ret
.size dispatch,.-dispatch
.type helper,@function
helper:
    autiasp
    ret
.size helper,.-helper
""")
        self.assertTrue(any(item.code == "ASM-PAC-HEURISTIC" and "tail branch" in item.message for item in findings), findings)

    def test_stack_imbalance_warns_at_return(self):
        findings = self.scan_source("stack-bad.S", """\
.text
.type f,@function
f:
    stp x29, x30, [sp, #-64]!
    ldp x29, x30, [sp], #48
    ret
.size f,.-f
""")
        matched = [item for item in findings if item.code == "ASM-STACK-IMBALANCE"]
        self.assertTrue(matched, findings)
        self.assertEqual(matched[0].line, 6)

    def test_stack_balanced_aarch64_frame_pointer_is_clean(self):
        findings = self.scan_source("stack-fp.S", """\
.text
.type f,@function
f:
    stp x29, x30, [sp, #-128]!
    mov x29, sp
    sub sp, sp, #32
    ldp x0, x1, [sp], #32
    mov sp, x29
    ldp x29, x30, [sp], #128
    ret
.size f,.-f
""")
        self.assertFalse(any(item.code in {"ASM-STACK-IMBALANCE", "ASM-STACK-SKIPPED"} for item in findings), findings)

    def test_stack_conditional_paths_and_numeric_labels(self):
        findings = self.scan_source("stack-paths.S", """\
.text
.type f,@function
f:
    stp x29, x30, [sp, #-48]!
    cbz x0, 1f
    str x0, [sp, #32]
1:
    add x0, x0, #1
    b.lt 1b
    ldp x29, x30, [sp], #48
    ret
.size f,.-f
""")
        self.assertFalse(any(item.code in {"ASM-STACK-IMBALANCE", "ASM-STACK-SKIPPED"} for item in findings), findings)

    def test_stack_imbalance_on_one_branch_path(self):
        findings = self.scan_source("stack-path-bad.S", """\
.text
.type f,@function
f:
    stp x29, x30, [sp, #-32]!
    cbz x0, .Ldone
    ldp x29, x30, [sp], #32
    ret
.Ldone:
    add x0, x0, #1
    ret
.size f,.-f
""")
        self.assertTrue(any(item.code == "ASM-STACK-IMBALANCE" for item in findings), findings)

    def test_stack_armv7_push_pop_pc(self):
        findings = self.scan_source("stack-armv7.S", """\
.syntax unified
.arm
.text
.type f,@function
f:
    push {r4-r7, lr}
    mov r0, #1
    pop {r4-r7, pc}
.size f,.-f
""")
        self.assertFalse(any(item.code in {"ASM-STACK-IMBALANCE", "ASM-STACK-SKIPPED"} for item in findings), findings)

    def test_stack_armv7_count_mismatch_warns(self):
        findings = self.scan_source("stack-armv7-bad.S", """\
.syntax unified
.arm
.text
.type f,@function
f:
    push {r4-r7, lr}
    mov r0, #1
    pop {r4-r6, pc}
.size f,.-f
""")
        self.assertTrue(any(item.code == "ASM-STACK-IMBALANCE" for item in findings), findings)

    def test_stack_x86_push_pop_is_clean(self):
        findings = self.scan_source("stack-x86.S", """\
.text
.type f,@function
f:
    pushq %rbp
    movq %rsp, %rbp
    subq $0x20, %rsp
    addq $0x20, %rsp
    popq %rbp
    ret
.size f,.-f
""")
        self.assertFalse(any(item.code in {"ASM-STACK-IMBALANCE", "ASM-STACK-SKIPPED"} for item in findings), findings)

    def test_stack_riscv_addi_is_clean(self):
        findings = self.scan_source("stack-riscv.S", """\
.text
.type f,@function
f:
    addi sp, sp, -96
    addi sp, sp, 96
    ret
.size f,.-f
""")
        self.assertFalse(any(item.code in {"ASM-STACK-IMBALANCE", "ASM-STACK-SKIPPED"} for item in findings), findings)

    def test_indirect_branch_skips_with_info(self):
        findings = self.scan_source("stack-indirect.S", """\
.text
.type f,@function
f:
    stp x29, x30, [sp, #-16]!
    cbz x0, .Lind
    ldp x29, x30, [sp], #16
    ret
.Lind:
    br x1
.size f,.-f
""")
        self.assertTrue(any(item.code == "ASM-STACK-SKIPPED" for item in findings), findings)

    def test_dynamic_stack_pointer_skips_with_info(self):
        findings = self.scan_source("stack-dynamic.S", """\
.text
.type f,@function
f:
    pushq %rbp
    movq %rsp, %rbp
    leaq (%r15,%r14), %rsp
    ret
.size f,.-f
""")
        self.assertTrue(any(item.code == "ASM-STACK-SKIPPED" for item in findings), findings)

    def test_tail_branch_requires_restored_stack(self):
        findings = self.scan_source("stack-tail.S", """\
.text
.type f,@function
f:
    stp x29, x30, [sp, #-16]!
    ldp x29, x30, [sp], #16
    b external_helper
.size f,.-f
""")
        self.assertFalse(any(item.code in {"ASM-STACK-IMBALANCE", "ASM-STACK-SKIPPED"} for item in findings), findings)
        findings = self.scan_source("stack-tail-bad.S", """\
.text
.type f,@function
f:
    stp x29, x30, [sp, #-16]!
    b external_helper
.size f,.-f
""")
        self.assertTrue(any(item.code == "ASM-STACK-IMBALANCE" for item in findings), findings)

    def test_callee_saved_unsaved_write_warns(self):
        findings = self.scan_source("callee-bad.S", """\
.text
.type f,@function
f:
    stp x29, x30, [sp, #-16]!
    mov x20, x0
    ldp x29, x30, [sp], #16
    ret
.size f,.-f
""")
        matched = [item for item in findings if item.code == "ASM-CALLEE-SAVED-HEURISTIC"]
        self.assertTrue(matched, findings)
        self.assertIn("x20", matched[0].message)

    def test_callee_saved_stp_cover_is_clean(self):
        findings = self.scan_source("callee-ok.S", """\
.text
.type f,@function
f:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    mov x20, x0
    add x19, x19, #1
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
.size f,.-f
""")
        self.assertFalse(any(item.code == "ASM-CALLEE-SAVED-HEURISTIC" for item in findings), findings)

    def test_callee_saved_conditional_save_does_not_cover_other_path(self):
        for register, write in (("x19", "mov x19, x1"), ("x30", "bl external_helper")):
            with self.subTest(register=register):
                findings = self.scan_source("callee-conditional.S", f"""\
.text
.globl f
.type f,@function
f:
    sub sp, sp, #16
    cbz x0, 1f
    str {register}, [sp]
1:
    {write}
    ldr {register}, [sp]
    add sp, sp, #16
    ret
.size f,.-f
""")
                self.assertTrue(any(
                    item.code == "ASM-CALLEE-SAVED-HEURISTIC" and register in item.message
                    for item in findings
                ), findings)

    def test_callee_saved_branches_save_before_join(self):
        findings = self.scan_source("callee-join.S", """\
.text
.type f,@function
f:
    sub sp, sp, #16
    cbz x0, 1f
    str x19, [sp]
    b 2f
1:
    str x19, [sp]
2:
    add x19, x19, #1
    cbnz x0, 2b
    ldr x19, [sp]
    add sp, sp, #16
    ret
.size f,.-f
""")
        self.assertFalse(any(item.code == "ASM-CALLEE-SAVED-HEURISTIC" for item in findings), findings)

    def test_callee_saved_unreachable_write_is_ignored(self):
        findings = self.scan_source("callee-unreachable.S", """\
.text
.type f,@function
f:
    b .Lreturn
    mov x19, x0
.Lreturn:
    ret
.size f,.-f
""")
        self.assertFalse(any(item.code == "ASM-CALLEE-SAVED-HEURISTIC" for item in findings), findings)

    def test_callee_saved_bl_requires_lr_save(self):
        findings = self.scan_source("callee-bl.S", """\
.text
.type f,@function
f:
    sub sp, sp, #16
    bl helper
    add sp, sp, #16
    ret
.size f,.-f
""")
        matched = [item for item in findings if item.code == "ASM-CALLEE-SAVED-HEURISTIC"]
        self.assertTrue(matched, findings)
        self.assertIn("x30", matched[0].message)

    def test_callee_saved_simd_v8_warns(self):
        findings = self.scan_source("callee-simd.S", """\
.text
.type f,@function
f:
    stp x29, x30, [sp, #-16]!
    movi v8.4s, #0
    ldp x29, x30, [sp], #16
    ret
.size f,.-f
""")
        matched = [item for item in findings if item.code == "ASM-CALLEE-SAVED-HEURISTIC"]
        self.assertTrue(matched, findings)
        self.assertIn("v8", matched[0].message)

    def test_callee_saved_vpush_d8_d15_covers(self):
        findings = self.scan_source("callee-vpush.S", """\
.text
.type f,@function
f:
    stp x29, x30, [sp, #-16]!
    vpush {d8-d15}
    movi v8.4s, #0
    movi v15.4s, #0
    vpop {d8-d15}
    ldp x29, x30, [sp], #16
    ret
.size f,.-f
""")
        self.assertFalse(any(item.code == "ASM-CALLEE-SAVED-HEURISTIC" for item in findings), findings)

    def test_callee_saved_armv7_push_list_covers(self):
        findings = self.scan_source("callee-armv7.S", """\
.syntax unified
.arm
.text
.type f,@function
f:
    push {r4-r7, lr}
    add r5, r5, #1
    mov r6, r0
    pop {r4-r7, pc}
.size f,.-f
""")
        self.assertFalse(any(item.code == "ASM-CALLEE-SAVED-HEURISTIC" for item in findings), findings)

    def test_callee_saved_armv7_unsaved_r5_warns(self):
        findings = self.scan_source("callee-armv7-bad.S", """\
.syntax unified
.arm
.text
.type f,@function
f:
    push {lr}
    add r5, r5, #1
    pop {pc}
.size f,.-f
""")
        self.assertTrue(any(item.code == "ASM-CALLEE-SAVED-HEURISTIC" and "r5" in item.message for item in findings), findings)

    def test_callee_saved_x86_push_covers(self):
        findings = self.scan_source("callee-x86.S", """\
.text
.type f,@function
f:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    movq %rax, %rbx
    cmpq %rbx, %rax
    popq %rbx
    popq %rbp
    ret
.size f,.-f
""")
        self.assertFalse(any(item.code == "ASM-CALLEE-SAVED-HEURISTIC" for item in findings), findings)

    def test_callee_saved_x86_unsaved_r12_warns(self):
        findings = self.scan_source("callee-x86-bad.S", """\
.text
.type f,@function
f:
    pushq %rbp
    movq %rsp, %rbp
    movq %rax, %r12
    popq %rbp
    ret
.size f,.-f
""")
        self.assertTrue(any(item.code == "ASM-CALLEE-SAVED-HEURISTIC" and "r12" in item.message for item in findings), findings)

    def test_callee_saved_riscv_sd_covers(self):
        findings = self.scan_source("callee-riscv.S", """\
.text
.type f,@function
f:
    addi sp, sp, -16
    sd s0, 0(sp)
    sd ra, 8(sp)
    mv s0, a0
    ld s0, 0(sp)
    ld ra, 8(sp)
    addi sp, sp, 16
    ret
.size f,.-f
""")
        self.assertFalse(any(item.code == "ASM-CALLEE-SAVED-HEURISTIC" for item in findings), findings)

    def test_callee_saved_riscv_unsaved_s1_warns(self):
        findings = self.scan_source("callee-riscv-bad.S", """\
.text
.type f,@function
f:
    addi sp, sp, -16
    sd ra, 8(sp)
    mv s1, a0
    ld ra, 8(sp)
    addi sp, sp, 16
    ret
.size f,.-f
""")
        self.assertTrue(any(item.code == "ASM-CALLEE-SAVED-HEURISTIC" and "s1" in item.message for item in findings), findings)

    def test_callee_saved_ldp_from_sp_is_restore_not_write(self):
        findings = self.scan_source("callee-restore.S", """\
.text
.type f,@function
f:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
.size f,.-f
""")
        self.assertFalse(any(item.code == "ASM-CALLEE-SAVED-HEURISTIC" for item in findings), findings)

    def test_callee_saved_dispatcher_tail_helper_is_exempt(self):
        findings = self.scan_source("callee-dispatch.S", """\
.text
.type dispatch,@function
dispatch:
    stp x29, x30, [sp, #-16]!
    stp x19, x20, [sp, #16]
    b.eq helper
.size dispatch,.-dispatch
CRYPT_AARCH64_LOCAL_FUNC_START(helper)
helper:
    mov x20, x0
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
CRYPT_AARCH64_LOCAL_FUNC_END(helper)
""")
        self.assertFalse(any(item.code == "ASM-CALLEE-SAVED-HEURISTIC" for item in findings), findings)

    def test_callee_saved_included_unit_uses_caller_saves(self):
        path = self.tmpdir / "included.S"
        path.write_text("""\
.text
.type inner,@function
inner:
    movq %rax, %r12
    movq %rbx, %r13
    ret
.size inner,.-inner
""")
        findings = asm_guard.audit_source(path, self.tmpdir, may_be_included=True)
        matched = [item for item in findings if item.code == "ASM-CALLEE-SAVED-HEURISTIC"]
        self.assertTrue(matched, findings)
        self.assertEqual(matched[0].severity, "INFO")

    def test_callee_saved_armv7_apcs_alias_range_covers(self):
        findings = self.scan_source("callee-apcs.S", """\
.syntax unified
.arm
.text
.type f,@function
f:
    PUSH {v1-ip, lr}
    EOR v8, r0
    EOR v1, r1
    POP {v1-ip, pc}
.size f,.-f
""")
        self.assertFalse(any(item.code == "ASM-CALLEE-SAVED-HEURISTIC" for item in findings), findings)

    def test_riscv_jal_is_a_call_not_a_conditional_branch(self):
        findings = self.scan_source("riscv-jal.S", """\
.text
.type f,@function
f:
    addi sp, sp, -16
    sd ra, 8(sp)
    jal ra, ext_helper
    ld ra, 8(sp)
    addi sp, sp, 16
    ret
.size f,.-f
""")
        self.assertFalse(any(item.code == "ASM-STACK-IMBALANCE" for item in findings), findings)
        self.assertFalse(any(item.code == "ASM-STACK-SKIPPED" for item in findings), findings)

    def test_riscv_jal_zero_is_an_unconditional_jump(self):
        findings = self.scan_source("riscv-jal-zero.S", """\
.text
.type f,@function
f:
    addi sp, sp, -16
    sd ra, 8(sp)
    ld ra, 8(sp)
    addi sp, sp, 16
    jal zero, ext_helper
.size f,.-f
""")
        self.assertFalse(any(item.code == "ASM-STACK-IMBALANCE" for item in findings), findings)

    def test_gnu_backend_rw_stack_header_is_not_missing(self):
        gnu = shutil.which("readelf") or shutil.which("llvm-readelf")
        if not gnu:
            self.skipTest("no GNU-style readelf available")
        source = r"""
.text
.globl exported
.type exported,@function
exported:
    ret
.size exported,.-exported
.section .note.GNU-stack,"",@progbits
"""
        _, object_path = self.assemble("gnu-so", source, "x86_64-unknown-linux-gnu")
        shared_path = self.tmpdir / "gnu-so.so"
        link = [self.clang, "--target=x86_64-unknown-linux-gnu", "-fuse-ld=lld", "-shared", "-nostdlib",
                str(object_path), "-o", str(shared_path)]
        result = subprocess.run(link, text=True, capture_output=True)
        if result.returncode:
            self.skipTest(f"cannot link an ELF shared object here: {result.stderr.strip()[:120]}")
        objects, findings = asm_guard.inspect_objects([shared_path], ("gnu", [gnu]))
        self.assertEqual(findings, [])
        audit = asm_guard.audit_objects(objects)
        self.assertFalse(any(item.code == "ASM-STACK-HEADER-MISSING" for item in audit), audit)
        self.assertFalse(any(item.code == "ASM-EXEC-STACK" for item in audit), audit)

    def test_duplicate_and_unresolved_symbols_are_reported(self):
        duplicate = r"""
.text
.globl repeated
.type repeated,@function
repeated:
    ret
.size repeated,.-repeated
.section .note.GNU-stack,"",@progbits
"""
        _, first = self.assemble("duplicate-a", duplicate, "x86_64-unknown-linux-gnu")
        _, second = self.assemble("duplicate-b", duplicate, "x86_64-unknown-linux-gnu")
        objects = [self.inspect(first), self.inspect(second)]
        findings = asm_guard.audit_objects(objects)
        self.assertTrue(any(item.code == "ASM-DUPLICATE-SYMBOL" for item in findings), findings)

    def test_code_to_data_transition_without_function_end_warns(self):
        path = self.tmpdir / "fallthrough.S"
        path.write_text("""\n.text\n.type f,@function\nf:\n    nop\n.section .rodata\n""")
        findings = asm_guard.audit_source(path, self.tmpdir)
        self.assertTrue(any(item.code == "ASM-CODE-DATA-FALLTHROUGH" for item in findings), findings)

    def test_project_function_macro_in_readonly_section_is_detected(self):
        path = self.tmpdir / "macro-function.S"
        path.write_text("CRYPT_AARCH64_RODATA_SECTION\nCRYPT_AARCH64_FUNC_START(misplaced)\n")
        findings = asm_guard.audit_source(path, self.tmpdir)
        self.assertTrue(any(item.code == "ASM-FUNC-NONEXEC" for item in findings), findings)

    def test_previous_restores_the_prior_section(self):
        path = self.tmpdir / "previous-section.S"
        path.write_text(
            ".text\n.section .rodata\n.quad 0x1234\n.previous\n"
            ".type restored,@function\nrestored:\n    ret\n.size restored,.-restored\n"
        )
        findings = asm_guard.audit_source(path, self.tmpdir)
        self.assertFalse(any(item.code == "ASM-FUNC-NONEXEC" for item in findings), findings)

    def test_missing_local_branch_target_is_rejected(self):
        path = self.tmpdir / "bad-branch.S"
        path.write_text(".text\n.globl bad\n.type bad,@function\nbad:\n    jmp .Lmissing\n.size bad,.-bad\n")
        findings = asm_guard.audit_source(path, self.tmpdir)
        self.assertTrue(any(item.code == "ASM-BRANCH-TARGET" for item in findings), findings)

    def test_riscv_branch_targets_are_checked(self):
        mnemonics = ("beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez", "bltz", "bgez", "blez", "bgtz", "bgt", "ble", "bgtu", "bleu", "tail")
        path = self.tmpdir / "riscv-branches.S"
        lines = [".text", ".type riscv,@function", "riscv:"]
        for index, mnemonic in enumerate(mnemonics):
            operands = f"a0, a1, .Lmissing{index}" if mnemonic in {"beq", "bne", "blt", "bge", "bltu", "bgeu"} else f"a0, .Lmissing{index}" if mnemonic not in {"tail"} else f".Lmissing{index}"
            lines.append(f"    {mnemonic} {operands}")
        lines.append(".size riscv,.-riscv")
        path.write_text("\n".join(lines) + "\n")
        findings = asm_guard.audit_source(path, self.tmpdir)
        branch_findings = [item for item in findings if item.code == "ASM-BRANCH-TARGET"]
        self.assertEqual(len(branch_findings), len(mnemonics), findings)

    def test_bare_local_branch_label_requires_dot_L_or_function_macro(self):
        path = self.tmpdir / "bare-branch-label.S"
        path.write_text(
            ".text\n.globl caller\n.type caller,@function\ncaller:\n"
            "    bl helper\n    bmi tail\n    ret\n.size caller,.-caller\n"
            "helper:\n    ret\ntail:\n    ret\n"
        )
        findings = asm_guard.audit_source(path, self.tmpdir)
        hits = [item for item in findings if item.code == "ASM-BRANCH-LOCAL-CONVENTION"]
        self.assertEqual(len(hits), 2, findings)
        self.assertTrue(any("helper" in item.message for item in hits), findings)
        self.assertTrue(any("tail" in item.message for item in hits), findings)

    def test_bare_label_with_local_function_macro_is_clean(self):
        path = self.tmpdir / "local-function-macro.S"
        path.write_text(
            ".text\n.globl caller\ncaller:\n"
            "    bl helper\n    ret\n"
            "CRYPT_AARCH64_LOCAL_FUNC_START(helper)\n"
            "    ret\n"
            "CRYPT_AARCH64_LOCAL_FUNC_END(helper)\n"
        )
        findings = asm_guard.audit_source(path, self.tmpdir)
        self.assertFalse(any(item.code == "ASM-BRANCH-LOCAL-CONVENTION" for item in findings), findings)

    def test_dot_L_numeric_and_global_branch_targets_are_clean(self):
        path = self.tmpdir / "clean-branch-targets.S"
        path.write_text(
            ".text\n.globl caller\n.globl callee\ncaller:\n"
            "    b .Lloop\n.Lloop:\n"
            "    cbz w0, 1f\n1:\n"
            "    bl callee\n    ret\ncallee:\n    ret\n"
        )
        findings = asm_guard.audit_source(path, self.tmpdir)
        self.assertFalse(any(item.code == "ASM-BRANCH-LOCAL-CONVENTION" for item in findings), findings)

    def test_underscored_expanded_target_excluded_via_extra_functions(self):
        # Mach-O preprocessing expands CRYPT_AARCH64_SYM to a _-prefixed name and
        # the local function macro loses its .type, so only extra_functions knows it.
        findings = asm_guard._scan_assembly(
            ["bl _helper", "_helper:", "    ret"],
            [("f.S", i) for i in range(1, 4)],
            self.tmpdir,
            extra_functions={"helper"},
        )
        self.assertFalse(any(item.code == "ASM-BRANCH-LOCAL-CONVENTION" for item in findings), findings)

    def test_data_in_executable_section_is_reported_for_fallthrough_review(self):
        path = self.tmpdir / "embedded-data.S"
        path.write_text(".text\nfunction:\n    .quad 0x1234\n")
        findings = asm_guard.audit_source(path, self.tmpdir)
        self.assertTrue(any(item.code == "ASM-CODE-DATA-HEURISTIC" for item in findings), findings)

    def test_cli_requires_objects_unless_source_only_is_explicit(self):
        script = Path(asm_guard.__file__).resolve()
        with tempfile.TemporaryDirectory(prefix="asm-guard-cli-") as root:
            result = subprocess.run(
                [sys.executable, str(script), "--root", root], text=True, capture_output=True
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ASM-OBJECTS-MISSING", result.stdout)

            source_dir = Path(root) / "crypto"
            source_dir.mkdir()
            (source_dir / "fixture.S").write_text(
                ".text\n.globl fixture\n.type fixture,@function\nfixture:\n    ret\n.size fixture,.-fixture\n"
            )
            source_only = subprocess.run(
                [sys.executable, str(script), "--root", root, "--source-only"],
                text=True,
                capture_output=True,
            )
            self.assertEqual(source_only.returncode, 0, source_only.stdout + source_only.stderr)
            self.assertEqual(source_only.stdout, "")

            verbose = subprocess.run(
                [sys.executable, str(script), "--root", root, "--source-only", "--verbose"],
                text=True,
                capture_output=True,
            )
            self.assertEqual(verbose.returncode, 0, verbose.stdout + verbose.stderr)
            self.assertIn("ASM-ABI-HEURISTIC", verbose.stdout)

    def test_sdv_guard_uses_build_rules_instead_of_asm_options(self):
        script_dir = Path(asm_guard.__file__).resolve().parent
        script = (script_dir / "execute_sdv.sh").read_text()
        start = script.index("run_asm_guard()")
        guard = script[start:script.index("\nclean()", start)]
        for generator in ("Unix Makefiles", "Ninja", "Ninja Multi-Config"):
            with self.subTest(generator=generator), tempfile.TemporaryDirectory(prefix="asm-guard-sdv-") as temp:
                if generator.startswith("Ninja") and not shutil.which("ninja"):
                    self.skipTest("ninja is unavailable")
                root = Path(temp)
                scripts = root / "testcode" / "script"
                scripts.mkdir(parents=True)
                shutil.copyfile(script_dir / "asm_guard.py", scripts / "asm_guard.py")
                (root / "CMakeLists.txt").write_text(
                    "cmake_minimum_required(VERSION 3.16)\n"
                    "project(guard_fixture C ASM)\n"
                    'option(HITLS_ASM_X8664 "Enable assembly" ON)\n'
                    'option(FIXTURE_ASM "Build assembly source" OFF)\n'
                    "add_library(fixture OBJECT fixture.c)\n"
                    "if(FIXTURE_ASM)\n"
                    "  target_sources(fixture PRIVATE fixture.S)\n"
                    "endif()\n"
                )
                (root / "fixture.c").write_text("int fixture(void) { return 0; }\n")
                (root / "fixture.S").write_text(ELF_GOOD)
                configure = ["cmake", "-S", str(root), "-B", str(root / "build"), "-G", generator]
                result = subprocess.run(configure, text=True, capture_output=True)
                if generator == "Ninja Multi-Config" and "Could not create named generator" in result.stderr:
                    self.skipTest("CMake does not support Ninja Multi-Config")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                command = ["bash", "-c", 'HITLS_ROOT_DIR="$1"; SCRIPT_DIR="$2"\n' + guard + "\nrun_asm_guard",
                           "bash", str(root), str(scripts)]
                result = subprocess.run(command, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("source-only", result.stdout)

                result = subprocess.run(configure + ["-DFIXTURE_ASM=ON"], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                result = subprocess.run(command, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("ASM-OBJECTS-MISSING", result.stdout)

    def test_cli_pp_uses_expanded_branch_targets(self):
        script = Path(asm_guard.__file__).resolve()
        with tempfile.TemporaryDirectory(prefix="asm-guard-pp-label-") as temp:
            root = Path(temp)
            (root / "build" / "config").mkdir(parents=True)
            (root / "build" / "config" / "hitls_build_config.h").write_text("")
            path = root / "fixture.S"
            path.write_text(
                "#define END_LABEL .Ldone\n.text\n.globl f\n.type f,@function\nf:\n"
                "    jmp .Ldone\nEND_LABEL:\n    ret\n.size f,.-f\n"
            )
            command = [sys.executable, str(script), "--root", str(root), "--pp", "--pp-targets", "host",
                       "--source-only"]
            result = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            path.write_text(path.read_text().replace("jmp .Ldone", "jmp .Lmissing"))
            result = subprocess.run(command, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ASM-BRANCH-TARGET", result.stdout)
            self.assertIn("preprocessed for host", result.stdout)

    def test_end_directive_does_not_hide_missing_function_size(self):
        path = self.tmpdir / "end-directive.S"
        path.write_text(".text\n.type f,@function\nf:\n    ret\n.end\n")
        findings = asm_guard.audit_source(path, self.tmpdir)
        self.assertTrue(any(item.code == "ASM-FUNC-SIZE" for item in findings), findings)

    def test_self_test_uses_repository_root_as_working_directory(self):
        script_dir = Path(asm_guard.__file__).resolve().parent
        with patch.object(asm_guard.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.assertEqual(asm_guard.run_self_test(script_dir), 0)
            self.assertEqual(run.call_args.kwargs["cwd"], script_dir.parent.parent)

    def test_stack_and_constant_time_checks_are_explicitly_heuristic(self):
        path = self.tmpdir / "heuristics.S"
        path.write_text(
            ".text\n.globl heuristic\n.type heuristic,@function\nheuristic:\n"
            "    subq $16, %rsp\n    movq %rax, -256(%rsp)\n"
            "    movaps (%rax), %xmm0\n"
            "    testq %rdi, %rdi\n    jne .Lok\n"
            "    movq (%rdi,%rax,8), %rax\n.Lok:\n    ret\n"
            ".size heuristic,.-heuristic\n"
        )
        findings = asm_guard.audit_source(path, self.tmpdir)
        codes = {item.code for item in findings}
        self.assertIn("ASM-ABI-HEURISTIC", codes)
        self.assertIn("ASM-STACK-BOUNDS-HEURISTIC", codes)
        self.assertIn("ASM-ALIGNMENT-HEURISTIC", codes)
        self.assertIn("ASM-CT-BRANCH-HEURISTIC", codes)
        self.assertIn("ASM-CT-ADDRESS-HEURISTIC", codes)

    def test_pp_targets_derived_from_filename(self):
        self.assertEqual(
            asm_guard._pp_targets_for("ecp_sm2_armv8.S"),
            ["aarch64-linux-gnu", "arm64-apple-darwin"],
        )
        self.assertEqual(asm_guard._pp_targets_for("sha2_256_riscv64.S"), ["riscv64-linux-gnu"])
        self.assertEqual(asm_guard._pp_targets_for("sm3_armv7.S"), ["armv7-linux-gnueabi"])
        self.assertEqual(asm_guard._pp_targets_for("ecp256_pre_comp_table.s"), [None])

    def test_pp_scans_only_the_selected_platform_branch(self):
        path = self.tmpdir / "pp-branch.S"
        path.write_text(
            "#ifdef __APPLE__\n"
            ".section __TEXT,__const\n"
            "CRYPT_AARCH64_FUNC_START(badApple)\n"
            "    ret\n"
            "#else\n"
            ".section .rodata\n"
            "CRYPT_AARCH64_FUNC_START(badElf)\n"
            "    ret\n"
            "#endif\n"
        )
        apple = asm_guard.audit_preprocessed(
            path, self.tmpdir, self.clang, "arm64-apple-darwin", [], {"badApple", "badElf"}
        )
        elf = asm_guard.audit_preprocessed(
            path, self.tmpdir, self.clang, "x86_64-linux-gnu", [], {"badApple", "badElf"}
        )
        apple_errors = [item for item in apple if item.code == "ASM-FUNC-NONEXEC"]
        elf_errors = [item for item in elf if item.code == "ASM-FUNC-NONEXEC"]
        self.assertEqual(len(apple_errors), 1, apple)
        self.assertIn("badApple", apple_errors[0].message)
        self.assertEqual(apple_errors[0].line, 3)
        self.assertEqual(apple_errors[0].path, "pp-branch.S")
        self.assertEqual(len(elf_errors), 1, elf)
        self.assertIn("badElf", elf_errors[0].message)
        self.assertEqual(elf_errors[0].line, 7)
        self.assertTrue(any("preprocessed for arm64-apple-darwin" in item.message for item in apple))

    def test_pp_splits_percent_statement_separators(self):
        path = self.tmpdir / "pp-percent.S"
        path.write_text(
            "#define FS(n) .globl _##n %% _##n:\n"
            ".section .rodata\n"
            "FS(misplaced)\n"
        )
        findings = asm_guard.audit_preprocessed(
            path, self.tmpdir, self.clang, "x86_64-linux-gnu", [], {"misplaced"}
        )
        errors = [item for item in findings if item.code == "ASM-FUNC-NONEXEC"]
        self.assertEqual(len(errors), 1, findings)
        self.assertIn("misplaced", errors[0].message)
        self.assertEqual(errors[0].line, 3)

    def test_pp_failure_is_reported(self):
        path = self.tmpdir / "pp-missing.S"
        path.write_text('#include "definitely_missing_header.h"\n.text\n')
        findings = asm_guard.audit_preprocessed(path, self.tmpdir, self.clang, None, [], set())
        self.assertTrue(any(item.code == "ASM-PP-FAIL" and item.severity == "ERROR" for item in findings), findings)

    def test_non_clang_driver_is_detected_for_target_support(self):
        self.assertTrue(asm_guard._cc_supports_target(self.clang))
        self.assertFalse(asm_guard._cc_supports_target(sys.executable))

    def test_non_L_dot_label_is_reported_in_source(self):
        path = self.tmpdir / "dot-label.S"
        path.write_text(".text\n.globl ok\nok:\n.abc:\n    ret\n.Lfine:\n    ret\n")
        findings = asm_guard.audit_source(path, self.tmpdir)
        leaked = [item for item in findings if item.code == "ASM-LOCAL-LABEL"]
        self.assertEqual(len(leaked), 1, findings)
        self.assertIn(".abc", leaked[0].message)
        self.assertEqual(leaked[0].line, 4)

    def test_non_L_dot_label_is_reported_in_objects(self):
        source = r"""
.text
.globl visible
.type visible,@function
visible:
.abc:
    ret
.size visible,.-visible
.section .note.GNU-stack,"",@progbits
"""
        _, object_path = self.assemble("dot-label-elf", source, "x86_64-unknown-linux-gnu")
        obj = self.inspect(object_path)
        findings = asm_guard.audit_objects([obj])
        leaked = [item for item in findings if item.code == "ASM-LEAKED-LABEL"]
        self.assertEqual(len(leaked), 1, findings)
        self.assertIn(".abc", leaked[0].message)
        self.assertFalse(any(".text" in item.message for item in leaked), findings)

        macho = ".section __TEXT,__text\n.globl _visible\n_visible:\n.abc:\n    ret\n"
        _, macho_path = self.assemble("dot-label-macho", macho, "arm64-apple-darwin")
        macho_obj = self.inspect(macho_path)
        self.assertTrue(
            any(item.code == "ASM-LEAKED-LABEL" for item in asm_guard.audit_objects([macho_obj]))
        )

        macho_clean = ".section __TEXT,__text\n.globl _visible\n_visible:\n.Lfine:\n    ret\n"
        _, clean_path = self.assemble("dot-label-clean", macho_clean, "arm64-apple-darwin")
        clean_obj = self.inspect(clean_path)
        self.assertFalse(
            any(item.code == "ASM-LEAKED-LABEL" for item in asm_guard.audit_objects([clean_obj]))
        )

    def test_pp_respects_macro_function_end_boundaries(self):
        path = self.tmpdir / "pp-end.S"
        path.write_text(
            "#define FUNC_START(n) .globl _##n %% _##n:\n"
            "#define CRYPT_AARCH64_FUNC_END(n)\n"
            "#define RODATA .section __TEXT,__const\n"
            "FUNC_START(fn)\n"
            "    ret\n"
            "CRYPT_AARCH64_FUNC_END(fn)\n"
            "RODATA\n"
            ".quad 1\n"
        )
        ends = asm_guard._collect_function_end_lines(path)
        self.assertEqual(ends.get("fn"), 6)
        findings = asm_guard.audit_preprocessed(
            path, self.tmpdir, self.clang, "arm64-apple-darwin", [], {"fn"}, ends
        )
        self.assertFalse(
            any(item.code == "ASM-CODE-DATA-FALLTHROUGH" for item in findings), findings
        )

    def test_lea_intel_rsp_adjustment_sign_matches_att(self):
        self.assertEqual(asm_guard._stack_instruction("lea", "rsp, [rsp+16]"), ("delta", -16))
        self.assertEqual(asm_guard._stack_instruction("lea", "rsp, [rsp-16]"), ("delta", 16))
        self.assertEqual(asm_guard._stack_instruction("lea", "16(%rsp), %rsp"), ("delta", -16))
        balanced = self.scan_source("lea-intel-ok.S", """\
.text
.intel_syntax noprefix
.type f,@function
f:
    sub rsp, 16
    lea rsp, [rsp+16]
    ret
.size f,.-f
""")
        self.assertFalse(
            any(item.code in {"ASM-STACK-IMBALANCE", "ASM-STACK-SKIPPED"} for item in balanced), balanced
        )
        leaky = self.scan_source("lea-intel-bad.S", """\
.text
.intel_syntax noprefix
.type f,@function
f:
    sub rsp, 16
    lea rsp, [rsp-16]
    ret
.size f,.-f
""")
        self.assertTrue(any(item.code == "ASM-STACK-IMBALANCE" for item in leaky), leaky)

    def test_dead_if_zero_region_is_not_scanned(self):
        findings = self.scan_source("if-zero.S", """\
.text
.type f,@function
f:
#if 0
    jmp .Lmissing
#endif
    ret
.size f,.-f
""")
        self.assertFalse(any(item.code == "ASM-BRANCH-TARGET" for item in findings), findings)
        live = self.scan_source("if-zero-live.S", """\
.text
.type g,@function
g:
#if 1
    jmp .Lstillmissing
#endif
    ret
.size g,.-g
""")
        self.assertTrue(any(item.code == "ASM-BRANCH-TARGET" for item in live), live)

    def test_readelf_dynsym_and_symtab_entries_are_deduplicated(self):
        readelf_output = (
            "ELF Header:\n"
            "  Class:                             ELF64\n"
            "  Machine:                           AArch64\n"
            "  Type:                              DYN\n"
            "Section Headers:\n"
            "  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al\n"
            "  [ 1] .text             PROGBITS        0000000000000000 000100 000010 00  AX  0   0  4\n"
            "  [ 2] .dynsym           DYNSYM          0000000000000000 000120 000030 18   A  3   1  8\n"
            "  [ 3] .symtab           SYMTAB          0000000000000000 000150 000060 18     4   2  8\n"
            "Symbol table '.dynsym' contains 2 entries:\n"
            "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
            "     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND \n"
            "     1: 0000000000000000    16 FUNC    GLOBAL DEFAULT    1 only_one\n"
            "Symbol table '.symtab' contains 3 entries:\n"
            "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
            "     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND \n"
            "     1: 0000000000000000    16 FUNC    GLOBAL DEFAULT    1 only_one\n"
            "     2: 0000000000000010    16 FUNC    GLOBAL DEFAULT    1 second\n"
        )
        obj = asm_guard._parse_readelf("/tmp/libfixture.so", readelf_output)
        self.assertIsNotNone(obj)
        names = [item.name for item in obj.symbols if item.name]
        self.assertEqual(names.count("only_one"), 1, names)
        findings = asm_guard.audit_objects([obj])
        self.assertFalse(any(item.code == "ASM-DUPLICATE-SYMBOL" for item in findings), findings)

    def test_saved_stack_pointer_round_trip_is_clean(self):
        aarch64 = self.scan_source("savesp-aarch64.S", """\
.text
.type f,@function
f:
    mov x9, sp
    sub sp, sp, #16
    mov sp, x9
    ret
.size f,.-f
""")
        self.assertFalse(
            any(item.code in {"ASM-STACK-IMBALANCE", "ASM-STACK-SKIPPED"} for item in aarch64), aarch64
        )
        x86 = self.scan_source("savesp-x86.S", """\
.text
.type g,@function
g:
    movq %rsp, %r11
    subq $16, %rsp
    movq %r11, %rsp
    ret
.size g,.-g
""")
        self.assertFalse(
            any(item.code in {"ASM-STACK-IMBALANCE", "ASM-STACK-SKIPPED"} for item in x86), x86
        )

    def test_callee_saved_armv7_push_lr_covers_bl(self):
        self.assertEqual(asm_guard._saved_registers("push", "{r4, lr}", "arm32"), {"r4", "lr"})
        findings = self.scan_source("callee-armv7-lr.S", """\
.syntax unified
.arm
.text
.type f,@function
f:
    push {r4, lr}
    bl helper
    pop {r4, pc}
.size f,.-f
""")
        matched = [item for item in findings if item.code == "ASM-CALLEE-SAVED-HEURISTIC"]
        self.assertFalse(any("lr" in item.message for item in matched), findings)

    def test_pac_retab_pairs_with_paciasp(self):
        findings = self.scan_source("retab-ok.S", """\
.text
.type f,@function
f:
    pacibsp
    retab
.size f,.-f
""")
        self.assertFalse(any(item.code == "ASM-PAC-HEURISTIC" for item in findings), findings)
        _, edges = asm_guard._analyze_function_body("g", [(1, "retab")], False)
        self.assertTrue(edges.get("auth_sites"), edges)

    def test_pp_config_flag_suppresses_missing_generated_header(self):
        build = self.tmpdir / "pp-config-build"
        flags, finding = asm_guard._pp_config_flags(build, ["-DHITLS_CONFIG_FILE=custom-config.h"])
        self.assertEqual(flags, [])
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "WARN")
        flags, finding = asm_guard._pp_config_flags(build, [])
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "ERROR")
        (build / "config").mkdir(parents=True)
        (build / "config" / "hitls_build_config.h").write_text("")
        flags, finding = asm_guard._pp_config_flags(build, [])
        self.assertIsNone(finding)
        self.assertIn("hitls_build_config.h", flags[0])
        self.assertIn("-DHITLS_CRYPTO_PROVIDER", flags)

    def test_cli_pp_flag_config_allows_missing_build_header(self):
        script = Path(asm_guard.__file__).resolve()
        with tempfile.TemporaryDirectory(prefix="asm-guard-pp-config-") as root:
            source_dir = Path(root) / "crypto"
            source_dir.mkdir()
            (source_dir / "fixture.S").write_text(
                ".text\n.globl fixture\n.type fixture,@function\nfixture:\n    ret\n.size fixture,.-fixture\n"
            )
            missing = subprocess.run(
                [sys.executable, str(script), "--root", root, "--pp", "--pp-targets", "host", "--source-only"],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(missing.returncode, 0, missing.stdout + missing.stderr)
            self.assertIn("ASM-PP-CONFIG", missing.stdout)
            custom = subprocess.run(
                [
                    sys.executable, str(script), "--root", root, "--pp", "--pp-targets", "host",
                    "--source-only", "--pp-flag=-DHITLS_CONFIG_FILE=custom-config.h",
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(custom.returncode, 0, custom.stdout + custom.stderr)


if __name__ == "__main__":
    unittest.main()
