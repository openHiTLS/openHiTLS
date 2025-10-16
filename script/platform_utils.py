#!/usr/bin/env python3
# coding: utf-8
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

"""
Platform, compiler, and linker detection utilities for openHiTLS build system.

This module provides independent detection for:
- Compiler type (gcc, clang, apple-clang)
- Linker type (gnu-ld, ld64, lld, gold)
- Operating system (linux, darwin, etc.)

The detection is dimension-independent: compiler choice doesn't imply linker choice,
and OS doesn't dictate compiler.
"""

import platform
import subprocess
import re
import os
from typing import Optional, Dict, Tuple


class CompilerDetector:
    """Detect compiler type by analyzing version output."""

    COMPILER_TYPES = {
        'gcc': 'gcc',
        'clang': 'clang',
        'apple-clang': 'apple-clang'
    }

    @staticmethod
    def detect_compiler_type(compiler_cmd: Optional[str] = None) -> str:
        """
        Detect compiler type from command.

        Args:
            compiler_cmd: Compiler command (default: $CC or 'cc')

        Returns:
            Compiler type: 'gcc', 'clang', or 'apple-clang'
        """
        if compiler_cmd is None:
            compiler_cmd = os.environ.get('CC', 'cc')

        try:
            # Run compiler with --version
            result = subprocess.run(
                [compiler_cmd, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            version_output = result.stdout.lower()

            # Detection logic:
            # 1. Apple Clang: contains both 'apple' and 'clang'
            # 2. Clang: contains 'clang' but not 'apple'
            # 3. GCC: contains 'gcc' or is fallback

            if 'apple' in version_output and 'clang' in version_output:
                return 'apple-clang'
            elif 'clang' in version_output:
                return 'clang'
            elif 'gcc' in version_output or 'gnu' in version_output:
                return 'gcc'
            else:
                # Fallback: assume gcc for unknown compilers
                return 'gcc'

        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError) as e:
            print(f"Warning: Failed to detect compiler type for '{compiler_cmd}': {e}")
            return 'gcc'  # Safe fallback

    @staticmethod
    def get_compiler_info(compiler_cmd: Optional[str] = None) -> Dict[str, str]:
        """
        Get detailed compiler information.

        Returns:
            Dict with 'type', 'version', 'path', 'output'
        """
        if compiler_cmd is None:
            compiler_cmd = os.environ.get('CC', 'cc')

        info = {
            'command': compiler_cmd,
            'type': 'unknown',
            'version': 'unknown',
            'path': 'unknown',
            'output': ''
        }

        try:
            # Get full path
            which_result = subprocess.run(
                ['which', compiler_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            if which_result.returncode == 0:
                info['path'] = which_result.stdout.strip()

            # Get version output
            result = subprocess.run(
                [compiler_cmd, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            info['output'] = result.stdout

            # Detect type
            info['type'] = CompilerDetector.detect_compiler_type(compiler_cmd)

            # Extract version
            version_match = re.search(r'(\d+\.\d+\.\d+)', result.stdout)
            if version_match:
                info['version'] = version_match.group(1)

        except Exception as e:
            print(f"Warning: Failed to get compiler info: {e}")

        return info


class LinkerDetector:
    """Detect linker type by analyzing version output and toolchain."""

    LINKER_TYPES = {
        'gnu-ld': 'gnu-ld',
        'ld64': 'ld64',
        'lld': 'lld',
        'gold': 'gold'
    }

    @staticmethod
    def detect_linker_type(linker_cmd: Optional[str] = None, compiler_cmd: Optional[str] = None) -> str:
        """
        Detect linker type.

        Strategy:
        1. If linker_cmd provided, detect from that command
        2. Otherwise, detect from compiler's default linker
        3. Fall back to OS-based heuristic

        Args:
            linker_cmd: Explicit linker command (e.g., 'ld', 'ld64')
            compiler_cmd: Compiler command to query for default linker

        Returns:
            Linker type: 'gnu-ld', 'ld64', 'lld', or 'gold'
        """
        # Strategy 1: Explicit linker command
        if linker_cmd:
            return LinkerDetector._detect_from_command(linker_cmd)

        # Strategy 2: Query compiler for linker
        if compiler_cmd:
            linker_from_compiler = LinkerDetector._detect_from_compiler(compiler_cmd)
            if linker_from_compiler:
                return linker_from_compiler

        # Strategy 3: OS-based heuristic
        return LinkerDetector._detect_from_os()

    @staticmethod
    def _detect_from_command(linker_cmd: str) -> str:
        """Detect linker type from direct command."""
        try:
            # Try ld --version
            result = subprocess.run(
                [linker_cmd, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            version_output = result.stdout.lower()

            # Detection patterns
            if 'lld' in version_output:
                return 'lld'
            elif 'gnu' in version_output and 'gold' in version_output:
                return 'gold'
            elif 'gnu' in version_output:
                return 'gnu-ld'
            elif 'ld64' in version_output or 'darwin' in version_output:
                return 'ld64'

            # Try ld -v (macOS style)
            result = subprocess.run(
                [linker_cmd, '-v'],
                capture_output=True,
                text=True,
                timeout=5
            )
            version_output = result.stdout.lower() + result.stderr.lower()

            if 'ld64' in version_output or 'darwin' in version_output:
                return 'ld64'

        except Exception as e:
            print(f"Warning: Failed to detect linker from command '{linker_cmd}': {e}")

        return LinkerDetector._detect_from_os()

    @staticmethod
    def _detect_from_compiler(compiler_cmd: str) -> Optional[str]:
        """Detect linker by querying compiler."""
        try:
            # Try: cc -Wl,--version
            result = subprocess.run(
                [compiler_cmd, '-Wl,--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            version_output = result.stdout.lower() + result.stderr.lower()

            if 'lld' in version_output:
                return 'lld'
            elif 'gnu' in version_output and 'gold' in version_output:
                return 'gold'
            elif 'gnu' in version_output:
                return 'gnu-ld'
            elif 'ld64' in version_output or 'darwin' in version_output:
                return 'ld64'

        except Exception:
            pass

        return None

    @staticmethod
    def _detect_from_os() -> str:
        """Fallback: detect linker based on OS."""
        system = platform.system().lower()

        if system == 'darwin':
            return 'ld64'
        elif system == 'linux':
            # Check if lld is available
            try:
                subprocess.run(['ld.lld', '--version'], capture_output=True, timeout=5)
                return 'lld'
            except Exception:
                pass

            # Default to GNU ld on Linux
            return 'gnu-ld'
        else:
            return 'gnu-ld'  # Safe fallback

    @staticmethod
    def get_linker_info(linker_cmd: Optional[str] = None, compiler_cmd: Optional[str] = None) -> Dict[str, str]:
        """
        Get detailed linker information.

        Returns:
            Dict with 'type', 'version', 'path', 'output'
        """
        info = {
            'command': linker_cmd or 'auto',
            'type': 'unknown',
            'version': 'unknown',
            'path': 'unknown',
            'output': ''
        }

        # Detect type
        info['type'] = LinkerDetector.detect_linker_type(linker_cmd, compiler_cmd)

        # Try to get more info if explicit linker command
        if linker_cmd:
            try:
                which_result = subprocess.run(
                    ['which', linker_cmd],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if which_result.returncode == 0:
                    info['path'] = which_result.stdout.strip()

                result = subprocess.run(
                    [linker_cmd, '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                info['output'] = result.stdout

                version_match = re.search(r'(\d+\.\d+)', result.stdout)
                if version_match:
                    info['version'] = version_match.group(1)

            except Exception as e:
                print(f"Warning: Failed to get linker info: {e}")

        return info


class PlatformDetector:
    """Detect operating system and architecture."""

    @staticmethod
    def get_current_platform() -> str:
        """
        Get normalized platform name.

        Returns:
            Platform name: 'linux', 'darwin', 'windows', etc.
        """
        system = platform.system().lower()

        # Normalize names
        if system == 'darwin':
            return 'darwin'
        elif system == 'linux':
            return 'linux'
        elif system == 'windows':
            return 'windows'
        else:
            return system

    @staticmethod
    def get_architecture() -> str:
        """Get CPU architecture."""
        machine = platform.machine().lower()

        # Normalize architecture names
        if machine in ('x86_64', 'amd64'):
            return 'x86_64'
        elif machine in ('aarch64', 'arm64'):
            return 'aarch64'
        elif machine.startswith('arm'):
            return 'arm'
        else:
            return machine

    @staticmethod
    def get_platform_info() -> Dict[str, str]:
        """Get comprehensive platform information."""
        return {
            'os': PlatformDetector.get_current_platform(),
            'arch': PlatformDetector.get_architecture(),
            'system': platform.system(),
            'release': platform.release(),
            'machine': platform.machine(),
            'python_version': platform.python_version()
        }


class BuildEnvironment:
    """Complete build environment detection and reporting."""

    @staticmethod
    def detect(compiler_cmd: Optional[str] = None, linker_cmd: Optional[str] = None) -> Dict:
        """
        Detect complete build environment.

        Returns:
            Dict with 'platform', 'compiler', 'linker' information
        """
        env = {
            'platform': PlatformDetector.get_platform_info(),
            'compiler': CompilerDetector.get_compiler_info(compiler_cmd),
            'linker': LinkerDetector.get_linker_info(linker_cmd, compiler_cmd)
        }
        return env


if __name__ == '__main__':
    # Test: detect and display build environment
    env = BuildEnvironment.detect()
    print("Platform:", env['platform']['os'], env['platform']['arch'])
    print("Compiler:", env['compiler']['type'], env['compiler']['version'])
    print("Linker:", env['linker']['type'])
