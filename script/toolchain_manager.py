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
Toolchain management for openHiTLS build system.

Handles toolchain file generation, selection, and listing.
"""

import os
import shutil
from typing import Optional, Dict


class ToolchainManager:
    """Manage CMake toolchain files for cross-compilation and compiler selection."""

    @staticmethod
    def list_available(toolchain_dir: str) -> None:
        """
        List all available toolchain files.

        Args:
            toolchain_dir: Directory containing toolchain files
        """
        if not os.path.exists(toolchain_dir):
            print("No toolchain directory found at: {}".format(toolchain_dir))
            return

        toolchains = []
        for f in os.listdir(toolchain_dir):
            if f.endswith('.cmake'):
                name = f[:-6]  # Remove .cmake extension
                toolchain_file = os.path.join(toolchain_dir, f)
                # Read first line for description
                try:
                    with open(toolchain_file) as tf:
                        first_line = tf.readline().strip()
                        if first_line.startswith('#'):
                            desc = first_line[1:].strip()
                        else:
                            desc = "No description"
                except Exception:
                    desc = "Error reading file"
                toolchains.append((name, desc))

        if not toolchains:
            print("No toolchain files found in: {}".format(toolchain_dir))
            return

        print("Available toolchains:")
        print("=" * 70)
        for name, desc in sorted(toolchains):
            print("  {:<30s} - {}".format(name, desc))
        print("=" * 70)
        print("\nUsage: python3 configure.py --toolchain <name> ...")

    @staticmethod
    def get_cxx_compiler_path(c_compiler_path: str) -> str:
        """
        Get C++ compiler path based on C compiler.

        Args:
            c_compiler_path: Path to C compiler

        Returns:
            Path to C++ compiler
        """
        # Map C compiler to C++ compiler
        if 'gcc' in c_compiler_path:
            return c_compiler_path.replace('gcc', 'g++')
        elif 'clang' in c_compiler_path:
            return c_compiler_path.replace('clang', 'clang++')
        elif c_compiler_path == 'cc':
            return 'c++'
        else:
            return 'c++'

    @staticmethod
    def get_cmake_system_name(platform: str) -> str:
        """
        Convert platform name to CMake system name.

        Args:
            platform: Platform identifier (linux, darwin, windows)

        Returns:
            CMake-compatible system name
        """
        platform_map = {
            'darwin': 'Darwin',
            'linux': 'Linux',
            'windows': 'Windows'
        }
        return platform_map.get(platform, platform.capitalize())

    @staticmethod
    def generate_from_detection(compiler_info: Dict, linker_type: str, platform_info: Dict) -> str:
        """
        Generate toolchain file content from auto-detected environment.

        Args:
            compiler_info: Compiler detection results
            linker_type: Detected linker type
            platform_info: Platform detection results

        Returns:
            Toolchain file content as string
        """
        compiler_type = compiler_info.get('type', 'unknown')
        compiler_path = compiler_info.get('path', 'cc')
        arch = platform_info.get('arch', 'unknown')
        platform = platform_info.get('os', 'linux')

        toolchain = "# Auto-generated toolchain from detection\n"
        toolchain += "# Compiler: {}\n".format(compiler_type)
        toolchain += "# Linker:   {}\n".format(linker_type)
        toolchain += "# Platform: {}\n\n".format(platform)

        toolchain += "set(CMAKE_SYSTEM_NAME \"{}\")\n".format(
            ToolchainManager.get_cmake_system_name(platform)
        )
        toolchain += "set(CMAKE_SYSTEM_PROCESSOR \"{}\")\n\n".format(arch)

        toolchain += "set(CMAKE_C_COMPILER \"{}\")\n".format(compiler_path)
        toolchain += "set(CMAKE_CXX_COMPILER \"{}\")\n".format(
            ToolchainManager.get_cxx_compiler_path(compiler_path)
        )
        toolchain += "set(CMAKE_ASM_COMPILER \"{}\")\n\n".format(compiler_path)

        toolchain += "# Metadata\n"
        toolchain += "set(TOOLCHAIN_DETECTED_COMPILER \"{}\")\n".format(compiler_type)
        toolchain += "set(TOOLCHAIN_DETECTED_LINKER \"{}\")\n".format(linker_type)
        toolchain += "set(TOOLCHAIN_DETECTED_PLATFORM \"{}\")\n".format(platform)

        return toolchain

    @staticmethod
    def generate_from_args(compiler_info: Dict, linker_type: str, platform_info: Dict) -> str:
        """
        Generate toolchain file content from command-line arguments.

        Args:
            compiler_info: Compiler detection results
            linker_type: Linker type from arguments
            platform_info: Platform detection results

        Returns:
            Toolchain file content as string
        """
        compiler_type = compiler_info.get('type', 'unknown')
        compiler_path = compiler_info.get('path', 'cc')
        arch = platform_info.get('arch', 'unknown')
        platform = platform_info.get('os', 'linux')

        toolchain = "# Toolchain from command-line arguments\n"
        toolchain += "# Compiler: {}\n".format(compiler_type)
        toolchain += "# Linker:   {}\n".format(linker_type)
        toolchain += "# Platform: {}\n\n".format(platform)

        toolchain += "set(CMAKE_SYSTEM_NAME \"{}\")\n".format(
            ToolchainManager.get_cmake_system_name(platform)
        )
        toolchain += "set(CMAKE_SYSTEM_PROCESSOR \"{}\")\n\n".format(arch)

        toolchain += "set(CMAKE_C_COMPILER \"{}\")\n".format(compiler_path)
        toolchain += "set(CMAKE_CXX_COMPILER \"{}\")\n".format(
            ToolchainManager.get_cxx_compiler_path(compiler_path)
        )
        toolchain += "set(CMAKE_ASM_COMPILER \"{}\")\n\n".format(compiler_path)

        toolchain += "# Metadata\n"
        toolchain += "set(TOOLCHAIN_DETECTED_COMPILER \"{}\")\n".format(compiler_type)
        toolchain += "set(TOOLCHAIN_DETECTED_LINKER \"{}\")\n".format(linker_type)
        toolchain += "set(TOOLCHAIN_DETECTED_PLATFORM \"{}\")\n".format(platform)

        return toolchain

    @staticmethod
    def select_or_generate(args, compiler_type: str, linker_type: str, platform: str,
                          build_dir: str, srcdir: str) -> None:
        """
        Select or generate toolchain file.

        Args:
            args: Command-line arguments namespace
            compiler_type: Detected/specified compiler type
            linker_type: Detected/specified linker type
            platform: Detected/specified platform
            build_dir: Build directory path
            srcdir: Source directory path
        """
        from platform_utils import CompilerDetector, PlatformDetector

        toolchain_path = os.path.join(build_dir, 'toolchain.cmake')

        # If toolchain already exists and no explicit toolchain/compiler specified, keep existing
        if os.path.exists(toolchain_path) and not args.toolchain and not args.compiler:
            return

        if args.toolchain:
            # Use specified toolchain file
            src_path = os.path.join(srcdir, 'config/toolchain', '{}.cmake'.format(args.toolchain))
            if not os.path.exists(src_path):
                raise FileNotFoundError(
                    "Toolchain file not found: {}\n"
                    "Run 'python3 configure.py --list-toolchains' to see available options.".format(src_path)
                )
            shutil.copy(src_path, toolchain_path)

        elif args.compiler:
            # Generate from command-line arguments
            compiler_info = CompilerDetector.get_compiler_info()
            platform_info = PlatformDetector.get_platform_info()

            toolchain_cmake = ToolchainManager.generate_from_args(
                compiler_info, linker_type, platform_info
            )
            with open(toolchain_path, 'w') as f:
                f.write(toolchain_cmake)

        else:
            # Auto-detect (silent)
            compiler_info = CompilerDetector.get_compiler_info()
            platform_info = PlatformDetector.get_platform_info()

            toolchain_cmake = ToolchainManager.generate_from_detection(
                compiler_info, linker_type, platform_info
            )
            with open(toolchain_path, 'w') as f:
                f.write(toolchain_cmake)
