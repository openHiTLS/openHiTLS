#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
Customize the openHiTLS build.
Generate the modules.cmake file based on command line arguments and configuration files.

Options usage and examples:
1 Enable the feature on demand and specify the implementation type of the feature, c or assembly.
    # Use 'enable' to specify the features to be constructed.
    # Compile C code if there is no other parameter.
    ./configure.py --enable all                                        # Build all features of openHiTLS.
    ./configure.py --enable hitls_crypto                               # Build all features in the lib hitls_crypto.
    ./configure.py --enable md                                         # Build all sub features of md.
    ./configure.py --enable sha2 sha3 hmac                             # Specifies to build certain features.

    # Use 'enable' to specify the features to be constructed.
    # Use 'asm_type' to specify the assembly type.
    # If there are features in enable list that supports assembly, compile its assembly implementation.
    ./configure.py --enable sm3 aes ... --asm_type armv8

    # Use 'enable' to specify the features to be constructed.
    # Use 'asm_type' to specify the assembly type.
    # Use 'asm' to specify the assembly feature(s), which is(are) based on the enabled features.
    # Compile the assembly code of the features in the asm, and the C code of other features in the enable list.
    ./configure.py --enable sm3 aes ... --asm_type armv8 --asm sm3

2 Compile options: Add or delete compilation options based on the default compilation options (compile.json).
    ./configure.py --add_options "-O0 -g" --del_options "-O2 -D_FORTIFY_SOURCE=2"

3 Link options: Add or delete link options based on the default link options (compile.json).
    ./configure.py --add_link_flags "xxx xxx" --del_link_flags "xxx xxx"

4 Set the endian mode of the system. Set the endian mode of the system. The default value is little endian.
    ./configure.py --endian big

5 Specifies the system type.
    ./configure.py --system linux

6 Specifies the number of system bits.
    ./configure.py --bits 32

7 Generating modules.cmake
    ./configure.py -m

8 Specifies the directory where the compilation middleware is generated. The default directory is ./output.
    ./configure.py --build_dir build

9 Specifies the lib type.
    ./configure.py --lib_type static
    ./configure.py --lib_type static shared object

10 You can directly specify the compilation configuration files, omitting the above 1~9 command line parameters.
   For the file format, please refer to the compile_config.json and feature_config.json files generated after executing
   the above 1~9 commands.
    ./configure.py --feature_config path/to/xxx.json --compile_config path/to/xxx.json

Note:
    Options for different functions can be combined.
"""


import sys
sys.dont_write_bytecode = True
import os
import argparse
import traceback
import glob
import shutil
from script.methods import copy_file, save_json_file, trans2list
from script.config_parser import (FeatureParser, CompileParser, FeatureConfigParser,
                                  CompileConfigParser, CompleteOptionParser)
from script.platform_utils import CompilerDetector, LinkerDetector, PlatformDetector
from script.toolchain_manager import ToolchainManager

srcdir = os.path.dirname(os.path.realpath(sys.argv[0]))
work_dir = os.path.abspath(os.getcwd())


def list_available_toolchains():
    """List all available toolchain files."""
    toolchain_dir = os.path.join(srcdir, 'config/toolchain')
    ToolchainManager.list_available(toolchain_dir)


def check_securec_submodule():
    """Check if securec submodule is initialized."""
    securec_dir = os.path.join(srcdir, 'platform/Secure_C')
    securec_makefile = os.path.join(securec_dir, 'Makefile')
    securec_git = os.path.join(securec_dir, '.git')

    # Check if it's a valid submodule directory
    return os.path.exists(securec_makefile) or os.path.exists(securec_git)


def init_securec_submodule():
    """Initialize securec git submodule."""
    import subprocess

    print("=" * 70)
    print("[INFO] Securec dependency not found, initializing git submodule...")
    print("=" * 70)

    try:
        result = subprocess.run(
            ['git', 'submodule', 'update', '--init', '--recursive', 'platform/Secure_C'],
            cwd=srcdir,
            check=True,
            capture_output=True,
            text=True
        )
        print("[SUCCESS] Securec submodule initialized successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to initialize securec submodule:")
        print(f"  {e.stderr}")
        print("\n[HINT] Please manually initialize the submodule:")
        print("  git submodule update --init --recursive platform/Secure_C")
        print("  OR manually clone:")
        print("  git clone https://gitee.com/openeuler/libboundscheck.git platform/Secure_C")
        return False
    except FileNotFoundError:
        print("[WARNING] Git command not found, cannot auto-initialize submodule")
        print("\n[HINT] Please manually download securec dependency:")
        print("  git clone https://gitee.com/openeuler/libboundscheck.git platform/Secure_C")
        return False


def build_securec_with_cmake(force_rebuild=False):
    """Build securec library using CMake (cross-platform preferred method)."""
    import subprocess

    securec_dir = os.path.join(srcdir, 'platform/Secure_C')
    securec_lib_dir = os.path.join(securec_dir, 'lib')
    build_dir = os.path.join(srcdir, 'build')

    print("[INFO] Attempting CMake build (cross-platform)...")

    try:
        # Check if CMake is available
        subprocess.run(['cmake', '--version'],
                      capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[WARNING] CMake not found, will try Makefile instead")
        return False

    try:
        # CMake will handle securec build via SecureC.cmake
        # Just verify the build directory exists
        if not os.path.exists(build_dir):
            os.makedirs(build_dir)

        # The actual build will happen when user runs cmake
        # Here we just verify the setup is correct
        if os.path.exists(os.path.join(srcdir, 'platform/SecureC.cmake')):
            print("[SUCCESS] CMake configuration ready for securec")
            print("[INFO] Securec will be built automatically when running: cmake ..")
            return True
        else:
            print("[WARNING] SecureC.cmake not found")
            return False

    except Exception as e:
        print(f"[WARNING] CMake setup failed: {e}")
        return False


def build_securec_with_make(force_rebuild=False):
    """Build securec library using Makefile (fallback method)."""
    import subprocess

    securec_dir = os.path.join(srcdir, 'platform/Secure_C')
    securec_lib_dir = os.path.join(securec_dir, 'lib')

    print("[INFO] Building with Makefile (fallback)...")

    # Detect compiler
    try:
        detector = CompilerDetector()
        compiler = detector.detect()
        print(f"[INFO] Using compiler: {compiler}")
    except Exception:
        compiler = 'gcc'  # Fallback to gcc
        print(f"[INFO] Using default compiler: {compiler}")

    try:
        # Clean first if needed
        if force_rebuild:
            subprocess.run(['make', 'clean'], cwd=securec_dir, capture_output=True)

        # Build securec
        result = subprocess.run(
            ['make', '-j', f'CC={compiler}'],
            cwd=securec_dir,
            check=True,
            capture_output=True,
            text=True
        )
        print("[SUCCESS] Securec library built successfully with Makefile!")
        print(f"[INFO] Library location: {securec_lib_dir}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Makefile build failed:")
        print(f"  {e.stderr}")
        return False
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        return False


def build_securec_library(force_rebuild=False):
    """
    Build securec library using CMake (preferred) or Makefile (fallback).

    Strategy:
    1. Try CMake first (better cross-platform support)
    2. Fallback to Makefile if CMake fails
    3. Both methods output to platform/Secure_C/lib/
    """
    import subprocess

    securec_dir = os.path.join(srcdir, 'platform/Secure_C')
    securec_lib_dir = os.path.join(securec_dir, 'lib')

    # Check if already built (skip if not forcing rebuild)
    if not force_rebuild and os.path.exists(securec_lib_dir):
        lib_files = []
        for ext in ['*.so', '*.dylib', '*.dll', '*.a']:
            lib_files.extend(glob.glob(os.path.join(securec_lib_dir, ext)))

        if lib_files:
            print("[INFO] Securec library already built, skipping build...")
            return True

    if force_rebuild and os.path.exists(securec_lib_dir):
        print("[INFO] Force rebuilding securec library...")
        shutil.rmtree(securec_lib_dir, ignore_errors=True)

    print("=" * 70)
    print("[INFO] Building securec library...")
    print("=" * 70)

    # Try CMake first (better cross-platform support)
    if build_securec_with_cmake(force_rebuild):
        return True

    # Fallback to Makefile
    print("[INFO] CMake build not available, trying Makefile...")
    if build_securec_with_make(force_rebuild):
        return True

    # Both methods failed
    print("\n" + "=" * 70)
    print("[ERROR] Failed to build securec library with both CMake and Makefile")
    print("=" * 70)
    print("\n[HINT] Please manually build securec:")
    print(f"  cd {securec_dir}")
    print(f"  make -j")
    print("\nOr ensure CMake is installed and run:")
    print(f"  mkdir -p build && cd build")
    print(f"  cmake .. && make")
    return False


def ensure_securec_dependency(auto_init=True, auto_build=True, force_rebuild=False):
    """
    Ensure securec dependency is ready.

    Args:
        auto_init: Automatically initialize git submodule if not present
        auto_build: Automatically build securec if not built
        force_rebuild: Force rebuild even if already built

    Returns:
        bool: True if dependency is ready, False otherwise
    """
    securec_dir = os.path.join(srcdir, 'platform/Secure_C')

    # Step 1: Check if submodule is initialized
    if not check_securec_submodule():
        if not auto_init:
            print("=" * 70)
            print("[WARNING] Securec dependency not found!")
            print("=" * 70)
            print("Please initialize the submodule manually:")
            print("  git submodule update --init --recursive platform/Secure_C")
            print("OR download manually:")
            print("  git clone https://gitee.com/openeuler/libboundscheck.git platform/Secure_C")
            return False

        if not init_securec_submodule():
            return False

    # Step 2: Build securec library
    if not auto_build and not force_rebuild:
        # Just check if already built
        securec_lib_dir = os.path.join(securec_dir, 'lib')
        if not os.path.exists(securec_lib_dir) or not os.listdir(securec_lib_dir):
            print("=" * 70)
            print("[WARNING] Securec library not built!")
            print("=" * 70)
            print("Please build manually:")
            print(f"  cd {securec_dir}")
            print("  make -j")
            return False
        return True

    return build_securec_library(force_rebuild)


def get_cfg_args():
    parser = argparse.ArgumentParser(prog='openHiTLS', description='parser configure arguments')
    try:
        # Version/Release Build Configuration Parameters
        parser.add_argument('-m', '--module_cmake', action='store_true', help='generate moudules.cmake file')
        parser.add_argument('--build_dir', metavar='dir', type=str, default=os.path.join(srcdir, 'build'),
                            help='compile temp directory')
        parser.add_argument('--output_dir', metavar='dir', type=str, default=os.path.join(srcdir, 'output'),
                            help='compile output directory')
        parser.add_argument('--hkey', metavar='hkey', type=str, default="b8fc4931453af3285f0f",
                            help='Key used by the HMAC.')
        # Configuration file
        parser.add_argument('--feature_config', metavar='file_path', type=str, default='',
                            help='Configuration file of the compilation features.')
        parser.add_argument('--compile_config', metavar='file_path', type=str, default='',
                            help='Configuration file of compilation parameters.')
        # Compilation Feature Configuration
        parser.add_argument('--enable', metavar='feature', nargs='+', default=[],
                            help='enable some libs or features, such as --enable sha256 aes gcm_asm, default is "all"')
        parser.add_argument('--disable', metavar='feature', nargs='+', default=['uio_sctp'],
                            help='disable some libs or features, such as --disable aes gcm_asm,\
                            default is disable "uio_sctp" ')
        parser.add_argument('--enable-sctp', action="store_true", help='enable sctp which is used in DTLS')
        parser.add_argument('--asm_type', type=str, help='Assembly Type, default is "no_asm".')
        parser.add_argument('--asm', metavar='feature', default=[], nargs='+', help='config asm, such as --asm sha2')
        # System Configuration
        parser.add_argument('--system', type=str,
                            help='To enable feature "sal_xxx", should specify the system.')
        parser.add_argument('--endian', metavar='little|big', type=str, choices=['little', 'big'],
                            help='Specify the platform endianness as little or big, default is "little".')
        parser.add_argument('--bits', metavar='32|64', type=int, choices=[32, 64],
                            help='To enable feature "bn", should specify the number of OS bits, default is "64".')
        # Compiler and Linker Configuration
        parser.add_argument('--toolchain', type=str,
                            help='Specify toolchain file name (without .cmake extension). '
                                 'Example: apple-clang-darwin, gcc-linux, arm-none-eabi-gcc')
        parser.add_argument('--list-toolchains', action='store_true',
                            help='List all available toolchain files and exit.')
        parser.add_argument('--compiler', type=str, choices=['gcc', 'clang', 'apple-clang'],
                            help='Specify the compiler type (auto-detected if not provided).')
        parser.add_argument('--linker', type=str, choices=['gnu-ld', 'ld64', 'lld', 'gold'],
                            help='Specify the linker type (auto-detected if not provided).')
        # Compiler Options, Link Options
        parser.add_argument('--lib_type', choices=['static', 'shared', 'object'], nargs='+',
                            help='set lib type, such as --lib_type staic shared, default is "staic shared object"')
        parser.add_argument('--add_options', default='', type=str,
                            help='add some compile options, such as --add_options="-O0 -g"')
        parser.add_argument('--del_options', default='', type=str,
                            help='delete some compile options such as --del_options="-O2 -Werror"')
        parser.add_argument('--add_link_flags', default='', type=str,
                            help='add some link flags such as --add_link_flags="-pie"')
        parser.add_argument('--del_link_flags', default='', type=str,
                            help='delete some link flags such as --del_link_flags="-shared -Wl,-z,relro"')

        parser.add_argument('--no_config_check', action='store_true', help='disable the configuration check')

        # Dependency Management
        parser.add_argument('--no-auto-deps', action='store_true',
                            help='Disable automatic dependency initialization and build. '
                                 'Use this if you want to manually manage securec dependency.')
        parser.add_argument('--force-rebuild-deps', action='store_true',
                            help='Force rebuild dependencies even if already built. '
                                 'This will clean and rebuild securec library.')

        parser.add_argument('--hitls_version', default='openHiTLS 0.3.0 31 Dec 2025', help='%(prog)s version str')
        parser.add_argument('--hitls_version_num', default=0x00300000, help='%(prog)s version num')
        parser.add_argument('--bundle_libs', action='store_true', help='Indicates that multiple libraries are bundled together. By default, it is not bound.\
                            It need to be used together with "-m"')
        # Compile the command apps.
        parser.add_argument('--executes', dest='executes', default=[], nargs='*', help='Enable hitls command apps')

        args = vars(parser.parse_args())

        args['tmp_feature_config'] = os.path.join(args['build_dir'], 'feature_config.json')
        args['tmp_compile_config'] = os.path.join(args['build_dir'], 'compile_config.json')

        # disable uio_sctp by default
        if args['enable_sctp'] or args['module_cmake']:
            if 'uio_sctp' in args['disable']:
                args['disable'].remove('uio_sctp')

    except argparse.ArgumentError as e:
        parser.print_help()
        raise ValueError("Error: Failed to obtain parameters.") from e

    return argparse.Namespace(**args)


class Configure:
    """Provides operations related to configuration and input parameter parsing:
    1 Parse input parameters.
    2 Read configuration files and input parameters.
    3 Update the final configuration files in the build directory.
    """
    config_json_file = 'config.json'
    feature_json_file = 'config/json/feature.json'
    complete_options_json_file = 'config/json/complete_options.json'
    default_compile_json_file = 'config/json/compile.json'

    def __init__(self, features: FeatureParser):
        self._features = features
        self._args = get_cfg_args()
        self._preprocess_args()

    @property
    def args(self):
        return self._args

    def _preprocess_args(self):
        if self._args.feature_config and not os.path.exists(self._args.feature_config):
            raise FileNotFoundError('File not found: %s' % self._args.feature_config)
        if self._args.compile_config and not os.path.exists(self._args.compile_config):
            raise FileNotFoundError('File not found: %s' % self._args.compile_config)

        if 'all' in self._args.enable:
            if len(self._args.enable) > 1:
                raise ValueError("Error: 'all' and other features cannot be set at the same time.")
        else:
            for fea in self._args.enable:
                if fea in self._features.libs or fea in self._features.feas_info:
                    continue
                raise ValueError("unrecognized fea '%s'" % fea)

        if self._args.asm_type:
            if self._args.asm_type not in self._features.asm_types:
                raise ValueError("Unsupported asm_type: asm_type should be one of [%s]" % self._features.asm_types)
        else:
            if self._args.asm and not self._args.asm_type:
                raise ValueError("Error: 'asm_type' and 'asm' must be set at the same time.")
        # The value of 'asm' will be verified later.

    @staticmethod
    def _load_config(is_fea_cfg, src_file, dest_file):
        if os.path.exists(dest_file):
            if src_file != '':
                raise FileExistsError('{} already exists'.format(dest_file))
        else:
            if src_file == '':
                # No custom configuration file is specified, create a default config file.
                cfg = FeatureConfigParser.default_cfg() if is_fea_cfg else CompileConfigParser.default_cfg()
                save_json_file(cfg, dest_file)
            else:
                copy_file(src_file, dest_file)

    def load_config_to_build(self):
        """Load the compilation feature and compilation option configuration files to the build directory:
            build/feature_config.json
            build/compile_config.json
        """
        if not os.path.exists(self._args.build_dir):
            os.makedirs(self._args.build_dir)
        self._load_config(True, self._args.feature_config, self._args.tmp_feature_config)
        self._load_config(False, self._args.compile_config, self._args.tmp_compile_config)

    def update_feature_config(self, gen_cmake):
        """Update the feature configuration file in the build based on the input parameters."""
        conf_custom_feature = FeatureConfigParser(self._features, self._args.tmp_feature_config)
    
        if self._args.executes:
            conf_custom_feature.enable_executes(self._args.executes)

        # If no feature is enabled before modules.cmake is generated, set enable to "all".
        if not conf_custom_feature.libs and not self._args.enable and gen_cmake:
            self._args.enable = ['all']

        # Set parameters by referring to "FeatureConfigParser.key_value".
        conf_custom_feature.set_param('libType', self._args.lib_type)
        if self._args.bundle_libs:
            conf_custom_feature.set_param('bundleLibs', self._args.bundle_libs)
        conf_custom_feature.set_param('endian', self._args.endian)
        # Only override system value if explicitly specified via command line
        # Otherwise, respect the value from feature_config.json
        if self._args.system is not None:
            # User explicitly specified --system on command line
            conf_custom_feature.set_param('system', self._args.system, False)
        else:
            # Check if feature_config.json has a valid system value
            current_system = conf_custom_feature._cfg.get('system')
            valid_systems = ['linux', 'darwin', 'none', '']
            if not current_system or current_system not in valid_systems:
                # No valid system in config file, use auto-detection as fallback
                system_value = PlatformDetector.get_current_platform()
                conf_custom_feature.set_param('system', system_value, False)
            # Otherwise, keep the system value from feature_config.json unchanged
        conf_custom_feature.set_param('bits', self._args.bits, False)

        enable_feas, asm_feas = conf_custom_feature.get_enable_feas(self._args.enable, self._args.asm)

        asm_type = self._args.asm_type if self._args.asm_type else ''
        if not asm_type and conf_custom_feature.asm_type != 'no_asm':
            asm_type = conf_custom_feature.asm_type

        if asm_type:
            conf_custom_feature.set_asm_type(asm_type)
            conf_custom_feature.set_asm_features(enable_feas, asm_feas, asm_type)
        if enable_feas:
            conf_custom_feature.set_c_features(enable_feas)

        self._args.securec_lib = conf_custom_feature.securec_lib
        # update feature and resave file.
        conf_custom_feature.update_feature(self._args.enable, self._args.disable, gen_cmake)
        conf_custom_feature.save(self._args.tmp_feature_config)

        self._args.bundle_libs = conf_custom_feature.bundle_libs

    def update_compile_config(self, all_options: CompleteOptionParser):
        """Update the compilation configuration file in the build based on the input parameters."""
        conf_custom_compile = CompileConfigParser(all_options, self._args.tmp_compile_config)

        if self._args.add_options:
            conf_custom_compile.change_options(self._args.add_options.strip().split(' '), True)
        if self._args.del_options:
            conf_custom_compile.change_options(self._args.del_options.strip().split(' '), False)

        if self._args.add_link_flags:
            conf_custom_compile.change_link_flags(self._args.add_link_flags.strip().split(' '), True)
        if self._args.del_link_flags:
            conf_custom_compile.change_link_flags(self._args.del_link_flags.strip().split(' '), False)

        conf_custom_compile.save(self._args.tmp_compile_config)


class CMakeGenerator:
    """ Generating CMake Commands and Scripts Based on Configuration Files """
    def __init__(self, args, features: FeatureParser, all_options: CompleteOptionParser):
        self._args = args
        self._cfg_feature = features
        self._cfg_compile = CompileParser(
            all_options,
            Configure.default_compile_json_file,
            compiler=getattr(args, 'compiler', None),
            linker=getattr(args, 'linker', None),
            platform=getattr(args, 'system', None)
        )
        self._cfg_custom_feature = FeatureConfigParser(features, args.tmp_feature_config)
        self._cfg_custom_feature.check_fea_opts()
        self._cfg_custom_compile = CompileConfigParser(
            all_options,
            args.tmp_compile_config,
            compiler=getattr(args, 'compiler', None),
            linker=getattr(args, 'linker', None),
            platform=getattr(args, 'system', None)
        )

        self._asm_type = self._cfg_custom_feature.asm_type

        self._platform = 'linux'
        self._approved_provider = False
        self._hmac = "sha256"

    def select_toolchain(self):
        """Select or generate toolchain file using ToolchainManager."""
        ToolchainManager.select_or_generate(
            self._args,
            self._cfg_compile.compiler,
            self._cfg_compile.linker,
            self._cfg_compile.platform,
            self._args.build_dir,
            srcdir
        )

    @staticmethod
    def _add_if_exists(inc_dirs, path):
        if os.path.exists(path):
            inc_dirs.add(path)
    @staticmethod
    def _get_common_include(modules: list):
        """ modules: ['::','::']"""
        inc_dirs = set()
        top_modules = set(x.split('::')[0] for x in modules)
        top_modules.add('bsl/log')
        top_modules.add('bsl/err')
        
        for module in top_modules:
            CMakeGenerator._add_if_exists(inc_dirs, module + '/include')
            CMakeGenerator._add_if_exists(inc_dirs, 'include/' + module)
        
        CMakeGenerator._add_if_exists(inc_dirs, 'config/macro_config')
        CMakeGenerator._add_if_exists(inc_dirs, '../../../../Secure_C/include')
        CMakeGenerator._add_if_exists(inc_dirs, '../../../platform/Secure_C/include')
        
        return inc_dirs

    def _get_module_include(self, mod: str, dep_mods: list):
        inc_dirs = set()
        dep_mods.append(mod)
        for dep in dep_mods:
            top_dir, sub_dir = dep.split('::')
            path = "{}/{}/include".format(top_dir, sub_dir)
            if os.path.exists(path):
                inc_dirs.add(path)
        top_mod, sub_mod = dep.split('::')

        cfg_inc = self._cfg_feature.modules[top_mod][sub_mod].get('.include', [])
        for inc_dir in cfg_inc:
            if os.path.exists(inc_dir):
                inc_dirs.add(inc_dir)
        return inc_dirs

    @staticmethod
    def _expand_srcs(srcs):
        if not srcs:
            return []

        ret = []
        for x in srcs:
            ret += glob.glob(x, recursive=True)
        if len(ret) == 0:
            raise SystemError("The .c file does not exist in the {} directory.".format(srcs))
        ret.sort()
        return ret

    @classmethod
    def _gen_cmd_cmake(cls, cmd: str, title, content_obj=None):
        if not content_obj:
            return '{}({})\n'.format(cmd, title)

        items = None
        if isinstance(content_obj, list) or isinstance(content_obj, set):
            items = content_obj
        elif isinstance(content_obj, dict):
            items = content_obj.values()
        elif isinstance(content_obj, str):
            items = [content_obj]
        else:
            raise ValueError('Unsupported type "%s"' % type(content_obj))

        content = ''
        for item in items:
            content += '    {}\n'.format(item)

        if len(items) == 1:
            return '{}({} {})\n'.format(cmd, title, item)
        else:
            return '{}({}\n{})\n'.format(cmd, title, content)

    def _get_module_src_set(self, lib, top_mod, sub_mod, mod_obj):
        srcs = self._cfg_feature.get_mod_srcs(top_mod, sub_mod, mod_obj)
        return self._expand_srcs(srcs)

    @staticmethod
    def _is_bundled_lib(lib_name):
        """
        Check if lib_name is a bundled library.
        Bundled libraries include:
        - 'hitls': standard bundle
        - 'hitls_iso', 'hitls_fips', 'hitls_sm': CMVP provider bundles
        """
        return lib_name == 'hitls' or lib_name in ['hitls_iso', 'hitls_fips', 'hitls_sm']

    def _gen_module_cmake(self, lib, mod, mod_obj, mods_cmake):
        top_mod, module_name = mod.split('::')
        inc_set = self._get_module_include(mod, mod_obj.get('deps', []))
        src_list = self._get_module_src_set(lib, top_mod, module_name, mod_obj)

        tgt_name = module_name + '-objs'
        cmake = '\n# Add module {} \n'.format(module_name)
        cmake += self._gen_cmd_cmake('add_library', '{} OBJECT'.format(tgt_name))

        cmake += self._gen_cmd_cmake('target_include_directories', '{} PRIVATE'.format(tgt_name), inc_set)
        cmake += self._gen_cmd_cmake('target_sources', '{} PRIVATE'.format(tgt_name), src_list)
        if any('sal_mem.c' in s for s in src_list):
            cmake += self._gen_cmd_cmake('add_library', '{} OBJECT {}'.format('show_macros_pre', '${CMAKE_SOURCE_DIR}/bsl/sal/src/sal_mem.c'))
            cmake += self._gen_cmd_cmake('target_compile_options', '{} PRIVATE -dM -E'.format('show_macros_pre'))
            cmake += self._gen_cmd_cmake('target_include_directories', '{} PRIVATE'.format('show_macros_pre'), inc_set)
            cmake += '''
                      add_custom_target(show_macros 
                                        COMMAND grep 'HITLS' $<TARGET_OBJECTS:show_macros_pre> > ${CMAKE_CURRENT_BINARY_DIR}/userdefined_macros.txt
                                        DEPENDS show_macros_pre
                                        )
                     '''
        cmake += 'target_compile_definitions(%s PUBLIC OPENHITLSDIR="${CMAKE_INSTALL_PREFIX}/")\n' % tgt_name
        mods_cmake[tgt_name] = cmake
    def _gen_shared_lib_cmake(self, lib_name, tgt_obj_list, tgt_list, macros):
        tgt_name = lib_name + '-shared'
        properties = 'OUTPUT_NAME {}'.format(lib_name)

        cmake = '\n'
        cmake += self._gen_cmd_cmake('add_library', '{} SHARED'.format(tgt_name), tgt_obj_list)
        cmake += self._gen_cmd_cmake('target_link_options', '{} PRIVATE'.format(tgt_name), '${SHARED_LNK_FLAGS}')
        if os.path.exists('{}/platform/Secure_C/lib'.format(srcdir)):
            cmake += self._gen_cmd_cmake('target_link_directories', '{} PRIVATE'.format(tgt_name), '{}/platform/Secure_C/lib'.format(srcdir))
        cmake += self._gen_cmd_cmake('set_target_properties', '{} PROPERTIES'.format(tgt_name), properties)
        cmake += 'install(TARGETS %s DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)\n' % tgt_name
        if (self._approved_provider):
            # Use the openssl command to generate an HMAC file.
            cmake += 'install(CODE "execute_process(COMMAND openssl dgst -hmac \\\"%s\\\" -%s -out lib%s.so.hmac lib%s.so)")\n' % (self._args.hkey, self._hmac, lib_name, lib_name)
            # Install the hmac file to the output directory.
            cmake += 'install(CODE "execute_process(COMMAND cp lib%s.so.hmac ${CMAKE_INSTALL_PREFIX}/lib/lib%s.so.hmac)")\n' % (lib_name, lib_name)

        if lib_name == 'hitls_bsl':
            # Always link libboundscheck for BSL (required for securec functions)
            libs_to_link = [str(self._args.securec_lib)]
            for item in macros:
                if item == '-DHITLS_BSL_SAL_DL' and 'dl' not in libs_to_link:
                    libs_to_link.insert(0, 'dl')
            cmake += self._gen_cmd_cmake("target_link_libraries", "hitls_bsl-shared " + " ".join(libs_to_link))
        if lib_name == 'hitls_crypto':
            cmake += self._gen_cmd_cmake("target_link_directories", "hitls_crypto-shared PRIVATE " + "${CMAKE_SOURCE_DIR}/platform/Secure_C/lib")
            cmake += self._gen_cmd_cmake("target_link_libraries", "hitls_crypto-shared hitls_bsl-shared")
        if lib_name == 'hitls_tls':
            cmake += self._gen_cmd_cmake("target_link_directories", "hitls_tls-shared PRIVATE " + "${CMAKE_SOURCE_DIR}/platform/Secure_C/lib")
            cmake += self._gen_cmd_cmake("target_link_libraries", "hitls_tls-shared hitls_pki-shared hitls_crypto-shared hitls_bsl-shared")
        if lib_name == 'hitls_pki':
            cmake += self._gen_cmd_cmake("target_link_directories", "hitls_pki-shared PRIVATE " + "${CMAKE_SOURCE_DIR}/platform/Secure_C/lib")
            cmake += self._gen_cmd_cmake(
                "target_link_libraries", "hitls_pki-shared hitls_crypto-shared hitls_bsl-shared")
        if lib_name == 'hitls_auth':
            cmake += self._gen_cmd_cmake("target_link_directories", "hitls_auth-shared PRIVATE " + "${CMAKE_SOURCE_DIR}/platform/Secure_C/lib")
            cmake += self._gen_cmd_cmake(
                "target_link_libraries", "hitls_auth-shared hitls_crypto-shared hitls_bsl-shared")
        elif self._is_bundled_lib(lib_name):
            # Bundled library (hitls, hitls_iso, hitls_fips, hitls_sm) contains all modules
            cmake += self._gen_cmd_cmake("target_link_directories", "{}-shared PRIVATE".format(lib_name) + " ${CMAKE_SOURCE_DIR}/platform/Secure_C/lib")
            libs_to_link = [str(self._args.securec_lib)]
            for item in macros:
                if item == '-DHITLS_BSL_SAL_DL' and 'dl' not in libs_to_link:
                    libs_to_link.insert(0, 'dl')
            cmake += self._gen_cmd_cmake("target_link_libraries", "{}-shared {}".format(lib_name, " ".join(libs_to_link)))
        if self._approved_provider:
            cmake += self._gen_cmd_cmake("target_link_libraries", "{}-shared m {}".format(lib_name, str(self._args.securec_lib)))
        tgt_list.append(tgt_name)
        return cmake

    def _gen_static_lib_cmake(self, lib_name, tgt_obj_list, tgt_list):
        tgt_name = lib_name + '-static'
        properties = 'OUTPUT_NAME {}'.format(lib_name)

        cmake = '\n'
        cmake += self._gen_cmd_cmake('add_library', '{} STATIC'.format(tgt_name), tgt_obj_list)
        cmake += self._gen_cmd_cmake('set_target_properties', '{} PROPERTIES'.format(tgt_name), properties)
        cmake += 'install(TARGETS %s DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)\n' % tgt_name

        tgt_list.append(tgt_name)
        return cmake

    def _gen_obejct_lib_cmake(self, lib_name, tgt_obj_list, tgt_list, macros):
        tgt_name = lib_name + '-object'
        properties = 'OUTPUT_NAME lib{}.o'.format(lib_name)

        cmake = '\n'
        cmake += self._gen_cmd_cmake('add_executable', tgt_name, tgt_obj_list)
        cmake += self._gen_cmd_cmake('target_link_options', '{} PRIVATE'.format(tgt_name), '${SHARED_LNK_FLAGS}')
        if os.path.exists('{}/platform/Secure_C/lib'.format(srcdir)):
            cmake += self._gen_cmd_cmake('target_link_directories', '{} PRIVATE'.format(tgt_name), '{}/platform/Secure_C/lib'.format(srcdir))
        cmake += self._gen_cmd_cmake('set_target_properties', '{} PROPERTIES'.format(tgt_name), properties)
        cmake += 'install(TARGETS %s DESTINATION ${CMAKE_INSTALL_PREFIX}/obj)\n' % tgt_name

        # Note: Object libraries are relocatable object files (created with -r flag).
        # On macOS (ld64), even relocatable objects need all symbols defined.
        # Link external libraries and built shared libraries to resolve undefined symbols.

        # Build library dependency configuration dynamically
        # Use actual configured bounds-checking library name (e.g., boundscheck, securec, sec_shared.z)
        securec = str(self._args.securec_lib)

        # Check if dl library is needed (when -DHITLS_BSL_SAL_DL is defined)
        needs_dl = any(item == '-DHITLS_BSL_SAL_DL' for item in macros)

        library_link_config = {
            'hitls_bsl': {
                'deps': (['dl'] if needs_dl else []) + [securec]
            },
            'hitls_crypto': {
                'deps': ['hitls_bsl-shared']
            },
            'hitls_tls': {
                'deps': ['hitls_pki-shared', 'hitls_crypto-shared', 'hitls_bsl-shared']
            },
            'hitls_pki': {
                'deps': ['hitls_crypto-shared', 'hitls_bsl-shared']
            },
            'hitls_auth': {
                'deps': ['hitls_crypto-shared', 'hitls_bsl-shared']
            }
        }

        # Check exact match first, then handle bundled libraries (hitls, hitls_iso, hitls_fips, hitls_sm)
        if lib_name in library_link_config:
            config = library_link_config[lib_name]
        elif self._is_bundled_lib(lib_name):
            # Bundled library configuration
            config = {
                'deps': (['dl'] if needs_dl else []) + [securec],
                'link_dirs': '${CMAKE_SOURCE_DIR}/platform/Secure_C/lib'
            }
        else:
            config = None

        if config:
            libs_to_link = []

            # Add library dependencies
            libs_to_link.extend(config.get('deps', []))

            # Add special link_directories if specified
            if 'link_dirs' in config:
                cmake += self._gen_cmd_cmake("target_link_directories",
                                            "{}-object PRIVATE".format(lib_name),
                                            config['link_dirs'])

            # Generate target_link_libraries command
            if libs_to_link:
                cmake += self._gen_cmd_cmake("target_link_libraries",
                                            "{}-object {}".format(lib_name, " ".join(libs_to_link)))

        tgt_list.append(tgt_name)
        return cmake

    def _get_definitions(self):
        ret = '"${CMAKE_C_FLAGS} -DOPENHITLS_VERSION_S=\'\\"%s\\"\' -DOPENHITLS_VERSION_I=%lu %s' % (
                self._args.hitls_version, self._args.hitls_version_num, '-D__FILENAME__=\'\\"$(notdir $(subst .o,,$@))\\"\'')
        if self._approved_provider:
            icv_key = '-DCMVP_INTEGRITYKEY=\'\\"%s\\"\'' % self._args.hkey
            ret += ' %s' % icv_key
        ret += '"'
        return ret

    def _gen_lib_cmake(self, lib_name, inc_dirs, lib_obj, macros):
        lang = self._cfg_feature.libs[lib_name].get('lang', 'C')
        cmake = 'project({} {})\n\n'.format(lib_name, lang)
        cmake += self._gen_cmd_cmake('set', 'CMAKE_ASM_NASM_OBJECT_FORMAT elf64')
        cmake += self._gen_cmd_cmake('set', 'CMAKE_C_FLAGS', '${CC_ALL_OPTIONS}')
        cmake += self._gen_cmd_cmake('set', 'CMAKE_ASM_FLAGS', '${CC_ALL_OPTIONS}')
        cmake += self._gen_cmd_cmake('set', 'CMAKE_C_FLAGS', self._get_definitions())
        cmake += self._gen_cmd_cmake('include_directories', '', inc_dirs)
        for _, mod_cmake in lib_obj['mods_cmake'].items():
            cmake += mod_cmake

        tgt_obj_list = list('$<TARGET_OBJECTS:{}>'.format(x) for x in lib_obj['mods_cmake'].keys())

        tgt_list = []
        lib_type = self._cfg_custom_feature.lib_type
        if 'shared' in lib_type:
            cmake += self._gen_shared_lib_cmake(lib_name, tgt_obj_list, tgt_list, macros)
        if 'static' in lib_type:
            cmake += self._gen_static_lib_cmake(lib_name, tgt_obj_list, tgt_list)
        if 'object' in lib_type:
            cmake += self._gen_obejct_lib_cmake(lib_name, tgt_obj_list, tgt_list, macros)
        lib_obj['cmake'] = cmake
        lib_obj['targets'] = tgt_list

    def _gen_exe_cmake(self, exe_name, inc_dirs, exe_obj):
        lang = self._cfg_feature.executes[exe_name].get('lang', 'C')
        definitions = '"${CMAKE_C_FLAGS} -DHITLS_VERSION=\'\\"%s\\"\' %s -DCMVP_INTEGRITYKEY=\'\\"%s\\"\'"' % (
            self._args.hitls_version, '-D__FILENAME__=\'\\"$(notdir $(subst .o,,$@))\\"\'', self._args.hkey)
        cmake = 'project({} {})\n\n'.format(exe_name, lang)
        cmake += self._gen_cmd_cmake('set', 'CMAKE_C_FLAGS', '${CC_ALL_OPTIONS}')

        # Detect platform and set shared library extension
        cmake += '# Detect platform-specific shared library extension\n'
        cmake += 'if(APPLE)\n'
        cmake += '    set(SHARED_LIB_EXT ".dylib")\n'
        cmake += 'else()\n'
        cmake += '    set(SHARED_LIB_EXT ".so")\n'
        cmake += 'endif()\n\n'

        # Dynamically determine provider library name based on CMVP mode
        cmake += '# Dynamically determine provider library name based on CMVP mode\n'
        lib_name = self._get_bundle_lib_name()
        cmake += 'set(HITLS_PROVIDER_LIB_NAME "lib{}${{SHARED_LIB_EXT}}")\n'.format(lib_name)
        cmake += 'message(STATUS "Provider library for apps: ${HITLS_PROVIDER_LIB_NAME}")\n\n'

        # Add the macro definition to CMAKE_C_FLAGS
        definitions_with_provider = definitions[:-1] + ' -DHITLS_PROVIDER_LIB_NAME=\'\\"${HITLS_PROVIDER_LIB_NAME}\\"\'"'
        cmake += self._gen_cmd_cmake('set', 'CMAKE_C_FLAGS', definitions_with_provider)

        cmake += self._gen_cmd_cmake('include_directories', '', inc_dirs)
        for _, mod_cmake in exe_obj['mods_cmake'].items():
            cmake += mod_cmake

        tgt_obj_list = list('$<TARGET_OBJECTS:{}>'.format(x) for x in exe_obj['mods_cmake'].keys())
        cmake += self._gen_cmd_cmake('add_executable', exe_name, tgt_obj_list)
        lib_type = self._cfg_custom_feature.lib_type
        if 'shared' in lib_type:
            cmake += self._gen_cmd_cmake('add_dependencies', exe_name,
                                        'hitls_tls-shared hitls_pki-shared hitls_crypto-shared hitls_bsl-shared')
        elif 'static' in lib_type:
            cmake += self._gen_cmd_cmake('add_dependencies', exe_name,
                                        'hitls_tls-static hitls_pki-static hitls_crypto-static hitls_bsl-static')

        common_link_dir = [
            '${CMAKE_CURRENT_LIST_DIR}', # libhitls_*
            '${CMAKE_SOURCE_DIR}/platform/Secure_C/lib',
        ]
        common_link_lib = [
            'hitls_tls', 'hitls_pki', 'hitls_crypto', 'hitls_bsl',
            'dl', 'pthread', 'm',
            str(self._args.securec_lib)
        ]
        cmake += self._gen_cmd_cmake('list', 'APPEND HITLS_APP_LINK_DIRS', common_link_dir)
        cmake += self._gen_cmd_cmake('list', 'APPEND HITLS_APP_LINK_LIBS', common_link_lib)
        cmake += self._gen_cmd_cmake('target_link_directories', '%s PRIVATE' % exe_name, '${HITLS_APP_LINK_DIRS}')
        cmake += self._gen_cmd_cmake('target_link_libraries', exe_name, '${HITLS_APP_LINK_LIBS}')
        cmake += self._gen_cmd_cmake('target_link_options', '{} PRIVATE'.format(exe_name), '${EXE_LNK_FLAGS}')

        cmake += 'install(TARGETS %s DESTINATION ${CMAKE_INSTALL_PREFIX})\n' % exe_name
        cmake += 'install(CODE "execute_process(COMMAND openssl dgst -hmac \\\"%s\\\" -sm3 -out %s.hmac %s)")\n' % (self._args.hkey, exe_name, exe_name)
        # Install the hmac file to the output directory.
        cmake += 'install(CODE "execute_process(COMMAND cp %s.hmac ${CMAKE_INSTALL_PREFIX}/%s.hmac)")\n' % (exe_name, exe_name)

        exe_obj['cmake'] = cmake
        exe_obj['targets'] = [exe_name]

    def _gen_bundled_lib_cmake(self, lib_name, inc_dirs, projects, macros):
        lang = 'C ASM'
        if 'mpa' in projects.keys():
            lang += 'ASM_NASM'

        cmake = 'project({} {})\n\n'.format(lib_name, lang)
        cmake += self._gen_cmd_cmake('set', 'CMAKE_ASM_NASM_OBJECT_FORMAT elf64')
        cmake += self._gen_cmd_cmake('set', 'CMAKE_C_FLAGS', '${CC_ALL_OPTIONS}')
        cmake += self._gen_cmd_cmake('set', 'CMAKE_ASM_FLAGS', '${CC_ALL_OPTIONS}')
        cmake += self._gen_cmd_cmake('set', 'CMAKE_C_FLAGS', self._get_definitions())
        cmake += self._gen_cmd_cmake('include_directories', '', inc_dirs)

        tgt_obj_list = []
        for _, lib_obj in projects.items():
            tgt_obj_list.extend(list('$<TARGET_OBJECTS:{}>'.format(x) for x in lib_obj['mods_cmake'].keys()))
            for _, mod_cmake in lib_obj['mods_cmake'].items():
                cmake += mod_cmake

        tgt_list = []
        lib_type = self._cfg_custom_feature.lib_type
        if 'shared' in lib_type:
            cmake += self._gen_shared_lib_cmake(lib_name, tgt_obj_list, tgt_list, macros)
        if 'static' in lib_type:
            cmake += self._gen_static_lib_cmake(lib_name, tgt_obj_list, tgt_list)
        if 'object' in lib_type:
            cmake += self._gen_obejct_lib_cmake(lib_name, tgt_obj_list, tgt_list, macros)

        return {lib_name: {'cmake': cmake, 'targets': tgt_list}}

    def _get_bundle_lib_name(self):
        """
        Determine the output library name based on CMVP mode.
        Returns 'hitls_iso', 'hitls_fips', 'hitls_sm', or 'hitls' (default).
        """
        # Collect all compile flags from the nested structure
        # compileFlag structure: {'option_type': {'CC_FLAGS_ADD': [flags], ...}}
        compile_flags = []
        compile_flag_dict = self._cfg_custom_compile.options
        for option_type, flags_dict in compile_flag_dict.items():
            if isinstance(flags_dict, dict) and 'CC_FLAGS_ADD' in flags_dict:
                compile_flags.extend(flags_dict['CC_FLAGS_ADD'])

        # Check for CMVP mode flags
        if '-DHITLS_CRYPTO_CMVP_ISO19790' in compile_flags:
            return 'hitls_iso'
        elif '-DHITLS_CRYPTO_CMVP_FIPS' in compile_flags:
            return 'hitls_fips'
        elif '-DHITLS_CRYPTO_CMVP_SM' in compile_flags:
            return 'hitls_sm'
        else:
            return 'hitls'

    def _gen_common_compile_c_flags(self):
        return self._gen_cmd_cmake('set', 'CMAKE_C_FLAGS', self._get_definitions())

    def _gen_projects_cmake(self, macros):
        lib_enable_modules, exe_enable_modules = self._cfg_custom_feature.get_enable_modules()

        projects = {}
        all_inc_dirs = set()
        for lib, lib_obj in lib_enable_modules.items():
            projects[lib] = {}
            projects[lib]['mods_cmake'] = {}
            inc_dirs = self._get_common_include(lib_obj.keys())
            for mod, mod_obj in lib_obj.items():
                self._gen_module_cmake(lib, mod, mod_obj, projects[lib]['mods_cmake'])
            if self._args.bundle_libs:
                all_inc_dirs = all_inc_dirs.union(inc_dirs)
                continue
            self._gen_lib_cmake(lib, inc_dirs, projects[lib], macros)

        if self._args.bundle_libs:
            # Determine library name based on CMVP mode
            lib_name = self._get_bundle_lib_name()
            # update projects
            projects = self._gen_bundled_lib_cmake(lib_name, all_inc_dirs, projects, macros)

        for exe, exe_obj in exe_enable_modules.items():
            projects[exe] = {}
            projects[exe]['mods_cmake'] = {}
            inc_dirs = self._get_common_include(exe_obj.keys())
            for mod, mod_obj in exe_obj.items():
                self._gen_module_cmake(exe, mod, mod_obj, projects[exe]['mods_cmake'])
            self._gen_exe_cmake(exe, inc_dirs, projects[exe])

        return projects

    def _gen_target_cmake(self, lib_tgts):
        cmake = 'add_custom_target(openHiTLS)\n'
        cmake += self._gen_cmd_cmake('add_dependencies', 'openHiTLS', lib_tgts)
        return cmake

    def _gen_set_param_cmake(self, macro_file):
        compile_flags, link_flags = self._cfg_compile.union_options(self._cfg_custom_compile)
        macros = self._cfg_custom_feature.get_fea_macros()
        macros.sort()
        if self._args.no_config_check:
            macros.append('-DHITLS_NO_CONFIG_CHECK')

        if '-DHITLS_CRYPTO_CMVP_ISO19790' in compile_flags:
            self._approved_provider = True
            self._hmac = "sha256"
        elif '-DHITLS_CRYPTO_CMVP_SM' in compile_flags:
            self._approved_provider = True
            self._hmac = "sm3"

        compile_flags.extend(macros)
        hitls_macros = list(filter(lambda x: '-DHITLS' in x, compile_flags))
        with open(macro_file, "w") as f:
            f.write(" ".join(hitls_macros))
            f.close()
        self._cc_all_options = compile_flags
        compile_flags_str = '"{}"'.format(" ".join(compile_flags))

        # Concatenate link flags and deduplicate to handle flags from multiple sources
        # SHARED_LNK_FLAGS = SHARED + PUBLIC, EXE_LNK_FLAGS = EXE + PUBLIC
        shared_flags_list = link_flags['SHARED'] + link_flags['PUBLIC']
        exe_flags_list = link_flags['EXE'] + link_flags['PUBLIC']

        # Deduplicate while preserving order (keep first occurrence)
        shared_flags_list = list(dict.fromkeys(shared_flags_list))
        exe_flags_list = list(dict.fromkeys(exe_flags_list))

        shared_link_flags = '{}'.format(" ".join(shared_flags_list))
        exe_link_flags = '{}'.format(" ".join(exe_flags_list))

        cmake = self._gen_cmd_cmake('set', 'CC_ALL_OPTIONS', compile_flags_str) + "\n"
        cmake += self._gen_cmd_cmake('set', 'SHARED_LNK_FLAGS', shared_link_flags) + "\n"
        cmake += self._gen_cmd_cmake('set', 'EXE_LNK_FLAGS', exe_link_flags) + "\n"

        return cmake, macros

    def _gen_compiler_config_cmake(self):
        """Generate CMake configuration to ensure compiler consistency."""
        cmake = "# ============================================================\n"
        cmake += "# Compiler Configuration (detected by configure.py)\n"
        cmake += "# ============================================================\n"
        cmake += "# Detected compiler: {}\n".format(self._cfg_compile.compiler)
        cmake += "# Detected linker:   {}\n".format(self._cfg_compile.linker)
        cmake += "# Detected platform: {}\n".format(self._cfg_compile.platform)
        cmake += "#\n"
        cmake += "# Note: CMake will use its own compiler detection.\n"
        cmake += "# If you need to override, set CC/CXX environment variables\n"
        cmake += "# or use cmake -DCMAKE_C_COMPILER=... -DCMAKE_CXX_COMPILER=...\n"
        cmake += "# ============================================================\n\n"

        # Save detected configuration for verification
        cmake += "# Store detected configuration for consistency checks\n"
        cmake += "set(CONFIGURE_DETECTED_COMPILER \"{}\")\n".format(self._cfg_compile.compiler)
        cmake += "set(CONFIGURE_DETECTED_LINKER \"{}\")\n".format(self._cfg_compile.linker)
        cmake += "set(CONFIGURE_DETECTED_PLATFORM \"{}\")\n\n".format(self._cfg_compile.platform)

        return cmake

    def out_cmake(self, cmake_path, macro_file):
        self._cfg_custom_feature.check_bn_config()

        compiler_config_cmake = self._gen_compiler_config_cmake()
        set_param_cmake, macros = self._gen_set_param_cmake(macro_file)
        set_param_cmake += self._gen_common_compile_c_flags()

        projects = self._gen_projects_cmake(macros)

        lib_tgts = list(tgt for lib_obj in projects.values() for tgt in lib_obj['targets'])
        bottom_cmake = self._gen_target_cmake(lib_tgts)

        with open(cmake_path, "w") as f:
            f.write(compiler_config_cmake)
            f.write(set_param_cmake)
            for lib_obj in projects.values():
                f.write(lib_obj['cmake'])
                f.write('\n\n')
            f.write(bottom_cmake)


def main():
    os.chdir(srcdir)

    # The Python version cannot be earlier than 3.5.
    if sys.version_info < (3, 5):
        print("your python version %d.%d should not be lower than 3.5" % tuple(sys.version_info[:2]))
        raise Exception("your python version %d.%d should not be lower than 3.5" % tuple(sys.version_info[:2]))

    # Handle --list-toolchains early (before loading features)
    if '--list-toolchains' in sys.argv:
        list_available_toolchains()
        sys.exit(0)

    # Check and handle securec dependency early
    # Skip dependency check if called from CMake (with -m flag)
    # CMake handles securec build via SecureC.cmake
    is_cmake_invocation = '-m' in sys.argv or '--module_cmake' in sys.argv
    auto_deps = '--no-auto-deps' not in sys.argv
    force_rebuild = '--force-rebuild-deps' in sys.argv

    if not is_cmake_invocation and (auto_deps or force_rebuild):
        print("\n" + "=" * 70)
        print("Checking securec dependency...")
        print("=" * 70)
        if not ensure_securec_dependency(
            auto_init=auto_deps,
            auto_build=auto_deps,
            force_rebuild=force_rebuild
        ):
            print("\n" + "=" * 70)
            print("[ERROR] Failed to prepare securec dependency!")
            print("=" * 70)
            print("\nYou can:")
            print("  1. Fix the issue and run configure.py again")
            print("  2. Use --no-auto-deps to skip automatic dependency management")
            print("  3. Manually prepare securec and run configure.py")
            sys.exit(1)
        print()

    conf_feature = FeatureParser(Configure.feature_json_file)
    complete_options = CompleteOptionParser(Configure.complete_options_json_file)

    cfg = Configure(conf_feature)
    cfg.load_config_to_build()
    cfg.update_feature_config(cfg.args.module_cmake)
    cfg.update_compile_config(complete_options)

    if cfg.args.module_cmake:
        tmp_cmake = os.path.join(cfg.args.build_dir, 'modules.cmake')
        macro_file = os.path.join(cfg.args.build_dir, 'macro.txt')
        if (os.path.exists(macro_file)):
            os.remove(macro_file)

        # Generate toolchain file
        cmake_gen = CMakeGenerator(cfg.args, conf_feature, complete_options)
        cmake_gen.select_toolchain()
        cmake_gen.out_cmake(tmp_cmake, macro_file)

if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        exit(0)
    except:
        traceback.print_exc()
        exit(2)
