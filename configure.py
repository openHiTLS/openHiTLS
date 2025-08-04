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
from script.methods import copy_file, save_json_file, trans2list
from script.config_parser import (FeatureParser, CompileParser, FeatureConfigParser,
                                  CompileConfigParser, CompleteOptionParser)

srcdir = os.path.dirname(os.path.realpath(sys.argv[0]))
work_dir = os.path.abspath(os.getcwd())


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

        parser.add_argument('--hitls_version', default='openHiTLS 0.2.0 15 May 2025', help='%(prog)s version str')
        parser.add_argument('--hitls_version_num', default=0x00200000, help='%(prog)s version num')
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
        conf_custom_feature.set_param('system', self._args.system, False)
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
        self._cfg_compile = CompileParser(all_options, Configure.default_compile_json_file)
        self._cfg_custom_feature = FeatureConfigParser(features, args.tmp_feature_config)
        self._cfg_custom_feature.check_fea_opts()
        self._cfg_custom_compile = CompileConfigParser(all_options, args.tmp_compile_config)

        self._asm_type = self._cfg_custom_feature.asm_type

        self._platform = 'linux'
        self._iso_provider = False

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

    def _gen_module_cmake(self, lib, mod, mod_obj, mods_cmake):
        top_mod, module_name = mod.split('::')
        inc_set = self._get_module_include(mod, mod_obj.get('deps', []))
        src_list = self._get_module_src_set(lib, top_mod, module_name, mod_obj)

        tgt_name = module_name + '-objs'
        cmake = '\n# Add module {} \n'.format(module_name)
        cmake += self._gen_cmd_cmake('add_library', '{} OBJECT'.format(tgt_name))

        cmake += self._gen_cmd_cmake('target_include_directories', '{} PRIVATE'.format(tgt_name), inc_set)
        cmake += self._gen_cmd_cmake('target_sources', '{} PRIVATE'.format(tgt_name), src_list)
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
        if (self._iso_provider):
            # Use the openssl command to generate an HMAC file.
            cmake += 'install(CODE "execute_process(COMMAND openssl dgst -hmac \\\"%s\\\" -sha256 -out lib%s.so.hmac lib%s.so)")\n' % (self._args.hkey, lib_name, lib_name)
            # Install the hmac file to the output directory.
            cmake += 'install(CODE "execute_process(COMMAND cp lib%s.so.hmac ${CMAKE_INSTALL_PREFIX}/lib%s.so.hmac)")\n' % (lib_name, lib_name)

        if lib_name == 'hitls_bsl':
            for item in macros:
                if item == '-DHITLS_BSL_UIO' or item == '-DHITLS_BSL_UIO_SCTP':
                    cmake += self._gen_cmd_cmake("target_link_directories", "hitls_bsl-shared PRIVATE " + "${CMAKE_SOURCE_DIR}/platform/Secure_C/lib")
                    cmake += self._gen_cmd_cmake("target_link_libraries", "hitls_bsl-shared " + str(self._args.securec_lib))
                if item == '-DHITLS_BSL_SAL_DL':
                    cmake += self._gen_cmd_cmake("target_link_directories", "hitls_bsl-shared PRIVATE " + "${CMAKE_SOURCE_DIR}/platform/Secure_C/lib")
                    cmake += self._gen_cmd_cmake("target_link_libraries", "hitls_bsl-shared dl " + str(self._args.securec_lib))
        if lib_name == 'hitls_crypto':
            cmake += self._gen_cmd_cmake("target_link_directories", "hitls_crypto-shared PRIVATE " + "${CMAKE_SOURCE_DIR}/platform/Secure_C/lib")
            cmake += self._gen_cmd_cmake("target_link_libraries", "hitls_crypto-shared hitls_bsl-shared " + str(self._args.securec_lib))
        if lib_name == 'hitls_tls':
            cmake += self._gen_cmd_cmake("target_link_directories", "hitls_tls-shared PRIVATE " + "${CMAKE_SOURCE_DIR}/platform/Secure_C/lib")
            cmake += self._gen_cmd_cmake("target_link_libraries", "hitls_tls-shared hitls_pki-shared hitls_crypto-shared hitls_bsl-shared " + str(self._args.securec_lib))
        if lib_name == 'hitls_pki':
            cmake += self._gen_cmd_cmake("target_link_directories", "hitls_pki-shared PRIVATE " + "${CMAKE_SOURCE_DIR}/platform/Secure_C/lib")
            cmake += self._gen_cmd_cmake(
                "target_link_libraries", "hitls_pki-shared hitls_crypto-shared hitls_bsl-shared " + str(self._args.securec_lib))
        if lib_name == 'hitls_auth':
            cmake += self._gen_cmd_cmake("target_link_directories", "hitls_auth-shared PRIVATE " + "${CMAKE_SOURCE_DIR}/platform/Secure_C/lib")
            cmake += self._gen_cmd_cmake(
                "target_link_libraries", "hitls_auth-shared hitls_crypto-shared hitls_bsl-shared " + str(self._args.securec_lib))
        if self._iso_provider:
            cmake += self._gen_cmd_cmake("target_link_libraries", "hitls-shared m " + str(self._args.securec_lib))
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

    def _gen_obejct_lib_cmake(self, lib_name, tgt_obj_list, tgt_list):
        tgt_name = lib_name + '-object'
        properties = 'OUTPUT_NAME lib{}.o'.format(lib_name)

        cmake = '\n'
        cmake += self._gen_cmd_cmake('add_executable', tgt_name, tgt_obj_list)
        cmake += self._gen_cmd_cmake('target_link_options', '{} PRIVATE'.format(tgt_name), '${SHARED_LNK_FLAGS}')
        cmake += self._gen_cmd_cmake('set_target_properties', '{} PROPERTIES'.format(tgt_name), properties)
        cmake += 'install(TARGETS %s DESTINATION ${CMAKE_INSTALL_PREFIX}/obj)\n' % tgt_name

        tgt_list.append(tgt_name)
        return cmake

    def _get_definitions(self):
        ret = '"${CMAKE_C_FLAGS} -DOPENHITLS_VERSION_S=\'\\"%s\\"\' -DOPENHITLS_VERSION_I=%lu %s' % (
                self._args.hitls_version, self._args.hitls_version_num, '-D__FILENAME__=\'\\"$(notdir $(subst .o,,$@))\\"\'')
        if self._iso_provider:
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
            cmake += self._gen_obejct_lib_cmake(lib_name, tgt_obj_list, tgt_list)
        lib_obj['cmake'] = cmake
        lib_obj['targets'] = tgt_list

    def _gen_exe_cmake(self, exe_name, inc_dirs, exe_obj):
        lang = self._cfg_feature.executes[exe_name].get('lang', 'C')
        definitions = '"${CMAKE_C_FLAGS} -DHITLS_VERSION=\'\\"%s\\"\' %s"' % (
            self._args.hitls_version, '-D__FILENAME__=\'\\"$(notdir $(subst .o,,$@))\\"\'')
        cmake = 'project({} {})\n\n'.format(exe_name, lang)
        cmake += self._gen_cmd_cmake('set', 'CMAKE_C_FLAGS', '${CC_ALL_OPTIONS}')
        cmake += self._gen_cmd_cmake('set', 'CMAKE_C_FLAGS', definitions)

        cmake += self._gen_cmd_cmake('include_directories', '', inc_dirs)
        for _, mod_cmake in exe_obj['mods_cmake'].items():
            cmake += mod_cmake

        tgt_obj_list = list('$<TARGET_OBJECTS:{}>'.format(x) for x in exe_obj['mods_cmake'].keys())
        cmake += self._gen_cmd_cmake('add_executable', exe_name, tgt_obj_list)
        lib_type = self._cfg_custom_feature.lib_type
        if 'shared' in lib_type:
            cmake += self._gen_cmd_cmake('add_dependencies', exe_name,
                                        'hitls_pki-shared hitls_crypto-shared hitls_bsl-shared')
        elif 'static' in lib_type:
            cmake += self._gen_cmd_cmake('add_dependencies', exe_name,
                                        'hitls_pki-static hitls_crypto-static hitls_bsl-static')

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
            cmake += self._gen_obejct_lib_cmake(lib_name, tgt_obj_list, tgt_list)

        return {lib_name: {'cmake': cmake, 'targets': tgt_list}}

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
            # update projects
            projects = self._gen_bundled_lib_cmake('hitls', all_inc_dirs, projects, macros)

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

        if '-DHITLS_CRYPTO_CMVP_ISO19790' in compile_flags:
            self._iso_provider = True

        compile_flags.extend(macros)
        hitls_macros = list(filter(lambda x: '-DHITLS' in x, compile_flags))
        with open(macro_file, "w") as f:
            f.write(" ".join(hitls_macros))
            f.close()
        self._cc_all_options = compile_flags
        compile_flags_str = '"{}"'.format(" ".join(compile_flags))
        shared_link_flags = '{}'.format(" ".join(link_flags['SHARED']) + " " + " ".join(link_flags['PUBLIC']))
        exe_link_flags = '{}'.format(" ".join(link_flags['EXE']) + " " + " ".join(link_flags['PUBLIC']))

        cmake = self._gen_cmd_cmake('set', 'CC_ALL_OPTIONS', compile_flags_str) + "\n"
        cmake += self._gen_cmd_cmake('set', 'SHARED_LNK_FLAGS', shared_link_flags) + "\n"
        cmake += self._gen_cmd_cmake('set', 'EXE_LNK_FLAGS', exe_link_flags) + "\n"

        return cmake, macros

    def out_cmake(self, cmake_path, macro_file):
        self._cfg_custom_feature.check_bn_config()

        set_param_cmake, macros = self._gen_set_param_cmake(macro_file)
        set_param_cmake += self._gen_common_compile_c_flags()

        projects = self._gen_projects_cmake(macros)

        lib_tgts = list(tgt for lib_obj in projects.values() for tgt in lib_obj['targets'])
        bottom_cmake = self._gen_target_cmake(lib_tgts)

        with open(cmake_path, "w") as f:
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
        CMakeGenerator(cfg.args, conf_feature, complete_options).out_cmake(tmp_cmake, macro_file)

if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        exit(0)
    except:
        traceback.print_exc()
        exit(2)
