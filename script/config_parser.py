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

import sys
sys.dont_write_bytecode = True
import json
import os
import re
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))
from methods import trans2list, save_json_file
from platform_utils import CompilerDetector, LinkerDetector, PlatformDetector


class Feature:
    def __init__(self, name, target, is_lib, parent, children, deps, opts, impl, ins_set):
        self.name = name

        self.target = target
        self.is_lib = is_lib        # Indicates whether the target file is a lib or exe file.

        self.parent = parent
        self.children = children

        self.deps = deps
        self.opts = opts

        self.impl = impl            # Implementation mode
        self.ins_set = ins_set      # Instruction Set


    @classmethod
    def simple(cls, name, target, is_lib, parent, impl):
        return Feature(name, target, is_lib, parent, [], [], [], impl, [])


class FeatureParser:
    """ Parsing feature files """
    lib_dir_map = {
        "hitls_bsl": "bsl",
        "hitls_crypto": "crypto",
        "hitls_tls": "tls",
        "hitls_pki": "pki",
        "hitls_auth": "auth"
    }

    def __init__(self, file_path):
        self._fp = file_path
        with open(file_path, 'r', encoding='utf-8') as f:
            self._cfg = json.loads(f.read())
            self._file_check()

        # Features and related information.
        self._feas_info = self._get_feas_info()
        # Assembly type supported by the openHiTLS.
        self._asm_types = self._get_asm_types()

    @property
    def libs(self):
        return self._cfg['libs']

    @property
    def executes(self):
        return self._cfg['executes']

    @property
    def modules(self):
        return self._cfg['modules']

    @property
    def asm_types(self):
        return self._asm_types

    @property
    def feas_info(self):
        return self._feas_info

    def _file_check(self):
        if 'libs' not in self._cfg or 'modules' not in self._cfg:
            raise FileNotFoundError("The format of file %s is incorrect." % self._fp)

    @staticmethod
    def _add_key_value(obj, key, value):
        if value:
            obj[key] = value

    def _add_fea(self, feas_info, feature: Feature):
        fea_name = feature.name
        feas_info.setdefault(fea_name, {})

        if feature.is_lib:
            self._add_key_value(feas_info[fea_name], 'lib', feature.target)
        else:
            self._add_key_value(feas_info[fea_name], 'execute', feature.target)
        self._add_key_value(feas_info[fea_name], 'parent', feature.parent)
        self._add_key_value(feas_info[fea_name], 'children', feature.children)
        self._add_key_value(feas_info[fea_name], 'opts', feature.opts)
        self._add_key_value(feas_info[fea_name], 'deps', feature.deps)

        feas_info[fea_name].setdefault('impl', {})
        feas_info[fea_name]['impl'][feature.impl] = feature.ins_set if feature.ins_set else []


    def _parse_fea_obj(self, name, target, is_lib, parent, impl, fea_obj, feas_info):
        feature = Feature.simple(name, target, is_lib, parent, impl)
        if not fea_obj:
            self._add_fea(feas_info, feature)
            return

        feature.deps = fea_obj.get('deps', None)
        feature.opts = fea_obj.get('opts', None)
        feature.ins_set = fea_obj.get('ins_set', None)

        non_sub_keys = ['opts', 'deps', 'ins_set', 'help']
        for key, obj in fea_obj.items():
            if key not in non_sub_keys:
                feature.children.append(key)
                self._parse_fea_obj(key, target, is_lib, name, impl, obj, feas_info)

        self._add_fea(feas_info, feature)

    def parse_fearuers(self, all_feas, tmp_feas_info, target, target_obj, is_lib):
        tmp_feas_info[target] = {}
        for impl, impl_obj in target_obj['features'].items():
            for fea, fea_obj in impl_obj.items():
                self._parse_fea_obj(fea, target, is_lib, None, impl, fea_obj, tmp_feas_info[target])

        # Check that feature names in different target are unique.
        tgt_feas = set(tmp_feas_info[target].keys())
        repeat_feas = all_feas.intersection(tgt_feas)
        if len(repeat_feas) != 0:
            raise ValueError("Error: feature '%s' has been defined in other target." % (repeat_feas))
        all_feas.update(tgt_feas)

    def _get_feas_info(self):
        """
        description: Parse the feature.json file to obtain feature information
                     and check that feature names in different libraries are unique.
        return:
            feas_info: {
                "children":[],  "parent":[],  "deps":[],
                "opts":[[],[]], "lib":"",     "execute":""
                "impl":{"c":[], "armv8:[], ...}, # [] lists the instruction sets supported by the feature.
            }
        """
        all_feas = set()
        tmp_feas_info = {}
        for lib, lib_obj in self._cfg['libs'].items():
            self.parse_fearuers(all_feas, tmp_feas_info, lib, lib_obj, True)

        for exe, exe_obj in self._cfg['executes'].items():
            self.parse_fearuers(all_feas, tmp_feas_info, exe, exe_obj, False)

        feas_info = {}
        for obj in tmp_feas_info.values():
            feas_info.update(obj)
        self._fill_fea_modules(feas_info)
        self._correct_impl(feas_info)
        return feas_info

    def _fill_fea_modules(self, feas_info):
        for top_mod in self.modules:
            for mod, mod_obj in self.modules[top_mod].items():
                formated_mod = "{}::{}".format(top_mod, mod)
                for fea in mod_obj.get('.features', []):
                    if fea not in feas_info:
                        raise ValueError("Unrecognized '%s' in '.features' of '%s::%s'" % (fea, top_mod, mod))

                    if 'modules' not in feas_info[fea]:
                        feas_info[fea]['modules'] = [formated_mod]
                    else:
                        feas_info[fea]['modules'].append(formated_mod)
    
    @staticmethod
    def _correct_impl(feas_info):
        """Updated the implementation modes of sub-features based on the parent feature."""
        for fea in feas_info.keys():
            parent = feas_info[fea].get('parent', '')
            if not parent:
                continue
            if len(feas_info[fea]['impl'].keys()) == 1 and 'c' in feas_info[fea]['impl']:
                feas_info[fea]['impl'] = feas_info[parent]['impl']

    def _get_asm_types(self):
        asm_type_set = set()
        [asm_type_set.update(self.libs[lib]['features'].keys()) for lib in self.libs.keys()]
        asm_type_set.discard('c')
        asm_type_set.add('no_asm')
        asm_type_set.add('riscv64')
        return asm_type_set

    def get_module_deps(self, module, dep_list, result):
        return self._get_module_deps(module, dep_list, result)

    def _get_module_deps(self, module, dep_list, result):
        """
        Recursively obtains the modules on which the modules depend.
        module:   [IN]  module name, such as crypto::sha2
        dep_list: [OUT] Dependency list, which is an intermediate variable
        result:   [OUT] result
        """
        top_module, sub_module = module.split('::')
        mod_obj = self.modules[top_module][sub_module]

        if '.deps' not in mod_obj:
            result.update(dep_list)
            return

        for dep_mod in mod_obj['.deps']:
            if dep_mod in dep_list:
                # A dependency that already exists in a dependency chain is a circular dependency.
                raise Exception("Cyclic dependency")
            dep_list.append(dep_mod)
            self._get_module_deps(dep_mod, dep_list, result)
            dep_list.pop()

    def get_mod_srcs(self, top_mod, sub_mod, mod_obj):
        srcs = self._cfg['modules'][top_mod][sub_mod]['.srcs']
        asm_type = mod_obj.get('asmType', 'c')
        inc = mod_obj.get('incSet', '')

        blurred_srcs = []
        if not isinstance(srcs, dict):
            blurred_srcs.extend(trans2list(srcs))
            return blurred_srcs

        blurred_srcs.extend(trans2list(srcs.get('public', [])))
        if asm_type == 'c':
            blurred_srcs.extend(trans2list(srcs.get('no_asm', [])))
            return blurred_srcs

        if asm_type not in srcs:
            raise ValueError("Missing '.srcs[%s]' in modules '%s::%s'" % (asm_type, top_mod, sub_mod))
        if not isinstance(srcs[asm_type], dict):
            blurred_srcs.extend(trans2list(srcs[asm_type]))
            return blurred_srcs

        if inc:
            blurred_srcs.extend(trans2list(srcs[asm_type][inc]))
        else:
            first_key = list(srcs[asm_type].keys())[0]
            blurred_srcs.extend(trans2list(srcs[asm_type][first_key]))
        return blurred_srcs


class FeatureConfigParser:
    """ Parses the user feature configuration file. """
    # Specifications of keys and values in the file.
    key_value = {
        "system": {"require": False, "type": str, "choices": ["linux", "darwin", "none", ""], "default": "linux"},
        "bits": {"require": False, "type": int, "choices": [32, 64], "default": 64},
        "endian": {"require": True, "type": str, "choices": ["little", "big"], "default": "little"},
        "libType": {
            "require": True,
            "type": list,
            "choices": ["static", "shared", "object"],
            "default": ["static", "shared", "object"]
        },
        "asmType":{"require": True, "type": str, "choices": [], "default": "no_asm"},
        "libs":{"require": True, "type": dict, "choices": [], "default": {}},
        "bundleLibs":{"require": False, "type": bool, "choices": [True, False], "default": False},
        "securecLib":{"require": False, "type": str, "choices": ["boundscheck", "securec", "sec_shared.z", ""], "default": "boundscheck"},
        "executes":{"require": False, "type": dict, "default": {}}
    }

    def __init__(self, features: FeatureParser, file_path):
        self._features = features
        self._config_file = file_path
        with open(file_path, 'r', encoding='utf-8') as f:
            self._cfg = json.loads(f.read())
        self.key_value['asmType']['choices'] = list(features.asm_types)
        self.key_value['libs']['choices'] = list(features.libs)
        self._file_check()

    @classmethod
    def default_cfg(cls):
        config = {}
        for key in cls.key_value.keys():
            if cls.key_value[key]["require"]:
                config[key] = cls.key_value[key]["default"]
        return config

    @property
    def libs(self):
        return self._cfg['libs']

    @property
    def executes(self):
        return self._cfg.get('executes', {})

    @property
    def lib_type(self):
        return trans2list(self._cfg['libType'])

    @property
    def asm_type(self):
        return self._cfg['asmType']

    @property
    def bundle_libs(self):
        if 'bundleLibs' in self._cfg:
            return self._cfg['bundleLibs']
        return self.key_value['bundleLibs']['default']

    @property
    def securec_lib(self):
        if 'securecLib' in self._cfg:
            return self._cfg['securecLib']
        return self.key_value['securecLib']['default']

    @staticmethod
    def _get_fea_and_inc(asm_fea):
        if '::' in asm_fea:
            return asm_fea.split('::')
        else:
            return asm_fea, ''

    def enable_executes(self, targets):
        for target in targets:
            if 'executes' not in self._cfg:
                self._cfg['executes'] = {target: {}}
            else:
                self._cfg['executes'][target] = {}
            exe_objs = []
            for fea, fea_obj in self._features.feas_info.items():
                if fea_obj.get('execute', '') != target:
                    continue
                for i in fea_obj['impl'].keys():
                    self._cfg['executes'][target].setdefault(i, [])
                    self._cfg['executes'][target][i].append(fea)

    def _asm_fea_check(self, asm_fea, asm_type, info):
        fea, inc = self._get_fea_and_inc(asm_fea)
        feas_info = self._features.feas_info
        if fea not in feas_info:
            raise ValueError("Unsupported '%s' in %s" % (fea, info))
        if asm_type not in feas_info[fea]['impl']:
            raise ValueError("Feature '%s' has no assembly implementation of type '%s' in %s" % (fea, asm_type, info))
        if inc:
            if inc not in feas_info[fea]['impl'] and inc not in feas_info[fea]['impl'][asm_type]:
                raise ValueError("Unsupported instruction set of '%s' in %s" % (asm_fea, info))
        return fea, inc

    def _file_check(self):
        for key, value in self.key_value.items():
            if value['require']:
                if key not in self._cfg.keys():
                    raise ValueError("Error feature_config file: missing '%s'" % key)

        for key, value in self._cfg.items():
            if key not in self.key_value.keys():
                raise ValueError("Error feature_config file: unsupported config '%s'" % key)
            if not isinstance(value, self.key_value.get(key).get("type")):
                raise ValueError("Error feature_config file: wrong type of '%s'" % key)

            value_type = type(value)
            if value_type == str or value_type == str:
                if value not in self.key_value.get(key).get("choices"):
                    if key == "system":
                        print("Info: There is no {} implementation by default, you should set its SAL callbacks to make it work.".format(value))
                        continue
                    raise ValueError("Error feature_config file: wrong value of '%s'" % key)
            elif value_type == list:
                choices = set(self.key_value[key]["choices"])
                if not set(value).issubset(choices):
                    raise ValueError("Error feature_config file: wrong value of '%s'" % key)

        for lib, lib_obj in self._cfg['libs'].items():
            if lib not in self._features.libs:
                raise ValueError("Error feature_config file: unsupported lib '%s'" % lib)
            for fea in lib_obj.get('c', []):
                if fea not in self._features.feas_info:
                    raise ValueError("Error feature_config file: unsupported fea '%s' in lib '%s'" % (fea, lib))
            asm_feas = []
            for asm_fea in lib_obj.get('asm', []):
                fea, _ = self._asm_fea_check(asm_fea, self.asm_type, 'feature_config file')
                if fea in asm_feas:
                    raise ValueError("Error feature_config file: duplicate assembly feature '%s'" % fea)
                asm_feas.append(fea)

    def set_param(self, key, value, set_default=True):
        if key == 'bundleLibs':
            self._cfg[key] = value
            return
        if value:
            self._cfg[key] = value
            return
        if not set_default:
            return
        if key not in self._cfg or not self._cfg[key]:
            print("Warning: Configuration item '{}' is missing and has been set to the default value '{}'.".format(
                key, self.key_value.get(key).get('default')))
            self._cfg[key] = self.key_value.get(key).get('default')

    def _get_related_feas(self, fea, feas_info, related: set):
        related.add(fea)
        if 'parent' in feas_info[fea]:
            parent = feas_info[fea]['parent']
            for dep in feas_info[parent].get('deps', []):
                self._get_related_feas(dep, feas_info, related)
        if 'children' in feas_info[fea]:
            for child in feas_info[fea]['children']:
                self._get_related_feas(child, feas_info, related)
        if 'deps' in feas_info[fea]:
            for dep in feas_info[fea]['deps']:
                self._get_related_feas(dep, feas_info, related)

    def _get_parents(self, disables):
        parents = set()
        for d in disables:
            relation = self._features.feas_info.get(d)
            if relation and 'parent' in relation:
                parents.add(relation['parent'])
        return parents

    def _add_depend_feas(self, enable_feas, feas_info):
        related = set()
        for f in enable_feas:
            fea, inc = self._get_fea_and_inc(f)
            self._get_related_feas(fea, feas_info, related)

        enable_feas.update(related)

    def _check_asm_fea_enable(self, enable_feas, feas, feas_info):
        not_in_enable = []
        for f in feas:
            fea, _ = self._get_fea_and_inc(f)
            if fea in enable_feas: # This feature is already in the enable list.
                continue

            rel = feas_info[fea]
            is_enable = False
            while('parent' in rel):
                parent = rel['parent']
                if parent in enable_feas: # This feature is already in the enable list.
                    is_enable = True
                    break
                rel = feas_info[parent]
            if not is_enable:
                not_in_enable.append(fea)
        if not_in_enable:
            raise ValueError("To add '%s' assembly requires add it to 'enable' list" % not_in_enable)

    def get_enable_feas(self, arg_enable, arg_asm):
        """
            Get the enabled features form:
            1. build/feature_config.json
            2. argument: enable list
            3. argument: asm list
        """
        enable_feas = set()
        enable_asm_feas = set()
        # 1. Exist feas in build/feature_config.json
        for _, lib_obj in self._cfg['libs'].items():
            enable_feas.update(lib_obj.get('c', []))
            enable_asm_feas.update(lib_obj.get('asm', []))

        # 2. Obtains the properties from the input parameter: enable list.
        feas_info = self._features.feas_info
        if 'all' in arg_enable:  # all features
            enable_feas.update(set(x for x in feas_info.keys()))
        else:
            for enable in arg_enable:
                if enable in self._features.libs: # features in a lib
                    enable_feas.update(set(x for x, y in feas_info.items() if enable == y.get('lib', '')))
                else: # The feature is not lib and needs to be added separately.
                    enable_feas.add(enable)

        enable_feas.update(enable_asm_feas)
        self._add_depend_feas(enable_feas, feas_info)
        self._check_asm_fea_enable(enable_feas, arg_asm, feas_info)
        enable_asm_feas.update(arg_asm)
        return enable_feas, enable_asm_feas

    def _add_feature(self, fea, impl_type, inc=''):
        add_fea = fea if inc == '' else '{}::{}'.format(fea, inc)
        lib = self._features.feas_info[fea]['lib']
        if lib not in self._cfg['libs']:
            self._cfg['libs'][lib] = {impl_type: [add_fea]}
        elif impl_type not in self._cfg['libs'][lib]:
            self._cfg['libs'][lib][impl_type] = [add_fea]
        elif fea not in self._cfg['libs'][lib][impl_type]:
            self._cfg['libs'][lib][impl_type].append(add_fea)

    def set_asm_type(self, asm_type):
        if self._cfg['asmType'] == 'no_asm':
            self._cfg['asmType'] = asm_type
        elif self._cfg['asmType'] != asm_type:
            raise ValueError('Error asmType: %s is different from feature_config file.' % (asm_type))

    def set_asm_features(self, enable_feas, asm_feas, asm_type):
        feas_info = self._features.feas_info
        # Clear the assembly features first.
        for lib in self._cfg['libs']:
            if 'asm' in self._cfg['libs'][lib]:
                self._cfg['libs'][lib]['asm'] = []
        # Add assembly features.
        if asm_feas:
            for asm_feature in asm_feas:
                fea, inc = self._asm_fea_check(asm_feature, asm_type, 'input asm list')
                if inc and inc != asm_type:
                    raise ValueError("Input instruction '%s' is not the same as 'asm_type' '%s'" % (inc, asm_type))
                self._add_feature(fea, 'asm', inc)
        else:
            for fea in enable_feas:
                if asm_type not in feas_info[fea]['impl']:
                    continue
                self._add_feature(fea, 'asm')

    def set_c_features(self, enable_feas):
        for f in enable_feas:
            fea, _ = self._get_fea_and_inc(f)
            if self._features.feas_info[fea].get('execute'):
                continue
            if 'c' in self._features.feas_info[fea]['impl']:
                self._add_feature(fea, 'c')

    def _update_enable_feature(self, features, disables):
        """
        The sub-feature macro is derived from the parent feature macro in the code.
        Therefore, the sub-feature is removed and the parent feature is retained.
        """
        disable_parents = self._get_parents(disables)
        tmp_feas = features.copy()
        enable_set = set()
        feas_info = self._features.feas_info
        for f in tmp_feas:
            fea, _ = self._get_fea_and_inc(f)
            rel = feas_info[fea]
            if fea in disable_parents:
                if 'children' in rel:
                    enable_set.update(rel['children'])
                enable_set.discard(fea)
            else:
                is_fea_contained = False
                while 'parent' in rel:
                    if rel['parent'] in disables or rel['parent'] in features:
                        is_fea_contained = True
                        break
                    rel = feas_info[rel['parent']]
                if not is_fea_contained:
                    enable_set.add(fea)
        enable_set.difference_update(set(disables))
        return list(enable_set)

    def check_bn_config(self):
        lib = 'hitls_crypto'
        if lib not in self._cfg['libs']:
            return

        has_bn = False
        bn_pattern = "bn_"
        for impl_type in self._cfg['libs'][lib]:
            if 'bn' in self._cfg['libs'][lib][impl_type]:
                has_bn = True
                break
            for fea in self._cfg['libs'][lib][impl_type]:
                if re.match(bn_pattern, fea) :
                    has_bn = True
                    break

        if has_bn and 'bits' not in self._cfg:
            raise ValueError("If 'bn' is used, the 'bits' of the system must be configured.")

    def _re_sort_lib(self):
        # Change the key sequence of the 'libs' dictionary. Otherwise, the compilation fails.
        lib_sort = ['hitls_bsl', 'hitls_crypto', 'hitls_tls', "hitls_pki", "hitls_auth"]
        libs = self.libs.copy()
        self._cfg['libs'].clear()

        for lib in lib_sort:
            if lib in libs:
                self._cfg['libs'][lib] = libs[lib].copy()

    def update_feature(self, enables, disables, gen_cmake):
        '''
        update feature:
        1. Add the default lib and features: hitls_bsl: sal
        2. Delete features based on the relationship between features.
        '''
        libs = self._cfg['libs']
        if len(libs) == 0:
            if gen_cmake:
                raise ValueError("No features are enabled.")
            else:
                return

        libs.setdefault('hitls_bsl', {'c':['sal']})
        if 'hitls_bsl' not in libs:
            libs['hitls_bsl'] = {'c':['sal']}
        elif 'c' not in libs['hitls_bsl']:
            libs['hitls_bsl']['c'] = ['sal']
        elif 'sal' not in libs['hitls_bsl']['c']:
            libs['hitls_bsl']['c'].append('sal')

        for lib in libs:
            if 'c' in libs[lib]:
                libs[lib]['c'] = self._update_enable_feature(libs[lib]['c'], disables)
                libs[lib]['c'].sort()
            if 'asm' in libs[lib]:
                libs[lib]['asm'] = self._update_enable_feature(libs[lib]['asm'], disables)
                libs[lib]['asm'].sort()

        self._re_sort_lib()

        if 'all' in enables:
            # Only set defaults if not already configured (silently fill in missing values)
            if 'system' not in self._cfg or not self._cfg['system']:
                self._cfg['system'] = self.key_value.get('system').get('default')
            if 'bits' not in self._cfg or not self._cfg['bits']:
                self._cfg['bits'] = self.key_value.get('bits').get('default')

    def save(self, path):
        save_json_file(self._cfg, path)

    def get_fea_macros(self):
        macros = set()
        for lib, lib_value in self.libs.items():
            lib_upper = lib.upper()

            for fea in lib_value.get('c', []):
                macros.add("-D%s_%s" % (lib_upper, fea.upper()))
            for fea in lib_value.get('asm', []):
                fea = fea.split('::')[0]
                macros.add("-D%s_%s" % (lib_upper, fea.upper()))
                if 'bn' in fea:
                    macros.add("-D%s_%s_%s" % (lib_upper, 'BN', self.asm_type.upper()))
                else:
                    macros.add("-D%s_%s_%s" % (lib_upper, fea.upper(), self.asm_type.upper()))
            if lib_upper not in macros:
                macros.add("-D%s" % lib_upper)

        if self._cfg['endian'] == 'big':
            macros.add("-DHITLS_BIG_ENDIAN")
        system = self._cfg.get('system', "")
        if system == "linux":
            macros.add("-DHITLS_BSL_SAL_LINUX")
        elif system == "darwin":
            macros.add("-DHITLS_BSL_SAL_DARWIN")

        bits = self._cfg.get('bits', 0)
        if bits == 32:
            macros.add("-DHITLS_THIRTY_TWO_BITS")
        elif bits == 64:
            macros.add("-DHITLS_SIXTY_FOUR_BITS")

        return list(macros)

    def _re_get_fea_modules(self, fea, feas_info, asm_type, inc, modules):
        """Obtain the modules on which the current feature and subfeature depend."""
        for mod in feas_info[fea].get('modules', []):
            modules.setdefault(mod, {})
            modules[mod]["asmType"] = asm_type
            if inc:
                modules[mod]["incSet"] = inc

        for child in feas_info[fea].get('children', []):
            self._re_get_fea_modules(child, feas_info, asm_type, inc, modules)

    def _get_target_modules(self, target, is_lib):
        modules = {}
        feas_info = self._features.feas_info
        obj = self.libs if is_lib else self.executes
        for fea in obj[target].get('c', []):
            self._re_get_fea_modules(fea, feas_info, 'c', '', modules)

        for asm_fea in obj[target].get('asm', []):
            fea, inc = self._get_fea_and_inc(asm_fea)
            self._re_get_fea_modules(fea, feas_info, self.asm_type, inc, modules)

        for mod in modules:
            mod_dep_mods = set()
            self._features.get_module_deps(mod, [], mod_dep_mods)
            modules[mod]['deps'] = list(mod_dep_mods)
        if len(modules.keys()) == 0:
            raise ValueError("Error: no module is enabled in %s" % target)

        return modules

    def get_enable_modules(self):
        """
        Obtain the modules required for compiling each lib features
        and the modules on which the lib feature depends (for obtaining the include directory).
            1. Add modules and their dependent modules based on features.
            2. Check whether the dependent modules are enabled.
        return: {'lib/exe':{"mod1":{"deps":[], "asmType":"", "incSet":""}}}
                Module format: top_dir::sub_dir
        """
        enable_libs_mods = {}
        enable_exes_mods = {}
        enable_mods = set()
        for lib in self.libs.keys():
            enable_libs_mods[lib] = self._get_target_modules(lib, True)
            enable_mods.update(enable_libs_mods[lib])

        for exe in self.executes.keys():
            enable_exes_mods[exe] = self._get_target_modules(exe, False)
            enable_mods.update(enable_exes_mods[exe])

        # Check whether the dependent module is enabled.
        for lib in enable_libs_mods.keys():
            for mod in enable_libs_mods[lib]:
                for dep_mod in enable_libs_mods[lib][mod].get('deps', []):
                    if dep_mod == "platform::Secure_C":
                        continue
                    if dep_mod not in enable_mods:
                        raise ValueError("Error: '%s' depends on '%s', but '%s' is disabled." % (mod, dep_mod, dep_mod))
        for exe in enable_exes_mods.keys():
            for mod in enable_exes_mods[exe]:
                for dep_mod in enable_exes_mods[exe][mod].get('deps', []):
                    if dep_mod == "platform::Secure_C":
                        continue
                    if dep_mod not in enable_mods:
                        raise ValueError("Error: '%s' depends on '%s', but '%s' is disabled." % (mod, dep_mod, dep_mod))
        return enable_libs_mods, enable_exes_mods

    def filter_no_asm_config(self):
        self._cfg['asmType'] = 'no_asm'
        for lib in self._cfg['libs']:
            if 'asm' in self._cfg['libs'][lib]:
                self._cfg['libs'][lib]['asm'] = []

    def _check_fea_opts_arr(self, opts, fea, enable_feas):
        for opt_arr in opts:
            has_opt = False
            for opt_fea in opt_arr:
                if opt_fea in enable_feas:
                    has_opt = True
                    break
                parent = self._features.feas_info[opt_fea].get('parent', '')
                while parent:
                    if parent in enable_feas:
                        has_opt = True
                        break
                    parent = self._features.feas_info[parent].get('parent', '')
                if has_opt:
                    break
            if not has_opt:
                raise ValueError("At leaset one fea in %s must be enabled for '%s*'" % (opt_arr, fea))

    def _check_opts(self, fea, enable_feas):
        if 'opts' not in self._features.feas_info[fea]:
            return
        opts = self._features.feas_info[fea]['opts']
        if not isinstance(opts[0], list):
            opts = [opts]

        self._check_fea_opts_arr(opts, fea, enable_feas)

    def _check_family_opts(self, fea, key, enable_feas):
        values = self._features.feas_info[fea].get(key, [])
        if not isinstance(values, list):
            values = [values]
        for value in values:
            self._check_opts(value, enable_feas)
            self._check_family_opts(value, key, enable_feas)

    def check_fea_opts(self):
        enable_feas = set()
        for _, lib_obj in self.libs.items():
            enable_feas.update(lib_obj.get('c', []))
            enable_feas.update(lib_obj.get('asm', []))
        for fea in enable_feas:
            fea = fea.split("::")[0]
            self._check_opts(fea, enable_feas)
            self._check_family_opts(fea, 'parent', enable_feas)
            self._check_family_opts(fea, 'children', enable_feas)

class ConfigResolver:
    """
    Resolves configuration based on dimensions (compiler, linker, OS).
    Supports _EXTRA, _REMOVE, and _OVERRIDE operations.
    """

    @staticmethod
    def resolve_flags(common_flags, dimension_flags, dimension_value):
        """
        Resolve flags by merging common with dimension-specific flags.

        Args:
            common_flags: dict - common flags for all dimensions
            dimension_flags: dict - dimension-specific flags
            dimension_value: str - the current dimension value (e.g., 'gcc', 'ld64', 'darwin')

        Returns:
            dict - resolved flags
        """
        if dimension_value not in dimension_flags:
            # No dimension-specific config, process common flags for _REMOVE/_EXTRA/_OVERRIDE
            return ConfigResolver._process_common_operations(common_flags or {})

        resolved = {}
        specific_config = dimension_flags[dimension_value]

        # Handle inheritance
        if '_inherit' in specific_config:
            parent = specific_config['_inherit']
            if parent in dimension_flags:
                resolved = ConfigResolver.resolve_flags(
                    common_flags, dimension_flags, parent
                )

        # Start with common flags
        if not resolved:
            for key, value in (common_flags or {}).items():
                resolved[key] = list(value) if isinstance(value, list) else value

        # Process dimension-specific flags
        for key, value in specific_config.items():
            if key.startswith('_'):
                # Skip metadata keys
                continue

            # Determine operation type
            if key.endswith('_OVERRIDE'):
                # Complete override
                base_key = key.replace('_OVERRIDE', '')
                resolved[base_key] = list(value) if isinstance(value, list) else value
            elif key.endswith('_EXTRA'):
                # Add to existing
                base_key = key.replace('_EXTRA', '')
                if base_key not in resolved:
                    resolved[base_key] = []
                if isinstance(value, list):
                    resolved[base_key].extend(value)
                else:
                    resolved[base_key].append(value)
            elif key.endswith('_REMOVE'):
                # Remove from existing
                base_key = key.replace('_REMOVE', '')
                if base_key in resolved:
                    remove_items = value if isinstance(value, list) else [value]
                    resolved[base_key] = [
                        item for item in resolved[base_key]
                        if item not in remove_items
                    ]
            else:
                # Direct assignment (default behavior)
                resolved[key] = list(value) if isinstance(value, list) else value

        return resolved

    @staticmethod
    def _process_common_operations(common_flags):
        """
        Process _EXTRA/_REMOVE/_OVERRIDE operations within common flags.

        This handles cases where common flags contain operations but there's no
        dimension-specific config to apply them against.

        Args:
            common_flags: dict - common flags that may contain operation suffixes

        Returns:
            dict - resolved flags with operations applied
        """
        if not common_flags:
            return {}

        resolved = {}

        # First pass: collect base flags (non-operation keys)
        for key, value in common_flags.items():
            if not (key.endswith('_EXTRA') or key.endswith('_REMOVE') or key.endswith('_OVERRIDE')):
                resolved[key] = list(value) if isinstance(value, list) else value

        # Second pass: apply operations
        for key, value in common_flags.items():
            if key.endswith('_OVERRIDE'):
                # Complete override
                base_key = key.replace('_OVERRIDE', '')
                resolved[base_key] = list(value) if isinstance(value, list) else value
            elif key.endswith('_EXTRA'):
                # Add to existing
                base_key = key.replace('_EXTRA', '')
                if base_key not in resolved:
                    resolved[base_key] = []
                if isinstance(value, list):
                    resolved[base_key].extend(value)
                else:
                    resolved[base_key].append(value)
            elif key.endswith('_REMOVE'):
                # Remove from existing (or mark for later removal if base_key doesn't exist)
                base_key = key.replace('_REMOVE', '')
                if base_key in resolved:
                    remove_items = value if isinstance(value, list) else [value]
                    resolved[base_key] = [
                        item for item in resolved[base_key]
                        if item not in remove_items
                    ]
                else:
                    # Mark for deletion even if base_key doesn't exist yet
                    # This allows removal during union_options phase
                    resolved[key] = value

        return resolved


class CompleteOptionParser:
    """ Parses all compilation options. """
    # Sequence in which compilation options are added, including all compilation option types.
    option_order = [
        "CC_DEBUG_FLAGS",
        "CC_OPT_LEVEL",  # Optimization Level
        "CC_OVERALL_FLAGS",  # Overall Options
        "CC_WARN_FLAGS",  # Warning options
        "CC_LANGUAGE_FLAGS",  # Language Options
        "CC_CDG_FLAGS",  # Code Generation Options
        "CC_MD_DEPENDENT_FLAGS",  # Machine-Dependent Options
        "CC_OPT_FLAGS",  # Optimization Options
        "CC_SEC_FLAGS",  # Secure compilation options
        "CC_DEFINE_FLAGS",  # Custom Macro
        "CC_USER_DEFINE_FLAGS", # User-defined compilation options are reserved.
    ]

    def __init__(self, file_path):
        self._fp = file_path
        with open(file_path, 'r') as f:
            self._cfg = json.loads(f.read())
            self._file_check()

        self._option_type_map = {}
        for option_type in self._cfg['compileFlag']:
            for option in trans2list(self._cfg['compileFlag'][option_type]):
                self._option_type_map[option] = option_type

    @property
    def option_type_map(self):
        return self._option_type_map

    @property
    def type_options_map(self):
        return self._cfg['compileFlag']

    def _file_check(self):
        if 'compileFlag' not in self._cfg or 'linkFlag' not in self._cfg:
            raise FileNotFoundError("The format of file %s is incorrect." % self._fp)
        for option_type in self._cfg['compileFlag']:
            if option_type not in self.option_order:
                raise FileNotFoundError("The format of file %s is incorrect." % self._fp)

class CompileConfigParser:
    """ Parse the user compilation configuration file with 'common' nested format support.

    Uses ConfigResolver to handle dimensional configuration (compiler × linker × platform).
    Supports mixed format (nested 'common' + flat user-added sections) in self._cfg.
    Keeps original nested format in self._cfg for saving, resolves to flat format for usage.
    """

    def __init__(self, all_options: CompleteOptionParser, file_path='',
                 compiler=None, linker=None, platform=None):
        with open(file_path, 'r') as f:
            self._cfg = json.loads(f.read())
        self._all_options = all_options

        # Detect dimensions for resolving nested format
        self._compiler = compiler or CompilerDetector.detect_compiler_type()
        self._linker = linker or LinkerDetector.detect_linker_type()
        self._platform = platform or PlatformDetector.get_current_platform()

        # Resolve nested format to flat format (stored separately)
        self._resolved_compile_flags = self._resolve_compile_flags()
        self._resolved_link_flags = self._resolve_link_flags()

    def _resolve_compile_flags(self):
        """Resolve compileFlag from nested to flat format (without modifying self._cfg)."""
        if 'compileFlag' not in self._cfg:
            return {}

        compile_cfg = self._cfg['compileFlag']

        # Check if using nested format
        if 'common' not in compile_cfg:
            # Already flat format, return as-is
            return dict(compile_cfg)

        common_flags = compile_cfg.get('common', {})

        # Extract compiler-specific configs and flat sections
        compiler_configs = {}
        flat_sections = {}

        for k, v in compile_cfg.items():
            if k.startswith('_') or k == 'common':
                continue
            # Check if this is a compiler dimension (contains nested _EXTRA/_REMOVE/_OVERRIDE keys)
            # or a flat section (contains CC_FLAGS_ADD/CC_FLAGS_DEL)
            if isinstance(v, dict) and any(key in v for key in ['CC_FLAGS_ADD', 'CC_FLAGS_DEL']):
                # Flat section (user-added flags)
                flat_sections[k] = v
            else:
                # Compiler-specific config
                compiler_configs[k] = v

        # Resolve nested format using ConfigResolver
        resolved = ConfigResolver.resolve_flags(
            common_flags, compiler_configs, self._compiler
        )

        # Convert resolved nested format to flat format
        # All entries are converted to {'CC_FLAGS_ADD': [...]} or {'CC_FLAGS_DEL': [...]} format
        flattened = {}
        for key, value in resolved.items():
            if key.endswith('_EXTRA') or key.endswith('_OVERRIDE'):
                base_key = key.replace('_EXTRA', '').replace('_OVERRIDE', '')
                if base_key not in flattened:
                    flattened[base_key] = {'CC_FLAGS_ADD': []}
                # Extend existing CC_FLAGS_ADD list
                flags_to_add = value if isinstance(value, list) else [value]
                flattened[base_key]['CC_FLAGS_ADD'].extend(flags_to_add)
            elif key.endswith('_REMOVE'):
                # Handle _REMOVE suffix: convert to CC_FLAGS_DEL
                base_key = key.replace('_REMOVE', '')
                if base_key not in flattened:
                    flattened[base_key] = {}
                if 'CC_FLAGS_DEL' not in flattened[base_key]:
                    flattened[base_key]['CC_FLAGS_DEL'] = []
                flags_to_del = value if isinstance(value, list) else [value]
                flattened[base_key]['CC_FLAGS_DEL'].extend(flags_to_del)
            else:
                # Convert direct assignments to CC_FLAGS_ADD format
                if key not in flattened:
                    flattened[key] = {'CC_FLAGS_ADD': []}
                flags_to_add = value if isinstance(value, list) else [value]
                flattened[key]['CC_FLAGS_ADD'].extend(flags_to_add)

        # Merge flat sections (user-added flags) into the result
        for section_name, section_content in flat_sections.items():
            if section_name not in flattened:
                flattened[section_name] = {}
            for op_type, flags in section_content.items():
                if op_type not in flattened[section_name]:
                    flattened[section_name][op_type] = []
                flattened[section_name][op_type].extend(flags)

        return flattened

    def _resolve_link_flags(self):
        """Resolve linkFlag from nested to flat format (without modifying self._cfg)."""
        if 'linkFlag' not in self._cfg:
            return {'PUBLIC': [], 'SHARED': [], 'EXE': []}

        link_cfg = self._cfg['linkFlag']

        # Check if using nested format
        if 'common' not in link_cfg:
            # Already flat format, ensure all categories exist
            result = {'PUBLIC': [], 'SHARED': [], 'EXE': []}
            for key in ['PUBLIC', 'SHARED', 'EXE']:
                if key in link_cfg:
                    result[key] = list(link_cfg[key])
            return result

        common_flags = link_cfg.get('common', {})

        # Extract linker-specific configs and flat sections
        linker_configs = {}
        flat_categories = {}

        for k, v in link_cfg.items():
            if k.startswith('_') or k == 'common':
                continue
            # Check if this is a flat category (PUBLIC, SHARED, EXE)
            if k in ['PUBLIC', 'SHARED', 'EXE'] and isinstance(v, list):
                # Flat category (user-added flags)
                flat_categories[k] = v
            else:
                # Linker-specific config
                linker_configs[k] = v

        # Resolve nested format using ConfigResolver
        resolved = ConfigResolver.resolve_flags(
            common_flags, linker_configs, self._linker
        )

        # Convert to flat format (PUBLIC, SHARED, EXE)
        result = {'PUBLIC': [], 'SHARED': [], 'EXE': []}
        for key, value in resolved.items():
            # Handle _EXTRA suffix: PUBLIC_EXTRA → PUBLIC, etc.
            if key.endswith('_EXTRA') or key.endswith('_OVERRIDE'):
                base_key = key.replace('_EXTRA', '').replace('_OVERRIDE', '')
                result[base_key] = value if isinstance(value, list) else [value]
            else:
                # Direct mapping for PUBLIC, SHARED, EXE
                if key in result:
                    result[key] = value if isinstance(value, list) else [value]

        # Merge flat categories (user-added flags) into the result
        for category, flags in flat_categories.items():
            result[category].extend(flags)

        return result

    @property
    def options(self):
        return self._resolved_compile_flags

    @property
    def link_flags(self):
        return self._resolved_link_flags

    @classmethod
    def default_cfg(cls):
        config = {
            'compileFlag': {},
            'linkFlag': {}
        }
        return config

    def save(self, path):
        save_json_file(self._cfg, path)

    def change_options(self, options, is_add):
        """Add or remove compilation options.

        Modifies both self._cfg (for saving) and self._resolved_compile_flags (for usage).
        """
        option_op = 'CC_FLAGS_ADD' if is_add else 'CC_FLAGS_DEL'
        for option in options:
            option_type = 'CC_USER_DEFINE_FLAGS'
            if option in self._all_options.option_type_map:
                option_type = self._all_options.option_type_map[option]

            # Update original config (flat format alongside nested)
            if option_type not in self._cfg['compileFlag']:
                self._cfg['compileFlag'][option_type] = {}

            flags = self._cfg['compileFlag'][option_type]
            flags[option_op] = list(dict.fromkeys(flags.get(option_op, []) + [option]))

            # Update resolved flags (flat format for usage)
            if option_type not in self._resolved_compile_flags:
                self._resolved_compile_flags[option_type] = {}
            if option_op not in self._resolved_compile_flags[option_type]:
                self._resolved_compile_flags[option_type][option_op] = []
            self._resolved_compile_flags[option_type][option_op] = flags[option_op].copy()

    def change_link_flags(self, flags, is_add):
        """Add or remove link flags from all three categories (PUBLIC, SHARED, EXE).

        Modifies both self._cfg (for saving) and self._resolved_link_flags (for usage).
        User-added link flags are stored in flat format alongside nested common.
        """
        # Ensure linkFlag structure exists in original config
        if 'linkFlag' not in self._cfg:
            self._cfg['linkFlag'] = {}

        # Ensure all three categories exist in original config
        for category in ['PUBLIC', 'SHARED', 'EXE']:
            if category not in self._cfg['linkFlag']:
                self._cfg['linkFlag'][category] = []

        # Add or remove flags from all categories in both configs
        for category in ['PUBLIC', 'SHARED', 'EXE']:
            if is_add:
                # Add flags (dedup)
                for flag in flags:
                    # Update original config
                    if flag not in self._cfg['linkFlag'][category]:
                        self._cfg['linkFlag'][category].append(flag)
                    # Update resolved flags
                    if flag not in self._resolved_link_flags[category]:
                        self._resolved_link_flags[category].append(flag)
            else:
                # Remove flags
                for flag in flags:
                    # Update original config
                    if flag in self._cfg['linkFlag'][category]:
                        self._cfg['linkFlag'][category].remove(flag)
                    # Update resolved flags
                    if flag in self._resolved_link_flags[category]:
                        self._resolved_link_flags[category].remove(flag)

    def add_debug_options(self):
        flags_add = {'CC_FLAGS_ADD': ['-g3', '-gdwarf-2']}
        flags_del = {'CC_FLAGS_DEL': ['-O2', '-D_FORTIFY_SOURCE=2']}

        self._cfg['compileFlag']['CC_DEBUG_FLAGS'] = flags_add
        self._cfg['compileFlag']['CC_OPT_LEVEL'] = flags_del

    def filter_hitls_defines(self):
        for flag in list(self.link_flags.keys()):
            del self.link_flags[flag]

        for flag in list(self.options.keys()):
            if flag != 'CC_USER_DEFINE_FLAGS' and flag != 'CC_DEFINE_FLAGS':
                del self.options[flag]

class CompileParser:
    """
    Parse the compile.json file with dimensional format.
    json key and value:
        compileFlag: compilation options (indexed by compiler)
        linkFlag: link option (indexed by linker)
        systemDefines: OS-specific defines (indexed by OS)
    """

    def __init__(self, all_options: CompleteOptionParser, file_path,
                 compiler=None, linker=None, platform=None):
        self._fp = file_path
        self._all_options = all_options
        with open(file_path, 'r') as f:
            self._cfg = json.loads(f.read())

        # Detect or use provided dimensions
        self._compiler = compiler or CompilerDetector.detect_compiler_type()
        self._linker = linker or LinkerDetector.detect_linker_type()
        self._platform = platform or PlatformDetector.get_current_platform()

        # Resolve dimensional configurations
        self._resolved_compile_flags = self._resolve_compile_flags()
        self._resolved_link_flags = self._resolve_link_flags()
        self._resolved_system_defines = self._resolve_system_defines()

        self._file_check()

    @property
    def compiler(self):
        return self._compiler

    @property
    def linker(self):
        return self._linker

    @property
    def platform(self):
        return self._platform

    @property
    def options(self):
        """Returns resolved compile flags."""
        return self._resolved_compile_flags

    @property
    def link_flags(self):
        """Returns resolved link flags."""
        return self._resolved_link_flags

    def _resolve_compile_flags(self):
        """Resolve compileFlag based on compiler dimension."""
        if 'compileFlag' not in self._cfg:
            return {}

        compile_cfg = self._cfg['compileFlag']
        common_flags = compile_cfg.get('common', {})

        # Extract all compiler-specific configs (exclude metadata and common)
        compiler_configs = {
            k: v for k, v in compile_cfg.items()
            if not k.startswith('_') and k != 'common'
        }

        resolved = ConfigResolver.resolve_flags(
            common_flags, compiler_configs, self._compiler
        )

        # Merge with system defines if present
        if 'systemDefines' in self._cfg:
            system_defines = self._resolve_system_defines()
            for key, value in system_defines.items():
                if key in resolved:
                    if isinstance(resolved[key], list) and isinstance(value, list):
                        resolved[key].extend(value)
                    else:
                        resolved[key] = value
                else:
                    resolved[key] = value

        return resolved

    def _resolve_link_flags(self):
        """Resolve linkFlag based on linker dimension."""
        if 'linkFlag' not in self._cfg:
            return {}

        link_cfg = self._cfg['linkFlag']
        common_flags = link_cfg.get('common', {})

        # Extract all linker-specific configs
        linker_configs = {
            k: v for k, v in link_cfg.items()
            if not k.startswith('_') and k != 'common'
        }

        return ConfigResolver.resolve_flags(
            common_flags, linker_configs, self._linker
        )

    def _resolve_system_defines(self):
        """Resolve systemDefines based on OS dimension."""
        if 'systemDefines' not in self._cfg:
            return {}

        system_cfg = self._cfg['systemDefines']
        common_defines = system_cfg.get('common', {})

        # Extract all OS-specific configs
        os_configs = {
            k: v for k, v in system_cfg.items()
            if not k.startswith('_') and k != 'common'
        }

        return ConfigResolver.resolve_flags(
            common_defines, os_configs, self._platform
        )

    def _file_check(self):
        """Validate configuration file format."""
        if 'compileFlag' not in self._cfg:
            raise FileNotFoundError("Error compile file: missing 'compileFlag'")
        if 'linkFlag' not in self._cfg:
            raise FileNotFoundError("Error compile file: missing 'linkFlag'")


    def union_options(self, custom_cfg: CompileConfigParser):
        options = []
        for option_type in CompleteOptionParser.option_order:
            options.extend(self.options.get(option_type, []))
            if option_type not in custom_cfg.options:
                continue
            for option in custom_cfg.options[option_type].get('CC_FLAGS_ADD', []):
                if option not in options:
                    options.append(option)
            for option in custom_cfg.options[option_type].get('CC_FLAGS_DEL', []):
                if option in options:
                    options.remove(option)

        flags = self.link_flags
        # Merge custom link flags with all three categories
        for category in ['PUBLIC', 'SHARED', 'EXE']:
            # Add flags from custom config (if category exists)
            custom_flags = custom_cfg.link_flags.get(category, [])
            for flag in custom_flags:
                if flag not in flags[category]:
                    flags[category].append(flag)

        # Deduplicate all flag lists to handle duplicates from any source
        # Preserve order (keep first occurrence)
        flags['PUBLIC'] = list(dict.fromkeys(flags['PUBLIC']))
        flags['EXE'] = list(dict.fromkeys(flags['EXE']))
        flags['SHARED'] = list(dict.fromkeys(flags['SHARED']))

        return options, flags
