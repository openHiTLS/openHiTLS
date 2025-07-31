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
import shutil
import sys
sys.dont_write_bytecode = True
import os
import json

# Convert x to list
def trans2list(x):
    if x == None: return []
    if type(x) == list: return x
    if type(x) == set: return x
    if type(x) == str: return [x]

    raise ValueError('Unsupported type: "%s"' % type(x))

def unique_list(x):
    """ Deduplicate the list. """
    return list(dict.fromkeys(x))

def copy_file(src_file, dest_file, isCoverd=True):
    if not os.path.exists(src_file):
        raise FileNotFoundError('Src file not found: ' + src_file)

    if os.path.exists(dest_file):
        if isCoverd:
            shutil.copy2(src_file, dest_file)
    else:
        shutil.copy2(src_file, dest_file)

def save_json_file(content, path):
    with open(path, 'w') as f:
        f.write(json.dumps(content, indent=4))
