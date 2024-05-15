#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------------------------
#  This file is part of the openHiTLS project.
#  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
#  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
#  for license information.
# ---------------------------------------------------------------------------------------------
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

# list unique
def unique_list(x):
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
