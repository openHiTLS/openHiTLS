/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef BSL_PARAMS_INTERNAL_H
#define BSL_PARAMS_INTERNAL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_PARAMS

#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

struct BslParam {
    int32_t key;
    int32_t valueType;
    void *value;
    int32_t valueLen;
    int32_t useLen;
};


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_BSL_PARAMS */

#endif // BSL_PARAMS_INTERNAL_