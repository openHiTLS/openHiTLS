/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef BSL_PEM_LOCAL_H
#define BSL_PEM_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_BSL_PEM
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BSL_PEM_BEGIN_STR "-----BEGIN"
#define BSL_PEM_BEGIN_STR_LEN 10
#define BSL_PEM_END_STR "-----END"
#define BSL_PEM_END_STR_LEN 8
#define BSL_PEM_SHORT_DASH_STR "-----"
#define BSL_PEM_SHORT_DASH_STR_LEN 5

#ifdef __cplusplus
}
#endif
#endif /* HITLS_BSL_PEM */
#endif
