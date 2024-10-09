/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef EAL_COMMON_H
#define EAL_COMMON_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL)

#include <stdint.h>
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define EAL_ERR_REPORT(oper, type, id, err) \
    do { \
        EAL_EventReport((oper), (type), (id), (err)); \
        BSL_ERR_PUSH_ERROR((err)); \
    } while (0)

void EAL_EventReport(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_EAL

#endif // EAL_COMMON_H
