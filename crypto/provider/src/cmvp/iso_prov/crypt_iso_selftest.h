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

/**
 * @defgroup crypt_eal_provider
 * @ingroup crypt
 * @brief iso19790 provider header
 */

#ifndef CRYPT_EAL_ISO_SELFTEST_H
#define CRYPT_EAL_ISO_SELFTEST_H

#ifdef HITLS_CRYPTO_CMVP_ISO19790

#include <stdint.h>
#include "crypt_iso_provider.h"
#include "crypt_eal_provider.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int32_t CRYPT_Iso_Selftest(BSL_Param *param);

int32_t CRYPT_Iso_Log(void *provCtx, CRYPT_EVENT_TYPE event, CRYPT_ALGO_TYPE type, int32_t id);

int32_t CRYPT_Iso_EventOperation(void *provCtx, BSL_Param *param);

int32_t CRYPT_Iso_GetLogFunc(BSL_Param *param, CRYPT_EAL_CMVP_LogFunc *logFunc);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */
#endif /* CRYPT_EAL_ISO_SELFTEST_H */