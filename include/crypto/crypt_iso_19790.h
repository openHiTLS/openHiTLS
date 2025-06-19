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
 * @defgroup crypt_iso_19790
 * @ingroup crypt
 * @brief ISO 19790 header
 */

#ifndef CRYPT_ISO_19790_H
#define CRYPT_ISO_19790_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define CRYPT_PARAM_RUN_LOG_CB    0x1001

typedef enum {
    CRYPT_CMVP_INTEGRITY_TEST = 0,
    CRYPT_CMVP_KAT_TEST,
    CRYPT_CMVP_MAX
} CRYPT_CMVP_SELFTEST_TYPE;

typedef void (*Iso19790_log_cb)(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err);

typedef struct EAL_SelftestCtx CRYPT_SelftestCtx;

CRYPT_SelftestCtx *CRYPT_CMVP_SelftestNewCtx(CRYPT_EAL_LibCtx *libCtx, const char *attrName);

const char *CRYPT_CMVP_GetVersion(CRYPT_SelftestCtx *ctx);

int32_t CRYPT_CMVP_Selftest(CRYPT_SelftestCtx *ctx, CRYPT_CMVP_SELFTEST_TYPE type);

void CRYPT_CMVP_SelftestFreeCtx(CRYPT_SelftestCtx *ctx);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // CRYPT_ISO_19790_H