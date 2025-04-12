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

#ifndef ES_NOISE_SOURCE_H
#define ES_NOISE_SOURCE_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_ENTROPY) && defined(HITLS_CRYPTO_ENTROPY_SYS)

#include <stdint.h>
#include "bsl_list.h"
#include "es_health_test.h"
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* Whether to enable the health test */
    bool enableTest;
    /* Whether the noise source automatically performs the health test */
    bool autoTest;
    /* Whether the noise source is available */
    bool isEnable;
    /* Whether the noise source is initialized */
    bool isInit;
    /* Noise source name, which must be unique. */
    char *name;
    /* Initialization parameters of the noise source */
    void *para;
    /* Noise Source Handle */
    void *usrdata;
    /* Noise Source Initialization Interface. */
    void *(*init)(void *para);
    /* Interface for Obtaining Noise Sources. */
    int32_t (*read)(void *usrdata, uint32_t timeout, uint8_t *buf, uint32_t bufLen);
    /* Noise Source Deinitialization Interface. */
    void (*deinit)(void *usrdata);
    /* minimum entropy, bit entropy contained in a byte. */
    uint32_t minEntropy;
    ES_HealthTest state;
} ES_NoiseSource;

/* Noise Source List create. */
BslList *ES_NsListCreat(void);

/* Noise Source List Initialization. */
int32_t ES_NsListInit(BslList *nsList, bool enableTest);

/* Noise Source List deinitialization. */
void ES_NsListDeinit(BslList *nsList);

/* Noise Source List release. */
void ES_NsListFree(BslList *nsList);

/**
 * @brief add ns
 *
 * @param nsList [IN] noise source list
 * @param name [IN] Noise source name, which must be unique.
 * @param autoTest [IN] Whether the noise source automatically performs the health test.
 * @param minEntropy [IN] minimum entropy, bit entropy contained in a byte.
 * @param method [IN] noise source callback Interface.
 * @param para [IN] noise source health test parameter.
 *
 * @return CRYPT_SUCCESS succeeded.
 * For other error codes, see crypt_error.h.
 */
int32_t ES_NsAdd(BslList *nsList, const char *name, bool autoTest, uint32_t minEntropy,
    const CRYPT_EAL_NsMethod *method, const CRYPT_EAL_NsTestPara *para);

/**
 * @brief remove ns
 *
 * @param nsList [IN] noise source list
 * @param name [IN] Noise source name, which must be unique.
 *
 * @return CRYPT_SUCCESS succeeded.
 * For other error codes, see crypt_error.h.
 */
int32_t ES_NsRemove(BslList *nsList, const char *name);

/**
 * @brief Read the raw noise data.
 *
 * @param ns [IN] noise source handle
 * @param buf [IN] the raw noise data buffer.
 * @param bufLen [IN] the length of the raw noise data.
 *
 * @return CRYPT_SUCCESS succeeded.
 * For other error codes, see crypt_error.h.
 */
int32_t ES_NsRead(ES_NoiseSource *ns, uint8_t *buf, uint32_t bufLen);

/**
 * @brief Obtains the minimum value of the minimum entropy.
 *
 * @param nsList [IN] noise source list
 *
 * @return CRYPT_SUCCESS succeeded.
 * For other error codes, see crypt_error.h.
 */
uint32_t ES_NsListGetMinEntropy(BslList *nsList);

/* Obtains the handle of the cpu-jiiter. */
ES_NoiseSource *ES_CpuJitterGetCtx(void);

/* Obtains the handle of the timestamp. */
ES_NoiseSource *ES_TimeStampGetCtx(void);
#ifdef __cplusplus
}
#endif

#endif

#endif