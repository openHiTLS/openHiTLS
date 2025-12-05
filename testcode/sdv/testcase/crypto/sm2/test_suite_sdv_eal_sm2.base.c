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

#include "crypt_bn.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "stub_utils.h"
#include "crypt_eal_rand.h"
#include "securec.h"
#include "crypt_util_rand.h"
#include "crypt_encode.h"
#include "crypt_dsa.h"

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET3(int32_t, BN_RandRangeEx, void *, BN_BigNum *, const BN_BigNum *);

#define ERR_BAD_RAND 1
#define RAND_BUF_LEN 2048
#define UINT8_MAX_NUM 255

uint8_t g_RandOutput[RAND_BUF_LEN];
uint32_t g_RandBufLen = 0;

int32_t RandFunc(uint8_t *randNum, uint32_t randLen)
{
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % UINT8_MAX_NUM);
    }

    return 0;
}

int32_t RandFuncEx(void *libCtx, uint8_t *randNum, uint32_t randLen)
{
    (void)libCtx;
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % UINT8_MAX_NUM);
    }

    return 0;
}

int32_t RandFuncExSelfCheck(void *libCtx, uint8_t *randNum, uint32_t randLen)
{
    if (libCtx == NULL) {
        return CRYPT_PROVIDER_INVALID_LIB_CTX;
    }
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % UINT8_MAX_NUM);
    }

    return 0;
}

int32_t SetFakeRandOutput(uint8_t *in, uint32_t inLen)
{
    g_RandBufLen = inLen;
    return memcpy_s(g_RandOutput, sizeof(g_RandOutput), in, inLen);
}

int32_t FakeRandFunc(uint8_t *randNum, uint32_t randLen)
{
    if (randLen > RAND_BUF_LEN) {
        return ERR_BAD_RAND;
    }
    return memcpy_s(randNum, randLen, g_RandOutput, randLen);
}

int32_t FakeRandFuncEx(void *libCtx, uint8_t *randNum, uint32_t randLen)
{
    (void)libCtx;
    if (randLen > RAND_BUF_LEN) {
        return ERR_BAD_RAND;
    }
    return memcpy_s(randNum, randLen, g_RandOutput, randLen);
}

int32_t STUB_RandRangeK(void *libCtx, BN_BigNum *r, const BN_BigNum *p)
{
    (void)p;
    (void)libCtx;
    BN_Bin2Bn(r, g_RandOutput, g_RandBufLen);
    return CRYPT_SUCCESS;
}

void SetSm2PubKey(CRYPT_EAL_PkeyPub *pub, uint8_t *key, uint32_t len)
{
    pub->id = CRYPT_PKEY_SM2;
    pub->key.eccPub.data = key;
    pub->key.eccPub.len = len;
}

void SetSm2PrvKey(CRYPT_EAL_PkeyPrv *prv, uint8_t *key, uint32_t len)
{
    prv->id = CRYPT_PKEY_SM2;
    prv->key.eccPrv.data = key;
    prv->key.eccPrv.len = len;
}