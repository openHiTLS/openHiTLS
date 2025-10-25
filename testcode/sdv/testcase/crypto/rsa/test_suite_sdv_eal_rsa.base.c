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

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#include "crypt_bn.h"
#include "bsl_sal.h"
#include "crypt_algid.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "stub_utils.h"
#include "crypt_eal_rand.h"
#include "crypt_util_rand.h"
#include "eal_pkey_local.h"
#include "crypt_rsa.h"
#include "rsa_local.h"
#include "bn_basic.h"
#include "securec.h"

/* ============================================================================
 * Stub Definitions
 * ============================================================================ */
STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);
STUB_DEFINE_RET4(int32_t, BN_Gcd, BN_BigNum *, const BN_BigNum *, const BN_BigNum *, BN_Optimizer *);

#define SUCCESS 0
#define FAIL (-1)


#define RSA_MAX_KEYLEN 2048
#define RSA_MIN_KEYLEN 128

#define MAX_PARAM_LEN 2048
#define MAX_CIPHERTEXT_LEN 2048

#define PUB_EXP 3
#define KEYLEN_IN_BYTES(keyLen) ((keyLen) >> 3)

int32_t RandFunc(uint8_t *randNum, uint32_t randLen)
{
    const int maxNum = 255;
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % maxNum);
    }
    return 0;
}

int32_t RandFuncEx(void *libCtx, uint8_t *randNum, uint32_t randLen)
{
    (void)libCtx;
    const int maxNum = 255;
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)(rand() % maxNum);
    }
    return 0;
}

void *malloc_fail(uint32_t size)
{
    (void)size;
    return NULL;
}

void PubkeyFree(CRYPT_EAL_PkeyPub *pubkey)
{
    if (pubkey == NULL) {
        return;
    }
    free(pubkey);
}

void PrvkeyFree(CRYPT_EAL_PkeyPrv *prvkey)
{
    if (prvkey == NULL) {
        return;
    }
    free(prvkey);
}

#define TMP_BUFF_LEN 2048
static uint8_t g_RandBuf[TMP_BUFF_LEN];
int32_t STUB_ReplaceRandom(uint8_t *r, uint32_t randLen)
{
    if (randLen > TMP_BUFF_LEN) {
        return -1;
    }
    for (uint32_t i = 0; i < randLen; i++) {
        r[i] = g_RandBuf[i];
    }
    return 0;
}

int32_t STUB_ReplaceRandomEx(void *libCtx, uint8_t *r, uint32_t randLen)
{
    (void)libCtx;
    if (randLen > TMP_BUFF_LEN) {
        return -1;
    }
    for (uint32_t i = 0; i < randLen; i++) {
        r[i] = g_RandBuf[i];
    }
    return 0;
}

void SetRsaPara(CRYPT_EAL_PkeyPara *para, uint8_t *e, uint32_t eLen, uint32_t bits)
{
    para->id = CRYPT_PKEY_RSA;
    para->para.rsaPara.e = e;
    para->para.rsaPara.eLen = eLen;
    para->para.rsaPara.bits = bits;
}

void SetRsaPubKey(CRYPT_EAL_PkeyPub *pubKey, uint8_t *n, uint32_t nLen, uint8_t *e, uint32_t eLen)
{
    pubKey->id = CRYPT_PKEY_RSA;
    pubKey->key.rsaPub.n = n;
    pubKey->key.rsaPub.nLen = nLen;
    pubKey->key.rsaPub.e = e;
    pubKey->key.rsaPub.eLen = eLen;
}

void SetRsaPrvKey(CRYPT_EAL_PkeyPrv *prvKey, uint8_t *n, uint32_t nLen, uint8_t *d, uint32_t dLen)
{
    prvKey->id = CRYPT_PKEY_RSA;
    prvKey->key.rsaPrv.n = n;
    prvKey->key.rsaPrv.nLen = nLen;
    prvKey->key.rsaPrv.d = d;
    prvKey->key.rsaPrv.dLen = dLen;
}
