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

#include <stddef.h>
#include <string.h>
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_eal_mac.h"
#include "benchmark.h"

static int32_t MacSetUp(void **ctx, BenchCtx *bench, const CtxOps *ops, int32_t paraId)
{
    (void)ctx;
    (void)bench;
    (void)ops;
    (void)paraId;
    return CRYPT_SUCCESS;
}

static void MacTearDown(void *ctx)
{
    (void)ctx;
}

static int32_t DoMacCtrl(CRYPT_EAL_MacCtx *mac, int32_t paraId)
{
    if (paraId == CRYPT_MAC_CBC_MAC_SM4) {
        // cbc-mac-sm4 only support zeros padding
        int32_t padType = CRYPT_PADDING_ZEROS;
        return CRYPT_EAL_MacCtrl(mac, CRYPT_CTRL_SET_CBC_MAC_PADDING, &padType, sizeof(padType));
    }
    return CRYPT_SUCCESS;
}

static int32_t DoMac(void *ctx, BenchCtx *bench, BenchOptions *opts, uint32_t keyLen, uint32_t digestLen)
{
    (void)ctx;
    (void)bench;

    int32_t rc = CRYPT_SUCCESS;
    int32_t paraId = opts->paraId;
    uint8_t digest[256];
    CRYPT_EAL_MacCtx *mac = CRYPT_EAL_MacNewCtx(paraId);
    if (mac == NULL) {
        return CRYPT_ERR_ALGID;
    }

    if ((rc = CRYPT_EAL_MacInit(mac, g_key, keyLen)) != CRYPT_SUCCESS ||
        (rc = DoMacCtrl(mac, paraId)) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_MacUpdate(mac, g_plain, opts->len)) != CRYPT_SUCCESS ||
        (rc = CRYPT_EAL_MacFinal(mac, digest, &digestLen)) != CRYPT_SUCCESS) {
        printf("do mac init failed\n");
        goto ERR;
    }

ERR:
    CRYPT_EAL_MacFreeCtx(mac);
    return rc;
}

static int32_t MacOneShot(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    int rc;
    int32_t paraId = opts->paraId;
    const char *macName = GetAlgName(paraId);
    uint32_t keyLen = 16;
    uint32_t digestLen = 256;
    if (paraId == CRYPT_MAC_CMAC_AES192 || paraId == CRYPT_MAC_GMAC_AES192) {
        keyLen = 24;
    }
    if (paraId == CRYPT_MAC_CMAC_AES256 || paraId == CRYPT_MAC_GMAC_AES256) {
        keyLen = 32;
    }
    if (paraId == CRYPT_MAC_GMAC_AES128 || paraId == CRYPT_MAC_GMAC_AES192 || paraId == CRYPT_MAC_GMAC_AES256) {
        digestLen = 16;
    }
    BENCH_TIMES_VA(DoMac(ctx, bench, opts, keyLen, digestLen), rc, CRYPT_SUCCESS, opts->len, opts->times, "%s mac",
                   macName);
    return rc;
}

static int32_t g_paraIds[] = {
    CRYPT_MAC_HMAC_MD5,      CRYPT_MAC_HMAC_SHA1,     CRYPT_MAC_HMAC_SHA224,   CRYPT_MAC_HMAC_SHA256,
    CRYPT_MAC_HMAC_SHA384,   CRYPT_MAC_HMAC_SHA512,   CRYPT_MAC_HMAC_SHA3_224, CRYPT_MAC_HMAC_SHA3_256,
    CRYPT_MAC_HMAC_SHA3_384, CRYPT_MAC_HMAC_SHA3_512, CRYPT_MAC_HMAC_SM3,      CRYPT_MAC_CMAC_AES128,
    CRYPT_MAC_CMAC_AES192,   CRYPT_MAC_CMAC_AES256,   CRYPT_MAC_CMAC_SM4,      CRYPT_MAC_CBC_MAC_SM4,
    CRYPT_MAC_GMAC_AES128,   CRYPT_MAC_GMAC_AES192,   CRYPT_MAC_GMAC_AES256,   CRYPT_MAC_SIPHASH64,
    CRYPT_MAC_SIPHASH128,
};

DEFINE_OPS_MD(Mac);
DEFINE_BENCH_CTX_PARA(Mac, g_paraIds, SIZEOF(g_paraIds));
