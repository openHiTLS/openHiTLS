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
#include "crypt_eal_md.h"
#include "benchmark.h"

static int32_t MdSetUp(void **ctx, BenchCtx *bench, const CtxOps *ops, int32_t paraId)
{
    (void)ctx;
    (void)bench;
    (void)ops;
    (void)paraId;
    return CRYPT_SUCCESS;
}

static void MdTearDown(void *ctx)
{
    (void)ctx;
}

static int32_t MdOneShot(void *ctx, BenchCtx *bench, BenchOptions *opts)
{
    (void)ctx;
    int rc;
    int32_t paraId = opts->paraId;
    const char *mdName = GetAlgName(paraId);
    uint8_t digest[64]; // Maximum digest size for supported algorithms
    uint32_t digestLen = sizeof(digest);

    BENCH_TIMES_VA(CRYPT_EAL_Md(paraId, g_plain, opts->len, digest, &digestLen), rc, CRYPT_SUCCESS, opts->len,
                   opts->times, "%s digest", mdName);
    return rc;
}

static int32_t g_paraIds[] = {
    CRYPT_MD_MD5,      CRYPT_MD_SHA1,     CRYPT_MD_SHA224,   CRYPT_MD_SHA256,   CRYPT_MD_SHA384,
    CRYPT_MD_SHA512,   CRYPT_MD_SHA3_224, CRYPT_MD_SHA3_256, CRYPT_MD_SHA3_384, CRYPT_MD_SHA3_512,
    CRYPT_MD_SHAKE128, CRYPT_MD_SHAKE256, CRYPT_MD_SM3,
};

DEFINE_OPS_MD(Md);
DEFINE_BENCH_CTX_PARA(Md, g_paraIds, SIZEOF(g_paraIds));
