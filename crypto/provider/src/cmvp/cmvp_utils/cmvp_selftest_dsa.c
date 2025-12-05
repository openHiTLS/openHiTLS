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
 
#include "hitls_build.h"
#if defined(HITLS_CRYPTO_CMVP_ISO19790) || defined(HITLS_CRYPTO_CMVP_FIPS)

#include <string.h>
#include "crypt_cmvp_selftest.h"
#include "cmvp_common.h"
#include "err.h"
#include "crypt_bn.h"
#include "crypt_encode.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_util_rand.h"
#include "bsl_sal.h"

#define BITS_OF_BYTE 8

typedef struct {
    const char *p;
    const char *q;
    const char *g;
    const char *msg;
    const char *x; // The private key.
    const char *y;
    const char *k;
    const char *r;
    const char *s;
    CRYPT_MD_AlgId mdId;
} CMVP_DSA_VECTOR;

// https://www.rfc-editor.org/rfc/rfc6979#page-27
static const CMVP_DSA_VECTOR DSA_VECTOR = {
    .p = "a8adb6c0b4cf9588012e5deff1a871d383e0e2a85b5e8e03d814fe13a059705e"
         "663230a377bf7323a8fa117100200bfd5adf857393b0bbd67906c081e585410e"
         "38480ead51684dac3a38f7b64c9eb109f19739a4517cd7d5d6291e8af20a3fbf"
         "17336c7bf80ee718ee087e322ee41047dabefbcc34d10b66b644ddb3160a28c0"
         "639563d71993a26543eadb7718f317bf5d9577a6156561b082a10029cd44012b"
         "18de6844509fe058ba87980792285f2750969fe89c2cd6498db3545638d5379d"
         "125dccf64e06c1af33a6190841d223da1513333a7c9d78462abaab31b9f96d5f"
         "34445ceb6309f2f6d2c8dde06441e87980d303ef9a1ff007e8be2f0be06cc15f",
    .q = "e71f8567447f42e75f5ef85ca20fe557ab0343d37ed09edc3f6e68604d6b9dfb",
    .g = "5ba24de9607b8998e66ce6c4f812a314c6935842f7ab54cd82b19fa104abfb5d"
         "84579a623b2574b37d22ccae9b3e415e48f5c0f9bcbdff8071d63b9bb956e547"
         "af3a8df99e5d3061979652ff96b765cb3ee493643544c75dbe5bb39834531952"
         "a0fb4b0378b3fcbb4c8b5800a5330392a2a04e700bb6ed7e0b85795ea38b1b96"
         "2741b3f33b9dde2f4ec1354f09e2eb78e95f037a5804b6171659f88715ce1a9b"
         "0cc90c27f35ef2f10ff0c7c7a2bb0154d9b8ebe76a3d764aa879af372f4240de"
         "8347937e5a90cec9f41ff2f26b8da9a94a225d1a913717d73f10397d2183f1ba"
         "3b7b45a68f1ff1893caf69a827802f7b6a48d51da6fbefb64fd9a6c5b75c4561",
    .msg = "4e3a28bcf90d1d2e75f075d9fbe55b36c5529b17bc3a9ccaba6935c9e2054825"
           "5b3dfae0f91db030c12f2c344b3a29c4151c5b209f5e319fdf1c23b190f64f1f"
           "e5b330cb7c8fa952f9d90f13aff1cb11d63181da9efc6f7e15bfed4862d1a62c"
           "7dcf3ba8bf1ff304b102b1ec3f1497dddf09712cf323f5610a9d10c3d9132659",
    .x = "446969025446247f84fdea74d02d7dd13672b2deb7c085be11111441955a377b",
    .y = "5a55dceddd1134ee5f11ed85deb4d634a3643f5f36dc3a70689256469a0b651a"
         "d22880f14ab85719434f9c0e407e60ea420e2a0cd29422c4899c416359dbb1e5"
         "92456f2b3cce233259c117542fd05f31ea25b015d9121c890b90e0bad033be13"
         "68d229985aac7226d1c8c2eab325ef3b2cd59d3b9f7de7dbc94af1a9339eb430"
         "ca36c26c46ecfa6c5481711496f624e188ad7540ef5df26f8efacb820bd17a1f"
         "618acb50c9bc197d4cb7ccac45d824a3bf795c234b556b06aeb9291734532520"
         "84003f69fe98045fe74002ba658f93475622f76791d9b2623d1b5fff2cc16844"
         "746efd2d30a6a8134bfc4c8cc80a46107901fb973c28fc553130f3286c1489da",
    .k = "117a529e3fdfc79843a5a4c07539036b865214e014b4928c2a31f47bf62a4fdb",
    .r = "633055e055f237c38999d81c397848c38cce80a55b649d9e7905c298e2a51447",
    .s = "2bbf68317660ec1e4b154915027b0bc00ee19cfc0bf75d01930504f2ce10a8b0",
    .mdId = CRYPT_MD_SHA256
};

static bool GetPkey(void *libCtx, const char *attrName, CRYPT_EAL_PkeyCtx **pkeyPrv, CRYPT_EAL_PkeyCtx **pkeyPub,
    CRYPT_EAL_PkeyPara *para, CRYPT_EAL_PkeyPub *pub, CRYPT_EAL_PkeyPrv *prv)
{
    *pkeyPrv = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_DSA, 0, attrName);
    GOTO_ERR_IF_TRUE(*pkeyPrv == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    *pkeyPub = CRYPT_EAL_ProviderPkeyNewCtx(libCtx, CRYPT_PKEY_DSA, 0, attrName);
    GOTO_ERR_IF_TRUE(*pkeyPub == NULL, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    para->para.dsaPara.p = CMVP_StringsToBins(DSA_VECTOR.p, &(para->para.dsaPara.pLen));
    GOTO_ERR_IF_TRUE(para->para.dsaPara.p == NULL, CRYPT_CMVP_COMMON_ERR);
    para->para.dsaPara.q = CMVP_StringsToBins(DSA_VECTOR.q, &(para->para.dsaPara.qLen));
    GOTO_ERR_IF_TRUE(para->para.dsaPara.q == NULL, CRYPT_CMVP_COMMON_ERR);
    para->para.dsaPara.g = CMVP_StringsToBins(DSA_VECTOR.g, &(para->para.dsaPara.gLen));
    GOTO_ERR_IF_TRUE(para->para.dsaPara.g == NULL, CRYPT_CMVP_COMMON_ERR);
    prv->key.dsaPrv.data = CMVP_StringsToBins(DSA_VECTOR.x, &(prv->key.dsaPrv.len));
    GOTO_ERR_IF_TRUE(prv->key.dsaPrv.data == NULL, CRYPT_CMVP_COMMON_ERR);
    pub->key.dsaPub.data = CMVP_StringsToBins(DSA_VECTOR.y, &(pub->key.dsaPub.len));
    GOTO_ERR_IF_TRUE(pub->key.dsaPub.data == NULL, CRYPT_CMVP_COMMON_ERR);

    para->id = CRYPT_PKEY_DSA;
    pub->id = CRYPT_PKEY_DSA;
    prv->id = CRYPT_PKEY_DSA;
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPara(*pkeyPrv, para) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPara(*pkeyPub, para) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPrv(*pkeyPrv, prv) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySetPub(*pkeyPub, pub) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    return true;
ERR:
    return false;
}

static int32_t TestVectorRandom(uint8_t *r, uint32_t rLen)
{
    uint8_t *rand = NULL;
    uint32_t randLen;

    rand = CMVP_StringsToBins(DSA_VECTOR.k, &randLen);
    if (rand == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (randLen < rLen) {
        BSL_SAL_Free(rand);
        return CRYPT_CMVP_ERR_ALGO_SELFTEST;
    }

    for (uint32_t i = 0; i < randLen; i++) {
        r[i] = rand[i];
    }
    BSL_SAL_Free(rand);
    return 0;
}

static int32_t SignEncode(const char *signR, const char *signS, uint8_t *vectorSign, uint32_t *vectorSignLen)
{
    int ret = CRYPT_CMVP_ERR_ALGO_SELFTEST;
    BN_BigNum *bnR = NULL;
    BN_BigNum *bnS = NULL;

    uint8_t *r = NULL;
    uint8_t *s = NULL;
    uint32_t rLen, sLen;

    r = CMVP_StringsToBins(signR, &rLen);
    GOTO_ERR_IF_TRUE(r == NULL, CRYPT_CMVP_COMMON_ERR);
    s = CMVP_StringsToBins(signS, &sLen);
    GOTO_ERR_IF_TRUE(s == NULL, CRYPT_CMVP_COMMON_ERR);

    bnR = BN_Create(rLen * BITS_OF_BYTE);
    bnS = BN_Create(sLen * BITS_OF_BYTE);
    GOTO_ERR_IF_TRUE(BN_Bin2Bn(bnR, r, rLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(BN_Bin2Bn(bnS, s, sLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = CRYPT_EAL_EncodeSign(bnR, bnS, vectorSign, vectorSignLen);
    GOTO_ERR_IF_TRUE(ret != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = CRYPT_SUCCESS;
ERR:
    BSL_SAL_Free(r);
    BSL_SAL_Free(s);
    BN_Destroy(bnR);
    BN_Destroy(bnS);
    return ret;
}

static void FreeData(CRYPT_EAL_PkeyPara para, CRYPT_EAL_PkeyPub pub, CRYPT_EAL_PkeyPrv prv, uint8_t *msg, uint8_t *sign)
{
    BSL_SAL_Free(para.para.dsaPara.p);
    BSL_SAL_Free(para.para.dsaPara.q);
    BSL_SAL_Free(para.para.dsaPara.g);
    BSL_SAL_Free(msg);
    BSL_SAL_Free(pub.key.dsaPub.data);
    BSL_SAL_Free(prv.key.dsaPrv.data);
    BSL_SAL_Free(sign);
}

static bool CRYPT_CMVP_SelftestDsaInternal(void *libCtx, const char *attrName)
{
    bool ret = false;
    uint8_t *msg = NULL;
    uint8_t *sign = NULL;
    uint8_t *signVec = NULL;
    uint32_t msgLen, signLen;
    uint32_t signVecLen = 0;
    CRYPT_EAL_PkeyCtx *pkeyPrv = NULL;
    CRYPT_EAL_PkeyCtx *pkeyPub = NULL;
    CRYPT_EAL_PkeyPara para = { 0 };
    CRYPT_EAL_PkeyPub pub = { 0 };
    CRYPT_EAL_PkeyPrv prv = { 0 };
    CRYPT_EAL_RandFunc func = CRYPT_RandRegistGet();
    CRYPT_EAL_RandFuncEx funcEx = CRYPT_RandRegistExGet();
    CRYPT_RandRegistEx(NULL);

    msg = CMVP_StringsToBins(DSA_VECTOR.msg, &msgLen);
    GOTO_ERR_IF_TRUE(msg == NULL, CRYPT_CMVP_COMMON_ERR);
    GOTO_ERR_IF_TRUE(!GetPkey(libCtx, attrName, &pkeyPrv, &pkeyPub, &para, &pub, &prv), CRYPT_CMVP_ERR_ALGO_SELFTEST);
    signLen = CRYPT_EAL_PkeyGetSignLen(pkeyPrv);
    sign = BSL_SAL_Malloc(signLen);
    signVecLen = signLen;
    GOTO_ERR_IF_TRUE(sign == NULL, CRYPT_MEM_ALLOC_FAIL);
    signVec = BSL_SAL_Malloc(signLen);
    GOTO_ERR_IF_TRUE(signVec == NULL, CRYPT_MEM_ALLOC_FAIL);

    // regist rand function
    CRYPT_RandRegist(TestVectorRandom);
    // sign
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeySign(pkeyPrv, DSA_VECTOR.mdId, msg, msgLen, sign, &signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    // compare the signature
    GOTO_ERR_IF_TRUE(SignEncode(DSA_VECTOR.r, DSA_VECTOR.s, signVec, &signVecLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(signLen != signVecLen, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(memcmp(signVec, sign, signLen) != 0, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    // verify
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyVerify(pkeyPub, DSA_VECTOR.mdId, msg, msgLen, sign, signLen) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
ERR:
    FreeData(para, pub, prv, msg, sign);
    BSL_SAL_Free(signVec);
    CRYPT_EAL_PkeyFreeCtx(pkeyPrv);
    CRYPT_EAL_PkeyFreeCtx(pkeyPub);
    CRYPT_RandRegist(func);
    CRYPT_RandRegistEx(funcEx);
    return ret;
}

bool CRYPT_CMVP_SelftestDsa(void)
{
    return CRYPT_CMVP_SelftestDsaInternal(NULL, NULL);
}

bool CRYPT_CMVP_SelftestProviderDsa(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestDsaInternal(libCtx, attrName);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 || HITLS_CRYPTO_CMVP_FIPS */
