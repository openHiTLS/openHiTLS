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

/* BEGIN_HEADER */

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_asn1_internal.h"
#include "bsl_err.h"
#include "bsl_log.h"
#include "bsl_init.h"
#include "sal_file.h"
#include "eal_pkey_local.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_init.h"
#include "crypt_codecskey_local.h"
#include "crypt_codecskey.h"
#include "crypt_util_rand.h"
#include "bsl_obj_internal.h"
#include "crypt_eal_rand.h"
#include "bsl_params.h"
#include "crypt_params_key.h"
#include "stub_utils.h"

/* END_HEADER */

#ifdef HITLS_CRYPTO_PROVIDER
STUB_DEFINE_RET1(void *, BSL_SAL_Malloc, uint32_t);
STUB_DEFINE_RET1(CRYPT_PKEY_AlgId, CRYPT_EAL_PkeyGetId, const CRYPT_EAL_PkeyCtx *);
#endif

// clang-format off
/* They are placed in their respective implementations and belong to specific applications, not asn1 modules */
#define BSL_ASN1_CTX_SPECIFIC_TAG_VER       0
#define BSL_ASN1_CTX_SPECIFIC_TAG_ISSUERID  1
#define BSL_ASN1_CTX_SPECIFIC_TAG_SUBJECTID 2
#define BSL_ASN1_CTX_SPECIFIC_TAG_EXTENSION 3

BSL_ASN1_TemplateItem rsaPrvTempl[] = {
 {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0}, /* seq */
  {BSL_ASN1_TAG_INTEGER, 0, 1}, /* version */
  {BSL_ASN1_TAG_INTEGER, 0, 1}, /* n */
  {BSL_ASN1_TAG_INTEGER, 0, 1}, /* e */
  {BSL_ASN1_TAG_INTEGER, 0, 1}, /* d */
  {BSL_ASN1_TAG_INTEGER, 0, 1}, /* p */
  {BSL_ASN1_TAG_INTEGER, 0, 1}, /* q */
  {BSL_ASN1_TAG_INTEGER, 0, 1}, /* d mod (p-1) */
  {BSL_ASN1_TAG_INTEGER, 0, 1}, /* d mod (q-1) */
  {BSL_ASN1_TAG_INTEGER, 0, 1}, /* q^-1 mod p */
  {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE,
  BSL_ASN1_FLAG_OPTIONAL | BSL_ASN1_FLAG_HEADERONLY | BSL_ASN1_FLAG_SAME, 1}, /* OtherPrimeInfos OPTIONAL */
   {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 2}, /* OtherPrimeInfo */
    {BSL_ASN1_TAG_INTEGER, 0, 3}, /* ri */
    {BSL_ASN1_TAG_INTEGER, 0, 3}, /* di */
    {BSL_ASN1_TAG_INTEGER, 0, 3} /* ti */
};

typedef enum {
    RSA_PRV_VERSION_IDX = 0,
    RSA_PRV_N_IDX = 1,
    RSA_PRV_E_IDX = 2,
    RSA_PRV_D_IDX = 3,
    RSA_PRV_P_IDX = 4,
    RSA_PRV_Q_IDX = 5,
    RSA_PRV_DP_IDX = 6,
    RSA_PRV_DQ_IDX = 7,
    RSA_PRV_QINV_IDX = 8,
    RSA_PRV_OTHER_PRIME_IDX = 9
} RSA_PRV_TEMPL_IDX;
// clang-format on

#define BSL_ASN1_TIME_UTC_1 14
#define BSL_ASN1_TIME_UTC_2 15

#define BSL_ASN1_ID_ANY_1 7
#define BSL_ASN1_ID_ANY_2 24
#define BSL_ASN1_ID_ANY_3 34

int32_t BSL_ASN1_CertTagGetOrCheck(int32_t type, uint32_t idx, void *data, void *expVal)
{
    switch (type) {
        case BSL_ASN1_TYPE_CHECK_CHOICE_TAG: {
            if (idx == BSL_ASN1_TIME_UTC_1 || idx == BSL_ASN1_TIME_UTC_2) {
                uint8_t tag = *(uint8_t *)data;
                if (tag & BSL_ASN1_TAG_UTCTIME || tag & BSL_ASN1_TAG_GENERALIZEDTIME) {
                    *(uint8_t *)expVal = tag;
                    return BSL_SUCCESS;
                }
            }
            return BSL_ASN1_FAIL;
        }
        case BSL_ASN1_TYPE_GET_ANY_TAG: {
            BSL_ASN1_Buffer *param = (BSL_ASN1_Buffer *)data;
            BslOidString oidStr = {param->len, (char *)param->buff, 0};
            BslCid cid = BSL_OBJ_GetCID(&oidStr);
            if (idx == BSL_ASN1_ID_ANY_1 || idx == BSL_ASN1_ID_ANY_3) {
                if (cid == BSL_CID_RSASSAPSS) {
                    // note: any It can be encoded empty or it can be null
                    *(uint8_t *)expVal = BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE;
                    return BSL_SUCCESS;
                } else {
                    *(uint8_t *)expVal = BSL_ASN1_TAG_NULL; // is null
                    return BSL_SUCCESS;
                }
            }
            if (idx == BSL_ASN1_ID_ANY_2) {
                if (cid == BSL_CID_EC_PUBLICKEY) {
                    // note: any It can be encoded empty or it can be null
                    *(uint8_t *)expVal = BSL_ASN1_TAG_OBJECT_ID;
                    return BSL_SUCCESS;
                } else { //
                    *(uint8_t *)expVal = BSL_ASN1_TAG_NULL; // is null
                    return BSL_SUCCESS;
                }
                return BSL_ASN1_FAIL;
            }
        }
        default:
            break;
    }
    return BSL_ASN1_FAIL;
}

int32_t BSL_ASN1_SubKeyInfoTagGetOrCheck(int32_t type, int32_t idx, void *data, void *expVal)
{
    switch (type) {
        case BSL_ASN1_TYPE_CHECK_CHOICE_TAG: {
            if (idx == BSL_ASN1_TIME_UTC_1 || idx == BSL_ASN1_TIME_UTC_2) {
                uint8_t tag = *(uint8_t *)data;
                if (tag & BSL_ASN1_TAG_UTCTIME || tag & BSL_ASN1_TAG_GENERALIZEDTIME) {
                    return BSL_SUCCESS;
                }
            }
            return BSL_ASN1_FAIL;
        }
        case BSL_ASN1_TYPE_GET_ANY_TAG: {
            BSL_ASN1_Buffer *param = (BSL_ASN1_Buffer *)data;
            BslOidString oidStr = {param->len, (char *)param->buff, 0};
            BslCid cid = BSL_OBJ_GetCID(&oidStr);
            if (cid == BSL_CID_EC_PUBLICKEY) {
                // note: any It can be encoded empty or it can be null
                *(uint8_t *)expVal = BSL_ASN1_TAG_OBJECT_ID;
                return BSL_SUCCESS;
            } else { //
                *(uint8_t *)expVal = BSL_ASN1_TAG_NULL; // is null
                return BSL_SUCCESS;
            }
        }
        default:
            break;
    }
    return BSL_ASN1_FAIL;
}

static int32_t ReadCert(const char *path, uint8_t **buff, uint32_t *len)
{
    size_t readLen;
    size_t fileLen = 0;
    int32_t ret = BSL_SAL_FileLength(path, &fileLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    bsl_sal_file_handle stream = NULL;
    ret = BSL_SAL_FileOpen(&stream, path, "rb");
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    uint8_t *fileBuff = BSL_SAL_Malloc(fileLen);
    if (fileBuff == NULL) {
        BSL_SAL_FileClose(stream);
        return BSL_MALLOC_FAIL;
    }
    do {
        ret = BSL_SAL_FileRead(stream, fileBuff, 1, fileLen, &readLen);
        BSL_SAL_FileClose(stream);
        if (ret != BSL_SUCCESS) {
            break;
        }

        *buff = fileBuff;
        *len = (uint32_t)fileLen;
        return ret;
    } while (0);
    BSL_SAL_FREE(fileBuff);
    return ret;
}

static int32_t RandFunc(uint8_t *randNum, uint32_t randLen)
{
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)rand();
    }

    return 0;
}

static int32_t RandFuncEx(void *libCtx, uint8_t *randNum, uint32_t randLen)
{
    (void)libCtx;
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)rand();
    }

    return 0;
}


/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_RSA_PRV_TC001(char *path, Hex *version, Hex *n, Hex *e, Hex *d, Hex *p, Hex *q, Hex *dp,
                                      Hex *dq, Hex *qinv, int mdId, Hex *msg, Hex *sign)
{
    uint32_t fileLen = 0;
    uint8_t *fileBuff = NULL;
    int32_t ret = ReadCert(path, &fileBuff, &fileLen);
    ASSERT_EQ(ret, BSL_SUCCESS);
    uint8_t *rawBuff = fileBuff;
    uint8_t *signdata = NULL;

    BSL_ASN1_Buffer asnArr[RSA_PRV_OTHER_PRIME_IDX + 1] = {0};
    BSL_ASN1_Template templ = {rsaPrvTempl, sizeof(rsaPrvTempl) / sizeof(rsaPrvTempl[0])};
    ret = BSL_ASN1_DecodeTemplate(&templ, BSL_ASN1_CertTagGetOrCheck, &fileBuff, &fileLen, asnArr,
                                  RSA_PRV_OTHER_PRIME_IDX + 1);
    ASSERT_EQ(ret, BSL_SUCCESS);
    ASSERT_EQ(fileLen, 0);
    // version
    if (version->len != 0) {
        ASSERT_EQ_LOG("version compare tag", asnArr[RSA_PRV_VERSION_IDX].tag, BSL_ASN1_TAG_INTEGER);
        ASSERT_COMPARE("version compare", version->x, version->len, asnArr[RSA_PRV_VERSION_IDX].buff,
                       asnArr[RSA_PRV_VERSION_IDX].len);
    }

    // n
    ASSERT_EQ_LOG("n compare tag", asnArr[RSA_PRV_N_IDX].tag, BSL_ASN1_TAG_INTEGER);
    ASSERT_COMPARE("n compare", n->x, n->len, asnArr[RSA_PRV_N_IDX].buff, asnArr[RSA_PRV_N_IDX].len);

    // e
    ASSERT_EQ_LOG("e compare tag", asnArr[RSA_PRV_E_IDX].tag, BSL_ASN1_TAG_INTEGER);
    ASSERT_COMPARE("e compare", e->x, e->len, asnArr[RSA_PRV_E_IDX].buff, asnArr[RSA_PRV_E_IDX].len);

    // d
    ASSERT_EQ_LOG("d compare tag", asnArr[RSA_PRV_D_IDX].tag, BSL_ASN1_TAG_INTEGER);
    ASSERT_COMPARE("d compare", d->x, d->len, asnArr[RSA_PRV_D_IDX].buff, asnArr[RSA_PRV_D_IDX].len);
    // p
    ASSERT_EQ_LOG("p compare tag", asnArr[RSA_PRV_P_IDX].tag, BSL_ASN1_TAG_INTEGER);
    ASSERT_COMPARE("p compare", p->x, p->len, asnArr[RSA_PRV_P_IDX].buff, asnArr[RSA_PRV_P_IDX].len);
    // q
    ASSERT_EQ_LOG("q compare tag", asnArr[RSA_PRV_Q_IDX].tag, BSL_ASN1_TAG_INTEGER);
    ASSERT_COMPARE("q compare", q->x, q->len, asnArr[RSA_PRV_Q_IDX].buff, asnArr[RSA_PRV_Q_IDX].len);
    // d mod (p-1)
    ASSERT_EQ_LOG("dp compare tag", asnArr[RSA_PRV_DP_IDX].tag, BSL_ASN1_TAG_INTEGER);
    ASSERT_COMPARE("dp compare", dp->x, dp->len, asnArr[RSA_PRV_DP_IDX].buff, asnArr[RSA_PRV_DP_IDX].len);
    // d mod (q-1)
    ASSERT_EQ_LOG("dq compare tag", asnArr[RSA_PRV_DQ_IDX].tag, BSL_ASN1_TAG_INTEGER);
    ASSERT_COMPARE("dq compare", dq->x, dq->len, asnArr[RSA_PRV_DQ_IDX].buff, asnArr[RSA_PRV_DQ_IDX].len);
    // qinv
    ASSERT_EQ_LOG("qinv compare tag", asnArr[RSA_PRV_QINV_IDX].tag, BSL_ASN1_TAG_INTEGER);
    ASSERT_COMPARE("qinv compare", qinv->x, qinv->len, asnArr[RSA_PRV_QINV_IDX].buff, asnArr[RSA_PRV_QINV_IDX].len);

    // create
    CRYPT_EAL_PkeyPrv rsaPrv = {0};
    rsaPrv.id = CRYPT_PKEY_RSA;
    rsaPrv.key.rsaPrv.d = asnArr[RSA_PRV_D_IDX].buff;
    rsaPrv.key.rsaPrv.dLen = asnArr[RSA_PRV_D_IDX].len;
    rsaPrv.key.rsaPrv.n = asnArr[RSA_PRV_N_IDX].buff;
    rsaPrv.key.rsaPrv.nLen = asnArr[RSA_PRV_N_IDX].len;
    rsaPrv.key.rsaPrv.e = asnArr[RSA_PRV_E_IDX].buff;
    rsaPrv.key.rsaPrv.eLen = asnArr[RSA_PRV_E_IDX].len;
    rsaPrv.key.rsaPrv.p = asnArr[RSA_PRV_P_IDX].buff;
    rsaPrv.key.rsaPrv.pLen = asnArr[RSA_PRV_P_IDX].len;
    rsaPrv.key.rsaPrv.q = asnArr[RSA_PRV_Q_IDX].buff;
    rsaPrv.key.rsaPrv.qLen = asnArr[RSA_PRV_Q_IDX].len;
    rsaPrv.key.rsaPrv.dP = asnArr[RSA_PRV_DP_IDX].buff;
    rsaPrv.key.rsaPrv.dPLen = asnArr[RSA_PRV_DP_IDX].len;
    rsaPrv.key.rsaPrv.dQ = asnArr[RSA_PRV_DQ_IDX].buff;
    rsaPrv.key.rsaPrv.dQLen = asnArr[RSA_PRV_DQ_IDX].len;
    rsaPrv.key.rsaPrv.qInv = asnArr[RSA_PRV_QINV_IDX].buff;
    rsaPrv.key.rsaPrv.qInvLen = asnArr[RSA_PRV_QINV_IDX].len;

    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkeyCtx != NULL);
    int32_t pkcsv15 = mdId;
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeyCtx, &rsaPrv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), 0);

    /* Malloc signature buffer */
    uint32_t signLen = CRYPT_EAL_PkeyGetSignLen(pkeyCtx);
    signdata = (uint8_t *)BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(signdata != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("CRYPT_EAL_PkeySign Compare", sign->x, sign->len, signdata, signLen);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(signdata);
    BSL_SAL_FREE(rawBuff);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_PUBKEY_FILE_TC001(char *path, int fileType, int mdId, Hex *msg, Hex *sign)
{
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyCtx *reDecPkeyCtx = NULL;
    BSL_Buffer reEnc = {0};
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    if (fileType == CRYPT_PUBKEY_RSA || CRYPT_EAL_PkeyGetId(pkeyCtx) == CRYPT_PKEY_RSA) {
        int32_t pkcsv15 = mdId;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)),
                  0);
    }

    /* verify signature */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkeyCtx, mdId, msg->x, msg->len, sign->x, sign->len), CRYPT_SUCCESS);

    /* re-encode current pubkey, decode again, then verify again */
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyCtx, NULL, BSL_FORMAT_ASN1, fileType, &reEnc), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, fileType, &reEnc, NULL, 0, &reDecPkeyCtx), CRYPT_SUCCESS);
    if (fileType == CRYPT_PUBKEY_RSA || CRYPT_EAL_PkeyGetId(reDecPkeyCtx) == CRYPT_PKEY_RSA) {
        int32_t pkcsv15_2 = mdId;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(reDecPkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15_2, sizeof(pkcsv15_2)),
                  0);
    }
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(reDecPkeyCtx, mdId, msg->x, msg->len, sign->x, sign->len), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    CRYPT_EAL_PkeyFreeCtx(reDecPkeyCtx);
    BSL_SAL_FREE(reEnc.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_SUBPUBKEY_TC001(int encodeType, Hex *subKeyInfo)
{
    (void)encodeType;
    CRYPT_EAL_PkeyCtx *pctx = NULL;
    ASSERT_EQ(CRYPT_EAL_ParseAsn1SubPubkey(NULL, NULL, subKeyInfo->x, subKeyInfo->len, (void **)&pctx, false), 0);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pctx);
}
/* END_CASE */

static int32_t DecodeKeyFile(int isProvider, const char *path, int format, const char *formatStr, int fileType,
    const char *fileTypeStr, uint8_t *pwd, uint32_t pwdLen, CRYPT_EAL_PkeyCtx **pkeyCtx)
{
#ifdef HITLS_CRYPTO_PROVIDER
    (void)format;
    (void)fileType;
    if (isProvider) {
        BSL_Buffer pwdBuff = {pwd, pwdLen};
        return CRYPT_EAL_ProviderDecodeFileKey(NULL, NULL, BSL_CID_UNKNOWN, formatStr, fileTypeStr, path,
            &pwdBuff, pkeyCtx);
    }
    else
#endif
    {
        (void)isProvider;
        (void)formatStr;
        (void)fileTypeStr;
        return CRYPT_EAL_DecodeFileKey(format, fileType, path, pwd, pwdLen, pkeyCtx);
    }
}

static int32_t DecodeKeyBuff(int isProvider, BSL_Buffer *encode, int format, const char *formatStr, int fileType,
    const char *fileTypeStr, uint8_t *pwd, uint32_t pwdLen, CRYPT_EAL_PkeyCtx **pkeyCtx)
{
#ifdef HITLS_CRYPTO_PROVIDER
    (void)format;
    (void)fileType;
    if (isProvider) {
        BSL_Buffer pwdBuff = {pwd, pwdLen};
        return CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN, formatStr, fileTypeStr, encode,
            &pwdBuff, pkeyCtx);
    } else
#endif
    {
        (void)isProvider;
        (void)formatStr;
        (void)fileTypeStr;
        return CRYPT_EAL_DecodeBuffKey(format, fileType, encode, pwd, pwdLen, pkeyCtx);
    }
}

/* sign and optional compare in a reusable subroutine */
static int32_t PrikeySign(CRYPT_EAL_PkeyCtx *pkeyCtx, int mdId, int fileType, char *fileTypeStr, Hex *msg, Hex *sign)
{
    int32_t ret = CRYPT_INVALID_KEY;
    uint8_t *signdata = NULL;
    uint32_t signLen = 0;
    int32_t id = CRYPT_EAL_PkeyGetId(pkeyCtx);
    if (fileType == CRYPT_PRIKEY_RSA || strcmp(fileTypeStr, "PRIKEY_RSA") == 0 || id == CRYPT_PKEY_RSA) {
        int32_t pkcsv15 = mdId;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), 0);
    }

    signLen = CRYPT_EAL_PkeyGetSignLen(pkeyCtx);
    signdata = (uint8_t *)BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(signdata != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);

    if (sign->len != 0 && id != CRYPT_PKEY_SM2 && id != CRYPT_PKEY_ECDSA) {
        ASSERT_COMPARE("Signature Compare", sign->x, sign->len, signdata, signLen);
    }

    ret = CRYPT_SUCCESS;
EXIT:
    BSL_SAL_Free(signdata);
    return ret;
}

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_PRIKEY_FILE_TC001(int isProvider, char *path, int fileType, char *fileTypeStr, int mdId,
    Hex *msg, Hex *sign)
{
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    uint8_t *signdata = NULL;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    /* Re-encode current pkey, decode again, then sign again and verify */
    BSL_Buffer reEnc = {0};
    CRYPT_EAL_PkeyCtx *reDecPkeyCtx = NULL;

    ASSERT_EQ(DecodeKeyFile(isProvider, path, BSL_FORMAT_ASN1, "ASN1", fileType, fileTypeStr, NULL, 0, &pkeyCtx), 0);

    ASSERT_EQ(PrikeySign(pkeyCtx, mdId, fileType, fileTypeStr, msg, sign), CRYPT_SUCCESS);


    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyCtx, NULL, BSL_FORMAT_ASN1, fileType, &reEnc), CRYPT_SUCCESS);
    ASSERT_EQ(DecodeKeyBuff(isProvider, &reEnc, BSL_FORMAT_ASN1, "ASN1",
        fileType, fileTypeStr, NULL, 0, &reDecPkeyCtx), 0);
    ASSERT_EQ(PrikeySign(reDecPkeyCtx, mdId, fileType, fileTypeStr, msg, sign), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_Free(signdata);
    CRYPT_EAL_PkeyFreeCtx(reDecPkeyCtx);
    BSL_SAL_FREE(reEnc.data);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
}
/* END_CASE */

/* ecc: get raw prv, compare, check para, sign (no expected sign) */
static int32_t EccPrvSign(CRYPT_EAL_PkeyCtx *pkeyCtx, int mdId, int alg, Hex *msg, Hex *rawKey,
    int paraId)
{
    int32_t ret = CRYPT_INVALID_KEY;
    uint8_t *rawPriKey = NULL;
    uint32_t rawPriKeyLen = 100; /* buffer length used by existing tests */
    uint8_t *signdata = NULL;
    uint32_t signLen = 0;

    rawPriKey = (uint8_t *)BSL_SAL_Calloc(rawPriKeyLen, 1);
    ASSERT_TRUE(rawPriKey != NULL);

    CRYPT_EAL_PkeyPrv pkeyPrv = {0};
    pkeyPrv.id = alg;
    pkeyPrv.key.eccPrv.data = rawPriKey;
    pkeyPrv.key.eccPrv.len = rawPriKeyLen;
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkeyCtx, &pkeyPrv), CRYPT_SUCCESS);
    ASSERT_COMPARE("key cmp", rawKey->x, rawKey->len, rawPriKey, rawKey->len);
    ASSERT_EQ(CRYPT_EAL_PkeyGetId(pkeyCtx), alg);
    if (alg != CRYPT_PKEY_SM2) { /* sm2 is null */
        ASSERT_EQ(CRYPT_EAL_PkeyGetParaId(pkeyCtx), paraId);
    }
    /* sign */
    signLen = CRYPT_EAL_PkeyGetSignLen(pkeyCtx);
    signdata = (uint8_t *)BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(signdata != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);

    ret = CRYPT_SUCCESS;
EXIT:
    BSL_SAL_Free(signdata);
    BSL_SAL_Free(rawPriKey);
    return ret;
}

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_ECCPRIKEY_FILE_TC001(int isProvider, int noPubKey, char *path, int fileType, char *fileTypeStr,
    int mdId, Hex *msg, int alg, Hex *rawKey, int paraId, Hex *expectAsn1)
{
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    BSL_Buffer reEnc = {0};
    CRYPT_EAL_PkeyCtx *reDecPkeyCtx = NULL;
    uint32_t flag = CRYPT_ECC_PRIKEY_NO_PUBKEY;

    ASSERT_EQ(DecodeKeyFile(isProvider, path, BSL_FORMAT_ASN1, "ASN1", fileType, fileTypeStr, NULL, 0, &pkeyCtx), 0);
    ASSERT_EQ(EccPrvSign(pkeyCtx, mdId, alg, msg, rawKey, paraId), CRYPT_SUCCESS);
    if (noPubKey) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_FLAG, &flag, sizeof(flag)), CRYPT_SUCCESS);
    }

    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyCtx, NULL, BSL_FORMAT_ASN1, fileType, &reEnc), CRYPT_SUCCESS);
    if (expectAsn1->len != 0) {
        ASSERT_COMPARE("asn1 compare", reEnc.data, reEnc.dataLen, expectAsn1->x, expectAsn1->len);
    }
    ASSERT_EQ(DecodeKeyBuff(isProvider, &reEnc, BSL_FORMAT_ASN1, "ASN1", fileType, fileTypeStr,
        NULL, 0, &reDecPkeyCtx), 0);
    ASSERT_EQ(EccPrvSign(reDecPkeyCtx, mdId, alg, msg, rawKey, paraId), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
    if (noPubKey) {
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(reDecPkeyCtx, CRYPT_CTRL_GET_FLAG, &flag, sizeof(flag)), CRYPT_SUCCESS);
        ASSERT_EQ(flag, CRYPT_ECC_PRIKEY_NO_PUBKEY);
    }

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    CRYPT_EAL_PkeyFreeCtx(reDecPkeyCtx);
    BSL_SAL_FREE(reEnc.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_25519PRIKEY_FILE_TC001(int alg, char *path, int format, int type, Hex *prv)
{
    uint8_t rawPriKey[32] = {0};
    uint32_t rawPriKeyLen = 32;
    CRYPT_EAL_PkeyPrv pkeyPrv = {0};
    pkeyPrv.id = alg;
    pkeyPrv.key.eccPrv.data = rawPriKey;
    pkeyPrv.key.eccPrv.len = rawPriKeyLen;

    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(format, type, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPrv(pkeyCtx, &pkeyPrv), CRYPT_SUCCESS);
    ASSERT_COMPARE("key cmp", prv->x, prv->len, pkeyPrv.key.eccPrv.data, pkeyPrv.key.eccPrv.len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_25519PRIKEY_FILE_TC002(char *path, int format, int type, int ret)
{
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(format, type, path, NULL, 0, &pkeyCtx), ret);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_X25519PUBKEY_FILE_TC001(char *path, int fileType, Hex *expect)
{
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(fileType, CRYPT_PUBKEY_SUBKEY);
    ASSERT_EQ(CRYPT_EAL_PkeyGetId(pkeyCtx), CRYPT_PKEY_X25519);

    uint8_t rawPubKey[32] = {0};
    CRYPT_EAL_PkeyPub pkeyPub = {0};
    pkeyPub.id = CRYPT_PKEY_X25519;
    pkeyPub.key.curve25519Pub.data = rawPubKey;
    pkeyPub.key.curve25519Pub.len = sizeof(rawPubKey);
    ASSERT_EQ(CRYPT_EAL_PkeyGetPub(pkeyCtx, &pkeyPub), CRYPT_SUCCESS);
    ASSERT_COMPARE("key cmp", expect->x, expect->len, pkeyPub.key.curve25519Pub.data,
        pkeyPub.key.curve25519Pub.len);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_X25519_EXCH_TC001(char *prvPath, int prvFormat, int prvType,
    char *pubPath, int pubFormat, int pubType)
{
    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *prvCtx = NULL;
    CRYPT_EAL_PkeyCtx *pubCtx = NULL;
    CRYPT_EAL_PkeyCtx *peerCtx = NULL;
    uint8_t share1[32] = {0};
    uint8_t share2[32] = {0};
    uint32_t share1Len = sizeof(share1);
    uint32_t share2Len = sizeof(share2);

    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(prvFormat, prvType, prvPath, NULL, 0, &prvCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(pubFormat, pubType, pubPath, NULL, 0, &pubCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGetId(prvCtx), CRYPT_PKEY_X25519);
    ASSERT_EQ(CRYPT_EAL_PkeyGetId(pubCtx), CRYPT_PKEY_X25519);

    peerCtx = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X25519);
    ASSERT_TRUE(peerCtx != NULL);
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(peerCtx), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(prvCtx, peerCtx, share1, &share1Len), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyComputeShareKey(peerCtx, pubCtx, share2, &share2Len), CRYPT_SUCCESS);
    ASSERT_EQ(share1Len, share2Len);
    ASSERT_EQ(memcmp(share1, share2, share1Len), 0);

EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(prvCtx);
    CRYPT_EAL_PkeyFreeCtx(pubCtx);
    CRYPT_EAL_PkeyFreeCtx(peerCtx);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_ENCPK8_TC001(int isProvider, char *path, int fileType, char *fileTypeStr, Hex *pass,
    int mdId, Hex *msg, Hex *sign)
{
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    uint8_t *signdata = NULL;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    ASSERT_EQ(DecodeKeyFile(isProvider, path, BSL_FORMAT_ASN1, "ASN1", fileType, fileTypeStr,
        pass->x, pass->len, &pkeyCtx), 0);
    if (fileType == CRYPT_PRIKEY_RSA || CRYPT_EAL_PkeyGetId(pkeyCtx) == CRYPT_PKEY_RSA) {
        int32_t pkcsv15 = mdId;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)),
                  0);
    }

    /* Malloc signature buffer */
    uint32_t signLen = CRYPT_EAL_PkeyGetSignLen(pkeyCtx);
    signdata = (uint8_t *)BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(signdata != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);

    if (sign->len != 0) {
        ASSERT_COMPARE("Signature Compare", sign->x, sign->len, signdata, signLen);
    }
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_Free(signdata);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_BUFF_TC001(int isProvider, char *typeStr, int type, Hex *pass, Hex *data)
{
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    BSL_Buffer encode = {data->x, data->len};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    int32_t ret;
#ifdef HITLS_CRYPTO_PROVIDER
    ret = isProvider ? CRYPT_DECODE_ERR_NO_USABLE_DECODER : CRYPT_NULL_INPUT;
#else
    ret = CRYPT_NULL_INPUT;
#endif
    ASSERT_EQ(DecodeKeyBuff(isProvider, &encode, BSL_FORMAT_ASN1, "ASN1", type, typeStr, pass->x, pass->len, &pkeyCtx),
        ret);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_PUBKEY_BUFF_TC001(char *path, int fileType, int isComplete, Hex *asn1)
{
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    BSL_Buffer encodeAsn1 = {0};
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodePubKeyBuffInternal(pkeyCtx, BSL_FORMAT_ASN1,
        fileType, isComplete, &encodeAsn1), CRYPT_SUCCESS);

    ASSERT_COMPARE("asn1 compare.", encodeAsn1.data, encodeAsn1.dataLen, asn1->x, asn1->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(encodeAsn1.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_PEM_ENCODE_PUBKEY_BUFF_TC001(char *path, int fileType, int isComplete, char *pemPath)
{
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    BSL_Buffer encodePem = {0};
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodePubKeyBuffInternal(pkeyCtx, BSL_FORMAT_PEM,
        fileType, isComplete, &encodePem), CRYPT_SUCCESS);

    uint8_t *pem = NULL;
    uint32_t pemLen = 0;
    ASSERT_EQ(BSL_SAL_ReadFile(pemPath, &pem, &pemLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("pem compare.", encodePem.data, encodePem.dataLen, pem, pemLen);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(encodePem.data);
    BSL_SAL_FREE(pem);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_PRIKEY_BUFF_TC001(char *path, int fileType, Hex *asn1)
{
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    BSL_Buffer encodeAsn1 = {0};
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyCtx, NULL, BSL_FORMAT_ASN1, fileType, &encodeAsn1), CRYPT_SUCCESS);
    ASSERT_COMPARE("asn1 compare.", encodeAsn1.data, encodeAsn1.dataLen, asn1->x, asn1->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(encodeAsn1.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_ENCRYPTED_PRIKEY_BUFF_TC001(char *path, int fileType, int keyType, int hmacId, int symId,
    int saltLen, Hex *pwd, int itCnt, Hex *asn1, int isProvider)
{
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    BSL_Buffer encodeAsn1 = {0};
    BSL_Buffer encodeAsn1Out = {0};
    CRYPT_EAL_PkeyCtx *decodeCtx = NULL;
    CRYPT_Pbkdf2Param param = {0};
    param.pbesId = BSL_CID_PBES2;
    param.pbkdfId = BSL_CID_PBKDF2;
    param.hmacId = hmacId;
    param.symId = symId;
    param.pwd = pwd->x;
    param.pwdLen = pwd->len;
    param.saltLen = saltLen;
    param.itCnt = itCnt;
    CRYPT_EncodeParam paramEx = {CRYPT_DERIVE_PBKDF2, &param};
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider) {
        BSL_Buffer pwdBuf = {pwd->x, pwd->len};
        ASSERT_EQ(CRYPT_EAL_ProviderDecodeFileKey(NULL, NULL, keyType, BSL_FORMAT_UNKNOWN, NULL, path, &pwdBuf,
            &pkeyCtx), CRYPT_SUCCESS);
    } else {
#else
        (void)isProvider;
        (void)keyType;
#endif
        ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, pwd->x, pwd->len, &pkeyCtx),
            CRYPT_SUCCESS);
#ifdef HITLS_CRYPTO_PROVIDER
    }
#endif

    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyCtx, &paramEx, BSL_FORMAT_ASN1, fileType, &encodeAsn1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, fileType, &encodeAsn1, pwd->x, pwd->len, &decodeCtx),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(decodeCtx, NULL, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encodeAsn1Out),
        CRYPT_SUCCESS);
    ASSERT_COMPARE("asn1 compare.", encodeAsn1Out.data, encodeAsn1Out.dataLen, asn1->x, asn1->len);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    CRYPT_EAL_PkeyFreeCtx(decodeCtx);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(encodeAsn1.data);
    BSL_SAL_FREE(encodeAsn1Out.data);
    TestRandDeInit();
}
/* END_CASE */

static int32_t GetPkcs8EncPkeyCtx(int keyType, int isProvider,
    int hmacId, int symId, Hex *pwd, int saltLen, int itCnt,
    CRYPT_EncodeParam *outParamEx, CRYPT_Pbkdf2Param *outPbkdf2, CRYPT_EAL_PkeyCtx **outPkeyCtx)
{
    outPbkdf2->pbesId = BSL_CID_PBES2;
    outPbkdf2->pbkdfId = BSL_CID_PBKDF2;
    outPbkdf2->hmacId = hmacId;
    outPbkdf2->symId = symId;
    outPbkdf2->pwd = pwd->x;
    outPbkdf2->pwdLen = pwd->len;
    outPbkdf2->saltLen = saltLen;
    outPbkdf2->itCnt = itCnt;
    *outParamEx = (CRYPT_EncodeParam){CRYPT_DERIVE_PBKDF2, outPbkdf2};
    /* create and generate pkey */
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    if (isProvider) {
        pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, keyType, CRYPT_EAL_PKEY_UNKNOWN_OPERATE, "provider=default");
    } else {
#else
    (void)isProvider;
#endif
    pkeyCtx = CRYPT_EAL_PkeyNewCtx(keyType);
#ifdef HITLS_CRYPTO_PROVIDER
    }
#endif
    ASSERT_TRUE(pkeyCtx != NULL);

    uint8_t e[] = {1, 0, 1};
    CRYPT_EAL_PkeyPara para = {0};
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.e = e;
    para.para.rsaPara.eLen = 3;
    para.para.rsaPara.bits = 2048;
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkeyCtx, &para), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkeyCtx), CRYPT_SUCCESS);

    *outPkeyCtx = pkeyCtx;
    return CRYPT_SUCCESS;
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    return CRYPT_INVALID_ARG;
}

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_ENCRYPTED_PRIKEY_BUFF_TC002(int fileType, int keyType, int hmacId, int symId,
    int saltLen, Hex *pwd, int itCnt, int mdId, Hex *msg, int isProvider)
{
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);

    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyCtx *decodeCtx = NULL;
    BSL_Buffer encPk8 = {0};
    BSL_Buffer reEncPk8 = {0};
    uint8_t *signdata = NULL;
    CRYPT_Pbkdf2Param param = {0};
    CRYPT_EncodeParam paramEx = {0};
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(GetPkcs8EncPkeyCtx(keyType, isProvider, hmacId, symId, pwd, saltLen, itCnt,
        &paramEx, &param, &pkeyCtx), CRYPT_SUCCESS);
    /* encode -> encrypted pkcs8 */
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyCtx, &paramEx, BSL_FORMAT_ASN1, fileType, &encPk8), CRYPT_SUCCESS);
    /* decode the encrypted pkcs8 */
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, fileType, &encPk8, pwd->x, pwd->len, &decodeCtx),
        CRYPT_SUCCESS);

    /* sign with decoded key (no expected signature compare) */
    uint32_t signLen = CRYPT_EAL_PkeyGetSignLen(decodeCtx);
    signdata = (uint8_t *)BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(signdata != NULL);
    if (CRYPT_EAL_PkeyGetId(decodeCtx) == CRYPT_PKEY_RSA) {
        int32_t pkcsv15 = mdId;
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(decodeCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(pkcsv15)), 0);
    }
    ASSERT_EQ(CRYPT_EAL_PkeySign(decodeCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);

    /* encode again -> encrypted pkcs8 */
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(decodeCtx, &paramEx, BSL_FORMAT_ASN1, fileType, &reEncPk8), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    BSL_SAL_Free(signdata);
    CRYPT_EAL_PkeyFreeCtx(decodeCtx);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(encPk8.data);
    BSL_SAL_FREE(reEncPk8.data);
    TestRandDeInit();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_PRAPSSPRIKEY_BUFF_TC001(char *path, int fileType, int saltLen, int mdId, int mgfId, Hex *asn1)
{
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    BSL_Buffer encodeAsn1 = {0};
    CRYPT_MD_AlgId paramMdId = (CRYPT_MD_AlgId)mdId;
    CRYPT_MD_AlgId paramMgfId = (CRYPT_MD_AlgId)mgfId;
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &paramMdId, sizeof(paramMdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &paramMgfId, sizeof(paramMgfId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyCtx, NULL, BSL_FORMAT_ASN1, fileType, &encodeAsn1), CRYPT_SUCCESS);
    ASSERT_COMPARE("asn1 compare.", encodeAsn1.data, encodeAsn1.dataLen, asn1->x, asn1->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(encodeAsn1.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_AND_DECODE_RSAPSS_PUBLICKEY_TC001(int keyLen, int saltLen)
{
    TestMemInit();
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    uint8_t e[] = {1, 0, 1};  // RSA public exponent
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_EAL_PkeyPara para = {0};
    CRYPT_EAL_PkeyCtx *decodedPkey = NULL;
    CRYPT_MD_AlgId mdId = CRYPT_MD_SHA256;
    BSL_Buffer encode = {0};
    // set rsa para
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.e = e;
    para.para.rsaPara.eLen = 3; // public exponent length = 3
    para.para.rsaPara.bits = keyLen;
    // pss param
    BSL_Param pssParam[4] = {
        {CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &mdId, sizeof(mdId), 0},
        {CRYPT_PARAM_RSA_SALTLEN, BSL_PARAM_TYPE_INT32, &saltLen, sizeof(saltLen), 0},
        BSL_PARAM_END};
    // create new pkey ctx
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey != NULL);

    // set para and generate key pair
    ASSERT_EQ(CRYPT_EAL_PkeySetPara(pkey, &para), CRYPT_SUCCESS);
    ASSERT_EQ(TestRandInit(), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(pkey), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PSS, pssParam, 0), CRYPT_SUCCESS);
    // encode key
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkey, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encode),
        CRYPT_SUCCESS);
    // decode key
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encode, NULL, 0, &decodedPkey),
        CRYPT_SUCCESS);
    ASSERT_TRUE(decodedPkey != NULL);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    TestRandDeInit();
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_PkeyFreeCtx(decodedPkey);
    BSL_SAL_FREE(encode.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_ENCODE_RSAPSS_PUBLICKEY_BUFF_TC002(char *path, Hex *asn1)
{
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    BSL_Buffer encodeAsn1 = {0};
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, CRYPT_PUBKEY_SUBKEY, path, NULL, 0, &pkeyCtx),
        CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyCtx, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encodeAsn1), CRYPT_SUCCESS);
    ASSERT_COMPARE("asn1 compare.", encodeAsn1.data, encodeAsn1.dataLen, asn1->x, asn1->len);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(encodeAsn1.data);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_BUFF_PROVIDER_TC001(char *formatStr, char *typeStr, char *path, Hex *password)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)formatStr;
    (void)typeStr;
    (void)path;
    (void)password;
    SKIP_TEST();
#else
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    ASSERT_EQ(BSL_SAL_ReadFile(path, &data, &dataLen), BSL_SUCCESS);
    BSL_Buffer encode = {data, dataLen};
    BSL_Buffer pass = {password->x, password->len};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    ASSERT_EQ(CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN, NULL, NULL, &encode,
        &pass, &pkeyCtx), CRYPT_SUCCESS);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    pkeyCtx = NULL;
    encode.data = data;
    encode.dataLen = dataLen;
    ASSERT_EQ(CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN, formatStr, typeStr, &encode, &pass,
        &pkeyCtx), 0);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    pkeyCtx = NULL;
#ifdef HITLS_CRYPTO_PROVIDER
    /* default provider not loading */
    CRYPT_EAL_Cleanup(9); // 9 denotes to deinit CRYPT_EAL_INIT_CPU and CRYPT_EAL_INIT_PROVIDER
    encode.data = data;
    encode.dataLen = dataLen;
    ASSERT_EQ(CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN, NULL, NULL, &encode,
        &pass, &pkeyCtx), CRYPT_PROVIDER_INVALID_LIB_CTX);
    encode.data = data;
    encode.dataLen = dataLen;
    ASSERT_NE(CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN, formatStr, typeStr, &encode, &pass,
        &pkeyCtx), 0);
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    encode.data = data;
    encode.dataLen = dataLen;
    TestErrClear();
    ASSERT_EQ(CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN, formatStr, typeStr, &encode, &pass,
        &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
#endif
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(data);
#endif
}
/* END_CASE */

/**
 * @test SDV_BSL_ASN1_PARSE_BUFF_PROVIDER_TC002
 * title 1. Test the decode provider and key provider are not same
 *       2. Test the JSON2Key
 *
 */
/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_BUFF_PROVIDER_TC002(char *providerPath, char *providerName, int cmd, char *attrName,
    char *formatStr, char *typeStr, char *path)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)providerPath;
    (void)providerName;
    (void)cmd;
    (void)attrName;
    (void)formatStr;
    (void)typeStr;
    (void)path;
    SKIP_TEST();
#else
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_LibCtx *libCtx = CRYPT_EAL_LibCtxNew();
    ASSERT_TRUE(libCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_ProviderSetLoadPath(libCtx, providerPath), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, BSL_SAL_LIB_FMT_OFF, "default", NULL, NULL), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_ProviderLoad(libCtx, cmd, providerName, NULL, NULL), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_ProviderDecodeFileKey(libCtx, attrName, BSL_CID_UNKNOWN, formatStr, typeStr, path,
        NULL, &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    CRYPT_EAL_LibCtxFree(libCtx);
#endif
}
/* END_CASE */

/**
 * @test SDV_BSL_ASN1_PARSE_BUFF_STUB_TC001
 * title 1. Test the decode provider with stub malloc fail
 */
/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_BUFF_STUB_TC001(char *formatStr, char *typeStr, char *path, Hex *password)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)formatStr;
    (void)typeStr;
    (void)path;
    (void)password;
    SKIP_TEST();
#else
    int32_t ret;
    BSL_Buffer pass = {password->x, password->len};
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    uint32_t totalMallocCount = 0;
    BSL_Buffer encode = {0};

    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    ASSERT_EQ(BSL_SAL_ReadFile(path, &encode.data, &encode.dataLen), BSL_SUCCESS);

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);

    /* Phase 1: Probe - count malloc calls during successful execution */
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN, formatStr, typeStr, &encode,
        &pass, &pkeyCtx), CRYPT_SUCCESS);
    totalMallocCount = STUB_GetMallocCallCount();
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    pkeyCtx = NULL;

    /* Phase 2: Test - iteratively fail each malloc */
    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ret = CRYPT_EAL_ProviderDecodeBuffKey(NULL, NULL, BSL_CID_UNKNOWN, formatStr, typeStr, &encode,
            &pass, &pkeyCtx);
        if (ret == CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
            pkeyCtx = NULL;
        }
    }
EXIT:
    BSL_SAL_FREE(encode.data);
    STUB_RESTORE(BSL_SAL_Malloc);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    #endif
}
/* END_CASE */

#ifdef HITLS_CRYPTO_PROVIDER
static CRYPT_PKEY_AlgId g_stubPkeyGetIdRetVal = CRYPT_PKEY_RSA;

static CRYPT_PKEY_AlgId STUB_CRYPT_EAL_PkeyGetId(const CRYPT_EAL_PkeyCtx *pkey)
{
    (void)pkey;
    return g_stubPkeyGetIdRetVal;
}
#endif

/**
 * @test SDV_CRYPT_EAL_PROVIDER_DECODE_FILE_KEY_STUB_TC001
 * @title Test CRYPT_EAL_ProviderDecodeFileKey with CRYPT_EAL_PkeyGetId stub
 * @precon None
 * @brief
 *    1. Decode a key file with provider, expect success
 *    2. Replace CRYPT_EAL_PkeyGetId with stub that returns mismatched alg ID
 *    3. Decode again with specific pkeyAlgId, expect CRYPT_EAL_ERR_ALGID error
 *    4. Restore stub and verify normal behavior
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_PROVIDER_DECODE_FILE_KEY_STUB_TC001(char *path, char *formatStr, char *typeStr, int expectedAlgId)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)path;
    (void)formatStr;
    (void)typeStr;
    (void)expectedAlgId;
    SKIP_TEST();
#else
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyCtx *pkeyCtx2 = NULL;

    /* Step 1: Normal decode without stub, expect success */
    ASSERT_EQ(CRYPT_EAL_ProviderDecodeFileKey(NULL, NULL, BSL_CID_UNKNOWN, formatStr, typeStr, path,
        NULL, &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_TRUE(pkeyCtx != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeyGetId(pkeyCtx), expectedAlgId);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    pkeyCtx = NULL;

    /* Step 2: Replace CRYPT_EAL_PkeyGetId with stub returning different alg ID */
    g_stubPkeyGetIdRetVal = CRYPT_PKEY_SM2;  /* Return a different alg ID */
    STUB_REPLACE(CRYPT_EAL_PkeyGetId, STUB_CRYPT_EAL_PkeyGetId);

    /* Step 3: Decode with specific pkeyAlgId (RSA), stub returns SM2 -> should fail with CRYPT_EAL_ERR_ALGID */
    ASSERT_EQ(CRYPT_EAL_ProviderDecodeFileKey(NULL, NULL, CRYPT_PKEY_RSA, formatStr, typeStr, path,
        NULL, &pkeyCtx2), CRYPT_EAL_ERR_ALGID);

    /* Step 4: Restore stub */
    STUB_RESTORE(CRYPT_EAL_PkeyGetId);

    /* Step 5: Decode again with BSL_CID_UNKNOWN (no alg check), should succeed */
    ASSERT_EQ(CRYPT_EAL_ProviderDecodeFileKey(NULL, NULL, BSL_CID_UNKNOWN, formatStr, typeStr, path,
        NULL, &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_TRUE(pkeyCtx != NULL);

EXIT:
    STUB_RESTORE(CRYPT_EAL_PkeyGetId);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx2);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
#endif
}
/* END_CASE */

/**
 * @test SDV_CRYPT_EAL_PROVIDER_DECODE_FILE_KEY_STUB_TC002
 * @title Test CRYPT_EAL_ProviderDecodeFileKey with CRYPT_EAL_PkeyGetId stub returning matching alg ID
 * @precon None
 * @brief
 *    1. Replace CRYPT_EAL_PkeyGetId with stub returning matching alg ID
 *    2. Decode key file with matching pkeyAlgId, expect success
 *    3. Restore stub
 */
/* BEGIN_CASE */
void SDV_CRYPT_EAL_PROVIDER_DECODE_FILE_KEY_STUB_TC002(char *path, char *formatStr, char *typeStr, int pkeyAlgId)
{
#ifndef HITLS_CRYPTO_PROVIDER
    (void)path;
    (void)formatStr;
    (void)typeStr;
    (void)pkeyAlgId;
    SKIP_TEST();
#else
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;

    /* Replace CRYPT_EAL_PkeyGetId with stub returning same alg ID as requested */
    g_stubPkeyGetIdRetVal = pkeyAlgId;
    STUB_REPLACE(CRYPT_EAL_PkeyGetId, STUB_CRYPT_EAL_PkeyGetId);

    /* Decode with specific pkeyAlgId, stub returns matching alg ID -> should succeed */
    ASSERT_EQ(CRYPT_EAL_ProviderDecodeFileKey(NULL, NULL, pkeyAlgId, formatStr, typeStr, path,
        NULL, &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_TRUE(pkeyCtx != NULL);

EXIT:
    STUB_RESTORE(CRYPT_EAL_PkeyGetId);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    CRYPT_EAL_Cleanup(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_DSAKEY_BUFF_TC001(char *path, int fileType, Hex *asn1)
{
#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DSA)
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    BSL_Buffer encodeAsn1 = {0};
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyCtx, NULL, BSL_FORMAT_ASN1, fileType, &encodeAsn1), CRYPT_SUCCESS);
    ASSERT_COMPARE("asn1 compare.", encodeAsn1.data, encodeAsn1.dataLen, asn1->x, asn1->len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(encodeAsn1.data);
#else
    (void)path;
    (void)fileType;
    (void)asn1;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_DSAKEY_BUFF_TC002(char *path, int fileType)
{
#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DSA)
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    uint32_t totalMallocCount = STUB_GetMallocCallCount();
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    pkeyCtx = NULL;

    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx);
        CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
        pkeyCtx = NULL;
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
#else
    (void)path;
    (void)fileType;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_DSAKEY_BUFF_TC003(char *path, int fileType)
{
#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DSA)
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;

    BSL_Buffer encodeAsn1 = {0};
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyCtx, NULL, BSL_FORMAT_ASN1, fileType, &encodeAsn1), CRYPT_SUCCESS);
    uint32_t totalMallocCount = STUB_GetMallocCallCount();
    BSL_SAL_FREE(encodeAsn1.data);
    encodeAsn1.data = NULL;
    encodeAsn1.dataLen = 0;

    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ASSERT_NE(CRYPT_EAL_EncodeBuffKey(pkeyCtx, NULL, BSL_FORMAT_ASN1, fileType, &encodeAsn1), CRYPT_SUCCESS);
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(encodeAsn1.data);
    encodeAsn1.data = NULL;
    encodeAsn1.dataLen = 0;
#else
    (void)path;
    (void)fileType;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_DHKEY_BUFF_TC001(char *path, int fileType, Hex *asn1)
{
#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DH)
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    BSL_Buffer encodeAsn1 = {0};
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyCtx, NULL, BSL_FORMAT_ASN1, fileType, &encodeAsn1), CRYPT_SUCCESS);
    ASSERT_COMPARE("asn1 compare.", encodeAsn1.data, encodeAsn1.dataLen, asn1->x, asn1->len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(encodeAsn1.data);
#else
    (void)path;
    (void)fileType;
    (void)asn1;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_DHKEY_BUFF_TC002(char *path, int fileType)
{
#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DH)
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;

    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    uint32_t totalMallocCount = STUB_GetMallocCallCount();
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    pkeyCtx = NULL;

    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx);
        CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
        pkeyCtx = NULL;
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
#else
    (void)path;
    (void)fileType;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_DHKEY_BUFF_TC003(char *path, int fileType)
{
#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DH)
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;

    BSL_Buffer encodeAsn1 = {0};
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    STUB_REPLACE(BSL_SAL_Malloc, STUB_BSL_SAL_Malloc);
    STUB_EnableMallocFail(false);
    STUB_ResetMallocCount();
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyCtx, NULL, BSL_FORMAT_ASN1, fileType, &encodeAsn1), CRYPT_SUCCESS);
    uint32_t totalMallocCount = STUB_GetMallocCallCount();
    BSL_SAL_FREE(encodeAsn1.data);
    encodeAsn1.data = NULL;
    encodeAsn1.dataLen = 0;

    STUB_EnableMallocFail(true);
    for (uint32_t i = 0; i < totalMallocCount; i++) {
        STUB_ResetMallocCount();
        STUB_SetMallocFailIndex(i);
        ASSERT_NE(CRYPT_EAL_EncodeBuffKey(pkeyCtx, NULL, BSL_FORMAT_ASN1, fileType, &encodeAsn1), CRYPT_SUCCESS);
    }
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(encodeAsn1.data);
    encodeAsn1.data = NULL;
    encodeAsn1.dataLen = 0;
#else
    (void)path;
    (void)fileType;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_DSAKEY_BUFF_CMP(char *path, int fileType, Hex *asn1)
{
#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DSA)
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyCtx *pkeyAsn1Ctx = NULL;
    BSL_Buffer encodeAsn1 = {asn1->x, asn1->len};
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, fileType, &encodeAsn1, NULL, 0, &pkeyAsn1Ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(pkeyCtx, pkeyAsn1Ctx), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    CRYPT_EAL_PkeyFreeCtx(pkeyAsn1Ctx);
#else
    (void)path;
    (void)fileType;
    (void)asn1;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_DHKEY_BUFF_CMP(char *path, int fileType, Hex *asn1)
{
#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DH)
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    CRYPT_EAL_PkeyCtx *pkeyAsn1Ctx = NULL;
    BSL_Buffer encodeAsn1 = {asn1->x, asn1->len};
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, fileType, &encodeAsn1, NULL, 0, &pkeyAsn1Ctx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(pkeyCtx, pkeyAsn1Ctx), CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    CRYPT_EAL_PkeyFreeCtx(pkeyAsn1Ctx);
#else
    (void)path;
    (void)fileType;
    (void)asn1;
    SKIP_TEST();
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_DECODE_DSAKEY_BUFF_TC004()
{
#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DSA)
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);

    // DSA
    CRYPT_EAL_PkeyCtx *dsakey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_DSA, 0, NULL);
    int32_t algId = CRYPT_MD_SHA256;
    uint32_t L = 2048;
    uint32_t N = 256;
    uint32_t seedLen = 256;
    int32_t index = 0;
    BSL_Param params[6] = {
        {CRYPT_PARAM_DSA_ALGID, BSL_PARAM_TYPE_INT32, &algId, sizeof(int32_t), 0},
        {CRYPT_PARAM_DSA_PBITS, BSL_PARAM_TYPE_UINT32, &L, sizeof(uint32_t), 0},
        {CRYPT_PARAM_DSA_QBITS, BSL_PARAM_TYPE_UINT32, &N, sizeof(uint32_t), 0},
        {CRYPT_PARAM_DSA_SEEDLEN, BSL_PARAM_TYPE_UINT32, &seedLen, sizeof(uint32_t), 0},
        {CRYPT_PARAM_DSA_GINDEX, BSL_PARAM_TYPE_INT32, &index, sizeof(int32_t), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(dsakey, CRYPT_CTRL_GEN_PARA, params, 0), CRYPT_SUCCESS);
    uint32_t genFlag = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(dsakey, CRYPT_CTRL_SET_GEN_FLAG, &genFlag, sizeof(genFlag)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(dsakey), 0);

    BSL_Buffer encDSAAsn1 = {0};
    CRYPT_EAL_PkeyCtx *get_dsakey = NULL;
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(dsakey, NULL, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encDSAAsn1), CRYPT_SUCCESS);
    BSL_SAL_FREE(encDSAAsn1.data);
    encDSAAsn1.dataLen = 0;
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(dsakey, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encDSAAsn1), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_UNKNOWN, CRYPT_PUBKEY_SUBKEY, &encDSAAsn1, NULL, 0, &get_dsakey) , CRYPT_SUCCESS);
    // DH
    CRYPT_EAL_PkeyCtx *dhkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, CRYPT_PKEY_DH, 0, NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(dhkey, CRYPT_DH_RFC7919_2048) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(dhkey), 0);
    CRYPT_EAL_PkeyCtx *get_dhkey = NULL;
    BSL_Buffer encDHAsn1 = {0};
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(dhkey, NULL, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encDHAsn1), CRYPT_SUCCESS);
    BSL_SAL_FREE(encDHAsn1.data);
    encDHAsn1.dataLen = 0;
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(dhkey, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encDHAsn1), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_UNKNOWN, CRYPT_PUBKEY_SUBKEY, &encDHAsn1, NULL, 0, &get_dhkey) , CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(dsakey);
    CRYPT_EAL_PkeyFreeCtx(dhkey);
    CRYPT_EAL_PkeyFreeCtx(get_dsakey);
    CRYPT_EAL_PkeyFreeCtx(get_dhkey);
    BSL_SAL_FREE(encDSAAsn1.data);
    BSL_SAL_FREE(encDHAsn1.data);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/*
@test SDV_PKCS8_ENCODE_DHKEY_DSAKEY_TC001
@title DH, DSA key encoding
@step
1.openHiTLS calls CRYPT_EAL_EncodeBuffKey interface to encode the key in pem format,
    comparing if the encoding between openssl and openHiTLS is consistent
2.openHiTLS calls CRYPT_EAL_EncodeBuffKey interface to encode the key in asn1 format,
    comparing if the encoding between openssl and openHiTLS is consistent
@expect
1.Encoding succeeds, consistent with openssl
2.Encoding succeeds, consistent with openssl
*/
/* BEGIN_CASE */
void SDV_PKCS8_ENCODE_DHKEY_DSAKEY_TC001(char *path, int fileType, Hex *asn1)
{
#if defined(HITLS_CRYPTO_PROVIDER) && (defined(HITLS_CRYPTO_DSA) && defined(HITLS_CRYPTO_DSA))
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    BSL_Buffer encodeAsn1 = {0};
    BSL_Buffer encodePem = {0};
    BSL_Buffer pem = {0};
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyCtx, NULL, BSL_FORMAT_ASN1, fileType, &encodeAsn1), CRYPT_SUCCESS);
    ASSERT_COMPARE("asn1 compare.", encodeAsn1.data, encodeAsn1.dataLen, asn1->x, asn1->len);

    ASSERT_EQ(BSL_SAL_ReadFile(path, &pem.data, &pem.dataLen), 0);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyCtx, NULL, BSL_FORMAT_PEM, fileType, &encodePem), CRYPT_SUCCESS);
    ASSERT_COMPARE("asn1 compare.", encodePem.data, encodePem.dataLen, pem.data, pem.dataLen);
EXIT:
    BSL_SAL_FREE(pem.data);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(encodePem.data);
    BSL_SAL_FREE(encodeAsn1.data);
#else
    (void)path;
    (void)fileType;
    (void)asn1;
    SKIP_TEST();
#endif
}
/* END_CASE */

/*
@test SDV_PKCS8_DECODE_DHKEY_DSAKEY_TC001
@title DH, DSA key decoding
@step
1.openHiTLS calls CRYPT_EAL_DecodeFileKey interface to decode the key in pem format,
    comparing if the decrypted key is consistent with the original key
2.openHiTLS calls CRYPT_EAL_DecodeBuffKey interface to decode the key in asn1 format,
    comparing if the decrypted key is consistent with the original key
@expect
1.Encoding succeeds, consistent with openssl
2.Encoding succeeds, consistent with openssl
*/
/* BEGIN_CASE */
void SDV_PKCS8_DECODE_DHKEY_DSAKEY_TC001(char *path, int fileType,  Hex *asn1)
{
#if defined(HITLS_CRYPTO_PROVIDER) && (defined(HITLS_CRYPTO_DSA) && defined(HITLS_CRYPTO_DSA))
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyBypem = NULL;
    CRYPT_EAL_PkeyCtx *pkeyByAsn1 = NULL;
    BSL_Buffer decodeAsn1 = {0};
    decodeAsn1.data = BSL_SAL_Malloc(asn1->len);
    decodeAsn1.dataLen = asn1->len;
    memcpy_s(decodeAsn1.data, asn1->len, asn1->x, asn1->len);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyBypem), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, fileType, &decodeAsn1, NULL, 0, &pkeyByAsn1), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(pkeyBypem, pkeyByAsn1), 0);
EXIT:
    BSL_SAL_FREE(decodeAsn1.data);
    CRYPT_EAL_PkeyFreeCtx(pkeyBypem);
    CRYPT_EAL_PkeyFreeCtx(pkeyByAsn1);
#else
    (void)path;
    (void)fileType;
    (void)asn1;
    SKIP_TEST();
#endif
}
/* END_CASE */

/*
@test SDV_PKCS8_ENCDEC_DHKEY_DSAKEY_TC001
@title DH, DSA key decoding then encoding
@step
1.openHiTLS calls CRYPT_EAL_DecodeFileKey interface to decode pem file
2.openHiTLS calls CRYPT_EAL_DecodeBuffKey interface to decode asn1 data
3.Call CRYPT_EAL_EncodeBuffKey to encode the decoded key in pem format
4.Call CRYPT_EAL_EncodeBuffKey to encode the decoded key in asn1 format
5.openHiTLS calls CRYPT_EAL_DecodeFileKey interface to decode re-encoded pem
6.openHiTLS calls CRYPT_EAL_DecodeBuffKey interface to decode re-encoded asn1
7.Compare the decrypted key to see if it's consistent with the given key
@expect
1.Decoding succeeds
2.Decoding succeeds, consistent with key decoded from pem
3.Encoding succeeds, consistent with original pem file content
4.Encoding succeeds, consistent with original asn1 content
5.Decoding succeeds
6.Decoding succeeds
7.Keys are identical
*/
/* BEGIN_CASE */
void SDV_PKCS8_ENCDEC_DHKEY_DSAKEY_TC001(char *path, int fileType,  Hex *asn1)
{
#if defined(HITLS_CRYPTO_PROVIDER) && (defined(HITLS_CRYPTO_DSA) && defined(HITLS_CRYPTO_DSA))
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyBypem = NULL;
    CRYPT_EAL_PkeyCtx *pkeyByAsn1 = NULL;
    BSL_Buffer decodeAsn1 = {0};
    BSL_Buffer encodeAsn1 = {0};
    BSL_Buffer encodePem = {0};
    BSL_Buffer pem = {0};
    decodeAsn1.data = BSL_SAL_Malloc(asn1->len);
    decodeAsn1.dataLen = asn1->len;
    memcpy_s(decodeAsn1.data, asn1->len, asn1->x, asn1->len);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyBypem), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, fileType, &decodeAsn1, NULL, 0, &pkeyByAsn1), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(pkeyBypem, pkeyByAsn1), 0);

    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyBypem, NULL, BSL_FORMAT_ASN1, fileType, &encodeAsn1), CRYPT_SUCCESS);
    ASSERT_COMPARE("asn1 compare.", encodeAsn1.data, encodeAsn1.dataLen, asn1->x, asn1->len);

    ASSERT_EQ(BSL_SAL_ReadFile(path, &pem.data, &pem.dataLen), 0);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(pkeyByAsn1, NULL, BSL_FORMAT_PEM, fileType, &encodePem), CRYPT_SUCCESS);
    ASSERT_COMPARE("asn1 compare.", encodePem.data, encodePem.dataLen, pem.data, pem.dataLen);

    CRYPT_EAL_PkeyCtx *decpkeyBypem = NULL;
    CRYPT_EAL_PkeyCtx *decpkeyByAsn1 = NULL;
    BSL_Buffer decodeAsn1_2 = {0};
    decodeAsn1_2.data = BSL_SAL_Malloc(encodeAsn1.dataLen);
    decodeAsn1_2.dataLen = encodeAsn1.dataLen;
    memcpy_s(decodeAsn1_2.data, encodeAsn1.dataLen, encodeAsn1.data, encodeAsn1.dataLen);
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &decpkeyBypem), CRYPT_SUCCESS);
    ASSERT_EQ(
        CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, fileType, &decodeAsn1_2, NULL, 0, &decpkeyByAsn1), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCmp(decpkeyBypem, decpkeyByAsn1), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(decpkeyBypem, pkeyBypem), 0);
    ASSERT_EQ(CRYPT_EAL_PkeyCmp(pkeyByAsn1, decpkeyByAsn1), 0);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkeyBypem);
    CRYPT_EAL_PkeyFreeCtx(pkeyByAsn1);
    CRYPT_EAL_PkeyFreeCtx(decpkeyBypem);
    CRYPT_EAL_PkeyFreeCtx(decpkeyByAsn1);
    BSL_SAL_FREE(decodeAsn1.data);
    BSL_SAL_FREE(decodeAsn1_2.data);
    BSL_SAL_FREE(encodePem.data);
    BSL_SAL_FREE(encodeAsn1.data);
    BSL_SAL_FREE(pem.data);
#else
    (void)path;
    (void)fileType;
    (void)asn1;
    SKIP_TEST();
#endif
}
/* END_CASE */

#if defined(HITLS_CRYPTO_PROVIDER) && (defined(HITLS_CRYPTO_DSA) && defined(HITLS_CRYPTO_DSA))
static void Set_DSA_Pub(CRYPT_EAL_PkeyPub *pub, uint8_t *key, uint32_t keyLen)
{
    pub->id = CRYPT_PKEY_DSA;
    pub->key.dsaPub.data = key;
    pub->key.dsaPub.len = keyLen;
}

static void Set_DSA_Prv(CRYPT_EAL_PkeyPrv *prv, uint8_t *key, uint32_t keyLen)
{
    prv->id = CRYPT_PKEY_DSA;
    prv->key.dsaPrv.data = key;
    prv->key.dsaPrv.len = keyLen;
}

static void Set_DH_Prv(CRYPT_EAL_PkeyPrv *prv, uint8_t *key, uint32_t keyLen)
{
    prv->id = CRYPT_PKEY_DH;
    prv->key.dhPrv.data = key;
    prv->key.dhPrv.len = keyLen;
}

static void Set_DH_Pub(CRYPT_EAL_PkeyPub *pub, uint8_t *key, uint32_t keyLen)
{
    pub->id = CRYPT_PKEY_DH;
    pub->key.dhPub.data = key;
    pub->key.dhPub.len = keyLen;
}
#endif

/*
@test SDV_PKCS8_ERROR_ENCDEC_TC001
@title Encoding abnormal keys
@step
1.Generate a dh key and tamper with the dh key
2.Call CRYPT_EAL_EncodeBuffKey to encode the key
@expect
1.Key generation succeeds
2.Decoding succeeds
*/
/* BEGIN_CASE */
void SDV_PKCS8_ERROR_ENCDEC_TC001()
{
#if defined(HITLS_CRYPTO_PROVIDER) && (defined(HITLS_CRYPTO_DSA) && defined(HITLS_CRYPTO_DSA))
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);

    CRYPT_EAL_PkeyCtx *dsakey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, BSL_CID_DSA, 0, NULL);
    ASSERT_NE(dsakey, NULL);
    int32_t algId = CRYPT_MD_SHA256;
    uint32_t L = 2048;
    uint32_t N = 256;
    uint32_t seedLen = 256;
    int32_t index = 0;
    BSL_Param params[6] = {
        {CRYPT_PARAM_DSA_ALGID, BSL_PARAM_TYPE_INT32, &algId, sizeof(int32_t), 0},
        {CRYPT_PARAM_DSA_PBITS, BSL_PARAM_TYPE_UINT32, &L, sizeof(uint32_t), 0},
        {CRYPT_PARAM_DSA_QBITS, BSL_PARAM_TYPE_UINT32, &N, sizeof(uint32_t), 0},
        {CRYPT_PARAM_DSA_SEEDLEN, BSL_PARAM_TYPE_UINT32, &seedLen, sizeof(uint32_t), 0},
        {CRYPT_PARAM_DSA_GINDEX, BSL_PARAM_TYPE_INT32, &index, sizeof(int32_t), 0},
        BSL_PARAM_END
    };
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(dsakey, CRYPT_CTRL_GEN_PARA, params, 0), CRYPT_SUCCESS);
    uint32_t genFlag = 0;
    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(dsakey, CRYPT_CTRL_SET_GEN_FLAG, &genFlag, sizeof(genFlag)), CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(dsakey), CRYPT_SUCCESS);

    BSL_Buffer encDSAAsn1 = {0};
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(dsakey, NULL, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encDSAAsn1),
                CRYPT_SUCCESS);
    BSL_SAL_FREE(encDSAAsn1.data);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(dsakey, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encDSAAsn1), CRYPT_SUCCESS);

    uint8_t pubKey[1030];
    uint32_t pubKeyLen = sizeof(pubKey);
    uint8_t prvKey[1030];
    uint32_t prvKeyLen = sizeof(prvKey);
    uint8_t wrong[1030] = {1};
    CRYPT_EAL_PkeyPub pub = {0};
    CRYPT_EAL_PkeyPrv prv = {0};
    Set_DSA_Pub(&pub, pubKey, pubKeyLen);
    Set_DSA_Prv(&prv, prvKey, prvKeyLen);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(dsakey, &pub) == CRYPT_SUCCESS);
    pub.key.dsaPub.data = wrong;

    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(dsakey, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyPairCheck(dsakey, dsakey) == CRYPT_DSA_PAIRWISE_CHECK_FAIL);

    BSL_SAL_FREE(encDSAAsn1.data);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(dsakey, NULL, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encDSAAsn1),
                CRYPT_SUCCESS);
    BSL_SAL_FREE(encDSAAsn1.data);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(dsakey, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encDSAAsn1), CRYPT_SUCCESS);

    // DH
    CRYPT_EAL_PkeyCtx *dhkey = CRYPT_EAL_ProviderPkeyNewCtx(NULL, BSL_CID_DH, 0, NULL);
    ASSERT_TRUE(CRYPT_EAL_PkeySetParaById(dhkey, CRYPT_DH_RFC3526_2048) == CRYPT_SUCCESS);
    ASSERT_EQ(CRYPT_EAL_PkeyGen(dhkey), 0);

    BSL_Buffer encDHAsn1 = {0};
    ASSERT_EQ(
        CRYPT_EAL_EncodeBuffKey(dhkey, NULL, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encDHAsn1), CRYPT_SUCCESS);
    BSL_SAL_FREE(encDHAsn1.data);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(dhkey, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encDHAsn1), CRYPT_SUCCESS);

    Set_DH_Pub(&pub, pubKey, pubKeyLen);
    Set_DH_Prv(&prv, prvKey, prvKeyLen);
    ASSERT_TRUE(CRYPT_EAL_PkeyGetPub(dhkey, &pub) == CRYPT_SUCCESS);
    pub.key.dhPub.data = wrong;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPub(dhkey, &pub) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyPairCheck(dhkey, dhkey) == CRYPT_DH_PAIRWISE_CHECK_FAIL);

    BSL_SAL_FREE(encDHAsn1.data);
    ASSERT_EQ(
        CRYPT_EAL_EncodeBuffKey(dhkey, NULL, BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, &encDHAsn1), CRYPT_SUCCESS);
    BSL_SAL_FREE(encDHAsn1.data);
    ASSERT_EQ(CRYPT_EAL_EncodeBuffKey(dhkey, NULL, BSL_FORMAT_ASN1, CRYPT_PUBKEY_SUBKEY, &encDHAsn1), CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(dsakey);
    CRYPT_EAL_PkeyFreeCtx(dhkey);
    BSL_SAL_FREE(encDSAAsn1.data);
    BSL_SAL_FREE(encDHAsn1.data);
#else
    SKIP_TEST();
#endif
}
/* END_CASE */

/*
@test SDV_PKCS8_ERROR_ENCDEC_TC002
@title Decoding abnormal encoded data
@step
1.openHiTLS calls CRYPT_EAL_DecodeFileKey interface to decode abnormal data
@expect
1.Decoding fails
*/
/* BEGIN_CASE */
void SDV_PKCS8_ERROR_ENCDEC_TC002(char *path, int fileType,  Hex *asn1)
{
#if defined(HITLS_CRYPTO_PROVIDER) && (defined(HITLS_CRYPTO_DSA) && defined(HITLS_CRYPTO_DSA))
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyBypem = NULL;
    CRYPT_EAL_PkeyCtx *pkeyByAsn1 = NULL;
    BSL_Buffer decodeAsn1 = {0};
    decodeAsn1.data = BSL_SAL_Malloc(asn1->len);
    decodeAsn1.dataLen = asn1->len;
    memcpy_s(decodeAsn1.data, asn1->len, asn1->x, asn1->len);
    ASSERT_NE(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyBypem), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, fileType, &decodeAsn1, NULL, 0, &pkeyByAsn1), CRYPT_SUCCESS);
EXIT:
    BSL_SAL_FREE(decodeAsn1.data);
    CRYPT_EAL_PkeyFreeCtx(pkeyBypem);
    CRYPT_EAL_PkeyFreeCtx(pkeyByAsn1);
#else
    (void)path;
    (void)fileType;
    (void)asn1;
    SKIP_TEST();
#endif
}
/* END_CASE */

/*
@test SDV_PKCS8_ERROR_ENCDEC_TC003
@title Decoding empty pem and asn1
@step
1.openHiTLS calls CRYPT_EAL_DecodeFileKey interface to decode empty pem and asn1 data
@expect
1.Decoding fails
*/
/* BEGIN_CASE */
void SDV_PKCS8_ERROR_ENCDEC_TC003(char *path, int fileType,  Hex *asn1)
{
#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_DSA)
    CRYPT_EAL_Init(CRYPT_EAL_INIT_CPU|CRYPT_EAL_INIT_PROVIDER|CRYPT_EAL_INIT_PROVIDER_RAND);
    CRYPT_RandRegist(RandFunc);
    CRYPT_RandRegistEx(RandFuncEx);
    CRYPT_EAL_PkeyCtx *pkeyBypem = NULL;
    CRYPT_EAL_PkeyCtx *pkeyByAsn1 = NULL;
    BSL_Buffer decodeAsn1 = {0};
    decodeAsn1.data = BSL_SAL_Malloc(asn1->len);
    decodeAsn1.dataLen = asn1->len;
    memcpy_s(decodeAsn1.data, asn1->len, asn1->x, asn1->len);
    ASSERT_NE(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, path, NULL, 0, &pkeyBypem), CRYPT_SUCCESS);
    ASSERT_NE(
        CRYPT_EAL_DecodeFileKey(BSL_FORMAT_UNKNOWN, fileType, "eeeeeeee\a.pem", NULL, 0, &pkeyBypem), CRYPT_SUCCESS);
    ASSERT_NE(CRYPT_EAL_DecodeBuffKey(BSL_FORMAT_ASN1, fileType, &decodeAsn1, NULL, 0, &pkeyByAsn1), CRYPT_SUCCESS);
EXIT:
    BSL_SAL_FREE(decodeAsn1.data);
    CRYPT_EAL_PkeyFreeCtx(pkeyBypem);
    CRYPT_EAL_PkeyFreeCtx(pkeyByAsn1);
#else
    (void)path;
    (void)fileType;
    (void)asn1;
    SKIP_TEST();
#endif
}
/* END_CASE */