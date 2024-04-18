/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/* BEGIN_HEADER */

#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "bsl_sal.h"
#include "bsl_asn1.h"
#include "bsl_err.h"
#include "bsl_log.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "crypt_eal_encode.h"
#include "crypt_util_rand.h"
#include "bsl_obj_internal.h"

/* END_HEADER */

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

int32_t BSL_ASN1_CertTagGetOrCheck(int32_t type, int32_t idx, void *data, void *expVal)
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
            BslCid cid = BSL_OBJ_GetCIDFromOid(&oidStr);
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
            BslCid cid = BSL_OBJ_GetCIDFromOid(&oidStr);
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

void BinLogFixLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType, void *format, void *para1, void *para2,
                      void *para3, void *para4)
{
    (void)logLevel;
    (void)logType;
    printf("logId:%u\t", logId);
    printf(format, para1, para2, para3, para4);
    printf("\n");
}

void BinLogVarLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType, void *format, void *para)
{
    (void)logLevel;
    (void)logType;
    printf("logId:%u\t", logId);
    printf(format, para);
    printf("\n");
}

static void RegisterLogFunc()
{
    BSL_LOG_BinLogFuncs func = {0};
    func.fixLenFunc = BinLogFixLenFunc;
    func.varLenFunc = BinLogVarLenFunc;
    BSL_LOG_RegBinLogFunc(&func);
}

static int32_t RandFunc(uint8_t *randNum, uint32_t randLen)
{
    for (uint32_t i = 0; i < randLen; i++) {
        randNum[i] = (uint8_t)rand();
    }

    return 0;
}

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_RSA_PRV_TC001(char *path, Hex *version, Hex *n, Hex *e, Hex *d, Hex *p, Hex *q, Hex *dp,
                                      Hex *dq, Hex *qinv, int mdId, Hex *msg, Hex *sign)
{
    RegisterLogFunc();

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
    CRYPT_RSA_PkcsV15Para pkcsv15 = {mdId};
    ASSERT_EQ(CRYPT_EAL_PkeySetPrv(pkeyCtx, &rsaPrv), CRYPT_SUCCESS);

    ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(CRYPT_RSA_PkcsV15Para)), 0);

    /* Malloc signature buffer */
    uint32_t signLen = CRYPT_EAL_PkeyGetSignLen(pkeyCtx);
    signdata = (uint8_t *)BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(signdata != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);
    ASSERT_COMPARE("CRYPT_EAL_PkeySign Compare", sign->x, sign->len, signdata, signLen);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
    BSL_SAL_FREE(signdata);
    BSL_SAL_FREE(rawBuff);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_PUBKEY_FILE_TC001(char *path, int fileType, int mdId, Hex *msg, Hex *sign)
{
    RegisterLogFunc();

    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    ASSERT_EQ(CRYPT_EAL_PubKeyFileParse(BSL_PARSE_FORMAT_ASN1, fileType, path, &pkeyCtx), CRYPT_SUCCESS);
    if (fileType == CRYPT_PUBKEY_RSA) {
        CRYPT_RSA_PkcsV15Para pkcsv15 = {mdId};
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(CRYPT_RSA_PkcsV15Para)),
                  0);
    }

    /* verify signature */
    ASSERT_EQ(CRYPT_EAL_PkeyVerify(pkeyCtx, mdId, msg->x, msg->len, sign->x, sign->len), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_SUBPUBKEY_TC001(int encodeType, Hex *subKeyInfo)
{
    RegisterLogFunc();
    BSL_Buffer buff;
    buff.data = subKeyInfo->x;
    buff.dataLen = subKeyInfo->len;

    CRYPT_EAL_PkeyCtx *pctx = NULL;
    ASSERT_EQ(CRYPT_EAL_PubKeyBuffParse(BSL_PARSE_FORMAT_ASN1, encodeType, &buff, &pctx), CRYPT_SUCCESS);

exit:
    CRYPT_EAL_PkeyFreeCtx(pctx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_PRIKEY_FILE_TC001(char *path, int fileType, int mdId, Hex *msg, Hex *sign)
{
    RegisterLogFunc();
    CRYPT_RandRegist(RandFunc);

    uint8_t *signdata = NULL;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    ASSERT_EQ(CRYPT_EAL_PriKeyFileParse(BSL_PARSE_FORMAT_ASN1, fileType, path, NULL, 0, &pkeyCtx), CRYPT_SUCCESS);
    if (fileType == CRYPT_PRIKEY_RSA || CRYPT_EAL_PkeyGetId(pkeyCtx) == CRYPT_PKEY_RSA) {
        CRYPT_RSA_PkcsV15Para pkcsv15 = {mdId};
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(CRYPT_RSA_PkcsV15Para)),
                  0);
    }

    /* Malloc signature buffer */
    uint32_t signLen = CRYPT_EAL_PkeyGetSignLen(pkeyCtx);
    signdata = (uint8_t *)BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(signdata != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);

    if (fileType == CRYPT_PRIKEY_RSA) {
        ASSERT_COMPARE("Signature Compare", sign->x, sign->len, signdata, signLen);
    }

exit:
    BSL_SAL_Free(signdata);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_BSL_ASN1_PARSE_ENCPK8_TC001(char *path, int fileType, Hex *pass, int mdId, Hex *msg, Hex *sign)
{
    RegisterLogFunc();
    CRYPT_RandRegist(RandFunc);

    uint8_t *signdata = NULL;
    CRYPT_EAL_PkeyCtx *pkeyCtx = NULL;
    ASSERT_EQ(CRYPT_EAL_PriKeyFileParse(BSL_PARSE_FORMAT_ASN1, fileType, path, pass->x, pass->len, &pkeyCtx),
              CRYPT_SUCCESS);
    if (fileType == CRYPT_PRIKEY_RSA || CRYPT_EAL_PkeyGetId(pkeyCtx) == CRYPT_PKEY_RSA) {
        CRYPT_RSA_PkcsV15Para pkcsv15 = {mdId};
        ASSERT_EQ(CRYPT_EAL_PkeyCtrl(pkeyCtx, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &pkcsv15, sizeof(CRYPT_RSA_PkcsV15Para)),
                  0);
    }

    /* Malloc signature buffer */
    uint32_t signLen = CRYPT_EAL_PkeyGetSignLen(pkeyCtx);
    signdata = (uint8_t *)BSL_SAL_Malloc(signLen);
    ASSERT_TRUE(signdata != NULL);
    ASSERT_EQ(CRYPT_EAL_PkeySign(pkeyCtx, mdId, msg->x, msg->len, signdata, &signLen), CRYPT_SUCCESS);

    if (fileType == CRYPT_PRIKEY_RSA) {
        ASSERT_COMPARE("Signature Compare", sign->x, sign->len, signdata, signLen);
    }

exit:
    BSL_SAL_Free(signdata);
    CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
}
/* END_CASE */