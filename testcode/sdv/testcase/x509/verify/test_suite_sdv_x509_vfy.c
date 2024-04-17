/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/* BEGIN_HEADER */
#include "bsl_sal.h"
#include "securec.h"
#include "hitls_x509.h"
#include "hitls_x509_errno.h"
#include "bsl_type.h"
#include "bsl_log.h"
#include "bsl_init.h"
#include "bsl_list.h"
#include "hitls_verify_local.h"

/* END_HEADER */

void BinLogFixLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para1, void *para2, void *para3, void *para4)
{
    (void)logLevel;
    (void)logType;
    printf("logId:%u\t", logId);
    printf(format, para1, para2, para3, para4);
    printf("\n");
}

void BinLogVarLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para)
{
    (void)logLevel;
    (void)logType;
    printf("logId:%u\t", logId);
    printf(format, para);
    printf("\n");
}

void HITLS_X509_FreeStoreCtxMock(HITLS_X509_StoreCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    int ret;
    (void)BSL_SAL_AtomicDownReferences(&ctx->references, &ret);
    if (ret > 0) {
        return;
    }

    if (ctx->store != NULL) {
        BSL_LIST_FREE(ctx->store, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeCert);
    }
    if (ctx->crl != NULL) {
        BSL_LIST_FREE(ctx->crl, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeCrl);
    }

    BSL_SAL_ReferencesFree(&ctx->references);
    BSL_SAL_Free(ctx);
}

HITLS_X509_StoreCtx *HITLS_X509_NewStoreCtxMock(void)
{
    HITLS_X509_StoreCtx *ctx = (HITLS_X509_StoreCtx *)BSL_SAL_Malloc(sizeof(HITLS_X509_StoreCtx));
    if (ctx == NULL) {
        return NULL;
    }

    (void)memset_s(ctx, sizeof(HITLS_X509_StoreCtx), 0, sizeof(HITLS_X509_StoreCtx));
    ctx->store = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    if (ctx->store == NULL) {
        BSL_SAL_Free(ctx);
        return NULL;
    }
    ctx->crl = BSL_LIST_New(sizeof(HITLS_X509_Crl *));
    if (ctx->crl == NULL) {
        BSL_SAL_FREE(ctx->store);
        BSL_SAL_Free(ctx);
        return NULL;
    }
    ctx->verifyParam.maxDepth = 20;
    ctx->verifyParam.securityBits = 128;
    ctx->verifyParam.flags |= HITLS_X509_VFY_FLAG_CRL_ALL;
    ctx->verifyParam.flags |= HITLS_X509_VFY_FLAG_SECBITS;
    BSL_SAL_ReferencesInit(&(ctx->references));
    return ctx;
}

static int32_t HITLS_ParseCrlTest(char *path, HITLS_X509_Crl **crl)
{
    *crl = HITLS_X509_NewCrl();
    if (*crl == NULL) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    int32_t ret = HITLS_X509_ParseFileCrl(BSL_PARSE_FORMAT_ASN1, path, *crl);
    if (ret != HITLS_X509_SUCCESS) {
        return ret;
    }
    return ret;
}

static int32_t HITLS_ParseCertTest(char *path, HITLS_X509_Cert **cert)
{
    *cert = HITLS_X509_NewCert();
    if (*cert == NULL) {
        return HITLS_X509_ERR_INVALID_PARAM;
    }

    int32_t ret = HITLS_X509_ParseFileCert(BSL_PARSE_FORMAT_ASN1, path, *cert);
    if (ret != HITLS_X509_SUCCESS) {
        return ret;
    }
    return ret;
}

static int32_t HITLS_BuildChain(BslList *list, int type,
    char *path1, char *path2, char *path3, char *path4, char *path5)
{
    int32_t ret;
    
    char *path[] = {path1, path2, path3, path4, path5};
    for (size_t i = 0; i < sizeof(path) / sizeof(path[0]); i++) {
        if (path[i] == NULL) {
            continue;
        }
        if (type == 0) { // cert
            HITLS_X509_Cert *cert = NULL;
            ret = HITLS_ParseCertTest(path[i], &cert);
            if (ret != HITLS_X509_SUCCESS) {
                return ret;
            }
            ret = BSL_LIST_AddElement(list, cert, BSL_LIST_POS_END);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        } else { // crl
            HITLS_X509_Crl *crl = NULL;
            ret = HITLS_ParseCrlTest(path[i], &crl);
            if (ret != HITLS_X509_SUCCESS) {
                return ret;
            }
            ret = BSL_LIST_AddElement(list, crl, BSL_LIST_POS_END);
            if (ret != BSL_SUCCESS) {
                return ret;
            }
        }
    }
    return ret;
}

/* BEGIN_CASE */
void SDV_X509_STORE_VFY_PARAM_EXR_FUNC_TC001(char *path1, char *path2, char *path3, int secBits, int exp)
{
    int ret;
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_StoreCtx *storeCtx = NULL;
    storeCtx = HITLS_X509_NewStoreCtxMock();
    ASSERT_NE(storeCtx, NULL);
    storeCtx->verifyParam.securityBits = secBits;
    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ret = HITLS_BuildChain(chain, 0, path1, path2, path3, NULL, NULL);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);
    ret = HITLS_X509_VerifyParamAndExt(storeCtx, chain);
    ASSERT_EQ(ret, exp);
exit:
    HITLS_X509_FreeStoreCtxMock(storeCtx);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeCert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */


/* BEGIN_CASE */
void SDV_X509_STORE_VFY_CRL_FUNC_TC001(int type, int expResult, char *path1, char *path2, char *path3,
    char *crl1, char *crl2)
{
    int ret;
    TestMemInit();
    BSL_GLOBAL_Init();
    HITLS_X509_StoreCtx *storeCtx = NULL;
    storeCtx = HITLS_X509_NewStoreCtxMock();
    ASSERT_NE(storeCtx, NULL);
    if (type == 1) {
        storeCtx->verifyParam.flags ^= HITLS_X509_VFY_FLAG_CRL_ALL;
        storeCtx->verifyParam.flags |= HITLS_X509_VFY_FLAG_CRL_DEV;
    }

    BslList *chain = BSL_LIST_New(sizeof(HITLS_X509_Cert *));
    ASSERT_NE(chain, NULL);
    ret = HITLS_BuildChain(chain, 0, path1, path2, path3, NULL, NULL);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ret = HITLS_BuildChain(storeCtx->crl, 1, crl1, crl2, NULL, NULL, NULL);
    ASSERT_EQ(ret, HITLS_X509_SUCCESS);

    ret = HITLS_X509_VerifyCrl(storeCtx, chain);
    ASSERT_EQ(ret, expResult);
exit:
    HITLS_X509_FreeStoreCtxMock(storeCtx);
    BSL_LIST_FREE(chain, (BSL_LIST_PFUNC_FREE)HITLS_X509_FreeCert);
    BSL_GLOBAL_DeInit();
}
/* END_CASE */