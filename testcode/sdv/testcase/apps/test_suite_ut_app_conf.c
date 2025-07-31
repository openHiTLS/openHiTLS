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
#include <stdint.h>

#include "hitls_pki_errno.h"
#include "hitls_csr_local.h"
#include "app_errno.h"
#include "app_conf.h"

/* END_HEADER */
#define MAX_STR_CNT (10)

/* BEGIN_CASE */
void UT_HITLS_APP_SplitString_Api_TC001(void)
{
    char *res[MAX_STR_CNT] = {0};
    uint32_t cnt = 0;
    char *in = "Aa,Bb";
    char separator = ',';

    ASSERT_EQ(HITLS_APP_SplitString(NULL, separator, 1, res, MAX_STR_CNT, &cnt), HITLS_APP_INVALID_ARG);
    ASSERT_EQ(HITLS_APP_SplitString("", separator, 1, res, MAX_STR_CNT, &cnt), HITLS_APP_INVALID_ARG);
    ASSERT_EQ(HITLS_APP_SplitString(in, ' ', 1, res, MAX_STR_CNT, &cnt), HITLS_APP_INVALID_ARG);
    ASSERT_EQ(HITLS_APP_SplitString(in, separator, 1, NULL, MAX_STR_CNT, &cnt), HITLS_APP_INVALID_ARG);
    ASSERT_EQ(HITLS_APP_SplitString(in, separator, 1, res, 0, &cnt), HITLS_APP_INVALID_ARG);
    ASSERT_EQ(HITLS_APP_SplitString(in, separator, 1, res, MAX_STR_CNT, NULL), HITLS_APP_INVALID_ARG);

EXIT:
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APP_SplitString_Func_TC001(
    char *in, int allowEmpty, int expectCnt, char *expect1, char *expect2, char *expect3)
{
    char *res[MAX_STR_CNT] = {0};
    uint32_t cnt = 0;
    char separator = ',';
    char *expect[MAX_STR_CNT] = {expect1, expect2, expect3};

    ASSERT_EQ(HITLS_APP_SplitString(in, separator, allowEmpty, res, MAX_STR_CNT, &cnt), HITLS_APP_SUCCESS);
    ASSERT_EQ(cnt, expectCnt);
    for (uint32_t i = 0; i < cnt; i++) {
        ASSERT_EQ(strcmp(expect[i], res[i]), 0);
    }

EXIT:
    BSL_SAL_Free(res[0]);
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APP_SplitString_Error_TC001(char *in, int allowEmpty)
{
    char *res[MAX_STR_CNT] = {0};
    uint32_t cnt = 0;
    char separator = ',';

    ASSERT_EQ(HITLS_APP_SplitString(in, separator, allowEmpty, res, MAX_STR_CNT, &cnt), HITLS_APP_CONF_FAIL);

EXIT:
    BSL_SAL_FREE(res[0]);
}
/* END_CASE */

#define HITLS_X509_CSR_GEN_FLAG    0x02

/* BEGIN_CASE */
void UT_HITLS_APP_conf_subj_TC001(char *subjectName, int expectRet, int expectCnt, Hex *expectEncode)
{
    HITLS_X509_Csr *csr = HITLS_X509_CsrNew();
    ASSERT_NE(csr, NULL);
    BslList *csrSubject = NULL;
    BSL_ASN1_Buffer name = {0};
    BSL_Buffer nameEncoded = {0};
    ASSERT_EQ(HITLS_APP_CFG_ProcDnName(subjectName, HiTLS_AddSubjDnNameToCsr, csr), expectRet);
    if (expectRet == HITLS_APP_SUCCESS) {
        ASSERT_EQ(HITLS_X509_CsrCtrl(csr, HITLS_X509_GET_SUBJECT_DN, &csrSubject, sizeof(BslList *)), 0);
        ASSERT_EQ(BSL_LIST_COUNT(csrSubject), expectCnt);
        if (expectCnt != 0) {
            ASSERT_EQ(HITLS_X509_EncodeNameList(csrSubject, &name), 0);
            BSL_ASN1_TemplateItem item = {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0};
            BSL_ASN1_Template templ = {&item, 1};
            ASSERT_EQ(BSL_ASN1_EncodeTemplate(&templ, &name, 1, &nameEncoded.data, &nameEncoded.dataLen), 0);
            ASSERT_EQ(expectEncode->len, nameEncoded.dataLen);
            ASSERT_EQ(memcmp(expectEncode->x, nameEncoded.data, expectEncode->len), 0);
        }
    }
    
EXIT:
    BSL_SAL_FREE(nameEncoded.data);
    BSL_SAL_FREE(name.buff);
    HITLS_X509_CsrFree(csr);
    return;
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APP_conf_subj_TC002(void)
{
    HITLS_X509_Csr *csr = HITLS_X509_CsrNew();
    ASSERT_NE(csr, NULL);
    ASSERT_EQ(HITLS_APP_CFG_ProcDnName(NULL, HiTLS_AddSubjDnNameToCsr, csr), HITLS_APP_INVALID_ARG);
    ASSERT_EQ(HITLS_APP_CFG_ProcDnName("/ABC=1", NULL, NULL), HITLS_APP_INVALID_ARG);
    ASSERT_EQ(HITLS_APP_CFG_ProcDnName("/ABC=1", HiTLS_AddSubjDnNameToCsr, NULL), HITLS_APP_SUCCESS);
    ASSERT_EQ(HITLS_APP_CFG_ProcDnName("/pseudonym=testabc#", HiTLS_AddSubjDnNameToCsr, NULL), HITLS_APP_INVALID_ARG);
    ASSERT_EQ(HITLS_APP_CFG_ProcDnName("ABC", HiTLS_AddSubjDnNameToCsr, csr), HITLS_APP_INVALID_ARG);
    ASSERT_EQ(HITLS_APP_CFG_ProcDnName("/", HiTLS_AddSubjDnNameToCsr, csr), HITLS_APP_INVALID_ARG);
EXIT:
    HITLS_X509_CsrFree(csr);
    return;
}
/* END_CASE */

static int32_t ProcExt(BslCid cid, void *val, void *ctx)
{
    HITLS_X509_Ext *ext = ctx;
    switch (cid) {
        case BSL_CID_CE_SUBJECTALTNAME:
            return HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_SAN, val, sizeof(HITLS_X509_ExtSan));
        case BSL_CID_CE_BASICCONSTRAINTS:
            return HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_BCONS, val, sizeof(HITLS_X509_ExtBCons));
        case BSL_CID_CE_KEYUSAGE:
            return HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_KUSAGE, val, sizeof(HITLS_X509_ExtKeyUsage));
        case BSL_CID_CE_EXTKEYUSAGE:
            return HITLS_X509_ExtCtrl(ext, HITLS_X509_EXT_SET_EXKUSAGE, val, sizeof(HITLS_X509_ExtExKeyUsage));
        default:
            return HITLS_APP_CONF_FAIL;
    }
}

/* BEGIN_CASE */
void UT_HITLS_APP_conf_X509Ext_TC001(char *confPath, int expectLoadRet, int expectResult, Hex *expectAsn)
{
    BSL_CONF *conf = NULL;
    BSL_ASN1_Buffer asnExt = {0};
    HITLS_X509_Ext *ext = HITLS_X509_ExtNew(HITLS_X509_EXT_TYPE_CSR);
    ASSERT_NE(ext, NULL);
    conf = BSL_CONF_New(BSL_CONF_DefaultMethod());
    ASSERT_NE(conf, NULL);
    ASSERT_EQ(BSL_CONF_Load(conf, confPath), expectLoadRet);
    if (expectLoadRet == HITLS_APP_SUCCESS) {
        ASSERT_EQ(HITLS_APP_CONF_ProcExt(conf, "SAN", ProcExt, ext), expectResult);
        if (expectResult == HITLS_APP_SUCCESS) {
            ASSERT_EQ(HITLS_X509_EncodeExt(BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, ext->extList, &asnExt),
                HITLS_PKI_SUCCESS);
            ASSERT_EQ(asnExt.len, expectAsn->len);
            ASSERT_EQ(memcmp(asnExt.buff, expectAsn->x, expectAsn->len), 0);
        }
    }
EXIT:
    BSL_SAL_FREE(asnExt.buff);
    HITLS_X509_ExtFree(ext);
    BSL_CONF_Free(conf);
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APP_conf_X509Ext_TC002(void)
{
    HITLS_X509_Ext *ext = HITLS_X509_ExtNew(HITLS_X509_EXT_TYPE_CSR);
    BSL_CONF conf = {};
    ASSERT_NE(ext, NULL);
    ASSERT_EQ(HITLS_APP_CONF_ProcExt(NULL, "SAN", ProcExt, ext), HITLS_APP_CONF_FAIL);
    ASSERT_EQ(HITLS_APP_CONF_ProcExt(&conf, NULL, ProcExt, ext), HITLS_APP_CONF_FAIL);
    ASSERT_EQ(HITLS_APP_CONF_ProcExt(&conf, "SAN", NULL, ext), HITLS_APP_CONF_FAIL);
    ASSERT_EQ(HITLS_APP_CONF_ProcExt(&conf, "SAN", ProcExt, NULL), HITLS_APP_CONF_FAIL);
    conf.data = NULL;
    ASSERT_EQ(HITLS_APP_CONF_ProcExt(&conf, "SAN", ProcExt, ext), HITLS_APP_CONF_FAIL);
EXIT:
    HITLS_X509_ExtFree(ext);
}
/* END_CASE */
