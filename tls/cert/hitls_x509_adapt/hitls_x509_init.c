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
#include <stdint.h>
#include <stddef.h>
#include "hitls_error.h"
#include "hitls_cert_reg.h"
#include "hitls_x509_adapt.h"

int32_t HITLS_CertMethodInit(void)
{
#ifdef HITLS_TLS_CALLBACK_CERT
    HITLS_CERT_MgrMethod mgr = {
        .certStoreNew = (CERT_StoreNewCallBack)HITLS_X509_Adapt_StoreNew,
        .certStoreDup = (CERT_StoreDupCallBack)HITLS_X509_Adapt_StoreDup,
        .certStoreFree = (CERT_StoreFreeCallBack)HITLS_X509_Adapt_StoreFree,
        .certStoreCtrl = (CERT_StoreCtrlCallBack)HITLS_X509_Adapt_StoreCtrl,
        .buildCertChain = (CERT_BuildCertChainCallBack)HITLS_X509_Adapt_BuildCertChain,
        .verifyCertChain = (CERT_VerifyCertChainCallBack)HITLS_X509_Adapt_VerifyCertChain,

        .certEncode = (CERT_CertEncodeCallBack)HITLS_X509_Adapt_CertEncode,
        .certParse = (CERT_CertParseCallBack)HITLS_X509_Adapt_CertParse,
        .certDup = (CERT_CertDupCallBack)HITLS_X509_Adapt_CertDup,
        .certRef = (CERT_CertRefCallBack)HITLS_X509_Adapt_CertRef,
        .certFree = (CERT_CertFreeCallBack)HITLS_X509_Adapt_CertFree,
        .certCtrl = (CERT_CertCtrlCallBack)HITLS_X509_Adapt_CertCtrl,

        .keyParse = (CERT_KeyParseCallBack)HITLS_X509_Adapt_KeyParse,
        .keyDup = (CERT_KeyDupCallBack)HITLS_X509_Adapt_KeyDup,
        .keyFree = (CERT_KeyFreeCallBack)HITLS_X509_Adapt_KeyFree,
        .keyCtrl = (CERT_KeyCtrlCallBack)HITLS_X509_Adapt_KeyCtrl,

        .createSign = (CERT_CreateSignCallBack)HITLS_X509_Adapt_CreateSign,
        .verifySign = (CERT_VerifySignCallBack)HITLS_X509_Adapt_VerifySign,
#if defined(HITLS_TLS_SUITE_KX_RSA) || defined(HITLS_TLS_PROTO_TLCP11)
        .encrypt = (CERT_EncryptCallBack)HITLS_X509_Adapt_Encrypt,
        .decrypt = (CERT_DecryptCallBack)HITLS_X509_Adapt_Decrypt,
#endif

        .checkPrivateKey = (CERT_CheckPrivateKeyCallBack)HITLS_X509_Adapt_CheckPrivateKey,
    };

    return HITLS_CERT_RegisterMgrMethod(&mgr);
#else
    return HITLS_SUCCESS;
#endif
}

void HITLS_CertMethodDeinit(void)
{
#ifdef HITLS_TLS_CALLBACK_CERT
    HITLS_CERT_DeinitMgrMethod();
#endif
}
