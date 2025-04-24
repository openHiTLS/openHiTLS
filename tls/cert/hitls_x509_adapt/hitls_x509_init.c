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
        .certStoreNew = HITLS_X509_Adapt_StoreNew,
        .certStoreDup = HITLS_X509_Adapt_StoreDup,
        .certStoreFree = HITLS_X509_Adapt_StoreFree,
        .certStoreCtrl = HITLS_X509_Adapt_StoreCtrl,
        .buildCertChain = HITLS_X509_Adapt_BuildCertChain,
        .verifyCertChain = HITLS_X509_Adapt_VerifyCertChain,

        .certEncode = HITLS_X509_Adapt_CertEncode,
        .certParse = HITLS_X509_Adapt_CertParse,
        .certDup = HITLS_X509_Adapt_CertDup,
        .certRef = HITLS_X509_Adapt_CertRef,
        .certFree = HITLS_X509_Adapt_CertFree,
        .certCtrl = HITLS_X509_Adapt_CertCtrl,

        .keyParse = HITLS_X509_Adapt_KeyParse,
        .keyDup = HITLS_X509_Adapt_KeyDup,
        .keyFree = HITLS_X509_Adapt_KeyFree,
        .keyCtrl = HITLS_X509_Adapt_KeyCtrl,
                   
        .createSign = HITLS_X509_Adapt_CreateSign,
        .verifySign = HITLS_X509_Adapt_VerifySign,
#if defined(HITLS_TLS_SUITE_KX_RSA) || defined(HITLS_TLS_PROTO_TLCP11)
        .encrypt = HITLS_X509_Adapt_Encrypt,
        .decrypt = HITLS_X509_Adapt_Decrypt,
#endif

        .checkPrivateKey = HITLS_X509_Adapt_CheckPrivateKey,
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
