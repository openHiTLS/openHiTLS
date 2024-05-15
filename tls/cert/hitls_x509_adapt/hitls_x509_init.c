/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <stdint.h>
#include <stddef.h>
#include "hitls_error.h"
#include "hitls_cert_reg.h"
#include "hitls_x509_adapt_local.h"

int32_t HITLS_CertMethodInit(void)
{
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
        .encrypt = HITLS_X509_Adapt_Encrypt,
        .decrypt = HITLS_X509_Adapt_Decrypt,

        .checkPrivateKey = HITLS_X509_Adapt_CheckPrivateKey,
    };

    return HITLS_CERT_RegisterMgrMethod(&mgr);
}

int32_t HITLS_CertMethodDeInit(void)
{
    HITLS_CERT_DeinitMgrMethod();
    return HITLS_SUCCESS;
}
