/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HITLS_CSR_LOCAL_H
#define HITLS_CSR_LOCAL_H

#include <stdint.h>
#include "bsl_asn1.h"
#include "bsl_obj.h"
#include "sal_atomic.h"
#include "hitls_x509_local.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _HITLS_X509_ReqInfo {
    uint8_t *reqInfoRawData;
    uint32_t reqInfoRawDataLen;
    int32_t version;
    BSL_ASN1_List *subjectName; /* Entry is HITLS_X509_NameNode */
    void *ealPubKey;
    BSL_ASN1_List *attributes;
} HITLS_X509_ReqInfo;

/* PKCS #10 */
typedef struct _HITLS_X509_Csr {
    int8_t flag; // Used to mark csr parsing or generation, indicating resource release behavior.
    uint8_t *rawData;
    uint32_t rawDataLen;
    void *ealPrivKey; // used to sign csr
    CRYPT_MD_AlgId signMdId;

    HITLS_X509_ReqInfo reqInfo;
    HITLS_X509_Asn1AlgId signAlgId;
    BSL_ASN1_BitString signature;
    BSL_SAL_RefCount references;
} HITLS_X509_Csr;

#ifdef __cplusplus
}
#endif

#endif // HITLS_CSR_LOCAL_H