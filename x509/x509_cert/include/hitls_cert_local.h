/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HITLS_CERT_LOCAL_H
#define HITLS_CERT_LOCAL_H

#include <stdint.h>
#include "bsl_asn1.h"
#include "bsl_obj.h"
#include "sal_atomic.h"
#include "hitls_x509_local.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HITLS_X509_EXT_KU_DIGITAL_SIGN       0x0080
#define HITLS_X509_EXT_KU_NON_REPUDIATION    0x0040
#define HITLS_X509_EXT_KU_KEY_ENCIPHERMENT   0x0020
#define HITLS_X509_EXT_KU_DATA_ENCIPHERMENT  0x0010
#define HITLS_X509_EXT_KU_KEY_AGREEMENT      0x0008
#define HITLS_X509_EXT_KU_KEY_CERT_SIGN      0x0004
#define HITLS_X509_EXT_KU_CRL_SIGN           0x0002
#define HITLS_X509_EXT_KU_ENCIPHER_ONLY      0x0001
#define HITLS_X509_EXT_KU_DECIPHER_ONLY      0x8000

#define HITLS_X509_CERT_EXT_FLAG_KUSAGE (1 << 0)
#define HITLS_X509_CERT_EXT_FLAG_BCONS (1 << 1)

typedef struct _HITLS_X509_CertExt {
    BslList *list;
    uint32_t extFlags;
    // basic usage ext
    bool isCa;
    // -1 no check, 0 no intermediate certificate
    int32_t maxPathLen;
    // key usage ext
    uint64_t keyUsage;
} HITLS_X509_CertExt;

typedef struct {
    uint8_t *tbsRawData;
    uint32_t tbsRawDataLen;
    
    int32_t version;
    BSL_ASN1_Buffer serialNum;
    HITLS_X509_Asn1AlgId signAlgId;

    BSL_ASN1_List *issuerName;
    HITLS_X509_ValidTime validTime;
    BSL_ASN1_List *subjectName;

    void *ealPubKey;
    HITLS_X509_CertExt ext;
} HITLS_X509_CertTbs;

typedef struct _HITLS_X509_Cert {
    bool isCopy;
    uint8_t *rawData;
    uint32_t rawDataLen;
    HITLS_X509_CertTbs tbs;
    HITLS_X509_Asn1AlgId signAlgId;
    BSL_ASN1_BitString signature;
    BSL_SAL_RefCount references;
} HITLS_X509_Cert;

#ifdef __cplusplus
}
#endif

#endif // HITLS_CERT_LOCAL_H