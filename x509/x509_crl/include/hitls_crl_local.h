/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HITLS_CRL_LOCAL_H
#define HITLS_CRL_LOCAL_H

#include <stdint.h>
#include "bsl_asn1.h"
#include "bsl_obj.h"
#include "sal_atomic.h"
#include "hitls_x509_local.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    BSL_ASN1_List *extList;
} HITLS_X509_CrlExt;

typedef struct {
    BSL_ASN1_Buffer serialNumber;
    BSL_TIME time;
    BSL_ASN1_Buffer entryExt;
} HITLS_X509_CrlEntry;

typedef struct {
    uint8_t *tbsRawData;
    uint32_t tbsRawDataLen;
    
    int32_t version;
    HITLS_X509_Asn1AlgId signAlgId;

    BSL_ASN1_List *issuerName;
    HITLS_X509_ValidTime validTime;

    BSL_ASN1_List *revokedCerts;
    HITLS_X509_CrlExt crlExt;
} HITLS_X509_CrlTbs;

typedef struct _HITLS_X509_Crl {
    bool isCopy;
    uint8_t *rawData;
    uint32_t rawDataLen;
    HITLS_X509_CrlTbs tbs;
    HITLS_X509_Asn1AlgId signAlgId;
    BSL_ASN1_BitString signature;
    BSL_SAL_RefCount references;
} HITLS_X509_Crl;

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRL_LOCAL_H