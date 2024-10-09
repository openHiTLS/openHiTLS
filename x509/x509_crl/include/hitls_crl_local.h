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
    uint8_t flag;
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

HITLS_X509_Crl *HITLS_X509_CrlNew(void);
int32_t HITLS_X509_CrlMulParseBuff(int32_t format, BSL_Buffer *encode, HITLS_X509_List **crllist);
int32_t HITLS_X509_EncodeCrlTbs(HITLS_X509_CrlTbs *crlTbs, BSL_ASN1_Buffer *asn);
#ifdef __cplusplus
}
#endif

#endif // HITLS_CRL_LOCAL_H