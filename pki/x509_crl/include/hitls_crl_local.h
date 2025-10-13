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

#include "hitls_build.h"
#ifdef HITLS_PKI_X509_CRL
#include <stdint.h>
#include "bsl_asn1_internal.h"
#include "bsl_obj.h"
#include "sal_atomic.h"
#include "hitls_x509_local.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HITLS_X509_CRL_PARSE_FLAG  0x01
#define HITLS_X509_CRL_GEN_FLAG    0x02

#define BSL_TIME_REVOKE_TIME_IS_GMT  0x4

typedef struct _HITLS_X509_CrlEntry {
    uint8_t flag;
    BSL_ASN1_Buffer serialNumber;
    BSL_TIME time;
    BSL_ASN1_List *extList;
} HITLS_X509_CrlEntry;

typedef struct {
    uint8_t *tbsRawData;
    uint32_t tbsRawDataLen;

    int32_t version;
    HITLS_X509_Asn1AlgId signAlgId;

    BSL_ASN1_List *issuerName;
    HITLS_X509_ValidTime validTime;

    BSL_ASN1_List *revokedCerts;
    HITLS_X509_Ext crlExt;
} HITLS_X509_CrlTbs;

typedef enum {
    HITLS_X509_CRL_STATE_NEW = 0,
    HITLS_X509_CRL_STATE_SET,
    HITLS_X509_CRL_STATE_SIGN,
    HITLS_X509_CRL_STATE_GEN,
} HITLS_X509_CRL_STATE;

typedef struct _HITLS_X509_Crl {
    uint8_t flag;
    uint8_t state;

    uint8_t *rawData;
    uint32_t rawDataLen;
    HITLS_X509_CrlTbs tbs;
    HITLS_X509_Asn1AlgId signAlgId;
    BSL_ASN1_BitString signature;

    BSL_SAL_RefCount references;
} HITLS_X509_Crl;

int32_t HITLS_ParseCrlExtReason(HITLS_X509_ExtEntry *extEntry, void *val);

int32_t HITLS_ParseCrlExtInvalidTime(HITLS_X509_ExtEntry *extEntry, void *val);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_X509_CRL

#endif // HITLS_CRL_LOCAL_H