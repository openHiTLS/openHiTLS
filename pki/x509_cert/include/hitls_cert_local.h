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

#ifndef HITLS_CERT_LOCAL_H
#define HITLS_CERT_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_PKI_X509_CRT
#include <stdint.h>
#include <stdbool.h>
#include "bsl_asn1_internal.h"
#include "bsl_obj.h"
#include "sal_atomic.h"
#include "hitls_x509_local.h"

#ifdef __cplusplus
extern "C" {
#endif

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
    HITLS_X509_Ext ext;
} HITLS_X509_CertTbs;

typedef enum {
    HITLS_X509_CERT_STATE_NEW = 0,
    HITLS_X509_CERT_STATE_SET,
    HITLS_X509_CERT_STATE_SIGN,
    HITLS_X509_CERT_STATE_GEN,
} HITLS_X509_CERT_STATE;

typedef struct _HITLS_X509_Cert {
    uint8_t flag; // Used to mark certificate parsing or generation, indicating resource release behavior.
    uint8_t state;
    bool isProvider;

    uint8_t *rawData;
    uint32_t rawDataLen;
    HITLS_X509_CertTbs tbs;
    HITLS_X509_Asn1AlgId signAlgId;
    BSL_ASN1_BitString signature;

    BSL_SAL_RefCount references;

    CRYPT_EAL_LibCtx *libCtx;         // Provider context
    const char *attrName;             // Provider attribute name
} HITLS_X509_Cert;

#ifdef HITLS_PKI_X509_VFY
bool HITLS_X509_CheckIssued(HITLS_X509_Cert *issue, HITLS_X509_Cert *subject);
bool HITLS_X509_CertIsCA(HITLS_X509_Cert *cert);
#endif

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_X509_CRT

#endif // HITLS_CERT_LOCAL_H