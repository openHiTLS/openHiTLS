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

#ifndef HITLS_CSR_LOCAL_H
#define HITLS_CSR_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_PKI_X509_CSR
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
    HITLS_X509_Attrs *attributes;
} HITLS_X509_ReqInfo;

typedef enum {
    HITLS_X509_CSR_STATE_NEW = 0,
    HITLS_X509_CSR_STATE_SET,
    HITLS_X509_CSR_STATE_SIGN,
    HITLS_X509_CSR_STATE_GEN,
} HITLS_X509_CSR_STATE;

/* PKCS #10 */
typedef struct _HITLS_X509_Csr {
    uint8_t flag; // Used to mark csr parsing or generation, indicating resource release behavior.
    uint8_t state;

    uint8_t *rawData;
    uint32_t rawDataLen;

    HITLS_X509_ReqInfo reqInfo;
    HITLS_X509_Asn1AlgId signAlgId;
    BSL_ASN1_BitString signature;

    BSL_SAL_RefCount references;
    CRYPT_EAL_LibCtx *libCtx;         // Provider context
    const char *attrName;             // Provider attribute name
} HITLS_X509_Csr;

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_X509_CSR

#endif // HITLS_CSR_LOCAL_H