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

#include <stdint.h>
#include "bsl_asn1.h"
#include "bsl_obj.h"
#include "sal_atomic.h"
#include "hitls_x509_local.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HITLS_X509_CERT_PARSE_FLAG  0x01
#define HITLS_X509_CERT_GEN_FLAG    0x02

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

typedef struct _HITLS_X509_Cert {
    int8_t flag; // Used to mark certificate parsing or generation, indicating resource release behavior.

    uint8_t *rawData;
    uint32_t rawDataLen;
    HITLS_X509_CertTbs tbs;
    HITLS_X509_Asn1AlgId signAlgId;
    BSL_ASN1_BitString signature;

    void *ealPrivKey;         // Used to sign.
    CRYPT_MD_AlgId signMdId;
    BSL_SAL_RefCount references;
} HITLS_X509_Cert;

int32_t HITLS_X509_CheckIssued(HITLS_X509_Cert *issue, HITLS_X509_Cert *subject, bool *res);
int32_t HITLS_X509_CertIsCA(HITLS_X509_Cert *cert, bool *res);
int32_t HITLS_X509_CertMulParseBuff(int32_t format, BSL_Buffer *encode, HITLS_X509_List **certlist);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CERT_LOCAL_H