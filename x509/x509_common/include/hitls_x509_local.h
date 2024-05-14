/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HITLS_X509_LOCAL_H
#define HITLS_X509_LOCAL_H

#include <stdint.h>
#include "bsl_asn1.h"
#include "bsl_obj.h"
#include "hitls_x509.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Check whether conditions are met. If yes, an error code is returned.
 */
#define HITLS_X509_RETURN_RET_IF(ret)            \
    do {                                         \
        if (ret != 0) {                          \
            BSL_ERR_PUSH_ERROR(ret);             \
            return ret;                          \
        }                                        \
    } while (0)

#define HITLS_X509_GOTO_RET_IF(ret)              \
    do {                                         \
        if (ret != 0) {                          \
            BSL_ERR_PUSH_ERROR(ret);             \
            goto ERR;                            \
        }                                        \
    } while (0)

typedef struct _HITLS_X509_NameNode {
    BSL_ASN1_Buffer nameType;
    BSL_ASN1_Buffer nameValue;
    uint8_t layer;
} HITLS_X509_NameNode;

typedef struct _HITLS_X509_ExtEntry {
    BSL_ASN1_Buffer extnId;
    bool critical;
    BSL_ASN1_Buffer extnValue;
} HITLS_X509_ExtEntry;

typedef struct _HITLS_X509_ValidTime {
    bool isOptional;
    BSL_TIME start;
    BSL_TIME end;
} HITLS_X509_ValidTime;

typedef struct _HITLS_X509_Asn1AlgId {
    BslCid algId;
    union {
        CRYPT_RSA_PssPara rsaPssParam;
    };
} HITLS_X509_Asn1AlgId;

int32_t HITLS_X509_ParseTbsRawData(uint8_t *encode, uint32_t encodeLen, uint8_t **tbsRsaData, uint32_t *tbsRsaDataLen);

// The public key  parsing is more complex, and the crypto module completes it
int32_t HITLS_X509_ParseSignAlgInfo(BSL_ASN1_Buffer *algId, BSL_ASN1_Buffer *param, HITLS_X509_Asn1AlgId *x509Alg);

int32_t HITLS_X509_ParseNameList(BSL_ASN1_Buffer *name, BSL_ASN1_List *list);

int32_t HITLS_X509_ParseExt(BSL_ASN1_Buffer *extItem, HITLS_X509_ExtEntry *extEntry);

int32_t HITLS_X509_ParseItemDefault(void *item, uint32_t len,  BSL_ASN1_List *list);

int32_t HITLS_X509_ParseTime(BSL_ASN1_Buffer *before, BSL_ASN1_Buffer *after, HITLS_X509_ValidTime *time);

int32_t HITLS_X509_CmpNameNode(BSL_ASN1_List *nameOri, BSL_ASN1_List *name);

int32_t HITLS_X509_CheckAlg(CRYPT_EAL_PkeyCtx *pubkey, HITLS_X509_Asn1AlgId *subAlg);

#ifdef __cplusplus
}
#endif

#endif // HITLS_X509_LOCAL_H