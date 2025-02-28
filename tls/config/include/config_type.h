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
#ifndef CONFIG_TYPE_H
#define CONFIG_TYPE_H

#include <stdint.h>
#include <stdbool.h>
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Group information
 */
typedef struct {
    const char *name;           // group name
    int32_t paraId;             // parameter id CRYPT_PKEY_ParaId
    int32_t algId;              // algorithm id CRYPT_PKEY_AlgId
    int32_t secBits;           // security bits
    uint16_t groupId;           // iana group id
    uint32_t versionBits;       // TLS_VERSION_MASK
    bool isKem;                // true: KEM, false: KEX
} GroupInfo;

typedef struct {
    const char *name;
    uint16_t signatureScheme; // HITLS_SignHashAlgo, IANA specified
    int32_t keyType;          // HITLS_CERT_KeyType
    int32_t paraId;           // CRYPT_PKEY_ParaId
    int32_t signHashAlgId;    // combined sign hash algorithm id
    int32_t signAlgId;        // CRYPT_PKEY_AlgId
    int32_t hashAlgId;        // CRYPT_MD_AlgId
    int32_t secBits;          // security bits
    uint32_t certVersionBits;      // TLS_VERSION_MASK
    uint32_t chainVersionBits; // TLS_VERSION_MASK
} SignatureSchemeInfo;

int32_t ConfigLoadGroupInfo(HITLS_Config *config);

const GroupInfo *ConfigGetGroupInfo(const HITLS_Config *config, uint16_t groupId);

const GroupInfo *ConfigGetGroupInfoList(const HITLS_Config *config, uint32_t *size);

int32_t ConfigLoadSignatureSchemeInfo(HITLS_Config *config);

const SignatureSchemeInfo *ConfigGetSignatureSchemeInfo(const HITLS_Config *config, uint16_t signatureScheme);

const SignatureSchemeInfo *ConfigGetSignatureSchemeInfoList(const HITLS_Config *config, uint32_t *size);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_TYPE_H */
