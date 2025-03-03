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

#include <stddef.h>
#include "config_type.h"
#include "hitls_crypt_type.h"
#include "tls_config.h"
#include "hitls_error.h"
#include "crypt_algid.h"

#ifndef HITLS_TLS_FEATURE_PROVIDER

static const TLS_GroupInfo GROUP_INFO[] = {
    {
        "secp256r1",
        CRYPT_ECC_NISTP256, // CRYPT_ECC_NISTP256
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        128, // secBits
        HITLS_EC_GROUP_SECP256R1, // groupId
        TLS_VERSION_MASK | DTLS_VERSION_MASK, // versionBits
        false,
    },
    {
        "secp384r1",
        CRYPT_ECC_NISTP384, // CRYPT_ECC_NISTP384
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        192, // secBits
        HITLS_EC_GROUP_SECP384R1, // groupId
        TLS_VERSION_MASK | DTLS_VERSION_MASK, // versionBits
        false,
    },
    {
        "secp521r1",
        CRYPT_ECC_NISTP521, // CRYPT_ECC_NISTP521
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        256, // secBits
        HITLS_EC_GROUP_SECP521R1, // groupId
        TLS_VERSION_MASK | DTLS_VERSION_MASK, // versionBits
        false,
    },
    {
        "brainpoolP256r1",
        CRYPT_ECC_BRAINPOOLP256R1, // CRYPT_ECC_BRAINPOOLP256R1
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        128, // secBits
        HITLS_EC_GROUP_BRAINPOOLP256R1, // groupId
        TLS10_VERSION_BIT| TLS11_VERSION_BIT|TLS12_VERSION_BIT | DTLS_VERSION_MASK, // versionBits
        false,
    },
    {
        "brainpoolP384r1",
        CRYPT_ECC_BRAINPOOLP384R1, // CRYPT_ECC_BRAINPOOLP384R1
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        192, // secBits
        HITLS_EC_GROUP_BRAINPOOLP384R1, // groupId
        TLS10_VERSION_BIT| TLS11_VERSION_BIT|TLS12_VERSION_BIT | DTLS_VERSION_MASK, // versionBits
        false,
    },
    {
        "brainpoolP512r1",
        CRYPT_ECC_BRAINPOOLP512R1, // CRYPT_ECC_BRAINPOOLP512R1
        CRYPT_PKEY_ECDH, // CRYPT_PKEY_ECDH
        256, // secBits
        HITLS_EC_GROUP_BRAINPOOLP512R1, // groupId
        TLS10_VERSION_BIT| TLS11_VERSION_BIT|TLS12_VERSION_BIT | DTLS_VERSION_MASK, // versionBits
        false,
    },
    {
        "curve25519",
        CRYPT_PKEY_PARAID_MAX, // CRYPT_ECC_X25519
        CRYPT_PKEY_X25519, // CRYPT_PKEY_ECDH
        128, // secBits
        HITLS_EC_GROUP_CURVE25519, // groupId
        TLS_VERSION_MASK | DTLS_VERSION_MASK, // versionBits
        false,
    },
    {
        "sm2",
        CRYPT_ECC_SM2, // CRYPT_ECC_SM2
        CRYPT_PKEY_SM2, // CRYPT_PKEY_SM2
        128, // secBits
        HITLS_EC_GROUP_SM2, // groupId
        TLCP11_VERSION_BIT | DTLCP11_VERSION_BIT, // versionBits
        false,
    },
    {
        "ffdhe2048",
        CRYPT_DH_RFC3526_2048, // CRYPT_DH_2048
        CRYPT_PKEY_DH, // CRYPT_PKEY_DH
        112, // secBits
        HITLS_FF_DHE_2048, // groupId
        TLS13_VERSION_BIT, // versionBits
        false,
    },
    {
        "ffdhe3072",
        CRYPT_DH_RFC3526_3072, // Fixed constant name
        CRYPT_PKEY_DH,
        128,
        HITLS_FF_DHE_3072,
        TLS13_VERSION_BIT,
        false,
    },
    {
        "ffdhe4096",
        CRYPT_DH_RFC7919_4096, // CRYPT_DH_4096
        CRYPT_PKEY_DH, // CRYPT_PKEY_DH
        128, // secBits
        HITLS_FF_DHE_4096, // groupId
        TLS13_VERSION_BIT, // versionBits
        false,
    },
    {
        "ffdhe6144",
        CRYPT_DH_RFC7919_6144, // CRYPT_DH_6144
        CRYPT_PKEY_DH, // CRYPT_PKEY_DH
        128, // secBits
        HITLS_FF_DHE_6144, // groupId
        TLS13_VERSION_BIT, // versionBits
        false,
    },
    {
        "ffdhe8192",
        CRYPT_DH_RFC7919_8192, // CRYPT_DH_8192
        CRYPT_PKEY_DH, // CRYPT_PKEY_DH
        192, // secBits
        HITLS_FF_DHE_8192, // groupId
        TLS13_VERSION_BIT, // versionBits
        false,
    }
};

int32_t ConfigLoadGroupInfo(HITLS_Config *config)
{
    if (config == NULL) {
        return HITLS_INVALID_INPUT;
    }
    uint32_t size = 0;
    for (uint32_t i = 0; i < sizeof(GROUP_INFO) / sizeof(TLS_GroupInfo); i++) {
        if ((config->version & GROUP_INFO[i].versionBits) != 0) {
            size++;
        }
    }
    if (size == 0) {
        return HITLS_INVALID_INPUT;
    }
    BSL_SAL_FREE(config->groups);
    config->groups = BSL_SAL_Calloc(size, sizeof(uint16_t));
    if (config->groups == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }
    uint32_t index = 0;
    for (uint32_t i = 0; i < sizeof(GROUP_INFO) / sizeof(TLS_GroupInfo); i++) {
        if ((config->version & GROUP_INFO[i].versionBits) != 0) {
            config->groups[index] = GROUP_INFO[i].groupId;
            index++;
        }
    }
    config->groupsSize = size;
    return HITLS_SUCCESS;
}

const TLS_GroupInfo *ConfigGetGroupInfo(const HITLS_Config *config, uint16_t groupId)
{
    (void)config;
    for (uint32_t i = 0; i < sizeof(GROUP_INFO) / sizeof(TLS_GroupInfo); i++) {
        if (GROUP_INFO[i].groupId == groupId) {
            return &GROUP_INFO[i];
        }
    }
    return NULL;
}

const TLS_GroupInfo *ConfigGetGroupInfoList(const HITLS_Config *config, uint32_t *size)
{
    (void)config;
    *size = sizeof(GROUP_INFO) / sizeof(GROUP_INFO[0]);
    return &GROUP_INFO[0];
}
#endif
