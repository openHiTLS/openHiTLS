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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CMVP

#include "cmvp_common.h"
#include "crypt_cmvp_selftest.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "cmvp_integrity_hmac.h"
#include "crypt_eal_pkey.h"
#include "crypt_cmvp.h"
#include "securec.h"
#include "cmvp_gmt.h"

static const uint32_t CIPHER_SM4[] = {
    CRYPT_CIPHER_SM4_XTS,
    CRYPT_CIPHER_SM4_CBC,
    CRYPT_CIPHER_SM4_ECB,
    CRYPT_CIPHER_SM4_CTR,
    CRYPT_CIPHER_SM4_GCM,
    CRYPT_CIPHER_SM4_CFB,
    CRYPT_CIPHER_SM4_OFB,
};

int32_t CMVP_GmtDep(void)
{
    return CMVP_CheckIntegrity(NULL, NULL, CRYPT_MAC_HMAC_SM3);
}

int32_t CMVP_GmtModeSet(CRYPT_CMVP_MODE mode)
{
    if (CMVP_CspFlagGet() == true) {
        return CRYPT_CMVP_ERR_CSP_EXIST;
    }

    CMVP_ModeSet(mode);
    return CRYPT_SUCCESS;
}

void CMVP_GmtEventProcess(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err)
{
    (void)oper;
    (void)id;
    (void)type;
    (void)err;
    return;
}

bool CMVP_GmtPkeyC2(CRYPT_PKEY_AlgId id, const CRYPT_EAL_PkeyC2Data *data)
{
    if (data != NULL && data->mdId != CRYPT_MD_SM3) {
        return false;
    }

    return id == CRYPT_PKEY_SM2;
}

bool CMVP_GmtMdC2(CRYPT_MD_AlgId id)
{
    return id == CRYPT_MD_SM3;
}

bool CMVP_GmtCipherC2(CRYPT_CIPHER_AlgId id)
{
    for (uint32_t i = 0; i < sizeof(CIPHER_SM4) / sizeof(CIPHER_SM4[0]); i++) {
        if (id == CIPHER_SM4[i]) {
            return true;
        }
    }

    return false;
}

bool CMVP_GmtMacC2(CRYPT_MAC_AlgId id, uint32_t keyLen)
{
    (void)keyLen;
    return id == CRYPT_MAC_HMAC_SM3;
}

bool CMVP_GmtKdfC2(CRYPT_KDF_AlgId id, const CRYPT_EAL_KdfC2Data *data)
{
    switch (id) {
        case CRYPT_KDF_PBKDF2: {
            if (data->pbkdf2->macId != CRYPT_MAC_HMAC_SM3 || data->pbkdf2->saltLen < 8 || data->pbkdf2->iter < 1024) {
                return false;
            }
            return true;
        }
        default:
            return false;
    }
}

bool CMVP_GmtRandC2(CRYPT_RAND_AlgId id)
{
    return id == CRYPT_RAND_SM3 || id == CRYPT_RAND_SM4_CTR_DF;
}

static bool CMVP_GMT_SM4_Selftest(void)
{
    for (uint32_t i = 0; i < sizeof(CIPHER_SM4) / sizeof(CIPHER_SM4[0]); i++) {
        if (!CRYPT_CMVP_SelftestCipher(CIPHER_SM4[i])) {
            return false;
        }
    }
    return true;
}

int32_t CRYPT_CMVP_SelftestGM(void)
{
    uint32_t ret = 0;
    if (!CRYPT_CMVP_SelftestSM2()) {
        ret |= CRYPT_CMVP_GM_SM2;
    }
    if (!CMVP_GMT_SM4_Selftest()) {
        ret |= CRYPT_CMVP_GM_SM4;
    }
    if (!CRYPT_CMVP_SelftestMd(CRYPT_MD_SM3)) {
        ret |= CRYPT_CMVP_GM_SM3;
    }
    if (!CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SM3)) {
        ret |= CRYPT_CMVP_GM_MAC;
    }
    if (!CRYPT_CMVP_SelftestPbkdf2(CRYPT_MAC_HMAC_SM3)) {
        ret |= CRYPT_CMVP_GM_PBKDF;
    }
    if (!CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SM3) ||
        !CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SM4_CTR_DF)) {
        ret |= CRYPT_CMVP_GM_DRBG;
    }

    return (int32_t)ret;
}
#endif
