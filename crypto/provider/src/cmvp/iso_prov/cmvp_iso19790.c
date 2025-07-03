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
#ifdef HITLS_CRYPTO_CMVP_ISO19790

#include "securec.h"
#include "iso19790.h"
#include "cmvp_common.h"
#include "bsl_err.h"
#include "crypt_cmvp_selftest.h"
#include "crypt_utils.h"
#include "cmvp_integrity_hmac.h"
#include "cmvp_iso19790.h"

bool CMVP_Iso19790PkeyC2(CRYPT_PKEY_AlgId id, const CRYPT_EAL_PkeyC2Data *data)
{
    return ISO19790_AsymParamCheck(id, data);
}

bool CMVP_Iso19790MacC2(CRYPT_MAC_AlgId id, uint32_t keyLen)
{
    return ISO19790_MacParamCheck(id, keyLen);
}

bool CMVP_Iso19790KdfC2(CRYPT_KDF_AlgId id, const CRYPT_EAL_KdfC2Data *data)
{
    switch (id) {
        case CRYPT_KDF_SCRYPT:
            return false;
        case CRYPT_KDF_PBKDF2:
            return ISO19790_PbkdfParamCheck(data->pbkdf2);
        case CRYPT_KDF_KDFTLS12:
            return ISO19790_KdfTls12ParamCheck(data->hkdf->macId, data->hkdf->keyLen);
        case CRYPT_KDF_HKDF:
            return ISO19790_HkdfParamCheck(data->hkdf->macId, data->hkdf->keyLen);
        default:
            return false;
    }
}

int32_t CMVP_Iso19790KatTest(void *libCtx, const char *attrName)
{
    bool ret = false;
    ret = ISO19790_CipherKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = ISO19790_MdKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = ISO19790_MacKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = ISO19790_DrbgKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = ISO19790_KdfKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = ISO19790_PkeyKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    return CRYPT_SUCCESS;
}

int32_t CMVP_Iso19790CheckIntegrity(void *libCtx, const char *attrName)
{
    return CMVP_CheckIntegrity(libCtx, attrName, CRYPT_MAC_HMAC_SHA256);
}

#endif /* HITLS_CRYPTO_CMVP_ISO19790 */
