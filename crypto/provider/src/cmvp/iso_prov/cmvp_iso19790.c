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

#include "cmvp_iso19790.h"
#include "cmvp_common.h"
#include "crypt_errno.h"
#include "crypt_cmvp_selftest.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "cmvp_integrity_hmac.h"
#include "crypt_params_key.h"
#include "securec.h"
#include "bsl_sal.h"

void CMVP_Iso19790EventProcess(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err)
{
    if (oper == CRYPT_EVENT_RANDGEN) {
        CMVP_WriteSyslog("openHiTLS", err == CRYPT_SUCCESS ? LOG_INFO : LOG_ERR,
            "Excute - entropy collection, result: 0x%x", err);
        return;
    }
    if (oper == CRYPT_EVENT_INTEGRITY_TEST) {
        if (err == CRYPT_SUCCESS) {
            CMVP_WriteSyslog("openHiTLS", LOG_INFO, "Integrity test begin.");
        } else {
            CMVP_WriteSyslog("openHiTLS", LOG_ERR, "Integrity test failed, errcode: 0x%x", err);
        }
        return;
    }

    // ISO/IEC 19790:2012 AS09.33
    // The module shall provide an output status indication when zeroing is complete
    if (oper == CRYPT_EVENT_ZERO && err == CRYPT_SUCCESS) {
        CMVP_WriteSyslog("openHiTLS", LOG_INFO, "SSP already zeroisation - algorithm type: %d, id: %d", type, id);
    }
    /*
        ISO/IEC 19790:2012 AS06.26
        The following events of the cryptographic module should be recorded by the OS audit mechanism:
        ● Attempted to provide invalid input for the cryptographic officer function;
    */
    if (err != CRYPT_SUCCESS) {
        CMVP_WriteSyslog("openHiTLS", LOG_ERR, "Occur error - algorithm type: %d, id: %d, operate: %d, errcode: 0x%x",
            type, id, oper, err);
    }
    /*
        ISO/IEC 19790:2012 AS06.26
        The following events of the cryptographic module should be recorded by the OS audit mechanism:
        ● Modify, access, delete, and add encrypted data and SSPs；
        ● Use security-related encryption features
        ISO/IEC 19790:2012 AS02.24
        When a service uses approved encryption algorithms, security functions or processes,
        and specified services or processes in an approved manner,
        the service shall provide corresponding status indications.
    */
    CMVP_WriteSyslog("openHiTLS", LOG_INFO, "Excute - algorithm type: %d, id: %d, operate: %d", type, id, oper);
}

typedef struct {
    uint32_t algId;
    uint32_t mdId;
    bool signValid;
    bool verifyValid;
} ASYM_MD_MAP;

static const ASYM_MD_MAP ASYM_MD_LIST[] = {
    { CRYPT_PKEY_DSA, CRYPT_MD_SHA1, false, true },
    { CRYPT_PKEY_DSA, CRYPT_MD_SHA224, true, true },
    { CRYPT_PKEY_DSA, CRYPT_MD_SHA256, true, true },
    { CRYPT_PKEY_DSA, CRYPT_MD_SHA384, true, true },
    { CRYPT_PKEY_DSA, CRYPT_MD_SHA512, true, true },
    { CRYPT_PKEY_ECDSA, CRYPT_MD_SHA1, false, true },
    { CRYPT_PKEY_ECDSA, CRYPT_MD_SHA224, true, true },
    { CRYPT_PKEY_ECDSA, CRYPT_MD_SHA256, true, true },
    { CRYPT_PKEY_ECDSA, CRYPT_MD_SHA384, true, true },
    { CRYPT_PKEY_ECDSA, CRYPT_MD_SHA512, true, true },
    { CRYPT_PKEY_ECDSA, CRYPT_MD_SHA3_224, true, true },
    { CRYPT_PKEY_ECDSA, CRYPT_MD_SHA3_256, true, true },
    { CRYPT_PKEY_ECDSA, CRYPT_MD_SHA3_384, true, true },
    { CRYPT_PKEY_ECDSA, CRYPT_MD_SHA3_512, true, true },
    { CRYPT_PKEY_RSA, CRYPT_MD_SHA1, false, true },
    { CRYPT_PKEY_RSA, CRYPT_MD_SHA224, true, true },
    { CRYPT_PKEY_RSA, CRYPT_MD_SHA256, true, true },
    { CRYPT_PKEY_RSA, CRYPT_MD_SHA384, true, true },
    { CRYPT_PKEY_RSA, CRYPT_MD_SHA512, true, true },
    { CRYPT_PKEY_SM2, CRYPT_MD_SM3, true, true },
    { CRYPT_PKEY_SLH_DSA, CRYPT_MD_SHA224, true, true },
    { CRYPT_PKEY_SLH_DSA, CRYPT_MD_SHA256, true, true },
    { CRYPT_PKEY_SLH_DSA, CRYPT_MD_SHA384, true, true },
    { CRYPT_PKEY_SLH_DSA, CRYPT_MD_SHA512, true, true },
    { CRYPT_PKEY_SLH_DSA, CRYPT_MD_SHA3_224, true, true },
    { CRYPT_PKEY_SLH_DSA, CRYPT_MD_SHA3_256, true, true },
    { CRYPT_PKEY_SLH_DSA, CRYPT_MD_SHA3_384, true, true },
    { CRYPT_PKEY_SLH_DSA, CRYPT_MD_SHA3_512, true, true },
    { CRYPT_PKEY_SLH_DSA, CRYPT_MD_SHAKE128, true, true },
    { CRYPT_PKEY_SLH_DSA, CRYPT_MD_SHAKE256, true, true },
    { CRYPT_PKEY_SLH_DSA, CRYPT_MD_MAX, true, true },
    { CRYPT_PKEY_ML_DSA, CRYPT_MD_SHA224, true, true },
    { CRYPT_PKEY_ML_DSA, CRYPT_MD_SHA256, true, true },
    { CRYPT_PKEY_ML_DSA, CRYPT_MD_SHA384, true, true },
    { CRYPT_PKEY_ML_DSA, CRYPT_MD_SHA512, true, true },
    { CRYPT_PKEY_ML_DSA, CRYPT_MD_SHA3_224, true, true },
    { CRYPT_PKEY_ML_DSA, CRYPT_MD_SHA3_256, true, true },
    { CRYPT_PKEY_ML_DSA, CRYPT_MD_SHA3_384, true, true },
    { CRYPT_PKEY_ML_DSA, CRYPT_MD_SHA3_512, true, true },
    { CRYPT_PKEY_ML_DSA, CRYPT_MD_SHAKE128, true, true },
    { CRYPT_PKEY_ML_DSA, CRYPT_MD_SHAKE256, true, true },
    { CRYPT_PKEY_ML_DSA, CRYPT_MD_MAX, true, true },
};

static bool GetVaildFlag(uint32_t algId, uint32_t mdId, bool isSign)
{
    if (algId == CRYPT_PKEY_ED25519) {
        return true;
    }
    for (uint32_t i = 0; i < sizeof(ASYM_MD_LIST) / sizeof(ASYM_MD_LIST[0]); i++) {
        if (isSign == true && algId == ASYM_MD_LIST[i].algId && mdId == ASYM_MD_LIST[i].mdId) {
            return ASYM_MD_LIST[i].signValid;
        } else if (isSign == false && algId == ASYM_MD_LIST[i].algId && mdId == ASYM_MD_LIST[i].mdId) {
            return ASYM_MD_LIST[i].verifyValid;
        }
    }
    return false;
}

// Check whether the RSA parameter is approved.
static bool RsaParamCheck(const CRYPT_EAL_PkeyC2Data *data)
{
    if (data->para != NULL) {
        CRYPT_RsaPara para = data->para->para.rsaPara;
        // The length of the RSA key must be at least 2048 bits.
        GOTO_ERR_IF_TRUE(para.bits < 2048, CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    if (data->pub != NULL) {
        CRYPT_RsaPub pub = data->pub->key.rsaPub;
        // The length of the RSA key must be at least 2048 bits. 8 bits are 1 byte.
        GOTO_ERR_IF_TRUE(pub.nLen < (2048 / 8), CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    if (data->prv != NULL) {
        CRYPT_RsaPrv prv = data->prv->key.rsaPrv;
        // The length of the RSA key must be at least 2048 bits. 8 bits are 1 byte.
        GOTO_ERR_IF_TRUE(prv.nLen < (2048 / 8), CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    if (data->pkcsv15 != NULL) {
        GOTO_ERR_IF_TRUE(
            (GetVaildFlag(CRYPT_PKEY_RSA, data->pkcsv15->mdId, false) == false), CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    if (data->pss != NULL) {
        BSL_Param *mdParam = BSL_PARAM_FindParam(data->pss, CRYPT_PARAM_RSA_MD_ID);
        GOTO_ERR_IF_TRUE(mdParam == NULL, CRYPT_CMVP_ERR_PARAM_CHECK);
        BSL_Param *mgfParam = BSL_PARAM_FindParam(data->pss, CRYPT_PARAM_RSA_MGF1_ID);
        GOTO_ERR_IF_TRUE(mgfParam == NULL, CRYPT_CMVP_ERR_PARAM_CHECK);
        GOTO_ERR_IF_TRUE((GetVaildFlag(CRYPT_PKEY_RSA, *(uint32_t *)(mdParam->value), false) == false),
            CRYPT_CMVP_ERR_PARAM_CHECK);
        GOTO_ERR_IF_TRUE((GetVaildFlag(CRYPT_PKEY_RSA, *(uint32_t *)(mgfParam->value), false) == false),
            CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    if (data->oaep != NULL) {
        BSL_Param *mdParam = BSL_PARAM_FindParam(data->oaep, CRYPT_PARAM_RSA_MD_ID);
        GOTO_ERR_IF_TRUE(mdParam == NULL, CRYPT_CMVP_ERR_PARAM_CHECK);
        BSL_Param *mgfParam = BSL_PARAM_FindParam(data->oaep, CRYPT_PARAM_RSA_MGF1_ID);
        GOTO_ERR_IF_TRUE(mgfParam == NULL, CRYPT_CMVP_ERR_PARAM_CHECK);
        GOTO_ERR_IF_TRUE((GetVaildFlag(CRYPT_PKEY_RSA, *(uint32_t *)(mdParam->value), false) == false),
            CRYPT_CMVP_ERR_PARAM_CHECK);
        GOTO_ERR_IF_TRUE((GetVaildFlag(CRYPT_PKEY_RSA, *(uint32_t *)(mgfParam->value), false) == false),
            CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    return true;
ERR:
    return false;
}

// Check whether the DSA parameter is approved
static bool DsaParamCheck(const CRYPT_EAL_PkeyC2Data *data)
{
    if (data->para == NULL) {
        return true;
    }
    uint32_t pLen = data->para->para.dsaPara.pLen;
    uint32_t qLen = data->para->para.dsaPara.qLen;
    // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf Chapter 3
    // (L, N) = (2048, 224)，(2048, 256), 8 bits: 1 byte
    if ((pLen != 2048 / 8 || qLen != 224 / 8) && (pLen != 2048 / 8 || qLen != 256 / 8) &&
        // (L, N) = (3072, 256), 8 bits: 1 byte
        (pLen != 3072 / 8 || qLen != 256 / 8)) {
        return false;
    }
    return true;
}

// Check whether the dh parameter is approved
static bool DhParamCheck(const CRYPT_EAL_PkeyC2Data *data)
{
    static const uint32_t list[] = {
        CRYPT_DH_RFC2409_768,
        CRYPT_DH_RFC2409_1024,
        CRYPT_DH_RFC3526_1536,
    };
    if (data->para != NULL) {
        uint32_t pLen = data->para->para.dhPara.pLen;
        uint32_t qLen = data->para->para.dhPara.qLen;
        // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf Chapter 5
        // (len(p), len(q)) = (2048, 224)
        // The length of p must be at least 2048 bits, and the length of q must be at least 224 bits.
        GOTO_ERR_IF_TRUE(((pLen != 2048 / 8 || qLen != 224 / 8) &&
            // (len(p), len(q)) = (2048, 256)
            (pLen != 2048 / 8 || qLen != 256 / 8)), CRYPT_CMVP_ERR_PARAM_CHECK);
    }
    if (data->paraId != CRYPT_PKEY_PARAID_MAX) {
        // The length of p must be at least 2048 bits, and the length of q must be at least 224 bits.
        for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
            GOTO_ERR_IF_TRUE((data->paraId == list[i]), CRYPT_CMVP_ERR_PARAM_CHECK);
        }
    }
    return true;
ERR:
    return false;
}

static bool EcdhParamCheck(const CRYPT_EAL_PkeyC2Data *data)
{
    // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf Chapters 3 and 5
    // Requires curve specified using SP 800-56A
    static const uint32_t list[] = {
        CRYPT_ECC_NISTP224,
        CRYPT_ECC_NISTP256,
        CRYPT_ECC_NISTP384,
        CRYPT_ECC_NISTP521,
        CRYPT_ECC_SM2,
        CRYPT_PKEY_PARAID_MAX,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (data->paraId == list[i]) {
            return true;
        }
    }
    return false;
}

static bool EcdsaParamCheck(const CRYPT_EAL_PkeyC2Data *data)
{
    // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf Chapters 3 and 5
    // Requires curve specified using SP 800-56A
    static const uint32_t list[] = {
        CRYPT_ECC_NISTP224,
        CRYPT_ECC_NISTP256,
        CRYPT_ECC_NISTP384,
        CRYPT_ECC_NISTP521,
        CRYPT_ECC_BRAINPOOLP256R1,
        CRYPT_ECC_BRAINPOOLP384R1,
        CRYPT_ECC_BRAINPOOLP512R1,
        CRYPT_PKEY_PARAID_MAX,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (data->paraId == list[i]) {
            return true;
        }
    }
    return false;
}

static bool ISO19790_AsymParamCheck(CRYPT_PKEY_AlgId id, const CRYPT_EAL_PkeyC2Data *data)
{
    // If the value is NULL, the interface does not need to check the algorithm parameters
    // and directly returns a success message.
    if (data == NULL) {
        return true;
    }

    switch (id) {
        case CRYPT_PKEY_DSA:
            GOTO_ERR_IF_TRUE(DsaParamCheck(data) != true, CRYPT_CMVP_ERR_PARAM_CHECK);
            break;
        case CRYPT_PKEY_RSA:
            GOTO_ERR_IF_TRUE(RsaParamCheck(data) != true, CRYPT_CMVP_ERR_PARAM_CHECK);
            break;
        case CRYPT_PKEY_DH:
            GOTO_ERR_IF_TRUE(DhParamCheck(data) != true, CRYPT_CMVP_ERR_PARAM_CHECK);
            break;
        case CRYPT_PKEY_ECDH:
            GOTO_ERR_IF_TRUE(EcdhParamCheck(data) != true, CRYPT_CMVP_ERR_PARAM_CHECK);
            break;
        case CRYPT_PKEY_ECDSA:
            GOTO_ERR_IF_TRUE(EcdsaParamCheck(data) != true, CRYPT_CMVP_ERR_PARAM_CHECK);
            break;
        default:
            break;
    }
    if (data->oper == CRYPT_EVENT_SIGN) {
        GOTO_ERR_IF_TRUE((GetVaildFlag(id, data->mdId, true) == false), CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    if (data->oper == CRYPT_EVENT_VERIFY) {
        GOTO_ERR_IF_TRUE((GetVaildFlag(id, data->mdId, false) == false), CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    return true;
ERR:
    return false;
}

static bool ISO19790_MacParamCheck(CRYPT_MAC_AlgId id, uint32_t keyLen)
{
    (void)id;
    // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf Chapter 10
    // Key lengths ≥ 112 bits, 8 bits: 1 byte
    if (keyLen >= (112 / 8)) {
        return true;
    }
    return false;
}

static bool ISO19790_KdfTls12ParamCheck(CRYPT_MAC_AlgId id, uint32_t keyLen)
{
    static const uint32_t list[] = {
        CRYPT_MAC_HMAC_SHA256,
        CRYPT_MAC_HMAC_SHA384,
        CRYPT_MAC_HMAC_SHA512,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf Chapter 8
        // Key lengths ≥ 112 bits, 8 bits: 1 byte
        if (id == list[i] && (keyLen >= (112 / 8))) {
            return true;
        }
    }
    return false;
}

static bool ISO19790_HkdfParamCheck(CRYPT_MAC_AlgId id, uint32_t keyLen)
{
    static const uint32_t list[] = {
        CRYPT_MAC_HMAC_SHA1,
        CRYPT_MAC_HMAC_SHA224,
        CRYPT_MAC_HMAC_SHA256,
        CRYPT_MAC_HMAC_SHA384,
        CRYPT_MAC_HMAC_SHA512
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf Chapter 8
        // Key lengths ≥ 112 bits, 8 bits: 1 byte
        if (id == list[i] && (keyLen >= (112 / 8))) {
            return true;
        }
    }
    return false;
}

static bool ISO19790_PbkdfParamCheck(const CRYPT_EAL_Pbkdf2Param *param)
{
    static const uint32_t list[] = {
        CRYPT_MAC_HMAC_SHA1,
        CRYPT_MAC_HMAC_SHA224,
        CRYPT_MAC_HMAC_SHA256,
        CRYPT_MAC_HMAC_SHA384,
        CRYPT_MAC_HMAC_SHA512,
        CRYPT_MAC_HMAC_SM3,
        CRYPT_MAC_HMAC_SHA3_224,
        CRYPT_MAC_HMAC_SHA3_256,
        CRYPT_MAC_HMAC_SHA3_384,
        CRYPT_MAC_HMAC_SHA3_512
    };

    bool ret = false;
    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (param->macId == list[i]) {
            ret = true;
            break;
        }
    }
    if (!ret) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return false;
    }
    if (param->saltLen < 16) { // FIPS SP800-132 section 5,The salt value must contain at least 16 bytes.
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return false;
    }
    if (param->iter < 1000) { // FIPS SP800-132 section 5,The number of iterations must be at least 1000.
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return false;
    }
    if (param->dkeyLen < 14) { // FIPS SP800-132 section 5,The length of the derived key must be at least 14 bytes.
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return false;
    }
    return true;
}

static bool ISO19790_CipherKat(void *libCtx, const char *attrName)
{
    static const uint32_t list[] = {
        CRYPT_CIPHER_AES128_ECB, CRYPT_CIPHER_AES192_ECB, CRYPT_CIPHER_AES256_ECB,
        CRYPT_CIPHER_AES128_CBC, CRYPT_CIPHER_AES192_CBC, CRYPT_CIPHER_AES256_CBC,
        CRYPT_CIPHER_AES128_CTR, CRYPT_CIPHER_AES192_CTR, CRYPT_CIPHER_AES256_CTR,
        CRYPT_CIPHER_AES128_CCM, CRYPT_CIPHER_AES192_CCM, CRYPT_CIPHER_AES256_CCM,
        CRYPT_CIPHER_AES128_GCM, CRYPT_CIPHER_AES192_GCM, CRYPT_CIPHER_AES256_GCM,
        CRYPT_CIPHER_AES128_XTS, CRYPT_CIPHER_AES256_XTS,
        CRYPT_CIPHER_AES128_OFB, CRYPT_CIPHER_AES192_OFB, CRYPT_CIPHER_AES256_OFB,
        CRYPT_CIPHER_AES128_CFB, CRYPT_CIPHER_AES192_CFB, CRYPT_CIPHER_AES256_CFB,
        CRYPT_CIPHER_CHACHA20_POLY1305,
        CRYPT_CIPHER_SM4_XTS, CRYPT_CIPHER_SM4_CBC, CRYPT_CIPHER_SM4_ECB,
        CRYPT_CIPHER_SM4_CTR, CRYPT_CIPHER_SM4_GCM, CRYPT_CIPHER_SM4_CFB,
        CRYPT_CIPHER_SM4_OFB,
    };

    bool ret = false;
    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (list[i] == CRYPT_CIPHER_CHACHA20_POLY1305) {
            ret = CRYPT_CMVP_SelftestProviderChacha20poly1305(libCtx, attrName);
        } else {
            ret = CRYPT_CMVP_SelftestProviderCipher(libCtx, attrName, list[i]);
        }
        if (!ret) {
            return false;
        }
    }
    return true;
}

static bool ISO19790_MdKat(void *libCtx, const char *attrName)
{
    static const uint32_t list[] = {
        CRYPT_MD_SHA1,
        CRYPT_MD_SHA224,
        CRYPT_MD_SHA256,
        CRYPT_MD_SHA384,
        CRYPT_MD_SHA512,
        CRYPT_MD_SHA3_224, CRYPT_MD_SHA3_256, CRYPT_MD_SHA3_384, CRYPT_MD_SHA3_512,
        CRYPT_MD_SHAKE128, CRYPT_MD_SHAKE256,
        CRYPT_MD_SM3,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (!CRYPT_CMVP_SelftestProviderMd(libCtx, attrName, list[i])) {
            return false;
        }
    }
    return true;
}

static bool ISO19790_MacKat(void *libCtx, const char *attrName)
{
    static const uint32_t list[] = {
        CRYPT_MAC_CMAC_AES128, CRYPT_MAC_CMAC_AES192, CRYPT_MAC_CMAC_AES256,
        CRYPT_MAC_CMAC_SM4,
        CRYPT_MAC_GMAC_AES128, CRYPT_MAC_GMAC_AES192, CRYPT_MAC_GMAC_AES256,
        CRYPT_MAC_HMAC_SHA1,
        CRYPT_MAC_HMAC_SHA224,
        CRYPT_MAC_HMAC_SHA256,
        CRYPT_MAC_HMAC_SHA384,
        CRYPT_MAC_HMAC_SHA512,
        CRYPT_MAC_HMAC_SM3,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (!CRYPT_CMVP_SelftestProviderMac(libCtx, attrName, list[i])) {
            return false;
        }
    }
    return true;
}

static bool ISO19790_DrbgKat(void *libCtx, const char *attrName)
{
    static const uint32_t list[] = {
        CRYPT_RAND_AES128_CTR, CRYPT_RAND_AES192_CTR, CRYPT_RAND_AES256_CTR,
        CRYPT_RAND_AES128_CTR_DF, CRYPT_RAND_AES192_CTR_DF, CRYPT_RAND_AES256_CTR_DF,
        CRYPT_RAND_SM4_CTR_DF,
        CRYPT_RAND_HMAC_SHA1,
        CRYPT_RAND_HMAC_SHA224, CRYPT_RAND_HMAC_SHA256, CRYPT_RAND_HMAC_SHA384, CRYPT_RAND_HMAC_SHA512,
        CRYPT_RAND_SHA1, CRYPT_RAND_SHA224, CRYPT_RAND_SHA256, CRYPT_RAND_SHA384, CRYPT_RAND_SHA512,
        CRYPT_RAND_SM3,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (!CRYPT_CMVP_SelftestProviderDrbg(libCtx, attrName, list[i])) {
            return false;
        }
    }
    return true;
}

static bool ISO19790_KdfKat(void *libCtx, const char *attrName)
{
    if (!CRYPT_CMVP_SelftestProviderKdfTls12(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderHkdf(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderScrypt(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderPbkdf2(libCtx, attrName, CRYPT_MAC_HMAC_SHA1)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderPbkdf2(libCtx, attrName, CRYPT_MAC_HMAC_SM3)) {
        return false;
    }
    return true;
}

static bool ISO19790_PkeyKat(void *libCtx, const char *attrName)
{
    if (!CRYPT_CMVP_SelftestProviderDsa(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderEcdsa(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderRsa(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderEd25519(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderSM2(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderEcdh(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderDh(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderX25519(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderMlkemEncapsDecaps(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderMldsaSignVerify(libCtx, attrName)) {
        return false;
    }
    if (!CRYPT_CMVP_SelftestProviderSlhdsaSignVerify(libCtx, attrName)) {
        return false;
    }
    return true;
}

bool CMVP_Iso19790PkeyPct(CRYPT_Iso_Pkey_Ctx *ctx)
{
    return CRYPT_CMVP_SelftestPkeyPct(ctx->ctx, ctx->algId);
}

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

int32_t CMVP_Iso19790Kat(void *libCtx, const char *attrName)
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
