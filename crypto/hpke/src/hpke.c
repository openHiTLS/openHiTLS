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

#include <string.h>
#include "securec.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_rand.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "crypt_bn.h"
#include "crypt_params_key.h"

#include "crypt_eal_hpke.h"

// Data from RFC9180
#define HPKE_HKDF_MAX_EXTRACT_KEY_LEN 64
#define HPKE_KEM_MAX_SHARED_KEY_LEN  64
#define HPKE_KEM_MAX_ENCAPSULATED_KEY_LEN  133
#define HPKE_KEM_MAX_PUBLIC_KEY_LEN  133
#define HPKE_KEM_MAX_PRIVATE_KEY_LEN  66
#define HPKE_KEM_DH_MAX_SHARED_KEY_LEN 66 // p521 key length
#define MAX_ECC_PARAM_LEN 66

#define HPKE_AEAD_NONCE_LEN  12
#define HPKE_AEAD_TAG_LEN  16

#define HPKE_KEM_SUITEID_LEN 5
#define HPKE_HPKE_SUITEID_LEN 10

struct EAL_HpkeCtx {
    uint32_t role;                    // Sender or Recipient
    CRYPT_HPKE_mode mode;             // HPKE mode
    CRYPT_HPKE_CipherSuite cipher;    // HPKE cipher suite
    uint8_t *exportSecret;            // Exported secret
    uint32_t exportSecretLen;         // Length of the exported secret
    uint8_t *symKey;                  // Symmetric key
    uint32_t symKeyLen;               // Length of the symmetric key
    uint8_t *baseNonce;               // Base nonce
    uint32_t baseNonceLen;            // Length of the base nonce
    uint64_t seq;                     // Message sequence number
};

static uint16_t HpkeI2OSP16(uint16_t value)
{
    uint16_t a = 0x1213;
    uint8_t *p = (uint8_t *)&a;
    if (p[0] == 0x13) { // little-endian
        return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
    } else {
        return value;
    }
}

static CRYPT_MAC_AlgId GetKdfMacAlgId(CRYPT_HPKE_CipherSuite *cipher)
{
    switch (cipher->kdfId) {
        case CRYPT_KDF_HKDF_SHA256:
            return CRYPT_MAC_HMAC_SHA256;
        case CRYPT_KDF_HKDF_SHA384:
            return CRYPT_MAC_HMAC_SHA384;
        case CRYPT_KDF_HKDF_SHA512:
            return CRYPT_MAC_HMAC_SHA512;
        default:
            return CRYPT_MAC_MAX;
    }
}

static CRYPT_CIPHER_AlgId GetAeadCipherAlgid(CRYPT_HPKE_CipherSuite *cipher)
{
    switch (cipher->aeadId) {
        case CRYPT_AEAD_AES_128_GCM:
            return CRYPT_CIPHER_AES128_GCM;
        case CRYPT_AEAD_AES_256_GCM:
            return CRYPT_CIPHER_AES256_GCM;
        case CRYPT_AEAD_CHACHA20_POLY1305:
            return CRYPT_CIPHER_CHACHA20_POLY1305;
        default:
            return CRYPT_CIPHER_MAX;
    }
}

static CRYPT_PKEY_AlgId GetPkeyAlgId(CRYPT_HPKE_CipherSuite *cipher)
{
    switch (cipher->kemId) {
        case CRYPT_KEM_DHKEM_P256_HKDF_SHA256:
        case CRYPT_KEM_DHKEM_P384_HKDF_SHA384:
        case CRYPT_KEM_DHKEM_P521_HKDF_SHA512:
            return CRYPT_PKEY_ECDH;
        case CRYPT_KEM_DHKEM_X25519_HKDF_SHA256:
            return CRYPT_PKEY_X25519;
        case CRYPT_KEM_DHKEM_X448_HKDF_SHA512:
            return CRYPT_PKEY_MAX;
        default:
            return CRYPT_PKEY_MAX;
    }
}

static CRYPT_MAC_AlgId GetKemMacAlgId(CRYPT_HPKE_CipherSuite *cipher)
{
    switch (cipher->kemId) {
        case CRYPT_KEM_DHKEM_P256_HKDF_SHA256:
            return CRYPT_MAC_HMAC_SHA256;
        case CRYPT_KEM_DHKEM_P384_HKDF_SHA384:
            return CRYPT_MAC_HMAC_SHA384;
        case CRYPT_KEM_DHKEM_P521_HKDF_SHA512:
            return CRYPT_MAC_HMAC_SHA512;
        case CRYPT_KEM_DHKEM_X25519_HKDF_SHA256:
            return CRYPT_MAC_HMAC_SHA256;
        case CRYPT_KEM_DHKEM_X448_HKDF_SHA512:
            return CRYPT_MAC_HMAC_SHA512;
        default:
            return CRYPT_MAC_MAX;
    }
}

static CRYPT_PKEY_ParaId GetPkeyCurveId(CRYPT_HPKE_CipherSuite *cipher)
{
    switch (cipher->kemId) {
        case CRYPT_KEM_DHKEM_P256_HKDF_SHA256:
            return CRYPT_ECC_NISTP256;
        case CRYPT_KEM_DHKEM_P384_HKDF_SHA384:
            return CRYPT_ECC_NISTP384;
        case CRYPT_KEM_DHKEM_P521_HKDF_SHA512:
            return CRYPT_ECC_NISTP521;
        default:
            return CRYPT_PKEY_PARAID_MAX;
    }
}

static uint32_t GetDhKemPrivateKeyLen(CRYPT_HPKE_CipherSuite *cipher)
{
    switch (cipher->kemId) {
        case CRYPT_KEM_DHKEM_P256_HKDF_SHA256:
            return 32;
        case CRYPT_KEM_DHKEM_P384_HKDF_SHA384:
            return 48;
        case CRYPT_KEM_DHKEM_P521_HKDF_SHA512:
            return 66;
        case CRYPT_KEM_DHKEM_X25519_HKDF_SHA256:
            return 32;
        case CRYPT_KEM_DHKEM_X448_HKDF_SHA512:
            return 56;
        default:
            return 0;
    }
}

static uint32_t GetKemSharedKeyLen(CRYPT_HPKE_CipherSuite *cipher)
{
    switch (cipher->kemId) {
        case CRYPT_KEM_DHKEM_P256_HKDF_SHA256:
            return 32;
        case CRYPT_KEM_DHKEM_P384_HKDF_SHA384:
            return 48;
        case CRYPT_KEM_DHKEM_P521_HKDF_SHA512:
            return 64;
        case CRYPT_KEM_DHKEM_X25519_HKDF_SHA256:
            return 32;
        case CRYPT_KEM_DHKEM_X448_HKDF_SHA512:
            return 64;
        default:
            return 0;
    }
}

static uint32_t GetEncapsulatedKeyLen(CRYPT_HPKE_CipherSuite *cipher)
{
    switch (cipher->kemId) {
        case CRYPT_KEM_DHKEM_P256_HKDF_SHA256:
            return 65;
        case CRYPT_KEM_DHKEM_P384_HKDF_SHA384:
            return 97;
        case CRYPT_KEM_DHKEM_P521_HKDF_SHA512:
            return 133;
        case CRYPT_KEM_DHKEM_X25519_HKDF_SHA256:
            return 32;
        case CRYPT_KEM_DHKEM_X448_HKDF_SHA512:
            return 56;
        default:
            return 0;
    }
}

static uint32_t GetKemExtractKeyLen(CRYPT_HPKE_CipherSuite *cipher)
{
    switch (cipher->kemId) {
        case CRYPT_KEM_DHKEM_P256_HKDF_SHA256:
            return 32;
        case CRYPT_KEM_DHKEM_P384_HKDF_SHA384:
            return 48;
        case CRYPT_KEM_DHKEM_P521_HKDF_SHA512:
            return 64;
        case CRYPT_KEM_DHKEM_X25519_HKDF_SHA256:
            return 32;
        case CRYPT_KEM_DHKEM_X448_HKDF_SHA512:
            return 64;
        default:
            return 0;
    }
}

static uint32_t GetKdfExtractKeyLen(CRYPT_HPKE_CipherSuite *cipher)
{
    switch (cipher->kdfId) {
        case CRYPT_KDF_HKDF_SHA256:
            return 32;
        case CRYPT_KDF_HKDF_SHA384:
            return 48;
        case CRYPT_KDF_HKDF_SHA512:
            return 64;
        default:
            return 0;
    }
}

static uint32_t GetAeadKeyLen(CRYPT_HPKE_CipherSuite *cipher)
{
    switch (cipher->aeadId) {
        case CRYPT_AEAD_AES_128_GCM:
            return 16;
        case CRYPT_AEAD_AES_256_GCM:
            return 32;
        case CRYPT_AEAD_CHACHA20_POLY1305:
            return 32;
        default:
            return 0;
    }
}

static int32_t CheckHpkeCipherSuite(CRYPT_HPKE_CipherSuite *cipher)
{
    if (GetKdfMacAlgId(cipher) == CRYPT_MAC_MAX) {
        return CRYPT_INVALID_ARG;
    }

    if (GetAeadCipherAlgid(cipher) == CRYPT_CIPHER_MAX) {
        return CRYPT_INVALID_ARG;
    }

    if (GetPkeyAlgId(cipher) == CRYPT_PKEY_MAX) {
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_SUCCESS;
}

CRYPT_EAL_HpkeCtx *CRYPT_EAL_HpkeNewCtx(CRYPT_HPKE_Role role, CRYPT_HPKE_mode mode, CRYPT_HPKE_CipherSuite cipher)
{
    if (role != CRYPT_HPKE_SENDER && role != CRYPT_HPKE_RECIPIENT) {
        return NULL;
    }

    if (mode != CRYPT_HPKE_MODE_BASE) {
        return NULL;
    }

    if (CheckHpkeCipherSuite(&cipher) != CRYPT_SUCCESS) {
        return NULL;
    }

    CRYPT_EAL_HpkeCtx *ctx = (CRYPT_EAL_HpkeCtx*)BSL_SAL_Malloc(sizeof(CRYPT_EAL_HpkeCtx));
    if (ctx == NULL) {
        return NULL;
    }
    (void)memset_s(ctx, sizeof(CRYPT_EAL_HpkeCtx), 0, sizeof(CRYPT_EAL_HpkeCtx));
    ctx->mode = mode;
    ctx->cipher = cipher;
    ctx->role = role;
    return ctx;
}

static int32_t CreatePkeyCtx(CRYPT_HPKE_CipherSuite *cipher, CRYPT_EAL_PkeyCtx **pkeyCtx)
{
    CRYPT_PKEY_AlgId algId = GetPkeyAlgId(cipher);
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(algId);
    if (pkey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    if (algId == CRYPT_PKEY_ECDH) {
        CRYPT_PKEY_ParaId curveId = GetPkeyCurveId(cipher);
        int32_t ret = CRYPT_EAL_PkeySetParaById(pkey, curveId);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(pkey);
            return ret;
        }
    }

    *pkeyCtx = pkey;
    return CRYPT_SUCCESS;
}

static int32_t CreatePubKey(CRYPT_HPKE_CipherSuite *cipher, const uint8_t *pubKey, uint32_t pubKeyLen,
    CRYPT_EAL_PkeyCtx **pkey)
{
    CRYPT_EAL_PkeyCtx *tmpPkey = NULL;
    int32_t ret = CreatePkeyCtx(cipher, &tmpPkey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint8_t keyData[HPKE_KEM_MAX_PUBLIC_KEY_LEN];
    if (memcpy_s(keyData, sizeof(keyData), pubKey, pubKeyLen) != EOK) {
        return CRYPT_SECUREC_FAIL;
    }

    CRYPT_EAL_PkeyPub pub = {0};
    pub.id = CRYPT_EAL_PkeyGetId(tmpPkey);
    pub.key.eccPub.data = keyData; // compatible curve25519Pub
    pub.key.eccPub.len = pubKeyLen;

    ret = CRYPT_EAL_PkeySetPub(tmpPkey, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(tmpPkey);
        return ret;
    }

    *pkey = tmpPkey;
    return CRYPT_SUCCESS;
}

static int32_t CreatePriKey(CRYPT_HPKE_CipherSuite *cipher, uint8_t *priKey, uint32_t priKeyLen,
    CRYPT_EAL_PkeyCtx **pkey)
{
    CRYPT_EAL_PkeyCtx *tmpPkey = NULL;
    int32_t ret = CreatePkeyCtx(cipher, &tmpPkey); 
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_EAL_PkeyPrv pub = {0};
    pub.id = CRYPT_EAL_PkeyGetId(tmpPkey);
    pub.key.eccPrv.data = priKey;
    pub.key.eccPrv.len = priKeyLen;

    ret = CRYPT_EAL_PkeySetPrv(tmpPkey, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(tmpPkey);
        return ret;
    }

    if (cipher->kemId == CRYPT_KEM_DHKEM_X25519_HKDF_SHA256) {
        ret = CRYPT_EAL_PkeyCtrl(tmpPkey, CRYPT_CTRL_GEN_X25519_PUBLICKEY, NULL, 0);
    } else {
        ret = CRYPT_EAL_PkeyCtrl(tmpPkey, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0);
    }

    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(tmpPkey);
        return ret;
    }

    *pkey = tmpPkey;
    return CRYPT_SUCCESS;
}

static void GenerateHpkeSuiteid(CRYPT_HPKE_CipherSuite *cipher, uint8_t *suiteid, uint32_t suiteidLen)
{
    uint32_t offset = 0;
    (void)memcpy_s(suiteid, suiteidLen, "HPKE", strlen("HPKE"));
    offset += strlen("HPKE");

    uint16_t id = HpkeI2OSP16(cipher->kemId);
    (void)memcpy_s(suiteid + offset, suiteidLen - offset, &id, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    id = HpkeI2OSP16(cipher->kdfId);
    (void)memcpy_s(suiteid + offset, suiteidLen - offset, &id, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    id = HpkeI2OSP16(cipher->aeadId);
    (void)memcpy_s(suiteid + offset, suiteidLen - offset, &id, sizeof(uint16_t));
}

static void GenerateKemSuiteid(CRYPT_HPKE_KEM_AlgId kemId, uint8_t *suiteid, uint32_t suiteidLen)
{
    uint32_t offset = 0;
    (void)memcpy_s(suiteid, suiteidLen, "KEM", strlen("KEM"));
    offset += strlen("KEM");

    uint16_t kemIdNew = HpkeI2OSP16(kemId);
    (void)memcpy_s(suiteid + offset, suiteidLen - offset, &kemIdNew, sizeof(uint16_t));
}

static int32_t CRYPT_EAL_HkdfExtract(CRYPT_MAC_AlgId macId, uint8_t *key, uint32_t keyLen, 
    uint8_t *salt, uint32_t saltLen, uint8_t *out, uint32_t outLen)
{
    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (ctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret;
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXTRACT;

    BSL_Param params[6] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    ret = BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, (void *)&macId, sizeof(macId));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return ret;
    }

    ret = BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, (void *)&mode, sizeof(mode));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return ret;
    }

    ret = BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS, (void *)key, keyLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return ret;
    }

    ret = BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, (void *)salt, saltLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return ret;
    }

    ret = BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_EXLEN, BSL_PARAM_TYPE_UINT32_PTR, &outLen, sizeof(outLen));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_EAL_KdfSetParam(ctx, params);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_EAL_KdfDerive(ctx, out, outLen);
    CRYPT_EAL_KdfFreeCtx(ctx);
    return ret;
}

static int32_t CRYPT_EAL_HkdfExpand(CRYPT_MAC_AlgId macId, uint8_t *prk, uint32_t prkLen, uint8_t *info,
    uint32_t infoLen, uint8_t *out, uint32_t outLen)
{
    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    if (ctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret;
    CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXPAND;

    BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
    ret = BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, (void *)&macId, sizeof(macId));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return ret;
    }

    ret = BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, (void *)&mode, sizeof(mode));
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return ret;
    }

    ret = BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_PRK, BSL_PARAM_TYPE_OCTETS, (void *)prk, prkLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return ret;
    }

    ret = BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS, (void *)info, infoLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_EAL_KdfSetParam(ctx, params);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_KdfFreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_EAL_KdfDerive(ctx, out, outLen);
    CRYPT_EAL_KdfFreeCtx(ctx);
    return ret;
}

static int32_t HpkeLabeledExtract(CRYPT_MAC_AlgId macId, uint8_t *salt, uint32_t saltLen,
    uint8_t *label, uint32_t labelLen, uint8_t *ikm, uint32_t ikmLen,
    uint8_t *suiteid, uint32_t suiteidLen, uint8_t *out, uint32_t outLen)
{
    // labeled_ikm = "HPKE-v1" || suite_id || label || ikm
    const uint8_t *version = (const uint8_t *)"HPKE-v1";
    uint32_t versionLen = strlen("HPKE-v1");
    uint32_t labeledIkmLen = versionLen + suiteidLen + labelLen + ikmLen;
    uint8_t *labeledIkm = (uint8_t *)BSL_SAL_Malloc(labeledIkmLen);
    if (labeledIkm == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t offset = 0;
    (void)memcpy_s(labeledIkm + offset, labeledIkmLen - offset, version, versionLen);
    offset += versionLen;
    (void)memcpy_s(labeledIkm + offset, labeledIkmLen - offset, suiteid, suiteidLen);
    offset += suiteidLen;
    (void)memcpy_s(labeledIkm + offset, labeledIkmLen - offset, label, labelLen);
    offset += labelLen;
    (void)memcpy_s(labeledIkm + offset, labeledIkmLen - offset, ikm, ikmLen);

    int32_t ret = CRYPT_EAL_HkdfExtract(macId, labeledIkm, labeledIkmLen, salt, saltLen, out, outLen);
    BSL_SAL_Free(labeledIkm);
    return ret;
}

static int32_t HpkeLabeledExpand(CRYPT_MAC_AlgId macId, uint8_t *prk, uint32_t prkLen,uint8_t *label, uint32_t labelLen,
    uint8_t *info, uint32_t infoLen, uint8_t *suiteid, uint32_t suiteidLen, uint8_t *out, uint32_t outLen)
{
    // labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
    const uint8_t *version = (const uint8_t *)"HPKE-v1";
    uint32_t versionLen = strlen("HPKE-v1");
    uint32_t labeledInfoLen = sizeof(uint16_t) + versionLen + suiteidLen + labelLen + infoLen;
    uint8_t *labeledInfo = (uint8_t *)BSL_SAL_Malloc(labeledInfoLen);
    if (labeledInfo == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t offset = 0;
    uint16_t outLenTmp = HpkeI2OSP16(outLen);
    (void)memcpy_s(labeledInfo, labeledInfoLen - offset, &outLenTmp, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    (void)memcpy_s(labeledInfo + offset, labeledInfoLen - offset, version, versionLen);
    offset += versionLen;
    (void)memcpy_s(labeledInfo + offset, labeledInfoLen - offset, suiteid, suiteidLen);
    offset += suiteidLen;
    (void)memcpy_s(labeledInfo + offset, labeledInfoLen - offset, label, labelLen);
    offset += labelLen;
    (void)memcpy_s(labeledInfo + offset, labeledInfoLen - offset, info, infoLen);

    int32_t ret = CRYPT_EAL_HkdfExpand(macId, prk, prkLen, labeledInfo, labeledInfoLen, out, outLen);
    BSL_SAL_Free(labeledInfo);
    return ret;
}

static int32_t HpkeExtractAndExpand(CRYPT_EAL_HpkeCtx *ctx, uint8_t *dh, uint32_t dhLen, uint8_t *kemContext,
    uint32_t kemContextLen, uint8_t *suiteid, uint32_t suiteidLen, uint8_t *sharedSecret, uint32_t sharedSecretLen)
{
    CRYPT_MAC_AlgId macId = GetKemMacAlgId(&ctx->cipher);
    uint8_t eaePrk[HPKE_HKDF_MAX_EXTRACT_KEY_LEN];
    uint32_t eaePrkLen = GetKemExtractKeyLen(&ctx->cipher);
    int32_t ret = HpkeLabeledExtract(macId, NULL, 0, (uint8_t *)"eae_prk", strlen("eae_prk"), dh, dhLen,
        suiteid, suiteidLen, eaePrk, eaePrkLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = HpkeLabeledExpand(macId, eaePrk, eaePrkLen, (uint8_t *)"shared_secret", strlen("shared_secret"),
        kemContext, kemContextLen, suiteid, suiteidLen,  sharedSecret, sharedSecretLen);
    BSL_SAL_CleanseData(eaePrk, eaePrkLen);
    return ret;
}

static int32_t GetPubKeyData(CRYPT_EAL_PkeyCtx *pkey, CRYPT_HPKE_CipherSuite *cipher,
    uint8_t *out, uint32_t *outLen)
{
    CRYPT_EAL_PkeyPub ephemPub = { 0 };
    ephemPub.id = GetPkeyAlgId(cipher);
    ephemPub.key.eccPub.len = *outLen;  // compatible curve25519Pub, CRYPT_Data type.
    ephemPub.key.eccPub.data = out;

    int32_t ret = CRYPT_EAL_PkeyGetPub(pkey, &ephemPub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    *outLen = ephemPub.key.eccPub.len;
    return CRYPT_SUCCESS;
}

static int32_t HpkeEncap(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, const uint8_t *pkR, uint32_t pkRLen,
    uint8_t *enc, uint32_t *encLen, uint8_t *sharedSecret, uint32_t sharedSecretLen)
{
    int32_t ret;
    CRYPT_EAL_PkeyCtx *pkeyS = pkey;
    if (pkeyS == NULL) {
        ret = CRYPT_EAL_HpkeGenerateKeyPair(ctx->cipher, NULL, 0, &pkeyS);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    uint8_t dh[HPKE_KEM_DH_MAX_SHARED_KEY_LEN];
    uint32_t dhLen = HPKE_KEM_DH_MAX_SHARED_KEY_LEN;
    CRYPT_EAL_PkeyCtx *pkeyR = NULL;
    uint8_t tmpEnc[HPKE_KEM_MAX_PUBLIC_KEY_LEN] = { 0 };
    uint32_t tmpEncLen = HPKE_KEM_MAX_PUBLIC_KEY_LEN;

    ret = GetPubKeyData(pkeyS, &ctx->cipher, tmpEnc, &tmpEncLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    ret = CreatePubKey(&ctx->cipher, pkR, pkRLen, &pkeyR);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    ret = CRYPT_EAL_PkeyComputeShareKey(pkeyS, pkeyR, dh, &dhLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    // kemContext = enc || pkRm
    uint32_t kemContextLen = tmpEncLen + pkRLen;
    uint8_t *kemContext = (uint8_t*)BSL_SAL_Malloc(kemContextLen);
    if (kemContext == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto end;
    }
    (void)memcpy_s(kemContext, kemContextLen, tmpEnc, tmpEncLen);
    (void)memcpy_s(kemContext + tmpEncLen, pkRLen, pkR, pkRLen);

    uint8_t suiteid[HPKE_KEM_SUITEID_LEN];
    GenerateKemSuiteid(ctx->cipher.kemId, suiteid, HPKE_KEM_SUITEID_LEN);
    ret = HpkeExtractAndExpand(ctx, dh, dhLen, kemContext, kemContextLen, suiteid, HPKE_KEM_SUITEID_LEN,
        sharedSecret, sharedSecretLen);
    BSL_SAL_Free(kemContext);

    (void)memcpy_s(enc, *encLen, tmpEnc, tmpEncLen);
    *encLen = tmpEncLen;
end:
    if (pkey == NULL) {
        CRYPT_EAL_PkeyFreeCtx(pkeyS);
    }
    CRYPT_EAL_PkeyFreeCtx(pkeyR);
    BSL_SAL_CleanseData(dh, HPKE_KEM_DH_MAX_SHARED_KEY_LEN);
    return ret;
}

static int32_t GenerateKeyScheduleContext(CRYPT_EAL_HpkeCtx *ctx, uint8_t *info, uint32_t infoLen, uint8_t *pskId,
    uint32_t pskIdLen, uint8_t *suiteid, uint32_t suiteidLen, uint8_t **keyScheduleContext,
    uint32_t *keyScheduleContextLen)
{
    uint32_t extractKeyLen = GetKdfExtractKeyLen(&ctx->cipher);
    uint32_t contextLen = sizeof(uint8_t) + extractKeyLen + extractKeyLen;
    uint8_t *context = (uint8_t *)BSL_SAL_Malloc(contextLen);
    if (context == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    context[0] = ctx->mode;
    uint32_t offset = sizeof(uint8_t);

    CRYPT_MAC_AlgId macId = GetKdfMacAlgId(&ctx->cipher);
    int32_t ret = HpkeLabeledExtract(macId, NULL, 0, (uint8_t*)"psk_id_hash", strlen("psk_id_hash"), pskId, pskIdLen,
        suiteid, suiteidLen, context + offset, extractKeyLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    offset += extractKeyLen;
    ret = HpkeLabeledExtract(macId, NULL, 0, (uint8_t*)"info_hash", strlen("info_hash"), info, infoLen,
        suiteid, suiteidLen, context + offset, extractKeyLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    *keyScheduleContext = context;
    *keyScheduleContextLen = contextLen;
    return CRYPT_SUCCESS;
end:
    BSL_SAL_ClearFree(context, contextLen);
    return ret;
}

static void FreeHpkeKeyInfo(CRYPT_EAL_HpkeCtx *ctx)
{
    BSL_SAL_ClearFree(ctx->symKey, ctx->symKeyLen);
    BSL_SAL_ClearFree(ctx->baseNonce, ctx->baseNonceLen);
    BSL_SAL_ClearFree(ctx->exportSecret, ctx->exportSecretLen);
    ctx->symKey = NULL;
    ctx->baseNonce = NULL;
    ctx->exportSecret = NULL;
    ctx->symKeyLen = 0;
    ctx->baseNonceLen = 0;
    ctx->exportSecretLen = 0;
}

static int32_t MallocHpkeKeyInfo(CRYPT_EAL_HpkeCtx *ctx)
{
    ctx->symKeyLen = GetAeadKeyLen(&ctx->cipher);
    ctx->symKey = BSL_SAL_Malloc(ctx->symKeyLen);

    ctx->baseNonceLen = HPKE_AEAD_NONCE_LEN;
    ctx->baseNonce = BSL_SAL_Malloc(HPKE_AEAD_NONCE_LEN);

    ctx->exportSecretLen = GetKdfExtractKeyLen(&ctx->cipher);
    ctx->exportSecret = BSL_SAL_Malloc(ctx->exportSecretLen);

    if (ctx->symKey == NULL || ctx->baseNonce == NULL || ctx->exportSecret == NULL) {
        FreeHpkeKeyInfo(ctx);
    }
    return CRYPT_SUCCESS;
}

static int32_t KeySchedule(CRYPT_EAL_HpkeCtx *ctx, uint8_t *sharedSecret, uint32_t sharedSecretLen, uint8_t *info,
    uint32_t infoLen)
{
    uint8_t suiteid[HPKE_HPKE_SUITEID_LEN];
    uint8_t suiteidLen = HPKE_HPKE_SUITEID_LEN;
    GenerateHpkeSuiteid(&ctx->cipher, suiteid, HPKE_HPKE_SUITEID_LEN);
    uint32_t contextLen;
    uint8_t *context = NULL;

    int32_t ret = GenerateKeyScheduleContext(ctx, info, infoLen, NULL, 0, suiteid, suiteidLen, &context, &contextLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_MAC_AlgId macId = GetKdfMacAlgId(&ctx->cipher);
    uint8_t secret[HPKE_KEM_MAX_SHARED_KEY_LEN] = {0};
    uint32_t secretLen = GetKdfExtractKeyLen(&ctx->cipher);
    ret = HpkeLabeledExtract(macId, sharedSecret, sharedSecretLen, (uint8_t*)"secret", strlen("secret"), NULL, 0,
        suiteid, suiteidLen, secret, secretLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    ret = MallocHpkeKeyInfo(ctx);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    ret = HpkeLabeledExpand(macId, secret, secretLen, (uint8_t*)"key", strlen("key"), context, contextLen,
        suiteid, suiteidLen, ctx->symKey, ctx->symKeyLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    ret = HpkeLabeledExpand(macId, secret, secretLen, (uint8_t*)"base_nonce", strlen("base_nonce"), context, contextLen,
        suiteid, suiteidLen, ctx->baseNonce,ctx->baseNonceLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    ret = HpkeLabeledExpand(macId, secret, secretLen, (uint8_t*)"exp", strlen("exp"), context, contextLen,
        suiteid, suiteidLen, ctx->exportSecret, ctx->exportSecretLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

end:
    BSL_SAL_CleanseData(secret, HPKE_KEM_MAX_SHARED_KEY_LEN);
    BSL_SAL_ClearFree(context, contextLen);
    if (ret != CRYPT_SUCCESS) {
        FreeHpkeKeyInfo(ctx);
    }
    return ret;
}

int32_t CRYPT_EAL_HpkeSetupSender(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, uint8_t *info, uint32_t infoLen,
    const uint8_t *pkR, uint32_t pkRLen, uint8_t *enc, uint32_t *encLen)
{
    if (ctx == NULL || pkR == NULL || pkRLen == 0 || enc == NULL || encLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (ctx->role != CRYPT_HPKE_SENDER) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->symKey != NULL || ctx->baseNonce != NULL || ctx->exportSecret != NULL) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (pkRLen != GetEncapsulatedKeyLen(&ctx->cipher)) {
        return CRYPT_INVALID_ARG;
    }

    if (*encLen < GetEncapsulatedKeyLen(&ctx->cipher)) {
        return CRYPT_INVALID_ARG;
    }

    uint8_t sharedSecret[HPKE_KEM_MAX_SHARED_KEY_LEN] = { 0 };
    uint32_t sharedSecretLen = GetKemSharedKeyLen(&ctx->cipher);
    int32_t ret = HpkeEncap(ctx, pkey, pkR, pkRLen, enc, encLen, sharedSecret, sharedSecretLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = KeySchedule(ctx, sharedSecret, sharedSecretLen, info, infoLen);
    BSL_SAL_CleanseData(sharedSecret, HPKE_KEM_MAX_SHARED_KEY_LEN);
    return ret;
}

static int32_t HpkeAeadEncrypt(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *nonce, uint32_t nonceLen, uint8_t *aad,
    uint32_t aadLen, const uint8_t *plain, uint32_t plainLen, uint8_t *cipher, uint32_t *cipherLen)
{
    CRYPT_CIPHER_AlgId id = GetAeadCipherAlgid(&ctx->cipher);
    CRYPT_EAL_CipherCtx *cipherCtx = CRYPT_EAL_CipherNewCtx(id);
    if (ctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t outLen = *cipherLen;
    int32_t ret = CRYPT_EAL_CipherInit(cipherCtx, ctx->symKey, ctx->symKeyLen, nonce, nonceLen, true);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    if (aad != NULL && aadLen > 0) {
        ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_SET_AAD, aad, aadLen);
        if (ret != CRYPT_SUCCESS) {
            goto end;
        }
    }

    ret = CRYPT_EAL_CipherUpdate(cipherCtx, plain, plainLen, cipher, &outLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_GET_TAG, cipher + outLen, HPKE_AEAD_TAG_LEN);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    *cipherLen = outLen + HPKE_AEAD_TAG_LEN;
end:
    CRYPT_EAL_CipherFreeCtx(cipherCtx);
    return ret;
}

int32_t CRYPT_EAL_HpkeSetSeq(CRYPT_EAL_HpkeCtx *ctx, uint64_t seq)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (seq == 0xFFFFFFFFFFFFFFFF) {
        return CRYPT_INVALID_ARG;
    }

    ctx->seq = seq;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_HpkeGetSeq(CRYPT_EAL_HpkeCtx *ctx, uint64_t *seq)
{
    if (ctx == NULL || seq == NULL) {
        return CRYPT_NULL_INPUT;
    }

    *seq = ctx->seq;
    return CRYPT_SUCCESS;
}

static void ComputeNonce(CRYPT_EAL_HpkeCtx *ctx, uint8_t *nonce, uint32_t nonceLen)
{
    uint64_t seq = ctx->seq;
    for (uint32_t i = 0; i < sizeof(seq); i++) {
        nonce[nonceLen - i -1] = seq & 0xFF;
        seq = seq >> 8;
    }

    for (uint32_t i = 0; i < nonceLen; i++) {
        nonce[i] ^= ctx->baseNonce[i];
    }
}

int32_t CRYPT_EAL_HpkeSeal(CRYPT_EAL_HpkeCtx *ctx, uint8_t *aad, uint32_t aadLen, const uint8_t *plain,
    uint32_t plainLen, uint8_t *cipher, uint32_t *cipherLen)
{
    if (ctx == NULL || plain == NULL || cipherLen == 0) {
        return CRYPT_NULL_INPUT;
    }

    if (ctx->role != CRYPT_HPKE_SENDER) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->symKey == NULL || ctx->baseNonce == NULL) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->seq + 1 == 0) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (cipher == NULL) {
        *cipherLen = plainLen + HPKE_AEAD_TAG_LEN;
        return CRYPT_SUCCESS;
    }

    if (*cipherLen < (plainLen + HPKE_AEAD_TAG_LEN)) {
        return CRYPT_INVALID_ARG;
    }

    uint8_t nonce[HPKE_AEAD_NONCE_LEN] = { 0 };
    ComputeNonce(ctx, nonce, HPKE_AEAD_NONCE_LEN);

    ctx->seq++;
    return HpkeAeadEncrypt(ctx, nonce, HPKE_AEAD_NONCE_LEN, aad, aadLen, plain, plainLen, cipher, cipherLen);
}

static int32_t HpkeDecap(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, const uint8_t *encapsulatedKey,
    uint32_t encapsulatedKeyLen, uint8_t *sharedSecret, uint32_t sharedSecretLen)
{
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    int32_t ret = CreatePubKey(&ctx->cipher, encapsulatedKey, encapsulatedKeyLen, &pkeyS);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint8_t *kemContext = NULL;
    uint8_t dh[HPKE_KEM_DH_MAX_SHARED_KEY_LEN];
    uint32_t dhLen = HPKE_KEM_DH_MAX_SHARED_KEY_LEN;
    ret = CRYPT_EAL_PkeyComputeShareKey(pkey, pkeyS, dh, &dhLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    uint8_t keyData[HPKE_KEM_MAX_PUBLIC_KEY_LEN];
    uint32_t keyDataLen = HPKE_KEM_MAX_PUBLIC_KEY_LEN;
    ret = GetPubKeyData(pkey, &ctx->cipher, keyData, &keyDataLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    // kemContext = enc || pkRm
    uint32_t kemContextLen = encapsulatedKeyLen + keyDataLen;
    kemContext = (uint8_t*)BSL_SAL_Malloc(kemContextLen);
    if (kemContext == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto end;
    }
    (void)memcpy_s(kemContext, kemContextLen, encapsulatedKey, encapsulatedKeyLen);
    (void)memcpy_s(kemContext + encapsulatedKeyLen, keyDataLen, keyData, keyDataLen);

    uint8_t suiteid[HPKE_KEM_SUITEID_LEN];
    GenerateKemSuiteid(ctx->cipher.kemId, suiteid, HPKE_KEM_SUITEID_LEN);
    ret = HpkeExtractAndExpand(ctx, dh, dhLen, kemContext, kemContextLen, suiteid, HPKE_KEM_SUITEID_LEN,
        sharedSecret, sharedSecretLen);

end:
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    BSL_SAL_CleanseData(dh, HPKE_KEM_DH_MAX_SHARED_KEY_LEN);
    BSL_SAL_Free(kemContext);
    return ret;
}

int32_t CRYPT_EAL_HpkeSetupRecipient(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, uint8_t *info, uint32_t infoLen,
    const uint8_t *encapsulatedKey, uint32_t encapsulatedKeyLen)
{
    if (ctx == NULL || pkey == NULL || encapsulatedKey == NULL || encapsulatedKeyLen == 0) {
        return CRYPT_NULL_INPUT;
    }

    if (ctx->role != CRYPT_HPKE_RECIPIENT) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->symKey != NULL || ctx->baseNonce != NULL || ctx->exportSecret != NULL) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (encapsulatedKeyLen != GetEncapsulatedKeyLen(&ctx->cipher)) {
        return CRYPT_INVALID_ARG;
    }

    uint8_t sharedSecret[HPKE_KEM_MAX_SHARED_KEY_LEN] = { 0 };
    uint32_t sharedSecretLen = GetKemSharedKeyLen(&ctx->cipher);
    int32_t ret = HpkeDecap(ctx, pkey, encapsulatedKey, encapsulatedKeyLen, sharedSecret, sharedSecretLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = KeySchedule(ctx, sharedSecret, sharedSecretLen, info, infoLen);
    BSL_SAL_CleanseData(sharedSecret, HPKE_KEM_MAX_SHARED_KEY_LEN);
    return ret;
}

static int32_t HpkeAeadDecrypt(CRYPT_EAL_HpkeCtx *ctx,const uint8_t *nonce, uint32_t nonceLen, uint8_t *aad,
    uint32_t aadLen, const uint8_t *cipher, uint32_t cipherLen, uint8_t *plain, uint32_t *plainLen)
{
    CRYPT_CIPHER_AlgId id = GetAeadCipherAlgid(&ctx->cipher);
    CRYPT_EAL_CipherCtx *cipherCtx = CRYPT_EAL_CipherNewCtx(id);
    if (ctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = CRYPT_EAL_CipherInit(cipherCtx, ctx->symKey, ctx->symKeyLen, nonce, nonceLen, false);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(cipherCtx);
        return ret;
    }

    if (aad != NULL && aadLen > 0) {
        ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_SET_AAD, (void *)aad, aadLen);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_CipherFreeCtx(cipherCtx);
            return ret;
        }
    }

    ret = CRYPT_EAL_CipherUpdate(cipherCtx, cipher, cipherLen - HPKE_AEAD_TAG_LEN, plain, plainLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(cipherCtx);
        return ret;
    }

    uint8_t newTag[HPKE_AEAD_TAG_LEN];
    ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_GET_TAG, (void *)newTag, HPKE_AEAD_TAG_LEN);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    if (memcmp(newTag, cipher + (cipherLen - HPKE_AEAD_TAG_LEN), HPKE_AEAD_TAG_LEN) != 0) {
        ret = CRYPT_HPKE_ERR_AEAD_TAG;
    }

end:
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(plain, *plainLen);
    }
    CRYPT_EAL_CipherFreeCtx(cipherCtx);
    return ret;
}

int32_t CRYPT_EAL_HpkeOpen(CRYPT_EAL_HpkeCtx *ctx, uint8_t *aad, uint32_t aadLen, const uint8_t *cipherText,
    uint32_t cipherTextLen, uint8_t *plainText, uint32_t *plainTextLen)
{
    if (ctx == NULL || cipherText == NULL || plainText == NULL || plainTextLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (ctx->role != CRYPT_HPKE_RECIPIENT) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (ctx->symKey == NULL || ctx->baseNonce == NULL) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (cipherTextLen <= HPKE_AEAD_TAG_LEN) {
        return CRYPT_INVALID_ARG;
    }

    if (ctx->seq + 1 == 0) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (cipherText == NULL) {
        *plainTextLen = cipherTextLen - HPKE_AEAD_TAG_LEN;
        return CRYPT_SUCCESS;
    }

    uint8_t nonce[HPKE_AEAD_NONCE_LEN] = { 0 };
    ComputeNonce(ctx, nonce, HPKE_AEAD_NONCE_LEN);

    ctx->seq++;
    return HpkeAeadDecrypt(ctx, nonce, HPKE_AEAD_NONCE_LEN, aad, aadLen, cipherText, cipherTextLen, plainText,
        plainTextLen);
}

void CRYPT_EAL_HpkeFreeCtx(CRYPT_EAL_HpkeCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    FreeHpkeKeyInfo(ctx);
    (void)memset_s(ctx, sizeof(CRYPT_EAL_HpkeCtx), 0, sizeof(CRYPT_EAL_HpkeCtx));
    free(ctx);
}

static int32_t GetEccOrder(CRYPT_HPKE_CipherSuite *cipher, BN_BigNum **order)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    int32_t ret = CreatePkeyCtx(cipher, &pkey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint8_t ecP[MAX_ECC_PARAM_LEN];
    uint8_t ecA[MAX_ECC_PARAM_LEN];
    uint8_t ecB[MAX_ECC_PARAM_LEN];
    uint8_t ecN[MAX_ECC_PARAM_LEN];
    uint8_t ecH[MAX_ECC_PARAM_LEN];
    uint8_t ecX[MAX_ECC_PARAM_LEN];
    uint8_t ecY[MAX_ECC_PARAM_LEN];

    CRYPT_EAL_PkeyPara para = {0};
    para.id = CRYPT_EAL_PkeyGetId(pkey);
    para.para.eccPara.p = ecP;
    para.para.eccPara.a = ecA;
    para.para.eccPara.b = ecB;
    para.para.eccPara.n = ecN;
    para.para.eccPara.h = ecH;
    para.para.eccPara.x = ecX;
    para.para.eccPara.y = ecY;
    para.para.eccPara.pLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.aLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.bLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.nLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.hLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.xLen = MAX_ECC_PARAM_LEN;
    para.para.eccPara.yLen = MAX_ECC_PARAM_LEN;
    ret = CRYPT_EAL_PkeyGetPara(pkey, &para);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    BN_BigNum *bn = BN_Create(para.para.eccPara.nLen * 8);
    if (bn == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = BN_Bin2Bn(bn, para.para.eccPara.n, para.para.eccPara.nLen);
    if (ret != CRYPT_SUCCESS) {
        BN_Destroy(bn);
        return ret;
    }

    *order = bn;
    return CRYPT_SUCCESS;
}

// static void HpkeI2OSPBuf(const uint8_t *from, uint8_t *to, uint32_t len)
// {
//     uint16_t a = 0x1213;
//     uint8_t *p = (uint8_t *)&a;
//     if (p[0] == 0x12) {
//         (void)memcpy_s(to, from, len);
//     }

//     uint32_t i;
//     for (i = 0; i < len; i++) { // little-endian
//         to[len - i - 1] = from[i];
//     }
// }

static int32_t ExpandEccPriKey(CRYPT_HPKE_CipherSuite *cipher, uint8_t *dkpPrk, uint32_t dkpPrkLen, uint8_t *suiteid,
    uint32_t suiteidLen, uint8_t *sk, uint32_t skLen)
{
    CRYPT_MAC_AlgId macId = GetKemMacAlgId(cipher);
    int32_t ret;

    BN_BigNum *skBn = BN_Create(skLen * 8);
    if (skBn == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    BN_BigNum *order = NULL;
    ret = GetEccOrder(cipher, &order);
    if (ret != CRYPT_SUCCESS) {
        BN_Destroy(skBn);
        return ret;
    }

    uint8_t counter = 0;
    uint8_t bitmask = (cipher->kemId == CRYPT_KEM_DHKEM_P521_HKDF_SHA512) ? 0x01 : 0xFF;
    do {
        ret = HpkeLabeledExpand(macId, dkpPrk, dkpPrkLen, (uint8_t *)"candidate", strlen("candidate"),
            (uint8_t *)&counter, 1, suiteid, suiteidLen, sk, skLen);
        if (ret != CRYPT_SUCCESS) {
            break;
        }

        sk[0] = sk[0] & bitmask;
        ret = BN_Bin2Bn(skBn, sk, skLen);
        if (ret != CRYPT_SUCCESS) {
            break;
        }
        counter++;
        if (counter == 0) { // RFC9180 7.1.3, up to 255 attempts.
            ret = CRYPT_HPKE_ERR_GEN_ASYM_KEY;
            break;
        }
    } while (BN_IsZero(skBn) || BN_Cmp(skBn, order) >= 0);
    BN_Destroy(skBn);
    BN_Destroy(order);

    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(sk, skLen);
        return ret;
    }
    // HpkeI2OSPBuf(bytes, sk, skLen);
    return CRYPT_SUCCESS;
}

static int32_t DeriveKeyPair(CRYPT_HPKE_CipherSuite *cipher, uint8_t *ikm, uint32_t ikmLen, CRYPT_EAL_PkeyCtx **pctx)
{
    uint8_t suiteid[HPKE_KEM_SUITEID_LEN];
    GenerateKemSuiteid(cipher->kemId, suiteid, HPKE_KEM_SUITEID_LEN);

    uint8_t dkpPrk[HPKE_HKDF_MAX_EXTRACT_KEY_LEN];
    uint32_t dkpPrkLen = GetKemExtractKeyLen(cipher);
    CRYPT_MAC_AlgId macId = GetKemMacAlgId(cipher);
    int32_t ret =  HpkeLabeledExtract(macId, (uint8_t *)"", 0, (uint8_t *)"dkp_prk", strlen("dkp_prk"),
        ikm, ikmLen, suiteid, HPKE_KEM_SUITEID_LEN, dkpPrk, dkpPrkLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    uint8_t sk[HPKE_KEM_MAX_PRIVATE_KEY_LEN] = { 0 };
    uint32_t skLen = GetDhKemPrivateKeyLen(cipher);
    if (cipher->kemId == CRYPT_KEM_DHKEM_X25519_HKDF_SHA256 || cipher->kemId == CRYPT_KEM_DHKEM_X448_HKDF_SHA512) {
        ret = HpkeLabeledExpand(macId, dkpPrk, dkpPrkLen, (uint8_t *)"sk", strlen("sk"), (uint8_t *)"", 0,
            suiteid, HPKE_KEM_SUITEID_LEN, sk, skLen);
    } else {
        ret = ExpandEccPriKey(cipher, dkpPrk, dkpPrkLen, suiteid, HPKE_KEM_SUITEID_LEN, sk, skLen);
    }
    BSL_SAL_CleanseData(dkpPrk, HPKE_HKDF_MAX_EXTRACT_KEY_LEN);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_EAL_PkeyCtx *pkey = NULL;
    ret = CreatePriKey(cipher, sk, skLen, &pkey);
    BSL_SAL_CleanseData(sk, skLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    *pctx = pkey;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_HpkeGenerateKeyPair(CRYPT_HPKE_CipherSuite cipher, uint8_t *ikm, uint32_t ikmLen,
    CRYPT_EAL_PkeyCtx **pctx)
{
    if (pctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if ((ikm == NULL && ikmLen != 0) || (ikm != NULL && ikmLen == 0)) {
        return CRYPT_INVALID_ARG;
    }

    int32_t ret = CheckHpkeCipherSuite(&cipher);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    uint32_t ikmNewLen = GetDhKemPrivateKeyLen(&cipher);
    if (ikmLen != 0) {
        if (ikmLen < ikmNewLen) {
            return CRYPT_INVALID_ARG;
        }
        return DeriveKeyPair(&cipher, ikm, ikmLen, pctx);
    }

    uint8_t ikmNew[HPKE_KEM_MAX_PRIVATE_KEY_LEN];
    ret = CRYPT_EAL_Randbytes(ikmNew, ikmNewLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = DeriveKeyPair(&cipher, ikmNew, ikmNewLen, pctx);
    BSL_SAL_CleanseData(ikmNew, ikmNewLen);
    return ret;
}

int32_t CRYPT_EAL_HpkeExportSecret(CRYPT_EAL_HpkeCtx *ctx, uint8_t *info, uint32_t infoLen, uint8_t *key,
    uint32_t keyLen)
{
    if (ctx == NULL || key == NULL || keyLen == 0) {
        return CRYPT_NULL_INPUT;
    }

    if (ctx->exportSecret == NULL) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (keyLen > 255 * GetKdfExtractKeyLen(&ctx->cipher)) {
        return CRYPT_INVALID_ARG;
    }

    uint8_t suiteid[HPKE_HPKE_SUITEID_LEN];
    GenerateHpkeSuiteid(&ctx->cipher, suiteid, HPKE_HPKE_SUITEID_LEN);

    CRYPT_MAC_AlgId macId = GetKdfMacAlgId(&ctx->cipher);
    return HpkeLabeledExpand(macId, ctx->exportSecret, ctx->exportSecretLen, (uint8_t *)"sec", strlen("sec"),
        info, infoLen, suiteid, HPKE_HPKE_SUITEID_LEN, key, keyLen);
}

int32_t CRYPT_EAL_HpkeGetParam(CRYPT_EAL_HpkeCtx *ctx, CRYPT_HPKE_PARAM_TYPE type, uint8_t *buff, uint32_t *buffLen)
{
    if (ctx == NULL || buffLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    uint32_t len = 0;
    uint8_t *p = NULL;
    switch (type) {
        case CRYPT_HPKE_PARAM_SYM_KEY:
            len = ctx->symKeyLen;
            p = ctx->symKey;
            break;
        case CRYPT_HPKE_PARAM_BASE_NONCE:
            len = ctx->baseNonceLen;
            p = ctx->baseNonce;
            break;
        case CRYPT_HPKE_PARAM_EXPORTER_SECRET:
            len = ctx->exportSecretLen;
            p = ctx->exportSecret;
            break;
        default:
            return CRYPT_INVALID_ARG;
    }

    if (p == NULL || len == 0) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (buff == NULL) {
        *buffLen = len;
        return CRYPT_SUCCESS;
    }

    if (*buffLen < len) {
        return CRYPT_INVALID_ARG;
    }

    (void)memcpy_s(buff, *buffLen, p, len);
    *buffLen = len;
    return CRYPT_SUCCESS;
}

static int32_t HpkeSetSymKey(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *buff, uint32_t buffLen)
{
    if (ctx->symKey != NULL) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (buffLen != GetAeadKeyLen(&ctx->cipher)) {
        return CRYPT_INVALID_ARG;
    }

    ctx->symKey = BSL_SAL_Malloc(buffLen);
    if (ctx->symKey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memcpy_s(ctx->symKey, buffLen, buff, buffLen);
    ctx->symKeyLen = buffLen;
    return CRYPT_SUCCESS;
}

static int32_t HpkeSetBaseNonce(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *buff, uint32_t buffLen)
{
    if (ctx->baseNonce != NULL) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (buffLen != HPKE_AEAD_NONCE_LEN) {
        return CRYPT_INVALID_ARG;
    }

    ctx->baseNonce = BSL_SAL_Malloc(buffLen);
    if (ctx->baseNonce == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memcpy_s(ctx->baseNonce, buffLen, buff, buffLen);
    ctx->baseNonceLen = buffLen;
    return CRYPT_SUCCESS;
}

static int32_t HpkeSetExporterSecret(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *buff, uint32_t buffLen)
{
    if (ctx->exportSecret != NULL) {
        return CRYPT_HPKE_ERR_CALL;
    }

    if (buffLen != GetKdfExtractKeyLen(&ctx->cipher)) {
        return CRYPT_INVALID_ARG;
    }    

    ctx->exportSecret = BSL_SAL_Malloc(buffLen);
    if (ctx->exportSecret == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    (void)memcpy_s(ctx->exportSecret, buffLen, buff, buffLen);
    ctx->exportSecretLen = buffLen;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_HpkeSetParam(CRYPT_EAL_HpkeCtx *ctx, CRYPT_HPKE_PARAM_TYPE type, const uint8_t *buff,
    uint32_t buffLen)
{
    if (ctx == NULL || buff == NULL || buffLen == 0) {
        return CRYPT_NULL_INPUT;
    }

    switch (type) {
        case CRYPT_HPKE_PARAM_SYM_KEY:
            return HpkeSetSymKey(ctx, buff, buffLen);
        case CRYPT_HPKE_PARAM_BASE_NONCE:
            return HpkeSetBaseNonce(ctx, buff, buffLen);
        case CRYPT_HPKE_PARAM_EXPORTER_SECRET:
            return HpkeSetExporterSecret(ctx, buff, buffLen);
        default:
            return CRYPT_INVALID_ARG;
    }
}
