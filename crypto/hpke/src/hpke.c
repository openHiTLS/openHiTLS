
#include "hitls_build.h"

#include "crypt_eal_pkey.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_rand.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "bsl_sal.h"
#include "crypt_bn.h"

#include "crypt_eal_hpke.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define HPKE_SUITE_ID_HPKE "HPKE"
#define HPKE_SUITE_ID_HPKE_LEN 5
#define HPKE_SUITE_ID_KEM "KEM"
#define HPKE_SUITE_ID_KEM_LEN 4

#define CRYPT_HPKE_ERR 0xFFFFFF
#define HPKE_AEAD_BASENONE_LEN 12

#define CRYPT_HPKE_CIPHER_UNKNOWN 0xFFFFFF
#define CRYPT_HPKE_MODE_UNKNOWN 0xFFFFFF
#define CRYPT_HPKE_CIPHER_NOT_SUPPORT 0xFFFFFF

#define CRYPT_HPKE_HKDF_EXTRACT_MAX_LEN 64


#define CRYPT_HPKE_KEM_MAX_NSECRET  64
#define CRYPT_HPKE_KEN_MAX_NENC 133
#define CRYPT_HPKE_KEN_MAX_NPK  133
#define CRYPT_HPKE_KEN_MAX_NSK  66

#define CRYPT_HPKE_AEAD_MAX_KEY_LEN  32
#define CRYPT_HPKE_AEAD_MAX_NONCE_LEN  12
#define CRYPT_HPKE_AEAD_MAX_TAG_LEN  16

#define CRYPT_HPKE_KEM_SUITEID_LEN 5
#define CRYPT_HPKE_HPKE_SUITEID_LEN 10

#define CRYPT_HPKE_DH_MAX_LEN 1024

/**
 * @ingroup crypt_eal_hpke
 * @brief HPKE context structure
 */
struct CRYPT_EAL_HpkeCtx {
    CRYPT_HPKE_MODE mode;             // HPKE mode
    CRYPT_HpkeCipherSuite cipher;     // HPKE cipher suite
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

// static void PrintfBuf(char *tag, const uint8_t *buff, uint32_t len)
// {
//     printf("[%s], len = %d\n", tag, len);
//     for (uint32_t i = 0; i < len; i++) {
//         printf("%02x ", buff[i]);
//     }
//     printf("\n");
// }

static CRYPT_MAC_AlgId GetKdfMacAlgId(CRYPT_HpkeCipherSuite *cipher)
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

static CRYPT_CIPHER_AlgId GetAeadCipherAlgid(CRYPT_HpkeCipherSuite *cipher)
{
    switch (cipher->aeadId) {
        case CRYPT_AEAD_AES_GCM_128:
            return CRYPT_CIPHER_AES128_GCM;
        case CRYPT_AEAD_AES_GCM_256:
            return CRYPT_CIPHER_AES256_GCM;
        case CRYPT_AEAD_CHACHA20_POLY1305:
            return CRYPT_CIPHER_CHACHA20_POLY1305;
        default:
            return CRYPT_CIPHER_MAX;
    }
}

static CRYPT_PKEY_AlgId GetPkeyAlgId(CRYPT_HpkeCipherSuite *cipher)
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

static CRYPT_MAC_AlgId GetKemMacAlgId(CRYPT_HpkeCipherSuite *cipher)
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

static CRYPT_PKEY_ParaId GetPkeyCurveId(CRYPT_HPKE_KEM_AlgId kemId)
{
    switch (kemId) {
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

static uint32_t HpkeGetNsk(CRYPT_HPKE_KEM_AlgId id)
{
    switch (id) {
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

static uint32_t HpkeGetNsecret(CRYPT_EAL_HpkeCtx *ctx)
{
    switch (ctx->cipher.kemId) {
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

static uint32_t HpkeGetNk(CRYPT_EAL_HpkeCtx *ctx)
{
    switch (ctx->cipher.aeadId) {
        case CRYPT_AEAD_AES_GCM_128:
            return 16;
        case CRYPT_AEAD_AES_GCM_256:
            return 32;
        case CRYPT_AEAD_CHACHA20_POLY1305:
            return 32;
        default:
            return 0;
    }
}

static uint32_t HpkeGetNh(CRYPT_EAL_HpkeCtx *ctx)
{
    switch (ctx->cipher.kdfId) {
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

static int32_t CheckHpkeCipherSuite(CRYPT_HpkeCipherSuite *cipher)
{
    if (GetKdfMacAlgId(cipher) == CRYPT_MAC_MAX) {
        return CRYPT_HPKE_CIPHER_UNKNOWN;
    }

    if (GetAeadCipherAlgid(cipher) == CRYPT_CIPHER_MAX) {
        return CRYPT_HPKE_CIPHER_UNKNOWN;
    }

    if (GetPkeyAlgId(cipher) == CRYPT_PKEY_MAX) {
        return CRYPT_HPKE_CIPHER_UNKNOWN;
    }
    return CRYPT_SUCCESS;
}

CRYPT_EAL_HpkeCtx *CRYPT_EAL_HpkeNewCtx(CRYPT_HPKE_MODE mode, CRYPT_HpkeCipherSuite cipher)
{
    int32_t ret = CheckHpkeCipherSuite(&cipher);
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }

    if (mode != CRYPT_HPKE_MODE_BASE) {
        return NULL;
    }

    CRYPT_EAL_HpkeCtx *ctx = (CRYPT_EAL_HpkeCtx*)malloc(sizeof(CRYPT_EAL_HpkeCtx));
    if (ctx == NULL) {
        return NULL;
    }
    memset(ctx, 0, sizeof(CRYPT_EAL_HpkeCtx));
    ctx->mode = mode;
    ctx->cipher = cipher;
    return ctx;
}

static int32_t CreatePkeyCtx(CRYPT_HpkeCipherSuite *cipher, CRYPT_EAL_PkeyCtx **pkeyCtx)
{
    CRYPT_PKEY_AlgId algId = GetPkeyAlgId(cipher);
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(algId);
    if (pkey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    if (algId == CRYPT_PKEY_ECDH) {
        CRYPT_PKEY_ParaId curveId = GetPkeyCurveId(cipher->kemId);
        int32_t ret = CRYPT_EAL_PkeySetParaById(pkey, curveId);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_EAL_PkeyFreeCtx(pkey);
            return ret;
        }
    }

    *pkeyCtx = pkey;
    return CRYPT_SUCCESS;
}

static CRYPT_EAL_PkeyCtx *CreatePubKey(CRYPT_HpkeCipherSuite *cipher, const uint8_t *pubKey, uint32_t pubKeyLen)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    int32_t ret = CreatePkeyCtx(cipher, &pkey);
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }

    CRYPT_EAL_PkeyPub pub = {0};
    pub.id = CRYPT_EAL_PkeyGetId(pkey);
    pub.key.eccPub.data = (uint8_t *)pubKey; // compatible curve25519Pub
    pub.key.eccPub.len = pubKeyLen;

    ret = CRYPT_EAL_PkeySetPub(pkey, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }
    return pkey;
}

static CRYPT_EAL_PkeyCtx *CreatePriKey(CRYPT_HpkeCipherSuite *cipher, const uint8_t *priKey, uint32_t priKeyLen)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    int32_t ret = CreatePkeyCtx(cipher, &pkey); 
    if (ret != CRYPT_SUCCESS) {
        return NULL;
    }

    CRYPT_EAL_PkeyPrv pub = {0};
    pub.id = CRYPT_EAL_PkeyGetId(pkey);
    pub.key.eccPrv.data = (uint8_t *)priKey;
    pub.key.eccPrv.len = priKeyLen;

    ret = CRYPT_EAL_PkeySetPrv(pkey, &pub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }

    if (cipher->kemId == CRYPT_KEM_DHKEM_X25519_HKDF_SHA256) {
        ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GEN_X25519_PUBLICKEY, NULL, 0);
    } else {
        ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0);
    }

    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return NULL;
    }

    return pkey;
}

static void GenerateHpkeSuiteid(CRYPT_HpkeCipherSuite *cipher, uint8_t *suiteid)
{
    memcpy(suiteid, "HPKE", 4);
    uint16_t id = HpkeI2OSP16(cipher->kemId);
    memcpy(suiteid + 4, &id, sizeof(uint16_t));

    id = HpkeI2OSP16(cipher->kdfId);
    memcpy(suiteid + 6, &id, sizeof(uint16_t));

    id = HpkeI2OSP16(cipher->aeadId);
    memcpy(suiteid + 8, &id, sizeof(uint16_t));
}

static void GenerateKemSuiteid(CRYPT_HPKE_KEM_AlgId kemId, uint8_t *suiteid)
{
    memcpy(suiteid, "KEM", 3);
    uint16_t kemIdNew = HpkeI2OSP16(kemId);
    memcpy(suiteid + 3, &kemIdNew, sizeof(uint16_t));
}

static int32_t LabeledExtract(CRYPT_MAC_AlgId macId, const uint8_t *salt, uint32_t saltLen,
    const uint8_t *label, uint32_t labelLen, const uint8_t *ikm, uint32_t ikmLen, const uint8_t *suiteid, uint32_t suiteidLen,
    uint8_t *out, uint32_t *outLen)
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
    memcpy(labeledIkm + offset, version, versionLen);
    offset += versionLen;
    memcpy(labeledIkm + offset, suiteid, suiteidLen);
    offset += suiteidLen;
    memcpy(labeledIkm + offset, label, labelLen);
    offset += labelLen;
    memcpy(labeledIkm + offset, ikm, ikmLen);

    int32_t ret = CRYPT_EAL_HkdfExtract(macId, labeledIkm, labeledIkmLen, salt, saltLen, out, outLen);
    BSL_SAL_Free(labeledIkm);
    return ret;
}

static int32_t LabeledExpand(CRYPT_MAC_AlgId macId, const uint8_t *prk, uint32_t prkLen,
    const uint8_t *label, uint32_t labelLen, const uint8_t *info, uint32_t infoLen, const uint8_t *suiteid, uint32_t suiteidLen,
    uint8_t *out, uint32_t outLen)
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
    memcpy(labeledInfo, &outLenTmp, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    memcpy(labeledInfo + offset, version, versionLen);
    offset += versionLen;
    memcpy(labeledInfo + offset, suiteid, suiteidLen);
    offset += suiteidLen;
    memcpy(labeledInfo + offset, label, labelLen);
    offset += labelLen;
    memcpy(labeledInfo + offset, info, infoLen);

    int32_t ret = CRYPT_EAL_HkdfExpand(macId, prk, prkLen, labeledInfo, labeledInfoLen, out, outLen);

    BSL_SAL_Free(labeledInfo);
    return ret;
}

static int32_t ExtractAndExpand(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *dh, uint32_t dhLen,
    const uint8_t *kemContext, uint32_t kemContextLen, const uint8_t *suiteid, uint32_t suiteidLen,
    uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    CRYPT_MAC_AlgId macId = GetKemMacAlgId(&ctx->cipher);
    uint8_t eaePrk[CRYPT_HPKE_HKDF_EXTRACT_MAX_LEN];
    uint32_t eaePrkLen = CRYPT_HPKE_HKDF_EXTRACT_MAX_LEN;
    int32_t ret = LabeledExtract(macId, NULL, 0, (const uint8_t *)"eae_prk", strlen("eae_prk"), dh, dhLen, suiteid, suiteidLen, eaePrk, &eaePrkLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = LabeledExpand(macId, eaePrk, eaePrkLen, (const uint8_t *)"shared_secret", strlen("shared_secret"), kemContext, kemContextLen, suiteid, suiteidLen, 
        sharedSecret, *sharedSecretLen);
    BSL_SAL_CleanseData(eaePrk, eaePrkLen);
    return ret;
}

static int32_t HpkeEncap(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, const uint8_t *pkR, uint32_t pkRLen,
    uint8_t *enc, uint32_t *encLen, uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    if (ctx == NULL || pkR == NULL || enc == NULL || encLen == NULL) {
        return CRYPT_INVALID_ARG;
    }

    int32_t ret;
    CRYPT_EAL_PkeyCtx *pkeyS = NULL;
    if (pkey != NULL) {
        pkeyS = pkey;
    } else {
        ret = CRYPT_EAL_HpkeGenerateKeyPair(ctx->cipher, NULL, 0, &pkeyS);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    uint8_t dh[CRYPT_HPKE_DH_MAX_LEN];
    uint32_t dhLen = CRYPT_HPKE_DH_MAX_LEN;
    CRYPT_EAL_PkeyCtx *pkeyR = NULL;

    CRYPT_EAL_PkeyPub ephemPub;
    ephemPub.id = GetPkeyAlgId(&ctx->cipher);
    ephemPub.key.eccPub.len = *encLen;  // compatible curve25519Pub
    ephemPub.key.eccPub.data = enc;
    ret = CRYPT_EAL_PkeyGetPub(pkeyS, &ephemPub);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }
    *encLen = ephemPub.key.eccPub.len;

    pkeyR = CreatePubKey(&ctx->cipher, pkR, pkRLen);
    if (pkeyR == NULL) {
        ret = CRYPT_INVALID_ARG;
        goto end;
    }

    ret = CRYPT_EAL_PkeyComputeShareKey(pkeyS, pkeyR, dh, &dhLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    // kemContext = enc || pkRm
    uint32_t kemContextLen = *encLen + pkRLen;
    uint8_t *kemContext = (uint8_t*)BSL_SAL_Malloc(kemContextLen);
    if (kemContext == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto end;
    }
    memcpy(kemContext, enc, *encLen);
    memcpy(kemContext + *encLen, pkR, pkRLen);

    uint8_t suiteid[CRYPT_HPKE_KEM_SUITEID_LEN];
    GenerateKemSuiteid(ctx->cipher.kemId, suiteid);
    ret = ExtractAndExpand(ctx, dh, dhLen, kemContext, kemContextLen, suiteid, CRYPT_HPKE_KEM_SUITEID_LEN, sharedSecret, sharedSecretLen);
    BSL_SAL_Free(kemContext);

end:
    if (pkey == NULL) {
        CRYPT_EAL_PkeyFreeCtx(pkeyS);
    }
    CRYPT_EAL_PkeyFreeCtx(pkeyR);
    BSL_SAL_CleanseData(dh, CRYPT_HPKE_DH_MAX_LEN);
    return ret;
}

static int32_t GenerateKeyScheduleContext(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *info, uint32_t infoLen,
    const uint8_t *suiteid, uint32_t suiteidLen, uint8_t **keyScheduleContext, uint32_t *keyScheduleContextLen)
{
    // psk_id_hash
    int32_t ret;
    uint8_t pskIdHash[CRYPT_HPKE_HKDF_EXTRACT_MAX_LEN];
    uint32_t pskIdHashLen = CRYPT_HPKE_HKDF_EXTRACT_MAX_LEN;
    CRYPT_MAC_AlgId macId = GetKdfMacAlgId(&ctx->cipher);
    ret = LabeledExtract(macId, NULL, 0, (const uint8_t*)"psk_id_hash", strlen("psk_id_hash"), (const uint8_t *)"", 0,
        suiteid, suiteidLen, pskIdHash, &pskIdHashLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // info_hash
    uint8_t infoHash[CRYPT_HPKE_HKDF_EXTRACT_MAX_LEN];
    uint32_t infoHashLen = CRYPT_HPKE_HKDF_EXTRACT_MAX_LEN;
    ret = LabeledExtract(macId, NULL, 0, (const uint8_t*)"info_hash", strlen("info_hash"), info, infoLen,
        suiteid, suiteidLen, infoHash, &infoHashLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // key_schedule_context = mode || psk_id_hash || info_hash
    uint32_t contextLen = 1 + pskIdHashLen + infoHashLen;
    uint8_t *context = (uint8_t*)BSL_SAL_Malloc(contextLen);
    if (context == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    context[0] = ctx->mode;
    memcpy(context + 1, pskIdHash, pskIdHashLen);
    memcpy(context + 1 + pskIdHashLen , infoHash, infoHashLen);

    *keyScheduleContext = context;
    *keyScheduleContextLen = contextLen;
    return CRYPT_SUCCESS;
}

static void FreeHpkeKeyInfo(CRYPT_EAL_HpkeCtx *ctx)
{
    BSL_SAL_ClearFree(ctx->symKey, ctx->symKeyLen);
    BSL_SAL_ClearFree(ctx->baseNonce, ctx->baseNonceLen);
    BSL_SAL_ClearFree(ctx->exportSecret, ctx->exportSecretLen);
    ctx->symKeyLen = 0;
    ctx->baseNonceLen = 0;
    ctx->exportSecretLen = 0;
}

static int32_t MallocHpkeKeyInfo(CRYPT_EAL_HpkeCtx *ctx)
{
    ctx->symKeyLen = HpkeGetNk(ctx);
    ctx->symKey = BSL_SAL_Malloc(ctx->symKeyLen);

    ctx->baseNonceLen = CRYPT_HPKE_AEAD_MAX_NONCE_LEN;
    ctx->baseNonce = BSL_SAL_Malloc(CRYPT_HPKE_AEAD_MAX_NONCE_LEN);

    ctx->exportSecretLen = HpkeGetNh(ctx);
    ctx->exportSecret = BSL_SAL_Malloc(ctx->exportSecretLen);

    if (ctx->symKey == NULL || ctx->baseNonce == NULL || ctx->exportSecret == NULL) {
        FreeHpkeKeyInfo(ctx);
    }
    return CRYPT_SUCCESS;
}

static int32_t KeySchedule(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *sharedSecret, uint32_t sharedSecretLen,
    const uint8_t *info, uint32_t infoLen)
{
    uint8_t suiteid[CRYPT_HPKE_HPKE_SUITEID_LEN];
    uint8_t suiteidLen = CRYPT_HPKE_HPKE_SUITEID_LEN;
    GenerateHpkeSuiteid(&ctx->cipher, suiteid);
    uint32_t contextLen;
    uint8_t *context = NULL;
    int32_t ret = GenerateKeyScheduleContext(ctx, info, infoLen, suiteid, suiteidLen, &context, &contextLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    CRYPT_MAC_AlgId macId = GetKdfMacAlgId(&ctx->cipher);
    uint8_t secret[CRYPT_HPKE_KEM_MAX_NSECRET] = {0};
    uint32_t secretLen = CRYPT_HPKE_KEM_MAX_NSECRET;
    ret = LabeledExtract(macId, sharedSecret, sharedSecretLen, (uint8_t*)"secret", strlen("secret"), NULL, 0, suiteid, suiteidLen, secret, &secretLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    ret = MallocHpkeKeyInfo(ctx);
    if (ret!= CRYPT_SUCCESS) {
        goto end;
    }

    ret = LabeledExpand(macId, secret, secretLen, (uint8_t*)"key", strlen("key"), context, contextLen, suiteid, suiteidLen, ctx->symKey, ctx->symKeyLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    ret = LabeledExpand(macId, secret, secretLen, (uint8_t*)"base_nonce", strlen("base_nonce"), context, contextLen, suiteid, suiteidLen, ctx->baseNonce,ctx->baseNonceLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    ret = LabeledExpand(macId, secret, secretLen, (uint8_t*)"exp", strlen("exp"), context, contextLen, suiteid, suiteidLen, ctx->exportSecret, ctx->exportSecretLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

end:
    memset(secret, 0, CRYPT_HPKE_KEM_MAX_NSECRET);
    BSL_SAL_Free(context);
    if (ret!= CRYPT_SUCCESS) {
        FreeHpkeKeyInfo(ctx);
    }
    return ret;
}

int32_t CRYPT_EAL_HpkeSetupSender(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, const uint8_t *info, uint32_t infoLen,
    const uint8_t *pkR, uint32_t pkRLen, uint8_t *enc, uint32_t *encLen)
{
    if (ctx == NULL || pkR == NULL || pkRLen == 0 || enc == NULL || encLen == NULL) {
        return CRYPT_INVALID_ARG;
    }

    uint8_t sharedSecret[CRYPT_HPKE_KEM_MAX_NSECRET] = { 0 };
    uint32_t sharedSecretLen = HpkeGetNsecret(ctx);
    int32_t ret = HpkeEncap(ctx, pkey, pkR, pkRLen, enc, encLen, sharedSecret, &sharedSecretLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = KeySchedule(ctx, sharedSecret, sharedSecretLen, info, infoLen);
    BSL_SAL_CleanseData(sharedSecret, CRYPT_HPKE_KEM_MAX_NSECRET);
    return ret;
}

static int32_t HpkeAeadEncrypt(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *nonce, uint32_t nonceLen,
    const uint8_t *aad, uint32_t aadLen, const uint8_t *plain, uint32_t plainLen, uint8_t *cipher, uint32_t *cipherLen)
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
        ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_SET_AAD, (void *)aad, aadLen);
        if (ret != CRYPT_SUCCESS) {
            goto end;
        }
    }

    ret = CRYPT_EAL_CipherUpdate(cipherCtx, plain, plainLen, cipher, &outLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_GET_TAG, cipher + outLen, CRYPT_HPKE_AEAD_MAX_TAG_LEN);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    *cipherLen = outLen + CRYPT_HPKE_AEAD_MAX_TAG_LEN;
end:
    CRYPT_EAL_CipherFreeCtx(cipherCtx);
    return ret;
}

int32_t CRYPT_EAL_HpkeSetSeq(CRYPT_EAL_HpkeCtx *ctx, uint64_t seq)
{
    if (ctx == NULL) {
        return CRYPT_INVALID_ARG;
    }

    ctx->seq = seq;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_HpkeGetSeq(CRYPT_EAL_HpkeCtx *ctx, uint64_t *seq)
{
    if (ctx == NULL) {
        return CRYPT_INVALID_ARG;
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

int32_t CRYPT_EAL_HpkeSeal(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *aad, uint32_t aadLen,
    const uint8_t *plain, uint32_t plainLen, uint8_t *cipher, uint32_t *cipherLen)
{
    if (ctx == NULL || plain == NULL || cipherLen == 0) {
        return CRYPT_INVALID_ARG;
    }

    if (ctx->seq + 1 == 0) {
        return CRYPT_INVALID_ARG;
    }

    if (cipher == NULL) {
        *cipherLen = plainLen + CRYPT_HPKE_AEAD_MAX_TAG_LEN; // TAG len
        return CRYPT_SUCCESS;
    }

    if (*cipherLen < (plainLen + CRYPT_HPKE_AEAD_MAX_TAG_LEN)) {
        return CRYPT_INVALID_ARG;
    }

    uint8_t nonce[CRYPT_HPKE_AEAD_MAX_NONCE_LEN] = { 0 };
    ComputeNonce(ctx, nonce, CRYPT_HPKE_AEAD_MAX_NONCE_LEN);

    ctx->seq++;
    return HpkeAeadEncrypt(ctx, nonce, CRYPT_HPKE_AEAD_MAX_NONCE_LEN, aad, aadLen, plain, plainLen, cipher, cipherLen);
}

static int32_t HpkeDecap(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, const uint8_t *encapsulatedKey,
    uint32_t encapsulatedKeyLen, uint8_t *sharedSecret, uint32_t *sharedSecretLen)
{
    CRYPT_EAL_PkeyCtx *pkeyS = CreatePubKey(&ctx->cipher, encapsulatedKey, encapsulatedKeyLen);
    if (pkeyS == NULL) {
        return CRYPT_INVALID_ARG;
    }

    uint8_t *kemContext = NULL;
    uint8_t dh[CRYPT_HPKE_DH_MAX_LEN];
    uint32_t dhLen = CRYPT_HPKE_DH_MAX_LEN;

    int32_t ret = CRYPT_EAL_PkeyComputeShareKey(pkey, pkeyS, dh, &dhLen);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    CRYPT_EAL_PkeyPub pubR = {0};
    uint8_t keyBuff[CRYPT_HPKE_KEN_MAX_NPK];
    pubR.id = GetPkeyAlgId(&ctx->cipher);
    pubR.key.eccPub.len = CRYPT_HPKE_KEN_MAX_NPK;
    pubR.key.eccPub.data = keyBuff;
    ret = CRYPT_EAL_PkeyGetPub(pkey, &pubR);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    // kemContext = enc || pkRm
    uint32_t pubRLen = pubR.key.eccPub.len;
    uint32_t kemContextLen = encapsulatedKeyLen + pubRLen;
    kemContext = (uint8_t*)BSL_SAL_Malloc(kemContextLen);
    if (kemContext == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto end;
    }
    memcpy(kemContext, encapsulatedKey, encapsulatedKeyLen);
    memcpy(kemContext + encapsulatedKeyLen, keyBuff, pubRLen);

    uint8_t suiteid[CRYPT_HPKE_KEM_SUITEID_LEN];
    GenerateKemSuiteid(ctx->cipher.kemId, suiteid);
    ret = ExtractAndExpand(ctx, dh, dhLen, kemContext, kemContextLen, suiteid, CRYPT_HPKE_KEM_SUITEID_LEN, sharedSecret, sharedSecretLen);

end:
    CRYPT_EAL_PkeyFreeCtx(pkeyS);
    BSL_SAL_CleanseData(dh, CRYPT_HPKE_DH_MAX_LEN);
    BSL_SAL_Free(kemContext);
    return ret;
}

int32_t CRYPT_EAL_HpkeSetupRecipient(CRYPT_EAL_HpkeCtx *ctx, CRYPT_EAL_PkeyCtx *pkey, const uint8_t *info,
    uint32_t infoLen, const uint8_t *encapsulatedKey, uint32_t encapsulatedKeyLen)
{
    if (ctx == NULL || pkey == NULL || encapsulatedKey == NULL || encapsulatedKeyLen == 0) {
        return CRYPT_INVALID_ARG;
    }

    uint8_t sharedSecret[CRYPT_HPKE_KEM_MAX_NSECRET] = { 0 };
    uint32_t sharedSecretLen = HpkeGetNsecret(ctx);
    int32_t ret = HpkeDecap(ctx, pkey, encapsulatedKey, encapsulatedKeyLen, sharedSecret, &sharedSecretLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = KeySchedule(ctx, sharedSecret, sharedSecretLen, info, infoLen);
    BSL_SAL_CleanseData(sharedSecret, CRYPT_HPKE_KEM_MAX_NSECRET);
    return ret;
}
static int32_t HpkeAeadDecrypt(CRYPT_EAL_HpkeCtx *ctx,const uint8_t *nonce, uint32_t nonceLen,
    const uint8_t *aad, uint32_t aadLen, const uint8_t *cipher, uint32_t cipherLen, uint8_t *plain, uint32_t *plainLen)
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

    ret = CRYPT_EAL_CipherUpdate(cipherCtx, cipher, cipherLen - CRYPT_HPKE_AEAD_MAX_TAG_LEN, plain, plainLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_CipherFreeCtx(cipherCtx);
        return ret;
    }

    uint8_t newTag[CRYPT_HPKE_AEAD_MAX_TAG_LEN];
    ret = CRYPT_EAL_CipherCtrl(cipherCtx, CRYPT_CTRL_GET_TAG, (void *)newTag, CRYPT_HPKE_AEAD_MAX_TAG_LEN);
    if (ret != CRYPT_SUCCESS) {
        goto end;
    }

    if (memcmp(newTag, cipher + (cipherLen - CRYPT_HPKE_AEAD_MAX_TAG_LEN), CRYPT_HPKE_AEAD_MAX_TAG_LEN) != 0) {
        ret = CRYPT_HPKE_ERR;
    }

end:
    if (ret != CRYPT_SUCCESS) {
        memset(plain, 0, *plainLen);
    }
    CRYPT_EAL_CipherFreeCtx(cipherCtx);
    return ret;
}

int32_t CRYPT_EAL_HpkeOpen(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *aad, uint32_t aadLen,
    const uint8_t *cipher, uint32_t cipherLen, uint8_t *plain, uint32_t *plainLen)
{
    if (ctx == NULL || cipher == NULL || plain == NULL || plainLen == NULL) {
        return CRYPT_INVALID_ARG;
    }

    if (cipherLen <= CRYPT_HPKE_AEAD_MAX_TAG_LEN) {
        return CRYPT_INVALID_ARG;
    }

    if (ctx->seq + 1 == 0) {
        return CRYPT_INVALID_ARG;
    }

    if (cipher == NULL) {
        *plainLen = cipherLen - CRYPT_HPKE_AEAD_MAX_TAG_LEN;
        return CRYPT_SUCCESS;
    }

    uint8_t nonce[CRYPT_HPKE_AEAD_MAX_NONCE_LEN] = { 0 };
    ComputeNonce(ctx, nonce, CRYPT_HPKE_AEAD_MAX_NONCE_LEN);

    ctx->seq++;

    return HpkeAeadDecrypt(ctx, nonce, CRYPT_HPKE_AEAD_MAX_NONCE_LEN, aad, aadLen, cipher, cipherLen, plain, plainLen);
}

int32_t CRYPT_EAL_HpkeExportSecret(CRYPT_EAL_HpkeCtx *ctx, const uint8_t *info,
    uint32_t infoLen, uint8_t *key, uint32_t keyLen)
{
    if (ctx == NULL || key == NULL || keyLen == 0) {
        return CRYPT_INVALID_ARG;
    }

    if (keyLen > 255 * HpkeGetNh(ctx)) {
        return CRYPT_HPKE_ERR;
    }

    uint8_t suiteid[CRYPT_HPKE_HPKE_SUITEID_LEN];
    GenerateHpkeSuiteid(&ctx->cipher, suiteid);

    CRYPT_MAC_AlgId macId = GetKdfMacAlgId(&ctx->cipher);
    return LabeledExpand(macId, ctx->exportSecret, ctx->exportSecretLen, (const uint8_t *)"sec", strlen("sec"), info, infoLen, suiteid, CRYPT_HPKE_HPKE_SUITEID_LEN,
        key, keyLen);
}

void CRYPT_EAL_HpkeFreeCtx(CRYPT_EAL_HpkeCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    FreeHpkeKeyInfo(ctx);
    memset(ctx, 0, sizeof(CRYPT_EAL_HpkeCtx));
    free(ctx);
}

static int32_t GetEccOrder(CRYPT_HpkeCipherSuite *cipher, BN_BigNum **order)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    int32_t ret = CreatePkeyCtx(cipher, &pkey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    #define ECC_PARAM_MAX_LEN 66
    uint8_t ecP[ECC_PARAM_MAX_LEN];
    uint8_t ecA[ECC_PARAM_MAX_LEN];
    uint8_t ecB[ECC_PARAM_MAX_LEN];
    uint8_t ecN[ECC_PARAM_MAX_LEN];
    uint8_t ecH[ECC_PARAM_MAX_LEN];
    uint8_t ecX[ECC_PARAM_MAX_LEN];
    uint8_t ecY[ECC_PARAM_MAX_LEN];

    CRYPT_EAL_PkeyPara para = {0};
    para.id = CRYPT_EAL_PkeyGetId(pkey);
    para.para.eccPara.p = ecP;
    para.para.eccPara.a = ecA;
    para.para.eccPara.b = ecB;
    para.para.eccPara.n = ecN;
    para.para.eccPara.h = ecH;
    para.para.eccPara.x = ecX;
    para.para.eccPara.y = ecY;
    para.para.eccPara.pLen = ECC_PARAM_MAX_LEN;
    para.para.eccPara.aLen = ECC_PARAM_MAX_LEN;
    para.para.eccPara.bLen = ECC_PARAM_MAX_LEN;
    para.para.eccPara.nLen = ECC_PARAM_MAX_LEN;
    para.para.eccPara.hLen = ECC_PARAM_MAX_LEN;
    para.para.eccPara.xLen = ECC_PARAM_MAX_LEN;
    para.para.eccPara.yLen = ECC_PARAM_MAX_LEN;
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
//         memcpy(to, from, len);
//     }

//     uint32_t i;
//     for (i = 0; i < len; i++) { // little-endian
//         to[len - i - 1] = from[i];
//     }
// }

static int32_t ExpandEcPriKey(CRYPT_HpkeCipherSuite *cipher, const uint8_t *dkpPrk, uint32_t dkpPrkLen, const uint8_t *suiteid, uint32_t suiteidLen,
    uint8_t *sk, uint32_t skLen)
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
        ret =  LabeledExpand(macId, dkpPrk, dkpPrkLen, (const uint8_t *)"candidate", strlen("candidate"), (const uint8_t *)&counter, 1, suiteid, suiteidLen, sk, skLen);
        if (ret != CRYPT_SUCCESS) {
            break;
        }

        sk[0] = sk[0] & bitmask;
        ret = BN_Bin2Bn(skBn, sk, skLen);
        if (ret != CRYPT_SUCCESS) {
            break;
        }
        counter++;
        if (counter == 0) {
            ret = CRYPT_HPKE_ERR;
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

static int32_t DeriveKeyPair(CRYPT_HpkeCipherSuite *cipher, const uint8_t *ikm, uint32_t ikmLen, CRYPT_EAL_PkeyCtx **pctx)
{
    uint8_t suiteid[CRYPT_HPKE_KEM_SUITEID_LEN];
    GenerateKemSuiteid(cipher->kemId, suiteid);

    uint8_t dkpPrk[CRYPT_HPKE_HKDF_EXTRACT_MAX_LEN];
    uint32_t dkpPrkLen = CRYPT_HPKE_HKDF_EXTRACT_MAX_LEN;
    CRYPT_MAC_AlgId macId = GetKemMacAlgId(cipher);
    int32_t ret =  LabeledExtract(macId, (const uint8_t *)"", 0, (const uint8_t *)"dkp_prk", strlen("dkp_prk"), ikm, ikmLen, suiteid, CRYPT_HPKE_KEM_SUITEID_LEN, dkpPrk, &dkpPrkLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    uint8_t sk[CRYPT_HPKE_KEN_MAX_NSK];
    uint32_t skLen = HpkeGetNsk(cipher->kemId);

    if (cipher->kemId == CRYPT_KEM_DHKEM_X25519_HKDF_SHA256 || cipher->kemId == CRYPT_KEM_DHKEM_X448_HKDF_SHA512) {
        ret = LabeledExpand(macId, dkpPrk, dkpPrkLen, (const uint8_t *)"sk", strlen("sk"), (const uint8_t *)"", 0, suiteid, CRYPT_HPKE_KEM_SUITEID_LEN, sk, skLen);
    } else {
        ret = ExpandEcPriKey(cipher, dkpPrk, dkpPrkLen, suiteid, CRYPT_HPKE_KEM_SUITEID_LEN, sk, skLen);
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(sk, skLen);
        return ret;
    }

    CRYPT_EAL_PkeyCtx *skRctx = CreatePriKey(cipher, sk, skLen);
    BSL_SAL_CleanseData(dkpPrk, CRYPT_HPKE_HKDF_EXTRACT_MAX_LEN);
    BSL_SAL_CleanseData(sk, skLen);
    if (skRctx == NULL) {
        return CRYPT_INVALID_ARG;
    }

    *pctx = skRctx;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_HpkeGenerateKeyPair(CRYPT_HpkeCipherSuite cipher, const uint8_t *ikm, uint32_t ikmLen, CRYPT_EAL_PkeyCtx **pctx)
{
    if (pctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = CheckHpkeCipherSuite(&cipher);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (ikm != NULL && ikmLen != 0) {
        return DeriveKeyPair(&cipher, ikm, ikmLen, pctx);
    }

    uint32_t ikmNewLen = HpkeGetNsk(cipher.kemId);
    uint8_t *ikmNew = BSL_SAL_Malloc(ikmNewLen);
    if (ikmNew == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_Randbytes(ikmNew, ikmNewLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    ret = DeriveKeyPair(&cipher, ikmNew, ikmNewLen, pctx);
    BSL_SAL_ClearFree(ikmNew, ikmNewLen);
    return ret;
}

int32_t CRYPT_EAL_HpkeGetParam(CRYPT_EAL_HpkeCtx *ctx, CRYPT_HPKE_PARAM_TYPE type, unsigned char *buff, uint32_t *buffLen)
{
    if (ctx == NULL || buffLen == NULL) {
        return CRYPT_INVALID_ARG;
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
            break;
    }

    if (p == NULL || len == 0) {
        return CRYPT_INVALID_ARG;
    }

    if (buff == NULL) {
        *buffLen = len;
        return CRYPT_SUCCESS;
    }

    if (*buffLen < len) {
        return CRYPT_INVALID_ARG;
    }
    *buffLen = len;
    memcpy(buff, p, len);
    return CRYPT_SUCCESS;
}