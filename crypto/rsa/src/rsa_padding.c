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
#ifdef HITLS_CRYPTO_RSA

#include "crypt_rsa.h"
#include "rsa_local.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "crypt_util_rand.h"
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "bsl_err_internal.h"

#define UINT32_SIZE 4

#ifdef HITLS_CRYPTO_RSA_EMSA_PSS
// maskedDB: [in] maskDB from MGF
//           [out] maskedDB = DB xor maskDB
// DB: PS || 0x01 || salt;
// msBit: indicates the number of valid bits in the most significant bytes of the EM,
// value 0 indicates that all bits are valid.
static void MaskDB(uint8_t *maskedDB, uint32_t len, const uint8_t *salt, uint32_t saltLen, uint32_t msBit)
{
    uint8_t *tmp = maskedDB + (len - saltLen) - 1; // init point to pos of 0x01
    *tmp ^= 0x01;
    tmp++;
    uint32_t i;
    for (i = 0; i < saltLen; i++) {
        tmp[i] ^= salt[i];
    }
    if (msBit != 0) {
        // Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero
        maskedDB[0] &= ((uint8_t)(0xFF >> (8 - msBit)));
    }
}

static int32_t PssEncodeLengthCheck(uint32_t modBits, uint32_t hLen,
    uint32_t saltLen, uint32_t dataLen, uint32_t padLen)
{
    if (modBits < RSA_MIN_MODULUS_BITS || modBits > RSA_MAX_MODULUS_BITS) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_KEY_BITS);
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    if (hLen > RSA_MAX_MODULUS_LEN || dataLen != hLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    uint32_t keyBytes = BN_BITS_TO_BYTES(modBits);
    if (keyBytes != padLen) { // The length required for padding does not match the key module length (API convention).
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_RSA_BUFF_LEN_NOT_ENOUGH;
    }
    if (saltLen == (uint32_t)CRYPT_RSA_SALTLEN_TYPE_AUTOLEN) {
        return CRYPT_SUCCESS;
    }
    if (saltLen > RSA_MAX_MODULUS_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_PSS_SALT_LEN);
        return CRYPT_RSA_ERR_PSS_SALT_LEN;
    }
    uint32_t emLen = keyBytes;
    // the octet length of EM will be one less than k if modBits - 1 is divisible by 8 and equal to k otherwise
    if (((modBits - 1) & 0x7) == 0) {
        emLen--;
    }
    if (emLen < hLen + saltLen + 2) { // RFC: If emLen < hLen + sLen + 2, output "encoding error" and stop.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_PSS_SALT_LEN);
        return CRYPT_RSA_ERR_PSS_SALT_LEN;
    }
    return CRYPT_SUCCESS;
}

#if defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_BSSA)
static int32_t GenPssSalt(void *libCtx, CRYPT_Data *salt,
    const EAL_MdMethod *mdMethod, int32_t saltLen, uint32_t padBuffLen)
{
    uint32_t hashLen = mdMethod->mdSize;
    if (saltLen == CRYPT_RSA_SALTLEN_TYPE_HASHLEN) { // saltLen is -1
        salt->len = hashLen;
    } else if (saltLen == CRYPT_RSA_SALTLEN_TYPE_MAXLEN || saltLen == CRYPT_RSA_SALTLEN_TYPE_AUTOLEN) {
        salt->len = padBuffLen - hashLen - 2; // rfc8017 page42: maximum emLen = hLen + sLen + 2
    } else {
        salt->len = (uint32_t)saltLen;
    }

    salt->data = BSL_SAL_Malloc(salt->len);
    if (salt->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    // Obtain the salt through the public random number.
    int32_t ret = CRYPT_RandEx(libCtx, salt->data, salt->len);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(salt->data);
        BSL_ERR_PUSH_ERROR(ret);
    }
    return ret;
}

/**
 * EMSA-PSS Encoding Operation
 *                                    +-----------+
 *                                    |     M     |
 *                                    +-----------+
 *                                          |
 *                                          V
 *                                        Hash
 *                                          |
 *                                          V
 *                            +--------+----------+----------+
 *                       M' = |Padding1|  mHash   |   salt   |
 *                            +--------+----------+----------+
 *                                           |
 *                 +--------+----------+     V
 *           DB =  |Padding2|   salt   |   Hash
 *                 +--------+----------+     |
 *                           |               |
 *                           V               |
 *                          xor <--- MGF <---|  maskDB = MGF(H, emLen - hLen - 1).
 *                           |               |
 *                           |               |
 *                           V               V
 *                 +-------------------+----------+--+
 *           EM =  |    maskedDB       |     H    |bc|
 *                 +-------------------+----------+--+
 * Output EM data with a fixed length (keyBytes) to the pad buffer.
 * Add 0s to the first byte, if the EM length + 1 = keyBytes.
 * Of which:
 * The data is the mHash in the preceding figure.
 * M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
 * DB = PS || 0x01 || salt; DB is an octet string of length emLen - hLen - 1
 * PS consisting of emLen - sLen - hLen - 2 zero octets, The length of PS may be 0.
 */
int32_t CRYPT_RSA_SetPss(CRYPT_RSA_Ctx *ctx, const EAL_MdMethod *hashMethod, const EAL_MdMethod *mgfMethod,
    uint32_t saltLen, const uint8_t *data, uint32_t dataLen, uint8_t *pad, uint32_t padLen)
{
    RETURN_RET_IF(ctx == NULL || hashMethod == NULL || mgfMethod == NULL || pad == NULL || data == NULL,
        CRYPT_NULL_INPUT);
    CRYPT_Data salt = {0};
    bool kat = false; // mark
    if (ctx->pad.salt.data != NULL) {
        kat = true;
        salt.data = ctx->pad.salt.data;
        salt.len = ctx->pad.salt.len;
        ctx->pad.salt.data = NULL;
        ctx->pad.salt.len = 0;
    } else if (saltLen != 0) {
        // Generate a salt information to the salt.
        RETURN_RET_IF(GenPssSalt(LIBCTX_FROM_RSA_CTX(ctx), &salt, hashMethod, (int32_t)saltLen, padLen) !=
            CRYPT_SUCCESS, CRYPT_RSA_ERR_GEN_SALT);
    }
    RETURN_RET_IF((salt.data == NULL && salt.len != 0), CRYPT_RSA_ERR_PSS_SALT_DATA);
    uint32_t keyBits = CRYPT_RSA_GetBits(ctx);
    uint32_t hLen = hashMethod->mdSize;
    int32_t ret = PssEncodeLengthCheck(keyBits, hLen, salt.len, dataLen, padLen);
    if (ret != CRYPT_SUCCESS) {
        if ((kat != true) && (saltLen != 0)) {
            BSL_SAL_ClearFree(salt.data, salt.len);
        }
        return ret;
    }
    uint8_t *em = pad;
    uint32_t emLen = BN_BITS_TO_BYTES(keyBits);
    // the octet length of EM will be one less than k if modBits - 1 is divisible by 8 and equal to k otherwise
    uint32_t msBit = ((keyBits - 1) & 0x7);
    if (msBit == 0) {
        emLen--;
        *em = 0;
        em++;
    }
    em[emLen - 1] = 0xbc; // EM = maskedDB || H || 0xbc.

    // set H
    static const uint8_t zeros8[8] = {0};
    const CRYPT_ConstData hashData[] = {{zeros8, sizeof(zeros8)}, {data, dataLen}, {salt.data, salt.len}};
    const uint32_t maskedDBLen = emLen - hLen - 1;
    uint8_t *h = em + maskedDBLen;
    GOTO_ERR_IF(CRYPT_CalcHash(ctx->pad.para.pss.mdProvCtx, hashMethod, hashData,
        sizeof(hashData) / sizeof(hashData[0]), h, &hLen), ret);
    // set maskedDB
    GOTO_ERR_IF(CRYPT_Mgf1(ctx->pad.para.pss.mgfProvCtx, mgfMethod, h, hLen, em, maskedDBLen), ret);
    MaskDB(em, maskedDBLen, salt.data, salt.len, msBit);
ERR:
    if ((kat != true) && (saltLen != 0)) {
        BSL_SAL_ClearFree(salt.data, salt.len);
    }
    return ret;
}
#endif // HITLS_CRYPTO_RSA_SIGN || HITLS_CRYPTO_RSA_BSSA

#ifdef HITLS_CRYPTO_RSA_VERIFY
static int32_t GetVerifySaltLen(const uint8_t *emData, const uint8_t *dbBuff, uint32_t maskedDBLen, uint32_t msBit,
    uint32_t *saltLen)
{
    uint32_t i = 0;
    uint8_t *tmpBuff = (uint8_t *)BSL_SAL_Dump(dbBuff, maskedDBLen);
    if (tmpBuff == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    if (msBit != 0) {
        tmpBuff[0] &= ((uint8_t)(0xFF >> (8 - msBit)));  // Set the leftmost 8emLen - emBits bits to zero
    }

    for (i = 0; i < maskedDBLen; i++) {
        tmpBuff[i] ^= emData[i];
        if (tmpBuff[i] != 0) {
            break;
        }
    }
    if (i == maskedDBLen || tmpBuff[i] != 0x01) {
        BSL_SAL_FREE(tmpBuff);
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_PSS_SALT_LEN);
        return CRYPT_RSA_ERR_PSS_SALT_LEN;
    }
    i++;
    BSL_SAL_FREE(tmpBuff);
    *saltLen = maskedDBLen - i;
    return CRYPT_SUCCESS;
}

static int32_t GetAndVerifyDB(void *provCtx, const EAL_MdMethod *mgfMethod, const CRYPT_Data *emData,
    const CRYPT_Data *dbBuff, uint32_t *saltLen, uint32_t msBit)
{
    uint32_t maskedDBLen = dbBuff->len;
    uint32_t hLen = emData->len - maskedDBLen - 1;
    uint32_t tmpSaltLen = *saltLen;
    const uint8_t *h = emData->data + maskedDBLen;
    int32_t ret = CRYPT_Mgf1(provCtx, mgfMethod, h, hLen, dbBuff->data, dbBuff->len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (tmpSaltLen == (uint32_t)CRYPT_RSA_SALTLEN_TYPE_AUTOLEN) {
        ret = GetVerifySaltLen(emData->data, dbBuff->data, maskedDBLen, msBit, &tmpSaltLen);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    // A ^ B == C => A ^ C == B
    MaskDB(dbBuff->data, dbBuff->len, h - tmpSaltLen, tmpSaltLen, msBit);
    if (memcmp(dbBuff->data, emData->data, maskedDBLen - tmpSaltLen) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NOR_VERIFY_FAIL);
        return CRYPT_RSA_NOR_VERIFY_FAIL;
    }
    *saltLen = tmpSaltLen;
    return CRYPT_SUCCESS;
}

static int32_t VerifyH(void *provCtx, const EAL_MdMethod *hashMethod, const CRYPT_Data *mHash, const CRYPT_Data *salt,
    const CRYPT_Data *h, const CRYPT_Data *hBuff)
{
    static const uint8_t zeros8[8] = {0};
    const CRYPT_ConstData hashData[] = {
        {zeros8, sizeof(zeros8)},
        {mHash->data, mHash->len},
        {salt->data, salt->len}
    };

    uint32_t hLen = hBuff->len;
    int32_t ret = CRYPT_CalcHash(provCtx, hashMethod, hashData, sizeof(hashData) / sizeof(hashData[0]), hBuff->data,
        &hLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (memcmp(h->data, hBuff->data, hLen) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NOR_VERIFY_FAIL);
        return CRYPT_RSA_NOR_VERIFY_FAIL;
    }
    return CRYPT_SUCCESS;
}

// Reverse verification process of EMSA-PSS Encoding Operation:
// MGF(H,maskedDBLen) ^ MaskedDB => DB' (PS||0x01||salt'),  H' = Hash(padding1 || mHash || salt') == H ?
int32_t CRYPT_RSA_VerifyPss(CRYPT_RSA_Ctx *ctx, const EAL_MdMethod *hashMethod, const EAL_MdMethod *mgfMethod,
    uint32_t saltLen, const uint8_t *data, uint32_t dataLen, const uint8_t *pad, uint32_t padLen)
{
    if (ctx == NULL || hashMethod == NULL || mgfMethod == NULL || pad == NULL || data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    uint32_t keyBits = CRYPT_RSA_GetBits(ctx);
    uint32_t hLen = hashMethod->mdSize;
    uint32_t saltLength = saltLen;
    if (saltLength == (uint32_t)CRYPT_RSA_SALTLEN_TYPE_HASHLEN) { // saltLength is -1
        saltLength = (uint32_t)ctx->pad.para.pss.mdMeth.mdSize;
    } else if (saltLength == (uint32_t)CRYPT_RSA_SALTLEN_TYPE_MAXLEN) { // saltLength is -2
        saltLength = (uint32_t)(padLen - ctx->pad.para.pss.mdMeth.mdSize - 2); // salt, obtains DRBG
    }
    RETURN_RET_IF_ERR(PssEncodeLengthCheck(keyBits, hLen, saltLength, dataLen, padLen), ret);
    //  EM = maskedDB || H || 0xbc
    RETURN_RET_IF((pad[padLen - 1] != 0xbc), CRYPT_RSA_NOR_VERIFY_FAIL);

    const uint8_t *em = pad;
    uint32_t emLen = BN_BITS_TO_BYTES(keyBits);
    // the octet length of EM will be one less than k if modBits - 1 is divisible by 8 and equal to k otherwise
    uint32_t msBit = ((keyBits - 1) & 0x7);
    if (msBit == 0) {
        emLen--;
        em++;
    }
    // if msBit == 0, 8emLen == emBits, pad[0] should be 0
    // the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB should be 0
    RETURN_RET_IF(((pad[0] >> msBit) != 0), CRYPT_RSA_NOR_VERIFY_FAIL);
    uint8_t *tmpBuff = BSL_SAL_Malloc(emLen); // for maskDB' / DB' and H'
    RETURN_RET_IF((tmpBuff == NULL), CRYPT_MEM_ALLOC_FAIL);

    const uint32_t maskedDBLen = emLen - hLen - 1;
    const CRYPT_Data dbBuff = {tmpBuff, maskedDBLen};
    const CRYPT_Data emData = {(uint8_t *)(uintptr_t)em, emLen};
    const CRYPT_Data mHash = {(uint8_t *)(uintptr_t)data, dataLen};
    const CRYPT_Data h     = {(uint8_t *)(uintptr_t)&em[maskedDBLen], hLen};
    const CRYPT_Data hBuff = {&tmpBuff[maskedDBLen], hLen};
    ret = GetAndVerifyDB(ctx->pad.para.pss.mgfProvCtx, mgfMethod, &emData, &dbBuff, &saltLength, msBit);
    if (ret != CRYPT_SUCCESS) {
        (void)memset_s(tmpBuff, emLen, 0, emLen);
        BSL_SAL_FREE(tmpBuff);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    const CRYPT_Data salt = {&tmpBuff[maskedDBLen - saltLength], saltLength};
    ret = VerifyH(ctx->pad.para.pss.mdProvCtx, hashMethod, &mHash, &salt, &h, &hBuff);
    (void)memset_s(tmpBuff, emLen, 0, emLen);
    BSL_SAL_FREE(tmpBuff);
    return ret;
}
#endif // HITLS_CRYPTO_RSA_VERIFY
#endif // HITLS_CRYPTO_RSA_EMSA_PSS

#ifdef HITLS_CRYPTO_RSA_EMSA_PKCSV15
static int32_t PkcsSetLengthCheck(uint32_t emLen, uint32_t hashLen, uint32_t algIdentLen)
{
    if (emLen > RSA_MAX_MODULUS_LEN || hashLen > RSA_MAX_MODULUS_LEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    if (hashLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    /* The length of the pad must exceed 11 bytes at least. tLen = hashLen + algIdentLen */
    if (emLen < hashLen + algIdentLen + 11) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_RSA_BUFF_LEN_NOT_ENOUGH;
    }
    return CRYPT_SUCCESS;
}

static int32_t PkcsGetIdentifier(CRYPT_MD_AlgId hashId, CRYPT_Data *algIdentifier)
{
    static uint8_t sha1TInfo[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
        0x00, 0x04, 0x14};
    static uint8_t sha224TInfo[] = {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c};
    static uint8_t sha256TInfo[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    static uint8_t sha384TInfo[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
    static uint8_t sha512TInfo[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
    static uint8_t md5TInfo[] = {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x02, 0x05, 0x05, 0x00, 0x04, 0x10};
    static uint8_t sm3TInfo[] = {0x30, 0x30, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01,
        0x83, 0x11, 0x05, 0x00, 0x04, 0x20};
    algIdentifier->data = NULL;
    algIdentifier->len = 0;

    if (hashId == CRYPT_MD_SHA1) {
        algIdentifier->data = (uint8_t *)sha1TInfo;
        algIdentifier->len = sizeof(sha1TInfo);
    } else if (hashId == CRYPT_MD_SHA224) {
        algIdentifier->data = (uint8_t *)sha224TInfo;
        algIdentifier->len = sizeof(sha224TInfo);
    } else if (hashId == CRYPT_MD_SHA256) {
        algIdentifier->data = (uint8_t *)sha256TInfo;
        algIdentifier->len = sizeof(sha256TInfo);
    } else if (hashId == CRYPT_MD_SHA384) {
        algIdentifier->data = (uint8_t *)sha384TInfo;
        algIdentifier->len = sizeof(sha384TInfo);
    } else if (hashId == CRYPT_MD_SHA512) {
        algIdentifier->data = (uint8_t *)sha512TInfo;
        algIdentifier->len = sizeof(sha512TInfo);
    } else if (hashId == CRYPT_MD_MD5) {
        algIdentifier->data = (uint8_t *)md5TInfo;
        algIdentifier->len = sizeof(md5TInfo);
    } else if (hashId == CRYPT_MD_SM3) {
        algIdentifier->data = (uint8_t *)sm3TInfo;
        algIdentifier->len = sizeof(sm3TInfo);
    } else {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_MD_ALGID);
        return CRYPT_RSA_ERR_MD_ALGID;
    }
    return CRYPT_SUCCESS;
}

// Pad output format:EM = 00 || 01 || PS || 00 || T; where T = algIdentifier || hash(M);
// hash(M) is the input parameter data of this function.
int32_t CRYPT_RSA_SetPkcsV15Type1(CRYPT_MD_AlgId hashId, const uint8_t *data, uint32_t dataLen,
    uint8_t *pad, uint32_t padLen)
{
    int32_t ret;
    uint32_t padSize;
    uint8_t *tmp = pad;
    uint32_t tmpLen = padLen;
    if (pad == NULL || data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_Data algIdentifier = {NULL, 0};
    ret = PkcsGetIdentifier(hashId, &algIdentifier);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = PkcsSetLengthCheck(padLen, dataLen, algIdentifier.len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // Considering that the data space and pad space may overlap,
    // move the data to the specified position(the end of the pad).
    if (memmove_s(pad + (padLen - dataLen), dataLen, data, dataLen) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    *tmp = 0x0;
    tmp++;
    *tmp = 0x1;
    tmp++;
    tmpLen -= 2; // Skip the first 2 bytes.

    // PS length: padSize = padLen - dataLen - algIdentifier.len - 3
    padSize = padLen - dataLen - algIdentifier.len - 3;
    if (memset_s(tmp, tmpLen, 0xff, padSize) != EOK) { // 0xff padded in PS
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    tmp += padSize;
    tmpLen -= padSize;

    *tmp = 0x0;
    tmp++;
    tmpLen--;

    if ((algIdentifier.len > 0) && memcpy_s(tmp, tmpLen, algIdentifier.data, algIdentifier.len) != EOK) {
        // padding when identifier exit
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_RSA_VERIFY
int32_t CRYPT_RSA_VerifyPkcsV15Type1(CRYPT_MD_AlgId hashId, const uint8_t *pad, uint32_t padLen,
    const uint8_t *data, uint32_t dataLen)
{
    if (pad == NULL || data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (padLen == 0 || dataLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }

    uint8_t *padBuff = BSL_SAL_Malloc(padLen);
    if (padBuff == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    int32_t ret = CRYPT_RSA_SetPkcsV15Type1(hashId, data, dataLen, padBuff, padLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_FREE(padBuff);
        return ret;
    }

    if (memcmp(pad, padBuff, padLen) != 0) {
        BSL_SAL_FREE(padBuff);
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NOR_VERIFY_FAIL);
        return CRYPT_RSA_NOR_VERIFY_FAIL;
    }
    BSL_SAL_FREE(padBuff);
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_RSA_VERIFY

#ifdef HITLS_CRYPTO_RSA_RECOVER
int32_t CRYPT_RSA_UnPackPkcsV15Type1(uint8_t *data, uint32_t dataLen, uint8_t *out, uint32_t *outLen)
{
    uint8_t *index = data;
    uint32_t tmpLen = dataLen;
    // Format of the data to be decrypted is EB = 00 || 01 || PS || 00 || T.
    // The PS padding is at least 8. Therefore, the length of the data to be decrypted is at least 11.
    if (dataLen < 11) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_RSA_BUFF_LEN_NOT_ENOUGH;
    }
    if (*index != 0x0 || *(index + 1) != 0x01) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }

    index += 2; // Skip first 2 bytes.
    tmpLen -= 2; // Skip first 2 bytes.
    uint32_t padNum = 0;
    while (*index == 0xff) {
        index++;
        tmpLen--;
        padNum++;
    }
    if (padNum < 8) { // The PS padding is at least 8.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_PAD_NUM);
        return CRYPT_RSA_ERR_PAD_NUM;
    }
    if (tmpLen == 0 || *index != 0x0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    index++;
    tmpLen--;

    if (memcpy_s(out, *outLen, index, tmpLen) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    *outLen = tmpLen;
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_RSA_RECOVER
#endif // HITLS_CRYPTO_RSA_EMSA_PKCSV15

#ifdef HITLS_CRYPTO_RSAES_OAEP
#ifdef HITLS_CRYPTO_RSA_ENCRYPT
static int32_t OaepSetLengthCheck(uint32_t outLen, uint32_t inLen, uint32_t hashLen)
{
    if (outLen > RSA_MAX_MODULUS_LEN || inLen > RSA_MAX_MODULUS_LEN || hashLen > HASH_MAX_MDSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    if (outLen == 0 || hashLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    // If mLen > k - 2hLen - 2, output "message too long" and stop.
    if (inLen + 2 * hashLen + 2 > outLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_ENC_BITS);
        return CRYPT_RSA_ERR_ENC_BITS;
    }
    return CRYPT_SUCCESS;
}

static int32_t OaepSetPs(const uint8_t *in, uint32_t inLen, uint8_t *db, uint32_t padLen, uint32_t hashLen)
{
    uint8_t *ps = db + hashLen;
    // Generate a padding string PS consisting of k - mLen - 2hLen - 2 zero octets.  The length of PS may be zero
    // This operation cannot be reversed because the OaepSetLengthCheck has checked the validity of the data.
    uint32_t psLen = padLen - inLen - 2 * hashLen - 2;
    // padding 0x00
    (void)memset_s(ps, psLen, 0, psLen);
    ps += psLen;
    *ps = 0x01;
    ps++;
    /**
     * padLen minus twice hashLen, then subtract 2 bytes of fixed data, and subtract the padding length.
     * The remaining length is the plaintext length.
     */
    if (inLen != 0 && memcpy_s(ps, padLen - 2 * hashLen - 2 - psLen, in, inLen) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}

static int32_t OaepSetMaskedDB(void *provCtx, const EAL_MdMethod *mgfMethod, uint8_t *db, uint8_t *seed,
    uint32_t padLen, uint32_t hashLen)
{
    int32_t ret;
    uint32_t i;
    uint32_t maskedDBLen = padLen - hashLen - 1;
    uint8_t *maskedDB = (uint8_t *)BSL_SAL_Malloc(maskedDBLen);
    if (maskedDB == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = CRYPT_Mgf1(provCtx, mgfMethod, seed, hashLen, maskedDB, maskedDBLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    for (i = 0; i < maskedDBLen; i++) {
        db[i] ^= maskedDB[i];
    }
EXIT:
    BSL_SAL_CleanseData(maskedDB, maskedDBLen);
    BSL_SAL_FREE(maskedDB);
    return ret;
}

static int32_t OaepSetSeedMask(void *provCtx, const EAL_MdMethod *mgfMethod, uint8_t *db, uint8_t *seed,
    uint32_t padLen, uint32_t hashLen)
{
    uint32_t i;
    int32_t ret;
    uint8_t seedmask[HASH_MAX_MDSIZE];
    uint32_t maskedDBLen = padLen - hashLen - 1;

    ret = CRYPT_Mgf1(provCtx, mgfMethod, db, maskedDBLen, seedmask, hashLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        goto EXIT;
    }
    for (i = 0; i < hashLen; i++) {
        seed[i] ^= seedmask[i];
    }
EXIT:
    BSL_SAL_CleanseData(seedmask, hashLen);
    return ret;
}

/**
*    _________________________________________________________________
*
*                                +----------+------+--+-------+
*                           DB = |  lHash   |  PS  |01|   M   |
*                                +----------+------+--+-------+
*                                               |
*                     +----------+              |
*                     |   seed   |              |
*                     +----------+              |
*                           |                   |
*                           |-------> MGF ---> xor
*                           |                   |
*                  +--+     V                   |
*                  |00|    xor <----- MGF <-----|
*                  +--+     |                   |
*                    |      |                   |
*                    V      V                   V
*                  +--+----------+----------------------------+
*            EM =  |00|maskedSeed|          maskedDB          |
*                  +--+----------+----------------------------+
*    _________________________________________________________________
*
*                   Figure 1: EME-OAEP Encoding Operation <rfc8017>
*/
int32_t CRYPT_RSA_SetPkcs1Oaep(CRYPT_RSA_Ctx *ctx, const uint8_t *in, uint32_t inLen, uint8_t *pad, uint32_t padLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    int32_t ret;
    const EAL_MdMethod *hashMethod = &ctx->pad.para.oaep.mdMeth;
    const EAL_MdMethod *mgfMethod = &ctx->pad.para.oaep.mgfMeth;

    if (hashMethod == NULL || mgfMethod == NULL || (in == NULL && inLen != 0) || pad == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    uint32_t hashLen = hashMethod->mdSize;

    /* If mLen > k - 2hLen - 2, output "message too long" and stop<rfc8017>
        k is output len, hLen is hashLen, mLen is inLen
    */
    ret = OaepSetLengthCheck(padLen, inLen, hashLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    *pad = 0x00;
    uint8_t *seed = pad + 1;
    // Generate a random octet string seed of length hLen<rfc8017>
    ret = CRYPT_RandEx(LIBCTX_FROM_RSA_CTX(ctx), seed, hashLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    uint8_t *db = seed + hashLen;

    // Calculate hash
    const CRYPT_ConstData data = {ctx->label.data, ctx->label.len};
    ret = CRYPT_CalcHash(ctx->pad.para.oaep.mdProvCtx, hashMethod, &data, 1, db, &hashLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ret = OaepSetPs(in, inLen, db, padLen, hashLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // set maskedDB
    ret = OaepSetMaskedDB(ctx->pad.para.oaep.mgfProvCtx, mgfMethod, db, seed, padLen, hashLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    // set seedmask
    ret = OaepSetSeedMask(ctx->pad.para.oaep.mgfProvCtx, mgfMethod, db, seed, padLen, hashLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}
#endif // HITLS_CRYPTO_RSA_ENCRYPT

#ifdef HITLS_CRYPTO_RSA_DECRYPT
static int32_t OaepVerifyLengthCheck(uint32_t outLen, uint32_t inLen, uint32_t hashLen)
{
    if (inLen > RSA_MAX_MODULUS_LEN || hashLen > HASH_MAX_MDSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    if (outLen == 0 || hashLen == 0 || inLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    // If k < 2hLen + 2, output "decryption error" and stop
    if (inLen < 2 * hashLen + 2) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_RSA_BUFF_LEN_NOT_ENOUGH;
    }
    return CRYPT_SUCCESS;
}

static int32_t OaepDecodeSeedMask(void *provCtx, const EAL_MdMethod *mgfMethod, const uint8_t *in, uint32_t inLen,
    CRYPT_Data *seedMask, uint32_t hashLen)
{
    uint32_t i;
    int32_t ret;

    const uint8_t *maskedSeed = in + 1;
    uint32_t maskedDBLen = inLen - hashLen - 1;
    const uint8_t *maskedDB = maskedSeed + hashLen;

    ret = CRYPT_Mgf1(provCtx, mgfMethod, maskedDB, maskedDBLen, seedMask->data, hashLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    for (i = 0; i < hashLen; i++) {
        seedMask->data[i] ^= maskedSeed[i];
    }
    return CRYPT_SUCCESS;
}

static int32_t OaepDecodeMaskedDB(void *provCtx, const EAL_MdMethod *mgfMethod, const CRYPT_Data *in,
    const uint8_t *seedMask, uint32_t hashLen, const CRYPT_Data *dbMaskData)
{
    int32_t ret;
    uint32_t i;
    const uint8_t *maskedDB = in->data + 1 + hashLen;
    uint32_t maskedDBLen = in->len - hashLen - 1;

    ret = CRYPT_Mgf1(provCtx, mgfMethod, seedMask, hashLen, dbMaskData->data, maskedDBLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    for (i = 0; i < maskedDBLen; i++) {
        dbMaskData->data[i] ^= maskedDB[i];
    }

    return ret;
}

static int32_t OaepVerifyHashMaskDB(void *provCtx, const EAL_MdMethod *hashMethod, CRYPT_Data *paramData,
    CRYPT_Data *dbMaskData, uint32_t hashLen, uint32_t *offset)
{
    int32_t ret;
    uint8_t hashVal[HASH_MAX_MDSIZE];
    CRYPT_ConstData data = {paramData->data, paramData->len};
    ret = CRYPT_CalcHash(provCtx, hashMethod, &data, 1, hashVal, &hashLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    if (memcmp(dbMaskData->data, hashVal, hashLen) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NOR_VERIFY_FAIL);
        return CRYPT_RSA_NOR_VERIFY_FAIL;
    }

    *offset = hashLen;
    while ((*offset) < dbMaskData->len && dbMaskData->data[(*offset)] == 0) {
        (*offset)++;
    }
    if ((*offset) >= dbMaskData->len) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NOR_VERIFY_FAIL);
        return CRYPT_RSA_NOR_VERIFY_FAIL;
    }

    if (dbMaskData->data[(*offset)] != 0x01) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NOR_VERIFY_FAIL);
        return CRYPT_RSA_NOR_VERIFY_FAIL;
    }

    (*offset)++;
    return ret;
}

int32_t CRYPT_RSA_VerifyPkcs1Oaep(RSA_PadingPara *pad, const uint8_t *in, uint32_t inLen, const uint8_t *param,
    uint32_t paramLen, uint8_t *msg, uint32_t *msgLen)
{
    if (pad == NULL || in == NULL || msg == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t hashLen = pad->mdMeth.mdSize;
    if (inLen <= (hashLen + 1)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    uint32_t maskedDBLen = inLen - hashLen - 1;
    int32_t ret;
    uint32_t offset;
    uint8_t seedMask[HASH_MAX_MDSIZE];
    CRYPT_Data seedData = { (uint8_t *)(uintptr_t)seedMask, HASH_MAX_MDSIZE };
    CRYPT_Data paramData = { (uint8_t *)(uintptr_t)param, paramLen };
    CRYPT_Data inData = { (uint8_t *)(uintptr_t)in, inLen };
    uint8_t *maskDB = (uint8_t *)BSL_SAL_Malloc(maskedDBLen);
    if (maskDB == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_Data dbMaskData = { maskDB, maskedDBLen };

    /* If k < 2hLen + 2, output "decryption error" and stop.<rfc8017>
        k is intLen , hLen is hashLen
    */
    GOTO_ERR_IF_EX(OaepVerifyLengthCheck(*msgLen, inLen, hashLen), ret);

    GOTO_ERR_IF_EX(OaepDecodeSeedMask(pad->mgfProvCtx, &pad->mgfMeth, in, inLen, &seedData, hashLen), ret);

    GOTO_ERR_IF_EX(OaepDecodeMaskedDB(pad->mgfProvCtx, &pad->mgfMeth, &inData, seedMask, hashLen, &dbMaskData), ret);

    GOTO_ERR_IF_EX(OaepVerifyHashMaskDB(pad->mdProvCtx, &pad->mdMeth, &paramData, &dbMaskData, hashLen, &offset), ret);

    if (memcpy_s(msg, *msgLen, maskDB + offset, maskedDBLen - offset) != EOK) {
        ret = CRYPT_RSA_NOR_VERIFY_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
    *msgLen = maskedDBLen - offset;
ERR:
    BSL_SAL_CleanseData(maskDB, maskedDBLen);
    BSL_SAL_FREE(maskDB);
    return ret;
}
#endif // HITLS_CRYPTO_RSA_DECRYPT
#endif // HITLS_CRYPTO_RSAES_OAEP

#if defined(HITLS_CRYPTO_RSA_ENCRYPT) && \
    (defined(HITLS_CRYPTO_RSAES_PKCSV15_TLS) || defined(HITLS_CRYPTO_RSAES_PKCSV15))
// Pad output format: EM = 00 || 02 || PS || 00 || M; where M indicates message.
int32_t CRYPT_RSA_SetPkcsV15Type2(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    // If mLen > k - 11, output "message too long" and stop.<rfc8017>
    if (inLen + 11 > outLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_RSA_BUFF_LEN_NOT_ENOUGH;
    }

    int32_t ret;
    uint32_t i;
    uint8_t *ps = out + 2;
    uint32_t psLen = outLen - inLen - 3;
    uint8_t *msg = out + psLen + 3;

    *out = 0x00;
    *(out + 1) = 0x02;
    *(out + outLen - inLen - 2) = 0x00;
    // msg padding, outLen minus the 3-byte constant, ps length, and start padding.
    if (inLen != 0 && memcpy_s(msg, outLen - (psLen + 3), in, inLen) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }

    // cal ps
    ret = CRYPT_RandEx(libCtx, ps, psLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ps[psLen] = 0;
    for (i = 0; i < psLen; i++) {
        if (*(ps + i) != 0) {
            continue;
        }
        do {
            // no zero
            ret = CRYPT_RandEx(libCtx, ps + i, 1);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
        } while (*(ps + i) == 0);
    }

    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_RSA_ENCRYPT && (EC_PKCSV15_TLS || EC_PKCSV15)

#ifdef HITLS_CRYPTO_RSA_DECRYPT
#ifdef HITLS_CRYPTO_RSAES_PKCSV15
int32_t CRYPT_RSA_VerifyPkcsV15Type2(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    uint32_t zeroIndex = 0;
    uint32_t index = ~(0);
    uint32_t firstZero = Uint32ConstTimeEqual(in[0], 0x00);
    uint32_t firstTwo = Uint32ConstTimeEqual(in[1], 0x02);
    // Check the ps starting from subscript 2.
    for (uint32_t i = 2; i < inLen; i++) {
        uint32_t equals0 = Uint32ConstTimeIsZero(in[i]);
        zeroIndex = Uint32ConstTimeSelect(index & equals0, i, zeroIndex);
        index = Uint32ConstTimeSelect(equals0, 0, index);
    }

    uint32_t valid = firstZero & firstTwo & (~index);
    // Pad output format: EM = 00 || 02 || PS || 00 || M; where M is a message, and PS must be >= 8.
    // Therefore, the subscript of the second 0 must be greater than or equal to 10.
    valid &= Uint32ConstTimeGe(zeroIndex, 10);

    zeroIndex++;
    if (valid == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NOR_VERIFY_FAIL);
        return CRYPT_RSA_NOR_VERIFY_FAIL;
    }

    if (inLen - zeroIndex > *outLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NOR_VERIFY_FAIL);
        return CRYPT_RSA_NOR_VERIFY_FAIL;
    }

    (void)memcpy_s(out, *outLen, in + zeroIndex, inLen - zeroIndex);
    *outLen = inLen - zeroIndex;

    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_RSAES_PKCSV15

#ifdef HITLS_CRYPTO_RSAES_PKCSV15_TLS
int32_t CRYPT_RSA_VerifyPkcsV15Type2TLS(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen)
{
    uint32_t masterSecretLen = *outLen;
    uint32_t zeroIndex = 0;
    uint32_t index = ~(0);
    uint32_t fist = Uint32ConstTimeEqual(in[0], 0x00);
    uint32_t second = Uint32ConstTimeEqual(in[1], 0x02);
    for (uint32_t i = 2; i < inLen; i++) {
        uint32_t equals0 = Uint32ConstTimeIsZero(in[i]);
        zeroIndex = Uint32ConstTimeSelect(index & equals0, i, zeroIndex);
        index = Uint32ConstTimeSelect(equals0, 0, index);
    }

    uint32_t valid = fist & second & (~index);
    // Pad output format: EM = 00 || 02 || PS || 00 || M; where M is a message, and PS must be >= 8.
    // Therefore, the subscript of the second 0 must be greater than or equal to 10.
    valid &= Uint32ConstTimeGe(zeroIndex, 10);
    zeroIndex++;
    uint32_t secretLen = inLen - zeroIndex;
    valid &= ~(Uint32ConstTimeGt(secretLen, *outLen));
    for (uint32_t i = 0; i < masterSecretLen; i++) {
        uint32_t mask = valid & Uint32ConstTimeLt(i, secretLen);
        uint32_t inIndex = mask & zeroIndex;
        out[i] = Uint8ConstTimeSelect(mask, *(in + inIndex + i), 0);
    }
    *outLen = secretLen;

    // if the 'plaintext' is PKCS15 , the valid should be 0xffffffff, else should be 0
    // so return 0 for success, else return 0xffffffff
    return ~valid;
}
#endif // HITLS_CRYPTO_RSAES_PKCSV15_TLS
#endif // HITLS_CRYPTO_RSA_DECRYPT

#endif /* HITLS_CRYPTO_RSA */