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
#ifdef HITLS_BSL_PEM_ENCRYPTED

#include <stdint.h>
#include <string.h>

#include "securec.h"

#include "bsl_err_internal.h"
#include "bsl_pem_internal.h"
#include "crypt_errno.h"
#include "crypt_md5.h"
#include "crypt_eal_cipher.h"
#include "crypt_codecskey_local.h"
#include "crypt_eal_md.h"

typedef struct NameToCID {
    const char *name;
    CRYPT_CIPHER_AlgId cid;
} PemNameToCID;

static CRYPT_CIPHER_AlgId GetCIDFromName(const char *name)
{
    static const PemNameToCID tab[] = {
        {"AES-128-CBC", CRYPT_CIPHER_AES128_CBC},
        {"AES-192-CBC", CRYPT_CIPHER_AES192_CBC},
        {"AES-256-CBC", CRYPT_CIPHER_AES256_CBC},
        {"AES-128-CTR", CRYPT_CIPHER_AES128_CTR},
        {"AES-192-CTR", CRYPT_CIPHER_AES192_CTR},
        {"AES-256-CTR", CRYPT_CIPHER_AES256_CTR},
        {"AES-128-XTS", CRYPT_CIPHER_AES128_XTS},
        {"AES-256-XTS", CRYPT_CIPHER_AES256_XTS},
        {"SM4-CBC", CRYPT_CIPHER_SM4_CBC},
        {"SM4-CTR", CRYPT_CIPHER_SM4_CTR},
        {"SM4-CFB", CRYPT_CIPHER_SM4_CFB},
        {"SM4-OFB", CRYPT_CIPHER_SM4_OFB},
        {"AES-128-CFB", CRYPT_CIPHER_AES128_CFB},
        {"AES-192-CFB", CRYPT_CIPHER_AES192_CFB},
        {"AES-256-CFB", CRYPT_CIPHER_AES256_CFB},
        {"AES-128-OFB", CRYPT_CIPHER_AES128_OFB},
        {"AES-192-OFB", CRYPT_CIPHER_AES192_OFB},
        {"AES-256-OFB", CRYPT_CIPHER_AES256_OFB},
        {"DES-CBC", CRYPT_CIPHER_DES_CBC},
        {"DES-OFB", CRYPT_CIPHER_DES_OFB},
        {"DES-CFB", CRYPT_CIPHER_DES_CFB},
        {"DES-EDE3-CBC", CRYPT_CIPHER_TDES_CBC},
        {"DES-EDE3-OFB", CRYPT_CIPHER_TDES_OFB},
        {"DES-EDE3-CFB", CRYPT_CIPHER_TDES_CFB},
    };
    uint32_t tabLen = sizeof(tab) / sizeof(PemNameToCID);
    for (uint32_t i = 0; i < tabLen; i++) {
        if (strcmp(name, tab[i].name) == 0) {
            return tab[i].cid;
        }
    }
    return CRYPT_CIPHER_MAX;
}

static int32_t BytesToKeyUpd(CRYPT_EAL_MdCtx *mdCtx, BSL_Buffer *salt, BSL_Buffer *data,
    int32_t *digestRound, uint8_t *digestBlock, uint32_t *digestLen)
{
    int32_t roundTmp = *digestRound;
    uint32_t lenTmp = *digestLen;
    int32_t ret = CRYPT_EAL_MdInit(mdCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (roundTmp != 0) {
        ret = CRYPT_EAL_MdUpdate(mdCtx, &(digestBlock[0]), lenTmp);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    roundTmp++;
    ret = CRYPT_EAL_MdUpdate(mdCtx, data->data, data->dataLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (salt != NULL && salt->data != NULL) {
        ret = CRYPT_EAL_MdUpdate(mdCtx, salt->data, salt->dataLen);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    lenTmp = 64; // reset lenTmp 64 eq digestBlock size.
    ret = CRYPT_EAL_MdFinal(mdCtx, &(digestBlock[0]), &lenTmp);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    *digestRound = roundTmp;
    *digestLen = lenTmp;

    return ret;
}

static int32_t BytesToKeyIterate(CRYPT_EAL_MdCtx *mdCtx, uint8_t *digestBlock, uint32_t *digestLen, int32_t count)
{
    int32_t ret = CRYPT_SUCCESS;
    for (int32_t i = 1; i < count; i++) {
        ret = CRYPT_EAL_MdInit(mdCtx);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        ret = CRYPT_EAL_MdUpdate(mdCtx, &(digestBlock[0]), *digestLen);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        *digestLen = 64; // reset lenTmp 64 eq digestBlock size.
        ret = CRYPT_EAL_MdFinal(mdCtx, &(digestBlock[0]), digestLen);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    return ret;
}

static int32_t BSL_PEM_BytesToKey(CRYPT_MD_AlgId mdId, int32_t count, BSL_Buffer *salt, BSL_Buffer *data,
    uint8_t *key, uint32_t keyLen, uint8_t *iv, uint32_t ivLen)
{
    int32_t ret = BSL_SUCCESS;
    uint8_t digestBlock[64]; // Current digest block
    int32_t digestRound = 0; // Digest generation round counter
    uint32_t digestLen = 0; // Actual length of the digest block
    uint32_t ivNum = ivLen;
    uint32_t keyNum = keyLen;
    CRYPT_EAL_MdCtx *mdCtx = CRYPT_EAL_MdNewCtx(mdId);
    if (mdCtx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    while (1) {
        ret = BytesToKeyUpd(mdCtx, salt, data, &digestRound, digestBlock, &digestLen);
        if (ret != CRYPT_SUCCESS) {
            break;
        }

        /* Handle count iterations */
        ret = BytesToKeyIterate(mdCtx, digestBlock, &digestLen, count);
        if (ret != CRYPT_SUCCESS) {
            goto ERR;
        }

        /* Handle key padding */
        uint32_t keyCopyLen = (keyNum < digestLen) ? keyNum : digestLen;
        if (key != NULL) {
            for (uint32_t i = 0; i < keyCopyLen; i++) {
                *key++ = digestBlock[i];
            }
        }
        keyNum -= keyCopyLen;

        /* handle iv */
        uint32_t ivSkipLen = digestLen - keyCopyLen;
        if (ivNum < ivSkipLen) {
            ivSkipLen = ivNum;
        }
        if (iv != NULL) {
            for (uint32_t i = 0; i < ivSkipLen; i++) {
                *iv++ = digestBlock[keyCopyLen + i];
            }
        }
        ivNum -= ivSkipLen;

        /* Check if key and iv are both filled */
        if (keyNum == 0 && ivNum == 0) {
            break;
        }
    }

ERR:
    CRYPT_EAL_MdFreeCtx(mdCtx);
    (void)memset_s(digestBlock, sizeof(digestBlock), 0, sizeof(digestBlock));
    return ret;
}

static int32_t PemHex2Bin(const char *s, uint32_t len, unsigned char*out, uint32_t out_len)
{
    uint32_t n = 0;
    for (uint32_t i = 0; i + 1 < len && n < out_len; i += 2) {
        int32_t hi = (s[i] > '9') ? (s[i] & 0x0F) + 9 : s[i] - '0';
        int32_t lo = (s[i + 1] > '9') ? (s[i + 1] & 0x0F) + 9 : s[i + 1] - '0';
        if ((unsigned)hi > 15 || (unsigned)lo > 15) {
            break;
        }
        out[n++] = (hi << 4) | lo;
    }
    return n < (len / 2) ? -1 : 0;
}

// parse DEK-Info: algId,iv
static int32_t PEM_GetInfo(char **data, uint32_t *dataLen, CRYPT_CIPHER_AlgId *cidOut,
    uint8_t *ivOut, uint32_t *ivlenOut, uint32_t *keylenOut)
{
    char *tmp = *data;
    uint32_t tmpLen = *dataLen;
    char algId[20] = { 0 };
    uint32_t len = BSL_PEM_SkipMatching(tmp, tmpLen, " ");
    tmp += len; // Point to the beginning of the algorithm
    tmpLen -= len;

    char *comma = BSL_PEM_SkipUntil(tmp, tmpLen, ",");
    if (comma == NULL) {
        return BSL_PEM_INVALID;
    }
    size_t algIdLen = comma - tmp;
    if (algIdLen > sizeof(algId) - 1) {
        return BSL_PEM_INVALID;
    }
    (void)memcpy_s(algId, sizeof(algId), tmp, (uint32_t)algIdLen);
    CRYPT_CIPHER_AlgId cid = GetCIDFromName(algId);
    if (cid == CRYPT_CIPHER_MAX) {
        return BSL_PEM_INVALID;
    }
    uint32_t ivlen;
    int32_t ret = CRYPT_EAL_CipherGetInfo(cid, CRYPT_INFO_IV_LEN, &ivlen);
    if (ret != BSL_SUCCESS) {
        return BSL_PEM_INVALID;
    }
    uint32_t keylen;
    ret = CRYPT_EAL_CipherGetInfo(cid, CRYPT_INFO_KEY_LEN, &keylen);
    if (ret != BSL_SUCCESS) {
        return BSL_PEM_INVALID;
    }
    tmp = comma + 1; // skip
    tmpLen = *dataLen - (uint32_t)(tmp - *data);
    char *ivEnd = BSL_PEM_SkipUntil(tmp, tmpLen, " \t\r\n");
    if (ivEnd == NULL) {
        return BSL_PEM_INVALID;
    }
    uint32_t hexIvLen = ivEnd - tmp;
    if (hexIvLen != ivlen * 2) { // 2 char for 1 hex number.
        return BSL_PEM_INVALID;
    }
    if (PemHex2Bin(tmp, hexIvLen, ivOut, *ivlenOut) != 0) {
        return BSL_PEM_INVALID;
    }
    tmp = ivEnd;
    tmpLen = *dataLen - (tmp - *data);
    len = BSL_PEM_SkipMatching(tmp, tmpLen, " \t\r\n");
    *data = tmp + len;
    *dataLen = tmpLen - len;
    *cidOut = cid;
    *ivlenOut = ivlen;
    *keylenOut = keylen;
    return BSL_SUCCESS;
}

static int32_t PEM_DecAsn1(char *data, uint32_t dataLen, CRYPT_CIPHER_AlgId cid, BSL_Buffer *iv, BSL_Buffer *key,
    BSL_Buffer *asn1Encode)
{
    uint8_t *tmp = NULL;
    uint32_t tmpLen;
    int32_t ret = BSL_PEM_GetAsn1Encode(data, dataLen, &tmp, &tmpLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    uint8_t *out = NULL;
    uint32_t outLen = tmpLen;
    CRYPT_EAL_CipherCtx *cipher = NULL;
    do {
        out = (uint8_t *)BSL_SAL_Calloc(outLen, 1);
        if (out == NULL) {
            ret = BSL_PEM_INVALID;
            break;
        }
        cipher = CRYPT_EAL_CipherNewCtx(cid);
        if (cipher == NULL) {
            ret = BSL_PEM_INVALID;
            break;
        }
        BSL_ERR_SET_MARK();
        (void)CRYPT_EAL_CipherCtrl(cipher, CRYPT_CTRL_DES_NOKEYCHECK, NULL, 0);
        BSL_ERR_POP_TO_MARK();
        ret = CRYPT_EAL_CipherInit(cipher, key->data, key->dataLen, iv->data, iv->dataLen, false);
        if (ret != BSL_SUCCESS) {
            break;
        }
        ret = CRYPT_EAL_CipherUpdate(cipher, tmp, tmpLen, out, &outLen);
        if (ret != BSL_SUCCESS) {
            break;
        }
        uint32_t outputLen = outLen;
        outLen = tmpLen - outLen;
        ret = CRYPT_EAL_CipherFinal(cipher, out + outputLen, &outLen);
        if (ret != BSL_SUCCESS) {
            break;
        }
        outputLen += outLen;
        BSL_SAL_Free(tmp);
        CRYPT_EAL_CipherFreeCtx(cipher);
        asn1Encode->data = out;
        asn1Encode->dataLen = outputLen;
        return BSL_SUCCESS;
    } while (0);
    BSL_SAL_Free(tmp);
    BSL_SAL_ClearFree(out, tmpLen);
    CRYPT_EAL_CipherFreeCtx(cipher);
    return ret;
}

static int32_t ParseEncryptedPemCpm(const char *src, uint32_t srcLen, char **data, uint32_t *dataLen)
{
    char *tmp = *data;
    uint32_t tmpLen = *dataLen;
    uint32_t len = BSL_PEM_SkipMatching(tmp, tmpLen, " \t");
    tmp += len;
    tmpLen -= len;
    if (tmpLen < srcLen || memcmp(tmp, src, srcLen) != 0) {
        return BSL_PEM_INVALID;
    }
    tmp += srcLen;
    tmpLen -= srcLen;
    *data = tmp;
    *dataLen = tmpLen;
    return BSL_SUCCESS;
}

int32_t CRYPT_EAL_ParseEncryptedPem(char *data, uint32_t dataLen,
    const uint8_t *pwd, uint32_t pwdLen, BSL_Buffer *asn1Encode)
{
    static const char procStr[] = "Proc-Type:";
    static const char encStr[] = "ENCRYPTED";
    static const char dekStr[] = "DEK-Info:";
    uint32_t procStrLen = sizeof(procStr) - 1;
    uint32_t encStrLen = sizeof(encStr) - 1;
    uint32_t dekStrLen = sizeof(dekStr) - 1;
    if (pwd == NULL || pwdLen == 0) {
        return BSL_PEM_NO_PWD;
    }
    char *temp = data;
    uint32_t tempLen = dataLen;
    int32_t ret = ParseEncryptedPemCpm(procStr, procStrLen, &temp, &tempLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = ParseEncryptedPemCpm("4,", 2, &temp, &tempLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    ret = ParseEncryptedPemCpm(encStr, encStrLen, &temp, &tempLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    int32_t len = BSL_PEM_SkipMatching(temp, tempLen, " \t\r\n");
    temp += len;
    tempLen -= len;
    ret = ParseEncryptedPemCpm(dekStr, dekStrLen, &temp, &tempLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    CRYPT_CIPHER_AlgId cid;
    uint8_t iv[64] = {0};
    BSL_Buffer ivBuff = {iv, sizeof(iv)};
    uint32_t keylen;
    ret = PEM_GetInfo(&temp, &tempLen, &cid, ivBuff.data, &ivBuff.dataLen, &keylen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    uint8_t key[64] = {0};
    // 8 is PKCS5_SALT_LEN, salt is taken from the first 8 bytes of the IV buffer.
    if (ivBuff.dataLen < 8) {
        BSL_ERR_PUSH_ERROR(BSL_PEM_INVALID);
        return BSL_PEM_INVALID;
    }
    BSL_Buffer saltBuf = {ivBuff.data, 8};
    BSL_Buffer dataBuf = {(uint8_t *)(uintptr_t)pwd, pwdLen};
    ret = BSL_PEM_BytesToKey(CRYPT_MD_MD5, 1, &saltBuf, &dataBuf, key, keylen,
        NULL, 0);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    // decrypt
    BSL_Buffer keyBuff = {key, keylen};
    return PEM_DecAsn1(temp, tempLen, cid, &ivBuff, &keyBuff, asn1Encode);
}

int32_t CRYPT_EAL_BytesToKey(int32_t cipherId, int32_t mdId, int32_t count,
    BSL_Buffer *salt, BSL_Buffer *data, BSL_Buffer *iv, BSL_Buffer *key)
{
    if (iv == NULL ||  iv->data == NULL || key == NULL || key->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (count <= 0 || data == NULL || data->data == NULL || data->dataLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint32_t nkey = 0;
    uint32_t niv = 0;
    int32_t ret = CRYPT_EAL_CipherGetInfo(cipherId, CRYPT_INFO_KEY_LEN, &nkey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_CipherGetInfo(cipherId, CRYPT_INFO_IV_LEN, &niv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (key->dataLen < nkey || iv->dataLen < niv) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    ret = BSL_PEM_BytesToKey(mdId, count, salt, data, key->data, nkey, iv->data, niv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    key->dataLen = nkey;
    iv->dataLen = niv;
    return CRYPT_SUCCESS;
}
#endif // HITLS_BSL_PEM_ENCRYPTED
