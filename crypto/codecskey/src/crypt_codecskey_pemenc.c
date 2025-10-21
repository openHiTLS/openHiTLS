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

typedef struct NameToCID {
    char *name;
    CRYPT_CIPHER_AlgId cid;
} PemNameToCID;

static int32_t GetCIDFromName(const char *name)
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
        {"RC2-CBC", CRYPT_CIPHER_RC2_CBC},
        {"RC2-OFB", CRYPT_CIPHER_RC2_OFB},
        {"RC2-CFB", CRYPT_CIPHER_RC2_CFB},
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
        {"BF-CBC", CRYPT_CIPHER_BF_CBC},
    };
    uint32_t tabLen = sizeof(tab) / sizeof(PemNameToCID);
    for (uint32_t i = 0; i < tabLen; i++) {
        if (strcmp(name, tab[i].name) == 0) {
            return tab[i].cid;
        }
    }
    return -1;
}

static int32_t BytesToKeyUpd(CRYPT_MD5_Ctx *c, const uint8_t *iv, const uint8_t *pwd, uint32_t pwdLen,
    int32_t *addmd, uint8_t *mdBuf, uint32_t *mds)
{
    int32_t addmdTmp = *addmd;
    uint32_t mdsTmp = *mds;
    int32_t ret = CRYPT_MD5_Init(c);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    if (addmdTmp != 0) {
        ret = CRYPT_MD5_Update(c, &(mdBuf[0]), mdsTmp);
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    }
    addmdTmp++;
    ret = CRYPT_MD5_Update(c, pwd, pwdLen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    if (iv != NULL) {
        ret = CRYPT_MD5_Update(c, iv, 8); // ivNum 8
        if (ret != BSL_SUCCESS) {
            return ret;
        }
    }
    mdsTmp = 64; // reset mdsTmp 64 eq mdbuf size.
    ret = CRYPT_MD5_Final(c, &(mdBuf[0]), &mdsTmp);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    *addmd = addmdTmp;
    *mds = mdsTmp;

    return ret;
}

static int32_t BSL_PEM_BytesToKey(const uint8_t *iv, uint32_t ivLen,
    const uint8_t *pwd, uint32_t pwdLen, uint32_t keyLen, uint8_t *key)
{
    int32_t ret = BSL_SUCCESS;
    uint8_t mdBuf[64];
    int32_t addmd = 0;
    uint32_t mds = 0;
    uint32_t ivNum = ivLen;
    uint32_t keyNum = keyLen;
    CRYPT_MD5_Ctx c = {0};

    while (1) {
        ret = BytesToKeyUpd(&c, iv, pwd, pwdLen, &addmd, mdBuf, &mds);
        if (ret != BSL_SUCCESS) {
            break;
        }

        /* Handle key padding */
        uint32_t keyCopyLen = (keyNum < mds) ? keyNum : mds;
        if (key != NULL) {
            for (uint32_t i = 0; i < keyCopyLen; i++) {
                *key++ = mdBuf[i];
            }
        }
        keyNum -= keyCopyLen;

        /* handle iv */
        uint32_t ivSkipLen = mds - keyCopyLen;
        if (ivNum < ivSkipLen) {
            ivSkipLen = ivNum;
        }
        ivNum -= ivSkipLen;

        /* Check if key and iv are both filled */
        if (keyNum == 0 && ivNum == 0) {
            break;
        }
    }

    CRYPT_MD5_Deinit(&c);
    (void)memset_s(mdBuf, sizeof(mdBuf), 0, sizeof(mdBuf));
    return ret;
}

static int32_t Str2Hex(const char *str, const uint32_t strLen, uint8_t *hex, uint32_t hexLen)
{
    if (strLen % 2 == 1) { // strLen must be a multiple of 2.
        return -1;
    }
    if (hexLen * 2 < strLen) { // hexLen at least strLen / 2.
        return -1;
    }
    for (uint32_t i = 0; i < strLen; i++) {
        if (sscanf_s(str + i * 2, "%2hhx", hex + i) == -1) { // 2 char for 1 hex number.
            return -1;
        }
    }
    return 0;
}

static int32_t PEM_GetInfo(char **header, CRYPT_CIPHER_AlgId *cidOut,
    uint8_t *ivOut, uint32_t *ivlenOut, uint32_t *keylenOut)
{
    char *tmp = *header;
    char *dekinfo = tmp;
    tmp += strcspn(tmp, " \t,");
    char c = *tmp;
    *tmp = '\0';
    CRYPT_CIPHER_AlgId cid = (CRYPT_CIPHER_AlgId)GetCIDFromName(dekinfo);
    *tmp = c;
    tmp += strspn(tmp, " \t");
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
    if (ivlen > 0 && *tmp++ != ',') {
        return BSL_PEM_INVALID;
    } else if (ivlen == 0 && *tmp == ',') {
        return BSL_PEM_INVALID;
    }
    if (strcspn(tmp, " \t\r\n,") != ivlen * 2) { // 2 char for 1 hex number.
        return BSL_PEM_INVALID;
    }
    if (Str2Hex(tmp, ivlen, ivOut, *ivlenOut) != 0) {
        return BSL_PEM_INVALID;
    }
    tmp += strcspn(tmp, " \t\r\n,");
    tmp += strspn(tmp, " \t\r\n,");
    *header = tmp;
    *cidOut = cid;
    *ivlenOut = ivlen;
    *keylenOut = keylen;
    return BSL_SUCCESS;
}

static int32_t PEM_DecAsn1(char **header, CRYPT_CIPHER_AlgId cid, BSL_Buffer *iv, BSL_Buffer *key,
    BSL_Buffer *asn1Encode)
{
    char *tmpPtr = *header;
    uint32_t inLen = (uint32_t)strcspn(tmpPtr, "-"); // until "-----END"
    uint8_t *tmp = NULL;
    uint32_t tmpLen;
    int32_t ret = BSL_PEM_GetAsn1Encode(tmpPtr, inLen, &tmp, &tmpLen);
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
        (void)CRYPT_EAL_CipherCtrl(cipher, CRYPT_CTRL_DES_NOKEYCHECK, NULL, 0);
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

int32_t CRYPT_EAL_ParseEncryptedPem(char *header, const uint8_t *pwd, uint32_t pwdLen, BSL_Buffer *asn1Encode)
{
    static const char procStr[] = "Proc-Type:";
    static const char encStr[] = "ENCRYPTED";
    static const char dekStr[] = "DEK-Info:";
    if (pwd == NULL || pwdLen == 0) {
        return BSL_PEM_NO_PWD;
    }
    header += sizeof(procStr) - 1;
    header += strspn(header, " \t");
    if (*header++ != '4' || *header++ != ',') {
        return BSL_PEM_INVALID;
    }
    header += strspn(header, " \t");
    if (strncmp(header, encStr, sizeof(encStr) - 1) != 0 ||
        strspn(header + sizeof(encStr) - 1, " \t\r\n") == 0) {
        return BSL_PEM_INVALID;
    }
    header += sizeof(encStr) - 1;
    header += strspn(header, " \t\r");
    if (*header++ != '\n') {
        return BSL_PEM_INVALID;
    }

    if (strncmp(header, dekStr, sizeof(dekStr) - 1) != 0) {
        return BSL_PEM_INVALID;
    }
    header += sizeof(dekStr) - 1;
    header += strspn(header, " \t");
    // get info
    CRYPT_CIPHER_AlgId cid;
    uint8_t iv[64] = {0};
    BSL_Buffer ivBuff = {iv, sizeof(iv)};
    uint32_t keylen;
    int32_t ret = PEM_GetInfo(&header, &cid, ivBuff.data, &ivBuff.dataLen, &keylen);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    uint8_t key[64] = {0};
    ret = BSL_PEM_BytesToKey(ivBuff.data, ivBuff.dataLen, pwd, pwdLen, keylen, key);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    // decrypt
    BSL_Buffer keyBuff = {key, keylen};
    return PEM_DecAsn1(&header, cid, &ivBuff, &keyBuff, asn1Encode);
}
#endif // HITLS_BSL_PEM_ENCRYPTED
