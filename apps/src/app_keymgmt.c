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

#include "app_keymgmt.h"
#include <stddef.h>
#include <stdbool.h>
#include <dirent.h>
#include <linux/limits.h>
#include "securec.h"
#include "bsl_uio.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_cipher.h"
#include "crypt_params_key.h"
#include "crypt_eal_cmvp.h"
#include "bsl_base64.h"
#include "crypt_errno.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "app_opt.h"
#include "app_utils.h"
#include "app_print.h"
#include "app_errno.h"
#include "app_function.h"
#include "app_sm.h"
#include "hitls_pki_pkcs12.h"
#include "hitls_pki_errno.h"
#include "bsl_bytes.h"

#ifdef HITLS_APP_SM_MODE

// include cipher key, mac key and asym key.
#define APP_KEYMGMT_MAX_KEY_LEN 128
#define APP_KEYMGMT_HMAC_KEY_LEN 64
#define APP_KEYMGMT_CBC_MAC_SM4_KEY_LEN 16
#define APP_KEYMGMT_MAX_KEY_COUNT 1024

#define APP_KEYMGMT_PBKDF2_IT_CNT_MIN 1024
#define APP_KEYMGMT_PBKDF2_SALT_LEN_MIN 8
#define APP_KEYMGMT_UUID_STR_LEN (2 * (HITLS_APP_UUID_LEN) + 1)
#define APP_KEYMGMT_KEY_EXPIRE_TIME (180 * 24 * 60 * 60) /* 180 days */
#define APP_KEYMGMT_KEY_VERSION 1
#define APP_KEYMGMT_SYNC_DATA_VERSION 1

typedef enum OptionChoice {
    HITLS_APP_OPT_KEYMGMT_ERR = -1,
    HITLS_APP_OPT_KEYMGMT_ROF = 0,
    HITLS_APP_OPT_KEYMGMT_HELP = 1,
    HITLS_APP_OPT_KEYMGMT_CREATE,
    HITLS_APP_OPT_KEYMGMT_DEL,
    HITLS_APP_OPT_KEYMGMT_ERASEKEY,
    HITLS_APP_OPT_KEYMGMT_ALGID,
    HITLS_APP_OPT_KEYMGMT_ITER,
    HITLS_APP_OPT_KEYMGMT_SALTLEN,
    HITLS_APP_OPT_KEYMGMT_GETVERSION,
    HITLS_APP_OPT_KEYMGMT_GETSTATUS,
    HITLS_APP_OPT_KEYMGMT_GETPUB,
    HITLS_APP_OPT_KEYMGMT_SELFTEST,
    HITLS_APP_PROV_ENUM,
    HITLS_SM_OPTIONS_ENUM,
} HITLSOptType;

typedef struct {
    uint32_t version;
    int32_t algId; // key will be used for algorithm.
    int32_t createTag; // to create a key.
    int32_t deleteTag; // to delete a key.
    int32_t eraseTag; // to erase all keys.
    int32_t getVersionTag; // to get version.
    int32_t getStatusTag; // to get status.
    int32_t selfTestTag; // to do self test.
    int32_t getPubTag; // to get public key.
    int32_t iter; // iteration count for generating p12 file.
    int32_t saltLen; // salt length for generating p12 file.
    AppProvider *provider;
    HITLS_APP_SM_Param *smParam;
} KeyMgmtCmdOpt;

typedef struct {
    HITLS_APP_KeyAttr attr;
    uint32_t keyLen;
    uint8_t key[APP_KEYMGMT_MAX_KEY_LEN];
} HITLS_SyncKeyInfo;

static int32_t GetAlgId(const char *name);
static void FreeKeyInfo(HITLS_APP_KeyInfo *keyInfo);
static int32_t CheckAlgMatchForFind(int32_t requestAlgId, int32_t storedAlgId);
static int32_t ReadAsymKey(AppProvider *provider, HITLS_APP_SM_Param *smParam, HITLS_APP_KeyInfo *keyInfo);

static const HITLS_CmdOption g_keyMgmtOpts[] = {
    {"help", HITLS_APP_OPT_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Display this function summary"},
    {"create", HITLS_APP_OPT_KEYMGMT_CREATE, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Create a key"},
    {"delete", HITLS_APP_OPT_KEYMGMT_DEL, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Delete a key"},
    {"erasekey", HITLS_APP_OPT_KEYMGMT_ERASEKEY, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Erase all keys"},
    {"getversion", HITLS_APP_OPT_KEYMGMT_GETVERSION, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Get version"},
    {"getstatus", HITLS_APP_OPT_KEYMGMT_GETSTATUS, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Get status"},
    {"getpub", HITLS_APP_OPT_KEYMGMT_GETPUB, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Get public key"},
    {"selftest", HITLS_APP_OPT_KEYMGMT_SELFTEST, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Self test"},
    {"algid", HITLS_APP_OPT_KEYMGMT_ALGID, HITLS_APP_OPT_VALUETYPE_STRING, "Key usage algorithm"},
    {"iter", HITLS_APP_OPT_KEYMGMT_ITER, HITLS_APP_OPT_VALUETYPE_POSITIVE_INT,
        "Iteration count for generating p12 file."},
    {"saltlen", HITLS_APP_OPT_KEYMGMT_SALTLEN, HITLS_APP_OPT_VALUETYPE_POSITIVE_INT,
        "Salt length for generating p12 file"},
    HITLS_APP_PROV_OPTIONS,
    HITLS_SM_OPTIONS,
    {NULL}
};

static void KeyAttrOrderCvt(HITLS_APP_KeyAttr *attr, bool toByte)
{
    if (toByte) {
        BSL_Uint32ToByte(attr->version, (uint8_t *)&attr->version);
        BSL_Uint32ToByte(attr->algId, (uint8_t *)&attr->algId);
        BSL_Uint64ToByte(attr->createTime, (uint8_t *)&attr->createTime);
        BSL_Uint64ToByte(attr->expireTime, (uint8_t *)&attr->expireTime);
    } else {
        attr->version = BSL_ByteToUint32((uint8_t *)&attr->version);
        attr->algId = BSL_ByteToUint32((uint8_t *)&attr->algId);
        attr->createTime = BSL_ByteToUint64((uint8_t *)&attr->createTime);
        attr->expireTime = BSL_ByteToUint64((uint8_t *)&attr->expireTime);
    }
}

static char *GetKeyFullPath(const char *workPath, const char *uuid, const char *suffix)
{
    char *path = BSL_SAL_Malloc(APP_MAX_PATH_LEN);
    if (path == NULL) {
        AppPrintError("keymgmt: Failed to allocate memory.\n");
        return NULL;
    }
    int32_t ret = sprintf_s(path, APP_MAX_PATH_LEN, "%s/%s%s", workPath, uuid, suffix);
    if (ret < 0) {
        BSL_SAL_Free(path);
        AppPrintError("keymgmt: Failed to get key full path, ret: %d.\n", ret);
        return NULL;
    }
    return path;
}

static char *GetKeyFilePath(const char *workPath, const char *uuid)
{
    return GetKeyFullPath(workPath, uuid, ".p12");
}

static char *GetPubKeyFilePath(const char *workPath, const char *uuid)
{
    return GetKeyFullPath(workPath, uuid, "-pub.pem");
}

static int32_t WriteKeyFile(KeyMgmtCmdOpt *keyMgmtOpt, const char *uuid, HITLS_PKCS12 *p12)
{
    CRYPT_Pbkdf2Param pbkdf2Param = {0};
    pbkdf2Param.pbesId = BSL_CID_PBES2;
    pbkdf2Param.pbkdfId = CRYPT_KDF_PBKDF2;
    pbkdf2Param.hmacId = CRYPT_MAC_HMAC_SM3;
    pbkdf2Param.symId = CRYPT_CIPHER_SM4_CBC;
    pbkdf2Param.saltLen = keyMgmtOpt->saltLen;
    pbkdf2Param.pwd = keyMgmtOpt->smParam->password;
    pbkdf2Param.pwdLen = keyMgmtOpt->smParam->passwordLen;
    pbkdf2Param.itCnt = keyMgmtOpt->iter;

    CRYPT_EncodeParam encParam = {0};
    encParam.deriveMode = CRYPT_DERIVE_PBKDF2;
    encParam.param = &pbkdf2Param;

    HITLS_PKCS12_KdfParam kdfParam = {0};
    kdfParam.saltLen = keyMgmtOpt->saltLen;
    kdfParam.itCnt = keyMgmtOpt->iter;
    kdfParam.macId = CRYPT_MD_SM3;
    kdfParam.pwd = keyMgmtOpt->smParam->password;
    kdfParam.pwdLen = keyMgmtOpt->smParam->passwordLen;

    HITLS_PKCS12_MacParam macParam = {0};
    macParam.algId = BSL_CID_PKCS12KDF;
    macParam.para = &kdfParam;

    HITLS_PKCS12_EncodeParam encodeParam = {0};
    encodeParam.encParam = encParam;
    encodeParam.macParam = macParam;

    char *path = GetKeyFilePath(keyMgmtOpt->smParam->workPath, uuid);
    if (path == NULL) {
        (void)AppPrintError("keymgmt: Failed to get key full path.\n");
        return HITLS_APP_INVALID_ARG;
    }

    int32_t ret = HITLS_PKCS12_GenFile(BSL_FORMAT_ASN1, p12, &encodeParam, true, path);
    BSL_SAL_Free(path);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("keymgmt: Failed to generate pkcs12 key file, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t AddAttrToBag(HITLS_PKCS12_Bag *bag, HITLS_APP_KeyInfo *keyInfo)
{
    HITLS_APP_KeyAttr attr = keyInfo->attr;
    KeyAttrOrderCvt(&attr, true);
    char attrValue[2 * sizeof(attr) + 1] = {0}; // 2: one byte to two hex chars.

    int32_t ret = HITLS_APP_OptToHex((uint8_t *)&attr, sizeof(attr), attrValue, sizeof(attrValue));
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("keymgmt: Failed to convert attr to hex, errCode: 0x%x.\n", ret);
        return ret;
    }
    BSL_Buffer attrValueBuf = {0};
    attrValueBuf.data = (uint8_t *)attrValue;
    attrValueBuf.dataLen = strlen(attrValue) + 1;
    ret = HITLS_PKCS12_BagCtrl(bag, HITLS_PKCS12_BAG_ADD_ATTR, &attrValueBuf, BSL_CID_FRIENDLYNAME);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("keymgmt: Failed to add attr to bag, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t AddCipherKeyToP12(HITLS_PKCS12 *p12, HITLS_APP_KeyInfo *keyInfo)
{
    BSL_Buffer value = {0};
    value.data = keyInfo->key;
    value.dataLen = keyInfo->keyLen;

    HITLS_PKCS12_Bag *bag = HITLS_PKCS12_BagNew(BSL_CID_SECRETBAG, BSL_CID_CE_KEYUSAGE, &value);
    if (bag == NULL) {
        AppPrintError("keymgmt: Failed to create the secret bag.\n");
        return HITLS_APP_X509_FAIL;
    }

    int32_t ret = AddAttrToBag(bag, keyInfo);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_PKCS12_BagFree(bag);
        return ret;
    }

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_SECRETBAG, bag, 0);
    HITLS_PKCS12_BagFree(bag);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("keymgmt: Failed to add the secret bag, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t AddAsymKeyToP12(HITLS_PKCS12 *p12, HITLS_APP_KeyInfo *keyInfo)
{
    HITLS_PKCS12_Bag *bag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, 0, keyInfo->pkeyCtx);
    if (bag == NULL) {
        AppPrintError("keymgmt: Failed to create the PKCS8ShroudedKeyBag.\n");
        return HITLS_APP_X509_FAIL;
    }

    int32_t ret = AddAttrToBag(bag, keyInfo);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_PKCS12_BagFree(bag);
        return ret;
    }

    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_KEYBAG, bag, 0);
    HITLS_PKCS12_BagFree(bag);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("keymgmt: Failed to set the private key bag, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return ret;
}

static int32_t HITLS_APP_WriteKey(KeyMgmtCmdOpt *keyMgmtOpt, HITLS_APP_KeyInfo *keyInfo, const char *uuid)
{
    HITLS_PKCS12 *p12 = HITLS_PKCS12_ProviderNew(APP_GetCurrent_LibCtx(), keyMgmtOpt->provider->providerAttr);
    if (p12 == NULL) {
        AppPrintError("keymgmt: Failed to create the pkcs12 context.\n");
        return HITLS_APP_X509_FAIL;
    }
    int32_t ret = 0;
    if (keyInfo->attr.algId == CRYPT_PKEY_SM2) {
        ret = AddAsymKeyToP12(p12, keyInfo);
    } else {
        ret = AddCipherKeyToP12(p12, keyInfo);
    }
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_PKCS12_Free(p12);
        return ret;
    }

    ret = WriteKeyFile(keyMgmtOpt, uuid, p12);
    HITLS_PKCS12_Free(p12);
    return ret;
}

static int32_t GenerateKeyAttr(int32_t algId, HITLS_APP_KeyAttr *attr,
    char **uuid)
{
    char *uuidStr = NULL;
    int32_t ret = CRYPT_EAL_RandbytesEx(APP_GetCurrent_LibCtx(), attr->uuid, sizeof(attr->uuid));
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("keymgmt: Failed to generate the uuid, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    ret = HITLS_APP_GetTime(&attr->createTime);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    attr->expireTime = attr->createTime + APP_KEYMGMT_KEY_EXPIRE_TIME;
    attr->version = APP_KEYMGMT_KEY_VERSION;
    attr->algId = algId;

    uuidStr = (char *)BSL_SAL_Malloc(APP_KEYMGMT_UUID_STR_LEN);
    if (uuidStr == NULL) {
        AppPrintError("keymgmt: Failed to allocate memory.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }

    ret = HITLS_APP_OptToHex(attr->uuid, sizeof(attr->uuid), uuidStr, APP_KEYMGMT_UUID_STR_LEN);
    if (ret != HITLS_APP_SUCCESS) {
        BSL_SAL_Free(uuidStr);
        AppPrintError("keymgmt: Failed to convert uuid to hex, errCode: 0x%x.\n", ret);
        return ret;
    }
    *uuid = uuidStr;
    return HITLS_APP_SUCCESS;
}

static int32_t CreateCipherKey(KeyMgmtCmdOpt *keyMgmtOpt, int32_t algId, HITLS_APP_KeyInfo *keyInfo)
{
    if (algId == CRYPT_MAC_HMAC_SM3) {
        keyInfo->keyLen = APP_KEYMGMT_HMAC_KEY_LEN;
    } else if (algId == CRYPT_MAC_CBC_MAC_SM4) {
        keyInfo->keyLen = APP_KEYMGMT_CBC_MAC_SM4_KEY_LEN;
    } else {
        int32_t ret = CRYPT_EAL_CipherGetInfo(algId, CRYPT_INFO_KEY_LEN, &keyInfo->keyLen);
        if (ret != CRYPT_SUCCESS) {
            AppPrintError("keymgmt: Failed to get the key length, errCode: 0x%x.\n", ret);
            return HITLS_APP_CRYPTO_FAIL;
        }
    }
    keyMgmtOpt->smParam->status = HITLS_APP_SM_STATUS_APPORVED;
    int32_t ret = CRYPT_EAL_RandbytesEx(APP_GetCurrent_LibCtx(), keyInfo->key, keyInfo->keyLen);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("keymgmt: Failed to generate the key, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CreateAsymKey(KeyMgmtCmdOpt *keyMgmtOpt, int32_t algId, HITLS_APP_KeyInfo *keyInfo)
{
    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(APP_GetCurrent_LibCtx(), algId, 0,
        keyMgmtOpt->provider->providerAttr);
    if (pkeyCtx == NULL) {
        AppPrintError("keymgmt: Failed to create the asym pkey context.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    keyMgmtOpt->smParam->status = HITLS_APP_SM_STATUS_APPORVED;
    int32_t ret = CRYPT_EAL_PkeyGen(pkeyCtx);
    if (ret != CRYPT_SUCCESS) {
        HITLS_APP_SM_PrintLog(ret);
        CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
        AppPrintError("keymgmt: Failed to generate the asym key, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }

    keyInfo->pkeyCtx = pkeyCtx;
    return HITLS_APP_SUCCESS;
}

static int32_t HITLS_APP_CreateKey(KeyMgmtCmdOpt *keyMgmtOpt, int32_t algId, char **uuid)
{
    HITLS_APP_KeyInfo keyInfo = {0};
    char *uuidStr = NULL;
    int32_t ret = HITLS_APP_SUCCESS;
    switch (algId) {
        case CRYPT_CIPHER_SM4_XTS:
        case CRYPT_CIPHER_SM4_CBC:
        case CRYPT_CIPHER_SM4_ECB:
        case CRYPT_CIPHER_SM4_CTR:
        case CRYPT_CIPHER_SM4_GCM:
        case CRYPT_CIPHER_SM4_CFB:
        case CRYPT_CIPHER_SM4_OFB:
        case CRYPT_MAC_HMAC_SM3:
        case CRYPT_MAC_CBC_MAC_SM4:
            ret = CreateCipherKey(keyMgmtOpt, algId, &keyInfo);
            break;
        case CRYPT_PKEY_SM2:
            ret = CreateAsymKey(keyMgmtOpt, algId, &keyInfo);
            break;
        default:
            AppPrintError("keymgmt: Invalid algorithm id: %d.\n", algId);
            ret = HITLS_APP_INVALID_ARG;
            break;
    }
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    ret = GenerateKeyAttr(algId, &keyInfo.attr, &uuidStr);
    if (ret != HITLS_APP_SUCCESS) {
        FreeKeyInfo(&keyInfo);
        return ret;
    }

    ret = HITLS_APP_WriteKey(keyMgmtOpt, &keyInfo, uuidStr);
    if (ret != HITLS_APP_SUCCESS) {
        BSL_SAL_Free(uuidStr);
        FreeKeyInfo(&keyInfo);
        return ret;
    }

    FreeKeyInfo(&keyInfo);
    *uuid = uuidStr;
    return HITLS_APP_SUCCESS;
}

static int32_t EraseKeyFile(char *path)
{
    size_t fileLen = 0;
    int32_t ret = BSL_SAL_FileLength(path, &fileLen);
    if (ret != BSL_SUCCESS) {
        AppPrintError("keymgmt: Failed to get file size: %s, errCode = 0x%x.\n", path, ret);
        return HITLS_APP_BSL_FAIL;
    }
    if (fileLen > APP_FILE_MAX_SIZE) {
        AppPrintError("keymgmt: File size exceed limit: %zu, fileLen:%zu, path:%s.\n",
            APP_FILE_MAX_SIZE, fileLen, path);
        return HITLS_APP_UIO_FAIL;
    }

    BSL_UIO *uio = BSL_UIO_New(BSL_UIO_FileMethod());
    if (uio == NULL) {
        AppPrintError("keymgmt: Failed to create uio.\n");
        return HITLS_APP_UIO_FAIL;
    }
    ret = BSL_UIO_Ctrl(uio, BSL_UIO_FILE_OPEN, BSL_UIO_FILE_WRITE, path);
    if (ret != BSL_SUCCESS) {
        AppPrintError("keymgmt: Failed to open key file, errCode: 0x%x.\n", ret);
        BSL_UIO_Free(uio);
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_SetIsUnderlyingClosedByUio(uio, true);

    uint32_t writeLen = 0;
    uint8_t *data = BSL_SAL_Calloc(fileLen, 1);
    if (data == NULL) {
        BSL_UIO_Free(uio);
        AppPrintError("keymgmt: Failed to allocate memory.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    ret = BSL_UIO_Write(uio, data, fileLen, &writeLen);
    if (ret != BSL_SUCCESS || writeLen != fileLen) {
        BSL_UIO_Free(uio);
        BSL_SAL_Free(data);
        AppPrintError("keymgmt: Failed to erase key file, errCode: 0x%x, writeLen: %u.\n", ret, writeLen);
        return HITLS_APP_UIO_FAIL;
    }
    BSL_UIO_Free(uio);
    BSL_SAL_Free(data);
    return HITLS_APP_SUCCESS;
}

static int32_t HITLS_APP_RmvKey(KeyMgmtCmdOpt *keyMgmtOpt, const char *uuid)
{
    char *path = GetKeyFilePath(keyMgmtOpt->smParam->workPath, uuid);
    if (path == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    keyMgmtOpt->smParam->status = HITLS_APP_SM_STATUS_APPORVED;
    int32_t ret = EraseKeyFile(path);
    if (ret != HITLS_APP_SUCCESS) {
        BSL_SAL_Free(path);
        return ret;
    }
    if (remove(path) != 0) {
        AppPrintError("keymgmt: Failed to remove key file, path: %s.\n", path);
        BSL_SAL_Free(path);
        return HITLS_APP_INVALID_ARG;
    }
    BSL_SAL_Free(path);
    return HITLS_APP_SUCCESS;
}

static void FreeKeyInfo(HITLS_APP_KeyInfo *keyInfo)
{
    if (keyInfo == NULL) {
        return;
    }
    if (keyInfo->keyLen != 0) {
        (void)BSL_SAL_CleanseData(keyInfo->key, keyInfo->keyLen);
    }
    keyInfo->keyLen = 0;
    if (keyInfo->pkeyCtx != NULL) {
        CRYPT_EAL_PkeyFreeCtx(keyInfo->pkeyCtx);
    }
    keyInfo->pkeyCtx = NULL;
}

static void HandleSomeOpt(KeyMgmtCmdOpt *keyMgmtOpt, HITLSOptType optType)
{
    switch (optType) {
        case HITLS_APP_OPT_KEYMGMT_CREATE:
            keyMgmtOpt->createTag = 1;
            break;
        case HITLS_APP_OPT_KEYMGMT_DEL:
            keyMgmtOpt->deleteTag = 1;
            break;
        case HITLS_APP_OPT_KEYMGMT_ERASEKEY:
            keyMgmtOpt->eraseTag = 1;
            break;
        case HITLS_APP_OPT_KEYMGMT_GETVERSION:
            keyMgmtOpt->getVersionTag = 1;
            break;
        case HITLS_APP_OPT_KEYMGMT_GETSTATUS:
            keyMgmtOpt->getStatusTag = 1;
            break;
        case HITLS_APP_OPT_KEYMGMT_GETPUB:
            keyMgmtOpt->getPubTag = 1;
            break;
        case HITLS_APP_OPT_KEYMGMT_SELFTEST:
            keyMgmtOpt->selfTestTag = 1;
            break;
        default:
            break;
    }
    return;
}

static int32_t HandleOpt(KeyMgmtCmdOpt *keyMgmtOpt)
{
    int32_t ret;
    int32_t optType;
    while ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF) {
        HITLS_APP_PROV_CASES(optType, keyMgmtOpt->provider);
        HITLS_APP_SM_CASES(optType, keyMgmtOpt->smParam);
        switch (optType) {
            case HITLS_APP_OPT_ERR:
                AppPrintError("keymgmt: Use -help for summary.\n");
                return HITLS_APP_OPT_UNKOWN;
            case HITLS_APP_OPT_HELP:
                HITLS_APP_OptHelpPrint(g_keyMgmtOpts);
                return HITLS_APP_HELP;
            case HITLS_APP_OPT_KEYMGMT_ALGID:
                if ((keyMgmtOpt->algId = GetAlgId(HITLS_APP_OptGetValueStr())) == -1) {
                    AppPrintError("keymgmt: Invalid algorithm id: %s.\n", HITLS_APP_OptGetValueStr());
                    return HITLS_APP_OPT_VALUE_INVALID;
                }
                break;
            case HITLS_APP_OPT_KEYMGMT_ITER:
                ret = HITLS_APP_OptGetInt(HITLS_APP_OptGetValueStr(), (int32_t *)&keyMgmtOpt->iter);
                if (ret != HITLS_APP_SUCCESS) {
                    return ret;
                }
                break;
            case HITLS_APP_OPT_KEYMGMT_SALTLEN:
                ret = HITLS_APP_OptGetInt(HITLS_APP_OptGetValueStr(), (int32_t *)&keyMgmtOpt->saltLen);
                if (ret != HITLS_APP_SUCCESS) {
                    return ret;
                }
                break;
            default:
                break;
        }
        HandleSomeOpt(keyMgmtOpt, optType);
    }
    if (HITLS_APP_GetRestOptNum() != 0) {
        AppPrintError("keymgmt: Extra arguments given.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CheckActionTag(KeyMgmtCmdOpt *keyMgmtOpt)
{
    int32_t count = 0;
    count += keyMgmtOpt->createTag;
    count += keyMgmtOpt->deleteTag;
    count += keyMgmtOpt->eraseTag;
    count += keyMgmtOpt->getVersionTag;
    count += keyMgmtOpt->getStatusTag;
    count += keyMgmtOpt->selfTestTag;
    count += keyMgmtOpt->getPubTag;
    if (count != 1) {
        AppPrintError("keymgmt: Only one action is allowed: -create, -delete, -erasekey, -getversion, -getstatus or " \
            "-selftest, -getpub.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CheckOptParam(KeyMgmtCmdOpt *keyMgmtOpt)
{
    int32_t ret = CheckActionTag(keyMgmtOpt);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (keyMgmtOpt->smParam->smTag != 1) {
        AppPrintError("keymgmt: The sm is not specified.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (keyMgmtOpt->smParam->workPath == NULL) {
        AppPrintError("keymgmt: The workpath is not specified.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (keyMgmtOpt->eraseTag == 1 || keyMgmtOpt->getVersionTag == 1 || keyMgmtOpt->getStatusTag == 1 ||
        keyMgmtOpt->selfTestTag == 1) {
        return HITLS_APP_SUCCESS;
    }
    if (keyMgmtOpt->deleteTag == 1 || keyMgmtOpt->getPubTag == 1) {
        if (keyMgmtOpt->smParam->uuid == NULL) {
            AppPrintError("keymgmt: The uuid is not specified.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
        return HITLS_APP_SUCCESS;
    }

    if (keyMgmtOpt->algId < 0) {
        AppPrintError("keymgmt: The algorithm is not specified.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (keyMgmtOpt->iter == -1) {
        keyMgmtOpt->iter = APP_KEYMGMT_PBKDF2_IT_CNT_MIN;
    }
    if (keyMgmtOpt->iter < APP_KEYMGMT_PBKDF2_IT_CNT_MIN) {
        AppPrintError("keymgmt: The number of iterations is invalid, iter: %d, min: %d.\n", keyMgmtOpt->iter,
            APP_KEYMGMT_PBKDF2_IT_CNT_MIN);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (keyMgmtOpt->saltLen == -1) {
        keyMgmtOpt->saltLen = APP_KEYMGMT_PBKDF2_SALT_LEN_MIN;
    }
    if (keyMgmtOpt->saltLen < APP_KEYMGMT_PBKDF2_SALT_LEN_MIN) {
        AppPrintError("keymgmt: The salt length is invalid, saltLen: %d, min: %d.\n", keyMgmtOpt->saltLen,
            APP_KEYMGMT_PBKDF2_SALT_LEN_MIN);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CreateKey(KeyMgmtCmdOpt *keyMgmtOpt)
{
    char *uuid = NULL;
    int32_t ret = HITLS_APP_CreateKey(keyMgmtOpt, keyMgmtOpt->algId, &uuid);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("keymgmt: Failed to create key, errCode: 0x%x.\n", ret);
        return ret;
    }
    AppPrintError("keymgmt: uuid: %s\n", uuid);
    BSL_SAL_Free(uuid);
    return HITLS_APP_SUCCESS;
}

static int32_t SplitUuidString(const char *uuid, BslList **uuidList)
{
    char *src = BSL_SAL_Dump(uuid, strlen(uuid) + 1);
    if (src == NULL) {
        AppPrintError("keymgmt: Failed to dump uuid string.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    
    BslList *list = BSL_LIST_New(sizeof(char *));
    if (list == NULL) {
        BSL_SAL_FREE(src);
        AppPrintError("keymgmt: Failed to create list.\n");
        return HITLS_APP_SAL_FAIL;
    }

    char sep[] = ",";
    char *nextTmp = NULL;
    char *tmp = strtok_s(src, sep, &nextTmp);
    while (tmp != NULL) {
        char *singleUuid = BSL_SAL_Dump(tmp, strlen(tmp) + 1);
        if (singleUuid == NULL) {
            BSL_SAL_FREE(src);
            BSL_LIST_FREE(list, BSL_SAL_Free);
            AppPrintError("keymgmt: Failed to dump single uuid string.\n");
            return HITLS_APP_MEM_ALLOC_FAIL;
        }
        int32_t ret = BSL_LIST_AddElement(list, singleUuid, BSL_LIST_POS_END);
        if (ret != BSL_SUCCESS) {
            BSL_SAL_FREE(singleUuid);
            BSL_SAL_FREE(src);
            BSL_LIST_FREE(list, BSL_SAL_Free);
            AppPrintError("keymgmt: Failed to add single uuid to list.\n");
            return HITLS_APP_SAL_FAIL;
        }
        tmp = strtok_s(NULL, sep, &nextTmp);
    }
    BSL_SAL_FREE(src);
    *uuidList = list;
    return HITLS_APP_SUCCESS;
}

static int32_t DeleteKeyByUuidList(KeyMgmtCmdOpt *keyMgmtOpt, BslList *uuidList)
{
    int32_t ret = HITLS_APP_SUCCESS;
    const char *oneUuid = BSL_LIST_GET_FIRST(uuidList);
    while (oneUuid != NULL) {
        ret = HITLS_APP_RmvKey(keyMgmtOpt, oneUuid);
        if (ret != HITLS_APP_SUCCESS) {
            return ret;
        }
        oneUuid = BSL_LIST_GET_NEXT(uuidList);
    }
    return HITLS_APP_SUCCESS;
}

static int32_t DeleteKey(KeyMgmtCmdOpt *keyMgmtOpt)
{
    BslList *uuidList = NULL;
    int32_t ret = SplitUuidString(keyMgmtOpt->smParam->uuid, &uuidList);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    ret = DeleteKeyByUuidList(keyMgmtOpt, uuidList);
    BSL_LIST_FREE(uuidList, BSL_SAL_Free);
    return ret;
}

static bool IsP12File(const char *file)
{
    const char *suffix = ".p12";
    size_t fileLen = strlen(file);
    if (fileLen != 2 * HITLS_APP_UUID_LEN + strlen(suffix)) { // 2: one byte to two hex chars.
        return false;
    }
    return strcmp(file + fileLen - strlen(suffix), suffix) == 0;
}

static int32_t GetAllKeyUuids(const char *workPath, BslList **fileList)
{
    char *uuid = NULL;
    int32_t ret = HITLS_APP_SUCCESS;
    DIR *dir = opendir(workPath);
    if (dir == NULL) {
        AppPrintError("keymgmt: Failed to open directory.\n");
        return HITLS_APP_INVALID_ARG;
    }

    BslList *list = BSL_LIST_New(sizeof(char *));
    if (list == NULL) {
        closedir(dir);
        AppPrintError("keymgmt: Failed to create list.\n");
        return HITLS_APP_SAL_FAIL;
    }

    struct dirent *dp = NULL;
    for (dp = readdir(dir); dp != NULL; dp = readdir(dir)) {
        if (dp->d_type == DT_REG && IsP12File(dp->d_name)) {
            uuid = BSL_SAL_Dump(dp->d_name, APP_KEYMGMT_UUID_STR_LEN);
            if (uuid == NULL) {
                closedir(dir);
                BSL_LIST_FREE(list, BSL_SAL_Free);
                AppPrintError("keymgmt: Failed to dump single uuid string.\n");
                return HITLS_APP_MEM_ALLOC_FAIL;
            }
            uuid[APP_KEYMGMT_UUID_STR_LEN - 1] = '\0';
            ret = BSL_LIST_AddElement(list, uuid, BSL_LIST_POS_END);
            if (ret != BSL_SUCCESS) {
                closedir(dir);
                BSL_LIST_FREE(list, BSL_SAL_Free);
                BSL_SAL_FREE(uuid);
                AppPrintError("keymgmt: Failed to add single uuid to list.\n");
                return HITLS_APP_SAL_FAIL;
            }
        }
    }
    closedir(dir);
    *fileList = list;
    return HITLS_APP_SUCCESS;
}

static int32_t EraseAllKeys(KeyMgmtCmdOpt *keyMgmtOpt)
{
    BslList *uuidList = NULL;
    int32_t ret = GetAllKeyUuids(keyMgmtOpt->smParam->workPath, &uuidList);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    ret = DeleteKeyByUuidList(keyMgmtOpt, uuidList);
    BSL_LIST_FREE(uuidList, BSL_SAL_Free);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("keymgmt: Failed to erase all keys, errCode: 0x%x.\n", ret);
        return ret;
    }
    AppPrintError("keymgmt: All keys deleted successfully.\n");
    return HITLS_APP_SUCCESS;
}

static int32_t GetVersion(KeyMgmtCmdOpt *keyMgmtOpt)
{
    CRYPT_SelftestCtx *selftestCtx = NULL;
    selftestCtx = CRYPT_CMVP_SelftestNewCtx(APP_GetCurrent_LibCtx(), keyMgmtOpt->provider->providerAttr);
    if (selftestCtx == NULL) {
        AppPrintError("keymgmt: Failed to get version, selftestCtx is NULL.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    keyMgmtOpt->smParam->status = HITLS_APP_SM_STATUS_APPORVED;
    const char *version = CRYPT_CMVP_GetVersion(selftestCtx);
    if (version == NULL) {
        CRYPT_CMVP_SelftestFreeCtx(selftestCtx);
        AppPrintError("keymgmt: Failed to get version, version is NULL.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    CRYPT_CMVP_SelftestFreeCtx(selftestCtx);
    AppPrintError("%s\n", version);
    return HITLS_APP_SUCCESS;
}

static int32_t GetStatus(KeyMgmtCmdOpt *keyMgmtOpt)
{
    keyMgmtOpt->smParam->status = HITLS_APP_SM_STATUS_APPORVED;
    AppPrintError("keymgmt: status: %d\n", keyMgmtOpt->smParam->status);
    return HITLS_APP_SUCCESS;
}

static int32_t SelfTest(KeyMgmtCmdOpt *keyMgmtOpt)
{
    CRYPT_SelftestCtx *selftestCtx = NULL;
    selftestCtx = CRYPT_CMVP_SelftestNewCtx(APP_GetCurrent_LibCtx(), keyMgmtOpt->provider->providerAttr);
    if (selftestCtx == NULL) {
        AppPrintError("keymgmt: Failed to self test, selftestCtx is NULL.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    keyMgmtOpt->smParam->status = HITLS_APP_SM_STATUS_APPORVED;
    BSL_Param params[] = {{0}, BSL_PARAM_END};
    int32_t type = CRYPT_CMVP_KAT_TEST;
    BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_CMVP_SELFTEST_TYPE, BSL_PARAM_TYPE_INT32, &type, sizeof(type));
    int32_t ret = CRYPT_CMVP_Selftest(selftestCtx, params);
    if (ret != CRYPT_SUCCESS) {
        HITLS_APP_SM_PrintLog(ret);
        AppPrintError("keymgmt: Failed to self test, errCode: 0x%x.\n", ret);
        CRYPT_CMVP_SelftestFreeCtx(selftestCtx);
        return HITLS_APP_CRYPTO_FAIL;
    }
    CRYPT_CMVP_SelftestFreeCtx(selftestCtx);
    AppPrintError("keymgmt: Self test passed.\n");
    return HITLS_APP_SUCCESS;
}

static int32_t GetPub(KeyMgmtCmdOpt *keyMgmtOpt)
{
    HITLS_APP_KeyInfo keyInfo = {0};
    int32_t ret = ReadAsymKey(keyMgmtOpt->provider, keyMgmtOpt->smParam, &keyInfo);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    char *path = GetPubKeyFilePath(keyMgmtOpt->smParam->workPath, keyMgmtOpt->smParam->uuid);
    if (path == NULL) {
        AppPrintError("keymgmt: Failed to get public key full path.\n");
        FreeKeyInfo(&keyInfo);
        return HITLS_APP_INVALID_ARG;
    }
    ret = HITLS_APP_PrintPubKey(keyInfo.pkeyCtx, path, BSL_FORMAT_PEM);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("keymgmt: Failed to write public key, errCode: 0x%x.\n", ret);
        FreeKeyInfo(&keyInfo);
        BSL_SAL_Free(path);
        return ret;
    }
    AppPrintError("keymgmt: Public key written successfully.\n");
    FreeKeyInfo(&keyInfo);
    BSL_SAL_Free(path);
    return HITLS_APP_SUCCESS;
}

static int32_t ProcessOptions(KeyMgmtCmdOpt *keyMgmtOpt)
{
    if (keyMgmtOpt->eraseTag == 1) {
        return EraseAllKeys(keyMgmtOpt);
    }
    if (keyMgmtOpt->getVersionTag == 1) {
        return GetVersion(keyMgmtOpt);
    }
    if (keyMgmtOpt->getStatusTag == 1) {
        return GetStatus(keyMgmtOpt);
    }
    if (keyMgmtOpt->getPubTag == 1) {
        return GetPub(keyMgmtOpt);
    }
    if (keyMgmtOpt->selfTestTag == 1) {
        return SelfTest(keyMgmtOpt);
    }
    if (keyMgmtOpt->createTag == 1) {
        return CreateKey(keyMgmtOpt);
    }
    if (keyMgmtOpt->deleteTag == 1) {
        return DeleteKey(keyMgmtOpt);
    }
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_KeyMgmtMain(int argc, char *argv[])
{
    int32_t ret;
    AppProvider appProvider = {NULL, NULL, NULL};
    HITLS_APP_SM_Param smParam = {NULL, 0, NULL, NULL, 0, HITLS_APP_SM_STATUS_OPEN};
    AppInitParam initParam = {CRYPT_RAND_SHA256, &appProvider, &smParam};
    KeyMgmtCmdOpt keyMgmtOpt = {1, -1, 0, 0, 0, 0, 0, 0, 0, -1, -1, &appProvider, &smParam};
    if ((ret = HITLS_APP_OptBegin(argc, argv, g_keyMgmtOpts)) != HITLS_APP_SUCCESS) {
        AppPrintError("keymgmt: Error in opt begin.\n");
        goto End;
    }
    if ((ret = HandleOpt(&keyMgmtOpt)) != HITLS_APP_SUCCESS) {
        goto End;
    }
    if ((ret = CheckOptParam(&keyMgmtOpt)) != HITLS_APP_SUCCESS) {
        goto End;
    }
    if ((ret = HITLS_APP_Init(&initParam)) != HITLS_APP_SUCCESS) {
        AppPrintError("keymgmt: Failed to init, errCode: 0x%x.\n", ret);
        goto End;
    }
    ret = ProcessOptions(&keyMgmtOpt);

End:
    HITLS_APP_Deinit(&initParam, ret);
    return ret;
}

static int32_t ReadKeyFile(AppProvider *provider, HITLS_APP_SM_Param *smParam, HITLS_PKCS12 **p12)
{
    char *path = GetKeyFilePath(smParam->workPath, smParam->uuid);
    if (path == NULL) {
        AppPrintError("keymgmt: Failed to get key full path.\n");
        return HITLS_APP_INVALID_ARG;
    }

    BSL_Buffer encPwd = {0};
    encPwd.data = smParam->password;
    encPwd.dataLen = smParam->passwordLen;

    HITLS_PKCS12_PwdParam pwdParam = {0};
    pwdParam.encPwd = &encPwd;
    pwdParam.macPwd = &encPwd;

    int32_t ret = HITLS_PKCS12_ProviderParseFile(APP_GetCurrent_LibCtx(), provider->providerAttr, "ASN1", path,
        &pwdParam, p12, true);
    BSL_SAL_Free(path);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("keymgmt: Failed to read key file, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t GetKeyAttr(HITLS_PKCS12_Bag *bag, HITLS_APP_KeyAttr *attr)
{
    char attrValue[2 * sizeof(*attr) + 1] = {0}; // 2: one byte to two hex chars.
    BSL_Buffer attrValueBuf = {0};
    attrValueBuf.data = (uint8_t *)attrValue;
    attrValueBuf.dataLen = sizeof(attrValue);

    int32_t ret = HITLS_PKCS12_BagCtrl(bag, HITLS_PKCS12_BAG_GET_ATTR, &attrValueBuf, BSL_CID_FRIENDLYNAME);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("keymgmt: Failed to get key attr, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    uint32_t attrLen = sizeof(HITLS_APP_KeyAttr);
    ret = HITLS_APP_StrToHex(attrValue, (uint8_t *)attr, &attrLen);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("keymgmt: Failed to convert attr to hex, errCode: 0x%x.\n", ret);
        return ret;
    }
    if (attrLen != sizeof(HITLS_APP_KeyAttr)) {
        AppPrintError("keymgmt: Attr len not match, attrLen: %u.\n", attrLen);
        return HITLS_APP_INFO_CMP_FAIL;
    }
    KeyAttrOrderCvt(attr, false);
    return HITLS_APP_SUCCESS;
}

static int32_t ReadCipherKey(AppProvider *provider, HITLS_APP_SM_Param *smParam, HITLS_APP_KeyInfo *keyInfo)
{
    HITLS_PKCS12 *p12 = NULL;

    int32_t ret = ReadKeyFile(provider, smParam, &p12);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("keymgmt: Failed to read cipher key, errCode: 0x%x.\n", ret);
        return ret;
    }

    HITLS_PKCS12_Bag *tmpBag = NULL;
    BslList *secretBags = NULL;
    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_SECRETBAGS, &secretBags, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_PKCS12_Free(p12);
        AppPrintError("keymgmt: Failed to get secret bags, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    tmpBag = BSL_LIST_GET_FIRST(secretBags);

    ret = GetKeyAttr(tmpBag, &keyInfo->attr);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_PKCS12_Free(p12);
        return ret;
    }

    BSL_Buffer value = {keyInfo->key, sizeof(keyInfo->key)};
    ret = HITLS_PKCS12_BagCtrl(tmpBag, HITLS_PKCS12_BAG_GET_VALUE, &value, 0);
    HITLS_PKCS12_Free(p12);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("keymgmt: Failed to get key value, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    keyInfo->keyLen = value.dataLen;
    return HITLS_APP_SUCCESS;
}

static int32_t ReadAsymKey(AppProvider *provider, HITLS_APP_SM_Param *smParam, HITLS_APP_KeyInfo *keyInfo)
{
    HITLS_PKCS12 *p12 = NULL;
    int32_t ret = ReadKeyFile(provider, smParam, &p12);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("keymgmt: Failed to read asym key, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    HITLS_PKCS12_Bag *tmpBag = NULL;
    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_ENTITY_KEYBAG, &tmpBag, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_PKCS12_Free(p12);
        AppPrintError("keymgmt: Failed to get entity key bag, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }

    ret = GetKeyAttr(tmpBag, &keyInfo->attr);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_PKCS12_BagFree(tmpBag);
        HITLS_PKCS12_Free(p12);
        return ret;
    }

    ret = HITLS_PKCS12_BagCtrl(tmpBag, HITLS_PKCS12_BAG_GET_VALUE, &keyInfo->pkeyCtx, 0);
    HITLS_PKCS12_BagFree(tmpBag);
    HITLS_PKCS12_Free(p12);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("keymgmt: Failed to get pkeyCtx, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_APP_FindKey(AppProvider *provider, HITLS_APP_SM_Param *smParam, int32_t algId,
    HITLS_APP_KeyInfo *keyInfo)
{
    if (provider == NULL || smParam == NULL || smParam->uuid == NULL || smParam->password == NULL ||
        smParam->passwordLen == 0 || smParam->workPath == NULL || keyInfo == NULL) {
        AppPrintError("keymgmt: Invalid argument to find key.\n");
        return HITLS_APP_INVALID_ARG;
    }
    int32_t ret;
    HITLS_APP_KeyInfo readKeyInfo = {0};
    switch (algId) {
        case CRYPT_CIPHER_SM4_XTS:
        case CRYPT_CIPHER_SM4_CBC:
        case CRYPT_CIPHER_SM4_ECB:
        case CRYPT_CIPHER_SM4_CTR:
        case CRYPT_CIPHER_SM4_GCM:
        case CRYPT_CIPHER_SM4_CFB:
        case CRYPT_CIPHER_SM4_OFB:
        case CRYPT_MAC_HMAC_SM3:
        case CRYPT_MAC_CBC_MAC_SM4:
            ret = ReadCipherKey(provider, smParam, &readKeyInfo);
            break;
        case CRYPT_PKEY_SM2:
            ret = ReadAsymKey(provider, smParam, &readKeyInfo);
            break;
        default:
            AppPrintError("keymgmt: Invalid algorithm id: %d.\n", algId);
            return HITLS_APP_INVALID_ARG;
    }
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("keymgmt: Failed to read key, errCode: 0x%x.\n", ret);
        return ret;
    }
    ret = CheckAlgMatchForFind(algId, readKeyInfo.attr.algId);
    if (ret != HITLS_APP_SUCCESS) {
        FreeKeyInfo(&readKeyInfo);
        return ret;
    }
    (void)memcpy_s(keyInfo, sizeof(*keyInfo), &readKeyInfo, sizeof(readKeyInfo));
    (void)BSL_SAL_CleanseData(readKeyInfo.key, readKeyInfo.keyLen);
    return HITLS_APP_SUCCESS;
}

static int32_t GetSm2Raw(const CRYPT_EAL_PkeyCtx *pkey, uint8_t *prv, uint32_t *prvLen, uint8_t *pub, uint32_t *pubLen)
{
    BSL_Param pubParam[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, *pubLen, 0}, BSL_PARAM_END};
    BSL_Param prvParam[2] = {{CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, prv, *prvLen, 0}, BSL_PARAM_END};

    int32_t ret = CRYPT_EAL_PkeyGetPubEx(pkey, pubParam);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("keymgmt: Failed to get pub, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    *pubLen = pubParam[0].useLen;

    ret = CRYPT_EAL_PkeyGetPrvEx(pkey, prvParam);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(pub, *pubLen);
        AppPrintError("keymgmt: Failed to get prv, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    *prvLen = prvParam[0].useLen;
    return HITLS_APP_SUCCESS;
}

static int32_t FillSyncKeyInfoFromSm2(const HITLS_APP_KeyInfo *keyInfo, HITLS_SyncKeyInfo *info)
{
    HITLS_APP_KeyAttr attr = keyInfo->attr;
    KeyAttrOrderCvt(&attr, true);
    (void)memcpy_s(&info->attr, sizeof(info->attr), &attr, sizeof(attr));

    uint8_t prv[APP_KEYMGMT_MAX_KEY_LEN] = {0};
    uint8_t pub[APP_KEYMGMT_MAX_KEY_LEN] = {0};
    uint32_t prvLen = sizeof(prv);
    uint32_t pubLen = sizeof(pub);
    int32_t ret = GetSm2Raw(keyInfo->pkeyCtx, prv, &prvLen, pub, &pubLen);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (pubLen + prvLen + sizeof(pubLen) + sizeof(prvLen) > sizeof(info->key)) {
        AppPrintError("keymgmt: Invalid pubLen(%u) and prvLen(%u).\n", pubLen, prvLen);
        BSL_SAL_CleanseData(prv, prvLen);
        BSL_SAL_CleanseData(pub, pubLen);
        return HITLS_APP_INVALID_ARG;
    }

    uint32_t used = 0;
    uint32_t len = 0;
    BSL_Uint32ToByte(pubLen, (uint8_t *)&len);
    (void)memcpy_s(info->key + used, sizeof(info->key) - used, &len, sizeof(len));
    used += sizeof(len);

    (void)memcpy_s(info->key + used, sizeof(info->key) - used, pub, pubLen);
    used += pubLen;

    BSL_Uint32ToByte(prvLen, (uint8_t *)&len);
    (void)memcpy_s(info->key + used, sizeof(info->key) - used, &len, sizeof(len));
    used += sizeof(len);

    (void)memcpy_s(info->key + used, sizeof(info->key) - used, prv, prvLen);
    used += prvLen;
    BSL_Uint32ToByte(used, (uint8_t *)&info->keyLen);
    BSL_SAL_CleanseData(prv, prvLen);
    BSL_SAL_CleanseData(pub, pubLen);
    return ret;
}

static int32_t FillSyncKeyInfoFromCipher(const HITLS_APP_KeyInfo *keyInfo, HITLS_SyncKeyInfo *info)
{
    HITLS_APP_KeyAttr attr = keyInfo->attr;
    KeyAttrOrderCvt(&attr, true);
    (void)memcpy_s(&info->attr, sizeof(info->attr), &attr, sizeof(attr));
    (void)memcpy_s(info->key, sizeof(info->key), keyInfo->key, keyInfo->keyLen);
    BSL_Uint32ToByte(keyInfo->keyLen, (uint8_t *)&info->keyLen);
    return HITLS_APP_SUCCESS;
}

// try read key info (cipher or asym) by uuid without knowing algId
static int32_t ReadCipherOrAsymKey(AppProvider *provider, HITLS_APP_SM_Param *smParam, HITLS_APP_KeyInfo *keyInfo)
{
    HITLS_PKCS12 *p12 = NULL;
    int32_t ret = ReadKeyFile(provider, smParam, &p12);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("keymgmt: Failed to read key, errCode: 0x%x.\n", ret);
        return ret;
    }
    // try asym first
    HITLS_PKCS12_Bag *keyBag = NULL;
    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_ENTITY_KEYBAG, &keyBag, 0);
    if (ret == HITLS_PKI_SUCCESS && keyBag != NULL) {
        ret = GetKeyAttr(keyBag, &keyInfo->attr);
        if (ret != HITLS_APP_SUCCESS) {
            HITLS_PKCS12_BagFree(keyBag);
            HITLS_PKCS12_Free(p12);
            return HITLS_APP_X509_FAIL;
        }
        ret = HITLS_PKCS12_BagCtrl(keyBag, HITLS_PKCS12_BAG_GET_VALUE, &keyInfo->pkeyCtx, 0);
        HITLS_PKCS12_BagFree(keyBag);
        HITLS_PKCS12_Free(p12);
        if (ret != HITLS_PKI_SUCCESS) {
            AppPrintError("keymgmt: Failed to get pkeyCtx, errCode: 0x%x.\n", ret);
            return HITLS_APP_X509_FAIL;
        }
        return HITLS_APP_SUCCESS;
    }
    // else secret bag
    BslList *secretBags = NULL;
    ret = HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GET_SECRETBAGS, &secretBags, 0);
    if (ret != HITLS_PKI_SUCCESS) {
        HITLS_PKCS12_Free(p12);
        AppPrintError("keymgmt: Failed to get secret bags, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    HITLS_PKCS12_Bag *tmpBag = BSL_LIST_GET_FIRST(secretBags);
    ret = GetKeyAttr(tmpBag, &keyInfo->attr);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_PKCS12_Free(p12);
        return ret;
    }
    BSL_Buffer value = {keyInfo->key, sizeof(keyInfo->key)};
    ret = HITLS_PKCS12_BagCtrl(tmpBag, HITLS_PKCS12_BAG_GET_VALUE, &value, 0);
    HITLS_PKCS12_Free(p12);
    if (ret != HITLS_PKI_SUCCESS) {
        AppPrintError("keymgmt: Failed to get key value, errCode: 0x%x.\n", ret);
        return HITLS_APP_X509_FAIL;
    }
    keyInfo->keyLen = value.dataLen;
    return HITLS_APP_SUCCESS;
}

static int32_t PrepareOneKey(AppProvider *provider, HITLS_APP_SM_Param *smParam, uint8_t *buf, size_t *index)
{
    HITLS_APP_KeyInfo keyInfo = {0};
    int32_t ret = ReadCipherOrAsymKey(provider, smParam, &keyInfo);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    HITLS_SyncKeyInfo info = {0};
    if (keyInfo.attr.algId == CRYPT_PKEY_SM2) {
        ret = FillSyncKeyInfoFromSm2(&keyInfo, &info);
    } else {
        ret = FillSyncKeyInfoFromCipher(&keyInfo, &info);
    }
    FreeKeyInfo(&keyInfo);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    (void)memcpy_s(buf + *index, sizeof(HITLS_SyncKeyInfo), &info, sizeof(HITLS_SyncKeyInfo));
    *index += sizeof(HITLS_SyncKeyInfo);
    BSL_SAL_CleanseData(info.key, sizeof(info.key));
    return HITLS_APP_SUCCESS;
}

static void PreparHeaderInfo(uint32_t n, uint8_t *buf, size_t *index)
{
    uint32_t version = APP_KEYMGMT_SYNC_DATA_VERSION;
    BSL_Uint32ToByte(version, (uint8_t *)&version);
    (void)memcpy_s(buf, sizeof(uint32_t), &version, sizeof(uint32_t));
    *index += sizeof(uint32_t);

    BSL_Uint32ToByte(n, (uint8_t *)&n);
    (void)memcpy_s(buf + *index, sizeof(uint32_t), &n, sizeof(uint32_t));
    *index += sizeof(uint32_t);
}

int32_t HITLS_APP_SendKey(AppProvider *provider, HITLS_APP_SM_Param *smParam, HITLS_APP_SendFunc sendFunc, void *ctx)
{
    if (provider == NULL || smParam == NULL || smParam->uuid == NULL || smParam->password == NULL ||
        smParam->passwordLen == 0 || smParam->workPath == NULL || sendFunc == NULL) {
        AppPrintError("keymgmt: Invalid argument to send key.\n");
        return HITLS_APP_INVALID_ARG;
    }

    char *uuid = smParam->uuid;
    BslList *uuidList = NULL;
    int32_t ret = SplitUuidString(uuid, &uuidList);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    uint32_t n = BSL_LIST_COUNT(uuidList);
    if (n == 0 || n > APP_KEYMGMT_MAX_KEY_COUNT) {
        BSL_LIST_FREE(uuidList, BSL_SAL_Free);
        AppPrintError("keymgmt: Invalid key count: %u.\n", n);
        return HITLS_APP_INVALID_ARG;
    }

    size_t total = sizeof(uint32_t) + sizeof(uint32_t) + n * sizeof(HITLS_SyncKeyInfo);
    uint8_t *buf = (uint8_t *)BSL_SAL_Malloc(total);
    if (buf == NULL) {
        BSL_LIST_FREE(uuidList, BSL_SAL_Free);
        AppPrintError("keymgmt: Failed to allocate memory, len: %zu.\n", total);
        return HITLS_APP_MEM_ALLOC_FAIL;
    }

    size_t index = 0;
    PreparHeaderInfo(n, buf, &index);
    smParam->uuid = BSL_LIST_GET_FIRST(uuidList);
    for (uint32_t i = 0; i < n; i++) {
        ret = PrepareOneKey(provider, smParam, buf, &index);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        smParam->uuid = BSL_LIST_GET_NEXT(uuidList);
    }
    smParam->uuid = uuid;
    BSL_LIST_FREE(uuidList, BSL_SAL_Free);
    if (ret != HITLS_APP_SUCCESS) {
        BSL_SAL_ClearFree(buf, index);
        return ret;
    }

    ret = sendFunc(ctx, buf, index);
    BSL_SAL_ClearFree(buf, index);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("keymgmt: TLCP send failed, errCode = 0x%x.\n", ret);
        return ret;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CreateCipherKeyFromSyncInfo(const HITLS_SyncKeyInfo *info, HITLS_APP_KeyInfo *outKeyInfo)
{
    if (info->keyLen > sizeof(outKeyInfo->key)) {
        AppPrintError("keymgmt: Invalid keyLen: %d.\n", info->keyLen);
        return HITLS_APP_INVALID_ARG;
    }
    (void)memcpy_s(outKeyInfo->key, sizeof(outKeyInfo->key), info->key, info->keyLen);
    outKeyInfo->keyLen = info->keyLen;
    return HITLS_APP_SUCCESS;
}

static int32_t CreateAndCheckAsymKey(AppProvider *provider, uint8_t *prv, uint32_t prvLen, uint8_t *pub,
    uint32_t pubLen, CRYPT_EAL_PkeyCtx **pkey)
{
    CRYPT_EAL_PkeyCtx *pkeyCtx = CRYPT_EAL_ProviderPkeyNewCtx(APP_GetCurrent_LibCtx(), CRYPT_PKEY_SM2, 0,
        provider->providerAttr);
    if (pkeyCtx == NULL) {
        AppPrintError("keymgmt: Failed to create the pkeyCtx.\n");
        return HITLS_APP_CRYPTO_FAIL;
    }
    BSL_Param prvParam[] = {{0}, BSL_PARAM_END};
    BSL_Param pubParam[] = {{0}, BSL_PARAM_END};

    (void)BSL_PARAM_InitValue(&prvParam[0], CRYPT_PARAM_EC_PRVKEY, BSL_PARAM_TYPE_OCTETS, prv, prvLen);
    (void)BSL_PARAM_InitValue(&pubParam[0], CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen);

    int32_t ret = CRYPT_EAL_PkeySetPrvEx(pkeyCtx, prvParam);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
        AppPrintError("keymgmt: Failed to set prv key, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    ret = CRYPT_EAL_PkeySetPubEx(pkeyCtx, pubParam);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
        AppPrintError("keymgmt: Failed to set pub key, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    ret = CRYPT_EAL_PkeyPairCheck(pkeyCtx, pkeyCtx);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_PkeyFreeCtx(pkeyCtx);
        HITLS_APP_SM_PrintLog(ret);
        AppPrintError("keymgmt: Check asymmetric key pairwise failed, errCode: 0x%x.\n", ret);
        return HITLS_APP_CRYPTO_FAIL;
    }
    *pkey = pkeyCtx;
    return HITLS_APP_SUCCESS;
}

static int32_t CreateAsymKeyFromSyncInfo(AppProvider *provider, HITLS_SyncKeyInfo *info, HITLS_APP_KeyInfo *outKeyInfo)
{
    if (info->keyLen < sizeof(uint32_t)) {
        AppPrintError("keymgmt: Invalid keyLen: %d.\n", info->keyLen);
        return HITLS_APP_INVALID_ARG;
    }
    uint32_t pubLen = 0;
    (void)memcpy_s(&pubLen, sizeof(pubLen), info->key, sizeof(uint32_t));
    pubLen = BSL_ByteToUint32((uint8_t *)&pubLen);
    uint32_t pos = sizeof(uint32_t);
    if (pubLen > info->keyLen - pos) {
        AppPrintError("keymgmt: Invalid pubLen: %d.\n", pubLen);
        return HITLS_APP_INVALID_ARG;
    }
    uint8_t *pub = info->key + pos;
    pos += pubLen;

    if (info->keyLen - pos < sizeof(uint32_t)) {
        AppPrintError("keymgmt: Invalid keyLen: %d.\n", info->keyLen);
        return HITLS_APP_INVALID_ARG;
    }
    uint32_t prvLen = 0;
    (void)memcpy_s(&prvLen, sizeof(prvLen), info->key + pos, sizeof(uint32_t));
    prvLen = BSL_ByteToUint32((uint8_t *)&prvLen);
    pos += sizeof(uint32_t);
    if (prvLen != info->keyLen - pos) {
        AppPrintError("keymgmt: Invalid prvLen(%d) or keyLen(%d).\n", prvLen, info->keyLen);
        return HITLS_APP_INVALID_ARG;
    }
    uint8_t *prv = info->key + pos;
    return CreateAndCheckAsymKey(provider, prv, prvLen, pub, pubLen, &outKeyInfo->pkeyCtx);
}

static int32_t ParseAndWriteKeyFile(KeyMgmtCmdOpt *keyMgmtOpt, HITLS_SyncKeyInfo *info)
{
    info->keyLen = BSL_ByteToUint32((uint8_t *)&info->keyLen);
    if (info->keyLen > sizeof(info->key)) {
        AppPrintError("keymgmt: Invalid keyLen: %d.\n", info->keyLen);
        return HITLS_APP_INVALID_ARG;
    }
    KeyAttrOrderCvt(&info->attr, false);

    HITLS_APP_KeyInfo keyInfo = {0};
    (void)memcpy_s(&keyInfo.attr, sizeof(keyInfo.attr), &info->attr, sizeof(info->attr));
    int32_t ret;
    if (keyInfo.attr.algId == CRYPT_PKEY_SM2) {
        ret = CreateAsymKeyFromSyncInfo(keyMgmtOpt->provider, info, &keyInfo);
    } else {
        ret = CreateCipherKeyFromSyncInfo(info, &keyInfo);
    }
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }

    char uuidStr[APP_KEYMGMT_UUID_STR_LEN];
    ret = HITLS_APP_OptToHex(keyInfo.attr.uuid, sizeof(keyInfo.attr.uuid), uuidStr, sizeof(uuidStr));
    if (ret != HITLS_APP_SUCCESS) {
        FreeKeyInfo(&keyInfo);
        AppPrintError("keymgmt: Failed to convert uuid to hex, errCode: 0x%x.\n", ret);
        return ret;
    }
    ret = HITLS_APP_WriteKey(keyMgmtOpt, &keyInfo, uuidStr);
    FreeKeyInfo(&keyInfo);
    return ret;
}

static int32_t CheckAndSetKdfParam(KeyMgmtCmdOpt *keyMgmtOpt, HITLS_APP_SM_Param *smParam, int32_t iter,
    int32_t saltLen)
{
    if (smParam == NULL || smParam->password == NULL || smParam->passwordLen == 0 ||
        smParam->workPath == NULL) {
        AppPrintError("keymgmt: The password is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    keyMgmtOpt->smParam = smParam;

    keyMgmtOpt->iter = iter == -1 ? APP_KEYMGMT_PBKDF2_IT_CNT_MIN : iter;
    keyMgmtOpt->saltLen = saltLen == -1 ? APP_KEYMGMT_PBKDF2_SALT_LEN_MIN : saltLen;

    if (keyMgmtOpt->iter < APP_KEYMGMT_PBKDF2_IT_CNT_MIN) {
        AppPrintError("keymgmt: The number of iterations is invalid, iter: %d.\n", keyMgmtOpt->iter);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (keyMgmtOpt->saltLen < APP_KEYMGMT_PBKDF2_SALT_LEN_MIN) {
        AppPrintError("keymgmt: The salt length is invalid, saltLen: %d.\n", keyMgmtOpt->saltLen);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    
    return HITLS_APP_SUCCESS;
}

int32_t HITLS_APP_ReceiveKey(AppProvider *provider, HITLS_APP_SM_Param *smParam, int32_t iter, int32_t saltLen,
    HITLS_APP_RecvFunc recvFunc, void *ctx)
{
    uint32_t version = 0;
    KeyMgmtCmdOpt keyMgmtOpt = {0};
    keyMgmtOpt.provider = provider;
    int32_t ret = CheckAndSetKdfParam(&keyMgmtOpt, smParam, iter, saltLen);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (recvFunc == NULL) {
        AppPrintError("keymgmt: The recvFunc is invalid.\n");
        return HITLS_APP_INVALID_ARG;
    }
    ret = recvFunc(ctx, &version, sizeof(uint32_t));
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("keymgmt: TLCP receive failed, errCode: 0x%x.\n", ret);
        return ret;
    }
    version = BSL_ByteToUint32((uint8_t *)&version);
    if (version != APP_KEYMGMT_SYNC_DATA_VERSION) {
        AppPrintError("keymgmt: Version mismatch, version: %d, expected: %d.\n", version,
            APP_KEYMGMT_SYNC_DATA_VERSION);
        return HITLS_APP_INVALID_ARG;
    }
    uint32_t n = 0;
    ret = recvFunc(ctx, &n, sizeof(uint32_t));
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("keymgmt: TLCP receive failed, errCode: 0x%x.\n", ret);
        return ret;
    }
    n = BSL_ByteToUint32((uint8_t *)&n);
    if (n == 0 || n > APP_KEYMGMT_MAX_KEY_COUNT) {
        AppPrintError("keymgmt: Invalid n: %d.\n", n);
        return HITLS_APP_INVALID_ARG;
    }

    HITLS_SyncKeyInfo keyInfo = {0};
    for (uint32_t i = 0; i < n; i++) {
        ret = recvFunc(ctx, &keyInfo, sizeof(HITLS_SyncKeyInfo));
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("keymgmt: TLCP receive failed, errCode: 0x%x.\n", ret);
            return ret;
        }
        ret = ParseAndWriteKeyFile(&keyMgmtOpt, &keyInfo);
        BSL_SAL_CleanseData(keyInfo.key, sizeof(keyInfo.key));
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("keymgmt: Failed to parse and write key file, errCode: 0x%x.\n", ret);
            return ret;
        }
    }
    return HITLS_APP_SUCCESS;
}

typedef struct {
    const int cipherId;
    const char *cipherAlgName;
} KeyMgmtAlgList;

static const KeyMgmtAlgList g_algIdList[] = {
    // For SM4, only expose "sm4" (normal 16-byte key) and "sm4_xts" (32-byte key)
    // Map "sm4" to SM4_CBC internally to reuse existing creation logic.
    {CRYPT_CIPHER_SM4_CBC, "sm4"},
    {CRYPT_CIPHER_SM4_XTS, "sm4_xts"},
    {CRYPT_MAC_HMAC_SM3, "hmac-sm3"},
    {CRYPT_MAC_CBC_MAC_SM4, "sm4-cbc-mac"},
    {CRYPT_PKEY_SM2, "sm2"},
};

static void PrintAlgList(void)
{
    AppPrintError("The current version supports only the following algorithms:\n");
    for (size_t i = 0; i < sizeof(g_algIdList) / sizeof(g_algIdList[0]); i++) {
        AppPrintError("%-19s", g_algIdList[i].cipherAlgName);
        // 4 algorithm names are displayed in each row
        if ((i + 1) % 4 == 0 && i != sizeof(g_algIdList) - 1) {
            AppPrintError("\n");
        }
    }
    AppPrintError("\n");
    return;
}

static int32_t GetAlgId(const char *name)
{
    for (size_t i = 0; i < sizeof(g_algIdList) / sizeof(g_algIdList[0]); i++) {
        if (strcmp(g_algIdList[i].cipherAlgName, name) == 0) {
            return g_algIdList[i].cipherId;
        }
    }
    PrintAlgList();
    return -1;
}

// Determine whether an algorithm ID is an SM4 non-XTS mode
static bool IsSm4NormalAlg(int32_t algId)
{
    switch (algId) {
        case CRYPT_CIPHER_SM4_CBC:
        case CRYPT_CIPHER_SM4_ECB:
        case CRYPT_CIPHER_SM4_CTR:
        case CRYPT_CIPHER_SM4_GCM:
        case CRYPT_CIPHER_SM4_CFB:
        case CRYPT_CIPHER_SM4_OFB:
            return true;
        default:
            return false;
    }
}

// Check whether the stored key algorithm matches the requested algorithm for FindKey
// For SM4, treat non-XTS modes as equivalent; XTS is distinct.
static int32_t CheckAlgMatchForFind(int32_t requestAlgId, int32_t storedAlgId)
{
    if (IsSm4NormalAlg(requestAlgId)) {
        if (!IsSm4NormalAlg(storedAlgId)) {
            AppPrintError(
                "keymgmt: The key file algorithm(%d) is not equal to the algorithm(%d) specified by the user.\n",
                storedAlgId, requestAlgId);
            return HITLS_APP_INVALID_ARG;
        }
        return HITLS_APP_SUCCESS;
    }
    if (storedAlgId != requestAlgId) {
        AppPrintError("keymgmt: The key file algorithm(%d) is not equal to the algorithm(%d) specified by the user.\n",
            storedAlgId, requestAlgId);
        return HITLS_APP_INVALID_ARG;
    }
    return HITLS_APP_SUCCESS;
}
#endif
