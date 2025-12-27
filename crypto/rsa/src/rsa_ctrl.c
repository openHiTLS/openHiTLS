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

#include "crypt_utils.h"
#include "rsa_local.h"
#include "crypt_errno.h"
#include "crypt_util_ctrl.h"
#include "securec.h"
#include "eal_md_local.h"

#ifdef HITLS_CRYPTO_RSA_EMSA_PKCSV15
static int32_t SetEmsaPkcsV15(CRYPT_RSA_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_SET_EMS_PKCSV15_LEN_ERROR);
        return CRYPT_RSA_SET_EMS_PKCSV15_LEN_ERROR;
    }
    static const uint32_t SIGN_MD_ID_LIST[] = { CRYPT_MD_SHA224, CRYPT_MD_SHA256,
        CRYPT_MD_SHA384, CRYPT_MD_SHA512, CRYPT_MD_SM3, CRYPT_MD_SHA1, CRYPT_MD_MD5
    };

    int32_t mdId = *(int32_t *)val;
    if (ParamIdIsValid(mdId, SIGN_MD_ID_LIST, sizeof(SIGN_MD_ID_LIST) / sizeof(SIGN_MD_ID_LIST[0])) == false) {
        // This hash algorithm is not supported.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_MD_ALGID);
        return CRYPT_RSA_ERR_MD_ALGID;
    }
    (void)memset_s(&(ctx->pad), sizeof(RSAPad), 0, sizeof(RSAPad));
    ctx->pad.type = EMSA_PKCSV15;
    ctx->pad.para.pkcsv15.mdId = mdId;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_RSA_EMSA_PSS

static int32_t SetEmsaPss(CRYPT_RSA_Ctx *ctx, RSA_PadingPara *pad, void *mdProvCtx, void *mgfProvCtx)
{
    uint32_t bits = CRYPT_RSA_GetBits(ctx);
    if (bits == 0) {
        // The valid key information does not exist.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    if (pad->saltLen < CRYPT_RSA_SALTLEN_TYPE_AUTOLEN) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_SALT_LEN);
        return  CRYPT_RSA_ERR_SALT_LEN;
    }
    uint32_t saltLen = (uint32_t)pad->saltLen;
    if (pad->saltLen == CRYPT_RSA_SALTLEN_TYPE_HASHLEN) {
        saltLen = pad->mdMeth.mdSize;
    }
    uint32_t bytes = BN_BITS_TO_BYTES(bits);
    // The minimum specification supported by RSA is 1K,
    // and the maximum hash length supported by the hash algorithm is 64 bytes.
    // Therefore, specifying the salt length as the maximum available length is satisfied.
    if (pad->saltLen != CRYPT_RSA_SALTLEN_TYPE_MAXLEN && pad->saltLen != CRYPT_RSA_SALTLEN_TYPE_AUTOLEN &&
        saltLen > bytes - pad->mdMeth.mdSize - 2) { // maximum length of the salt is padLen-mdMethod->GetDigestSize-2
        // The configured salt length does not meet the specification.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_PSS_SALT_LEN);
        return CRYPT_RSA_ERR_PSS_SALT_LEN;
    }
    (void)memset_s(&(ctx->pad), sizeof(RSAPad), 0, sizeof(RSAPad));
    (void)memcpy_s(&(ctx->pad.para.pss), sizeof(RSA_PadingPara), pad, sizeof(RSA_PadingPara));
    ctx->pad.type = EMSA_PSS;
    ctx->pad.para.pss.mdId = pad->mdId;
    ctx->pad.para.pss.mgfId = pad->mgfId;
    ctx->pad.para.pss.mdProvCtx = mdProvCtx;
    ctx->pad.para.pss.mgfProvCtx = mgfProvCtx;
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_RSA_EMSA_PSS

#ifdef HITLS_CRYPTO_RSA_EMSA_ISO9796_2
static int32_t SetEmsaIso9796_2(CRYPT_RSA_Ctx *ctx, RSA_PadingPara *pad)
{
    uint32_t bits = CRYPT_RSA_GetBits(ctx);
    if (bits == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    (void)memset_s(&(ctx->pad), sizeof(RSAPad), 0, sizeof(RSAPad));
    (void)memcpy_s(&(ctx->pad.para.iso9796_2), sizeof(RSA_PadingPara), pad, sizeof(RSA_PadingPara));
    ctx->pad.type = EMSA_ISO9796_2;
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_RSA_EMSA_ISO9796_2

#ifdef HITLS_CRYPTO_RSAES_OAEP

void SetOaep(CRYPT_RSA_Ctx *ctx, const RSA_PadingPara *val)
{
    (void)memset_s(&(ctx->pad), sizeof(RSAPad), 0, sizeof(RSAPad));
    (void)memcpy_s(&(ctx->pad.para.oaep), sizeof(RSA_PadingPara), val, sizeof(RSA_PadingPara));
    ctx->pad.type = RSAES_OAEP;
    return;
}

static int32_t SetOaepLabel(CRYPT_RSA_Ctx *ctx, const void *val, uint32_t len)
{
    uint8_t *data = NULL;
    // val can be NULL
    if ((val == NULL && len != 0) || (len == 0 && val != NULL)) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len == 0 && val == NULL) {
        BSL_SAL_FREE(ctx->label.data);
        ctx->label.len = 0;
        return CRYPT_SUCCESS;
    }
    data = (uint8_t *)BSL_SAL_Malloc(len);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    BSL_SAL_FREE(ctx->label.data);
    ctx->label.data = data;
    ctx->label.len = len;
    (void)memcpy_s(ctx->label.data, ctx->label.len, val, len);
    return CRYPT_SUCCESS;
}
#endif

#if defined(HITLS_CRYPTO_RSAES_PKCSV15) || defined(HITLS_CRYPTO_RSAES_PKCSV15_TLS)
static int32_t SetRsaesPkcsV15(CRYPT_RSA_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_SET_EMS_PKCSV15_LEN_ERROR);
        return CRYPT_RSA_SET_EMS_PKCSV15_LEN_ERROR;
    }

    (void)memset_s(&(ctx->pad), sizeof(RSAPad), 0, sizeof(RSAPad));
    ctx->pad.para.pkcsv15.mdId = *(const int32_t *)val;
    ctx->pad.type = RSAES_PKCSV15;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_RSAES_PKCSV15_TLS
static int32_t SetRsaesPkcsV15Tls(CRYPT_RSA_Ctx *ctx, const void *val, uint32_t len)
{
    int32_t ret = SetRsaesPkcsV15(ctx, val, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ctx->pad.type = RSAES_PKCSV15_TLS;
    return CRYPT_SUCCESS;
}
#endif

#ifdef HITLS_CRYPTO_RSA_EMSA_PSS
static int32_t SetSalt(CRYPT_RSA_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    if (ctx->pad.type != EMSA_PSS) {
        // In non-PSS mode, salt information cannot be set.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_SET_SALT_NOT_PSS_ERROR);
        return CRYPT_RSA_SET_SALT_NOT_PSS_ERROR;
    }
    RSA_PadingPara *pad = &(ctx->pad.para.pss);
    if (pad->mdMeth.id == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    uint32_t bytes = BN_BITS_TO_BYTES(CRYPT_RSA_GetBits(ctx));
    // The maximum salt length is padLen - mdMethod->GetDigestSize - 2
    if (len > bytes - pad->mdMeth.mdSize - 2) {
        // The configured salt length does not meet the specification.
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_SALT_LEN);
        return CRYPT_RSA_ERR_SALT_LEN;
    }
    ctx->pad.salt.data = val;
    ctx->pad.salt.len = len;
    return CRYPT_SUCCESS;
}

static int32_t GetSaltLen(CRYPT_RSA_Ctx *ctx, void *val, uint32_t len)
{
    if (val == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_GET_SALT_LEN_ERROR);
        return CRYPT_RSA_GET_SALT_LEN_ERROR;
    }
    if (ctx->prvKey == NULL && ctx->pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_NO_KEY_INFO);
        return CRYPT_RSA_NO_KEY_INFO;
    }
    if (ctx->pad.type != EMSA_PSS) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_GET_SALT_NOT_PSS_ERROR);
        return CRYPT_RSA_GET_SALT_NOT_PSS_ERROR;
    }
    int32_t *ret = val;
    int32_t valTmp;
    RSA_PadingPara *pad = &(ctx->pad.para.pss);
    if (pad->mdMeth.id == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_PSS_PARAMS);
        return CRYPT_RSA_ERR_PSS_PARAMS;
    }
    uint32_t bytes = BN_BITS_TO_BYTES(CRYPT_RSA_GetBits(ctx));
    if (pad->saltLen == CRYPT_RSA_SALTLEN_TYPE_HASHLEN) { // saltLen is -1
        valTmp = (int32_t)pad->mdMeth.mdSize;
    } else if (pad->saltLen == CRYPT_RSA_SALTLEN_TYPE_MAXLEN ||
        pad->saltLen == CRYPT_RSA_SALTLEN_TYPE_AUTOLEN) {
        // RFC 8017: Max(salt length) = ceil(bits/8) - mdSize - 2
        valTmp = (int32_t)(bytes - pad->mdMeth.mdSize - 2);
    } else {
        valTmp = (int32_t)pad->saltLen;
    }
    if (valTmp < 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_SALT_LEN);
        return CRYPT_RSA_ERR_SALT_LEN;
    }
    *ret = valTmp;
    return CRYPT_SUCCESS;
}
#endif

static uint32_t RSAGetKeyLen(const CRYPT_RSA_Ctx *ctx)
{
    return BN_BITS_TO_BYTES(CRYPT_RSA_GetBits(ctx));
}

static int32_t GetPadding(CRYPT_RSA_Ctx *ctx, void *val, uint32_t len)
{
    RSA_PadType *valTmp = val;
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *valTmp = ctx->pad.type;
    return CRYPT_SUCCESS;
}

static int32_t GetMd(CRYPT_RSA_Ctx *ctx, void *val, uint32_t len)
{
    CRYPT_MD_AlgId *valTmp = val;
    RETURN_RET_IF(val == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(len != sizeof(int32_t), CRYPT_INVALID_ARG);

    switch (ctx->pad.type) {
        case EMSA_PKCSV15:
            *valTmp = ctx->pad.para.pkcsv15.mdId;
            break;
        case EMSA_PSS:
            *valTmp = ctx->pad.para.pss.mdId;
            break;
        case EMSA_ISO9796_2:
            *valTmp = ctx->pad.para.iso9796_2.mdId;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_RSA_PAD_NO_SET_ERROR);
            return CRYPT_RSA_PAD_NO_SET_ERROR;
    }
    return CRYPT_SUCCESS;
}

#ifdef HITLS_CRYPTO_RSA_EMSA_PSS
static int32_t GetMgf(CRYPT_RSA_Ctx *ctx, void *val, uint32_t len)
{
    CRYPT_MD_AlgId *valTmp = val;
    RETURN_RET_IF(val == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(len != sizeof(int32_t), CRYPT_INVALID_ARG);
    if (ctx->pad.type == EMSA_PKCSV15) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_ALGID);
        return CRYPT_RSA_ERR_ALGID;
    }
    *valTmp = ctx->pad.para.pss.mgfId;
    return CRYPT_SUCCESS;
}
#endif

// Function to validate flag input
static int32_t CheckFlag(const void *val, uint32_t len, uint32_t *flag)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *flag = *(const uint32_t *)val;
    if (*flag == 0 || *flag >= CRYPT_RSA_MAXFLAG) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_FLAG_NOT_SUPPORT_ERROR);
        return CRYPT_RSA_FLAG_NOT_SUPPORT_ERROR;
    }
    return CRYPT_SUCCESS;
}

static int32_t SetFlag(CRYPT_RSA_Ctx *ctx, const void *val, uint32_t len)
{
    uint32_t flag;
    int32_t ret = CheckFlag(val, len, &flag);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ctx->flags |= flag;
    return CRYPT_SUCCESS;
}

static int32_t ClearFlag(CRYPT_RSA_Ctx *ctx, const void *val, uint32_t len)
{
    uint32_t flag;
    int32_t ret = CheckFlag(val, len, &flag);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ctx->flags &= ~flag;
    return CRYPT_SUCCESS;
}

static int32_t SetRsaPad(CRYPT_RSA_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (len != sizeof(int32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    int32_t pad = *(const int32_t *)val;
    if (pad < EMSA_PKCSV15 || pad > RSA_NO_PAD) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }

    ctx->pad.type = pad;
    return CRYPT_SUCCESS;
}

#if defined(HITLS_CRYPTO_RSAES_OAEP) || defined(HITLS_CRYPTO_RSA_EMSA_PSS) || \
    defined(HITLS_CRYPTO_RSA_EMSA_ISO9796_2)
static inline bool MdIdCheckSha1Sha2(CRYPT_MD_AlgId id)
{
    return (id >= CRYPT_MD_MD5 && id <= CRYPT_MD_SHA512);
}
#endif

#ifdef HITLS_CRYPTO_RSAES_OAEP

static int32_t RsaSetOaep(CRYPT_RSA_Ctx *ctx, BSL_Param *param)
{
    int32_t ret;
    uint32_t len = 0;
    RSA_PadingPara padPara = {0};
    const BSL_Param *temp = NULL;
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RSA_MD_ID)) != NULL) {
        len = sizeof(padPara.mdId);
        GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_RSA_MD_ID,
            BSL_PARAM_TYPE_INT32, &padPara.mdId, &len), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RSA_MGF1_ID)) != NULL) {
        len = sizeof(padPara.mgfId);
        GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_RSA_MGF1_ID,
            BSL_PARAM_TYPE_INT32, &padPara.mgfId, &len), ret);
    }
    if (MdIdCheckSha1Sha2(padPara.mdId) == false) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    if (MdIdCheckSha1Sha2(padPara.mgfId) == false) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    void *mdProvCtx = NULL;
    void *mgfProvCtx = NULL;
    void *libCtx = LIBCTX_FROM_RSA_CTX(ctx);
    EAL_MdMethod *mdMeth = EAL_MdFindMethodEx(padPara.mdId, libCtx, MDATTR_FROM_RSA_CTX(ctx),
        &padPara.mdMeth, &mdProvCtx, libCtx != NULL);
    EAL_MdMethod *mgfMeth = EAL_MdFindMethodEx(padPara.mgfId, libCtx, MDATTR_FROM_RSA_CTX(ctx),
        &padPara.mgfMeth, &mgfProvCtx, libCtx != NULL);
    if (mdMeth == NULL || mgfMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    padPara.mdProvCtx = mdProvCtx;
    padPara.mgfProvCtx = mgfProvCtx;
    SetOaep(ctx, &padPara);
ERR:
    return ret;
}
#endif

#ifdef HITLS_CRYPTO_RSA_EMSA_PSS

static int32_t RsaSetPss(CRYPT_RSA_Ctx *ctx, BSL_Param *param)
{
    int32_t ret;
    uint32_t len = 0;
    RSA_PadingPara padPara = {0};
    const BSL_Param *temp = NULL;
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RSA_MD_ID)) != NULL) {
        len = sizeof(padPara.mdId);
        GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &padPara.mdId, &len), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RSA_MGF1_ID)) != NULL) {
        len = sizeof(padPara.mgfId);
        GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_RSA_MGF1_ID, BSL_PARAM_TYPE_INT32, &padPara.mgfId, &len), ret);
    }
    if ((temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RSA_SALTLEN)) != NULL) {
        len = sizeof(padPara.saltLen);
        GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_RSA_SALTLEN,
            BSL_PARAM_TYPE_INT32, &padPara.saltLen, &len), ret);
    }
    if (MdIdCheckSha1Sha2(padPara.mdId) == false) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    if (MdIdCheckSha1Sha2(padPara.mgfId) == false) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    void *mdProvCtx = NULL;
    void *mgfProvCtx = NULL;
    void *libCtx = LIBCTX_FROM_RSA_CTX(ctx);
    EAL_MdMethod *mdMeth = EAL_MdFindMethodEx(padPara.mdId, libCtx, MDATTR_FROM_RSA_CTX(ctx),
        &padPara.mdMeth, &mdProvCtx, libCtx != NULL);
    EAL_MdMethod *mgfMeth = EAL_MdFindMethodEx(padPara.mgfId, libCtx, MDATTR_FROM_RSA_CTX(ctx),
        &padPara.mgfMeth, &mgfProvCtx, libCtx != NULL);
    if (mdMeth == NULL || mgfMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    ret = SetEmsaPss(ctx, &padPara, mdProvCtx, mgfProvCtx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    return ret;
}
#endif

#ifdef HITLS_CRYPTO_RSA_EMSA_ISO9796_2
static int32_t RsaSetIso9796_2(CRYPT_RSA_Ctx *ctx, BSL_Param *param)
{
    RSA_PadingPara padPara = {0};
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    const BSL_Param *temp = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_RSA_MD_ID);
    if (temp == NULL || temp->value == NULL || temp->valueLen == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_INPUT_VALUE);
        return CRYPT_RSA_ERR_INPUT_VALUE;
    }
    uint32_t len = sizeof(padPara.mdId);
    int32_t ret = CRYPT_SUCCESS;
    GOTO_ERR_IF(BSL_PARAM_GetValue(temp, CRYPT_PARAM_RSA_MD_ID, BSL_PARAM_TYPE_INT32, &padPara.mdId, &len), ret);

    void *mdProvCtx = NULL;
    void *libCtx = LIBCTX_FROM_RSA_CTX(ctx);
    EAL_MdMethod *mdMeth = EAL_MdFindMethodEx(padPara.mdId, libCtx, MDATTR_FROM_RSA_CTX(ctx),
        &padPara.mdMeth, &mdProvCtx, libCtx != NULL);
    if (mdMeth == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
        return CRYPT_EAL_ERR_ALGID;
    }
    padPara.mdProvCtx = mdProvCtx;
    ret = SetEmsaIso9796_2(ctx, &padPara);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }
ERR:
    return ret;
}
#endif

static int32_t RsaCommonCtrl(CRYPT_RSA_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    switch (opt) {
        case CRYPT_CTRL_UP_REFERENCES:
            return BSL_SAL_AtomicRefUpCtrl(&(ctx->references), val, len);
        case CRYPT_CTRL_GET_PUB_KEY_BITS:
        case CRYPT_CTRL_GET_BITS:
            return CRYPT_CTRL_GET_NUM32_EX(CRYPT_RSA_GetBits, ctx, val, len);
        case CRYPT_CTRL_GET_SECBITS:
            return CRYPT_CTRL_GET_NUM32_EX(CRYPT_RSA_GetSecBits, ctx, val, len);
        case CRYPT_CTRL_GET_PUBKEY_LEN:
        case CRYPT_CTRL_GET_PRVKEY_LEN:
            return CRYPT_CTRL_GET_NUM32_EX(RSAGetKeyLen, ctx, val, len);
        case CRYPT_CTRL_SET_RSA_FLAG:
            return SetFlag(ctx, val, len);
        case CRYPT_CTRL_CLR_RSA_FLAG:
            return ClearFlag(ctx, val, len);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_RSA_CTRL_NOT_SUPPORT_ERROR);
            return CRYPT_RSA_CTRL_NOT_SUPPORT_ERROR;
    }
}

#ifdef HITLS_CRYPTO_RSA_BSSA
static int32_t SetBssaParamCheck(CRYPT_RSA_Ctx *ctx, const void *val, uint32_t len)
{
    if (val == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_NO_PUBKEY_INFO);
        return CRYPT_RSA_ERR_NO_PUBKEY_INFO;
    }
    return CRYPT_SUCCESS;
}

static int32_t RsaSetBssa(CRYPT_RSA_Ctx *ctx, const void *val, uint32_t len)
{
    int32_t ret = SetBssaParamCheck(ctx, val, len);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    const uint8_t *r = (const uint8_t *)val;
    BN_Optimizer *opt = BN_OptimizerCreate();
    if (opt == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    RSA_Blind *blind = NULL;
    RSA_BlindParam *param = ctx->blindParam;
    if (param == NULL) {
        param = BSL_SAL_Calloc(1u, sizeof(RSA_BlindParam));
        if (param == NULL) {
            ret = CRYPT_MEM_ALLOC_FAIL;
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            goto ERR;
        }
        param->type = RSABSSA;
    }
    if (param->para.bssa != NULL) {
        RSA_BlindFreeCtx(param->para.bssa);
        param->para.bssa = NULL;
    }
    param->para.bssa = RSA_BlindNewCtx();
    if (param->para.bssa == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    blind = param->para.bssa;
    GOTO_ERR_IF(RSA_CreateBlind(blind, 0), ret);
    GOTO_ERR_IF(BN_Bin2Bn(blind->r, r, len), ret);
    if (BN_IsZero(blind->r) || (BN_Cmp(blind->r, ctx->pubKey->n) >= 0)) { // 1 <= r < n
        ret = CRYPT_RSA_ERR_BSSA_PARAM;
        BSL_ERR_PUSH_ERROR(CRYPT_RSA_ERR_BSSA_PARAM);
        goto ERR;
    }
    GOTO_ERR_IF(BN_ModInv(blind->rInv, blind->r, ctx->pubKey->n, opt), ret);
    GOTO_ERR_IF(BN_ModExp(blind->r, blind->r, ctx->pubKey->e, ctx->pubKey->n, opt), ret);
    ctx->blindParam = param;
ERR:
    if (ret != CRYPT_SUCCESS && ctx->blindParam == NULL && param != NULL) {
        RSA_BlindFreeCtx(param->para.bssa);
        BSL_SAL_FREE(param);
    }
    BN_OptimizerDestroy(opt);
    return ret;
}

#endif

int32_t CRYPT_RSA_Ctrl(CRYPT_RSA_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (opt) {
#ifdef HITLS_CRYPTO_RSA_EMSA_PKCSV15
        case CRYPT_CTRL_SET_RSA_EMSA_PKCSV15:
            return SetEmsaPkcsV15(ctx, val, len);
#endif
#ifdef HITLS_CRYPTO_RSA_EMSA_PSS
        case CRYPT_CTRL_SET_RSA_EMSA_PSS:
            return RsaSetPss(ctx, val);
        case CRYPT_CTRL_SET_RSA_SALT:
            return SetSalt(ctx, val, len);
        case CRYPT_CTRL_GET_RSA_SALTLEN:
            return GetSaltLen(ctx, val, len);
        case CRYPT_CTRL_GET_RSA_MGF:
            return GetMgf(ctx, val, len);
#endif
#ifdef HITLS_CRYPTO_RSA_EMSA_ISO9796_2
        case CRYPT_CTRL_SET_RSA_EMSA_ISO9796_2:
            return RsaSetIso9796_2(ctx, val);
#endif
        case CRYPT_CTRL_GET_RSA_PADDING:
            return GetPadding(ctx, val, len);
        case CRYPT_CTRL_GET_RSA_MD:
            return GetMd(ctx, val, len);
#ifdef HITLS_CRYPTO_RSAES_OAEP
        case CRYPT_CTRL_SET_RSA_RSAES_OAEP:
            return RsaSetOaep(ctx, val);
        case CRYPT_CTRL_SET_RSA_OAEP_LABEL:
            return SetOaepLabel(ctx, val, len);
#endif
#ifdef HITLS_CRYPTO_RSAES_PKCSV15
        case CRYPT_CTRL_SET_RSA_RSAES_PKCSV15:
            return SetRsaesPkcsV15(ctx, val, len);
#endif
#ifdef HITLS_CRYPTO_RSAES_PKCSV15_TLS
        case CRYPT_CTRL_SET_RSA_RSAES_PKCSV15_TLS:
            return SetRsaesPkcsV15Tls(ctx, val, len);
#endif
#ifdef HITLS_CRYPTO_RSA_NO_PAD
        case CRYPT_CTRL_SET_NO_PADDING:
            ctx->pad.type = RSA_NO_PAD;
            return CRYPT_SUCCESS;
#endif
        case CRYPT_CTRL_SET_RSA_PADDING:
            return SetRsaPad(ctx, val, len);
#if defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_RSA_VERIFY)
        case CRYPT_CTRL_GET_SIGNLEN:
            return CRYPT_CTRL_GET_NUM32_EX(CRYPT_RSA_GetSignLen, ctx, val, len);
#endif
#ifdef HITLS_CRYPTO_RSA_BSSA
        case CRYPT_CTRL_SET_RSA_BSSA_FACTOR_R:
            return RsaSetBssa(ctx, val, len);
#endif
        default:
            return RsaCommonCtrl(ctx, opt, val, len);
    }
}
#endif /* HITLS_CRYPTO_RSA */
