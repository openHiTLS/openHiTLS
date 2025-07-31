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
#ifdef HITLS_CRYPTO_KEY_INFO

#include <stdint.h>
#include <string.h>

#include "bsl_err_internal.h"
#include "bsl_obj_internal.h"
#include "bsl_print.h"

#include "crypt_utils.h"
#include "crypt_eal_pkey.h"
#include "crypt_errno.h"
#include "crypt_encode_decode_key.h"

#define CRYPT_UNKOWN_STRING "Unknown\n"
#define CRYPT_UNSUPPORT_ALG "Unsupported alg\n"

static inline int32_t PrintPubkeyBits(bool isEcc, uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio)
{
    if (!isEcc) {
        return BSL_PRINT_Fmt(layer, uio, "Public-Key: (%d bit)\n", CRYPT_EAL_PkeyGetKeyBits(pkey));
    }
    uint32_t bits = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_ECC_ORDER_BITS, &bits, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return BSL_PRINT_Fmt(layer, uio, "Public-Key: (%d bit)\n", bits);
}

#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
static int32_t GetEccPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPub *pub)
{
    uint32_t keyLen = CRYPT_EAL_PkeyGetKeyLen(pkey);
    if (keyLen == 0) {
        return CRYPT_DECODE_PRINT_NO_KEY;
    }
    uint8_t *buff = (uint8_t *)BSL_SAL_Malloc(keyLen);
    if (buff == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    pub->id = CRYPT_EAL_PkeyGetId(pkey);
    pub->key.eccPub.data = buff;
    pub->key.eccPub.len = keyLen;
    int32_t ret = CRYPT_EAL_PkeyGetPub(pkey, pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_Free(buff);
        pub->key.eccPub.data = NULL;
    }
    return ret;
}

static int32_t PrintEccPubkey(uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio)
{
    RETURN_RET_IF(PrintPubkeyBits(true, layer, pkey, uio) != 0, CRYPT_DECODE_PRINT_KEYBITS);

    /* pub key */
    CRYPT_EAL_PkeyPub pub = {0};
    int32_t ret = GetEccPub(pkey, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (BSL_PRINT_Fmt(layer, uio, "Pub:\n") != 0 ||
        BSL_PRINT_Hex(layer + 1, false, pub.key.eccPub.data, pub.key.eccPub.len, uio) != 0) {
        BSL_SAL_Free(pub.key.eccPub.data);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_ECC_PUB);
        return CRYPT_DECODE_PRINT_ECC_PUB;
    }
    BSL_SAL_Free(pub.key.eccPub.data);

    /* ASN1 OID */
    CRYPT_PKEY_ParaId paraId =
        CRYPT_EAL_PkeyGetId(pkey) == CRYPT_PKEY_SM2 ? CRYPT_ECC_SM2 : CRYPT_EAL_PkeyGetParaId(pkey);
    const char *name = BSL_OBJ_GetOidNameFromCID((BslCid)paraId);
    if (BSL_PRINT_Fmt(layer, uio, "ANS1 OID: %s\n", name == NULL ? CRYPT_UNKOWN_STRING : name) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_ECC_OID);
        return CRYPT_DECODE_PRINT_ECC_OID;
    }
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_ECDSA || HITLS_CRYPTO_SM2

#ifdef HITLS_CRYPTO_RSA
static int32_t GetRsaPub(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPub *pub)
{
    uint32_t keyLen = CRYPT_EAL_PkeyGetKeyLen(pkey);
    if (keyLen == 0) {
        return CRYPT_DECODE_PRINT_NO_KEY;
    }
    uint8_t *buff = (uint8_t *)BSL_SAL_Malloc(keyLen * 2);  // 2: n + e
    if (buff == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    pub->id = CRYPT_PKEY_RSA;
    pub->key.rsaPub.n = buff;
    pub->key.rsaPub.e = buff + keyLen;
    pub->key.rsaPub.nLen = keyLen;
    pub->key.rsaPub.eLen = keyLen;
    int32_t ret = CRYPT_EAL_PkeyGetPub(pkey, pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        BSL_SAL_Free(buff);
        pub->key.rsaPub.n = NULL;
        pub->key.rsaPub.e = NULL;
    }
    return ret;
}

int32_t CRYPT_EAL_PrintRsaPssPara(uint32_t layer, CRYPT_RSA_PssPara *para, BSL_UIO *uio)
{
    if (para == NULL || uio == NULL) {
        return CRYPT_INVALID_ARG;
    }
    /* hash */
    const char *mdIdName = BSL_OBJ_GetOidNameFromCID((BslCid)para->mdId);
    RETURN_RET_IF(BSL_PRINT_Fmt(layer, uio, "Hash Algorithm: %s%s\n",
        mdIdName == NULL ? CRYPT_UNKOWN_STRING : mdIdName, para->mdId ==
            CRYPT_MD_SHA1 ? " (default)" : "") != BSL_SUCCESS, CRYPT_DECODE_PRINT_RSAPSS_PARA);
    /* mgf */
    const char *mgfIdName = BSL_OBJ_GetOidNameFromCID((BslCid)para->mgfId);
    RETURN_RET_IF(BSL_PRINT_Fmt(layer, uio, "Mask Algorithm: %s%s\n",
        mgfIdName == NULL ? CRYPT_UNKOWN_STRING : mgfIdName, para->mgfId ==
            CRYPT_MD_SHA1 ? " (default)" : "") != BSL_SUCCESS, CRYPT_DECODE_PRINT_RSAPSS_PARA);
    /* saltLen */
    RETURN_RET_IF(BSL_PRINT_Fmt(layer, uio, "Salt Length: 0x%x%s\n",
        para->saltLen, para->saltLen == 20 ? " (default)" : "") != 0,
        CRYPT_DECODE_PRINT_RSAPSS_PARA);
    /* trailer is not supported */
    return CRYPT_SUCCESS;
}

static int32_t PrintRsaPssPara(uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio)
{
    CRYPT_RsaPadType padType = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_RSA_PADDING, &padType, sizeof(CRYPT_RsaPadType));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (padType != CRYPT_EMSA_PSS) {
        return CRYPT_SUCCESS;
    }

    CRYPT_RSA_PssPara para = {0};
    ret = CRYPT_EAL_GetRsaPssPara(pkey, &para);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (para.saltLen <= 0 && para.mdId == 0 && para.mgfId == 0) {
        return BSL_PRINT_Fmt(layer, uio, "No PSS parameter restrictions\n");
    }

    RETURN_RET_IF(BSL_PRINT_Fmt(layer, uio, "PSS parameter restrictions:\n") != 0,
        CRYPT_DECODE_PRINT_RSAPSS_PARA);

    return CRYPT_EAL_PrintRsaPssPara(layer + 1, &para, uio);
}

static int32_t PrintRsaPubkey(uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio)
{
    RETURN_RET_IF(PrintPubkeyBits(false, layer, pkey, uio) != 0, CRYPT_DECODE_PRINT_KEYBITS);

    /* pub key */
    CRYPT_EAL_PkeyPub pub = {0};
    int32_t ret = GetRsaPub(pkey, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (BSL_PRINT_Fmt(layer, uio, "Modulus:\n") != 0 ||
        BSL_PRINT_Hex(layer + 1, false, pub.key.rsaPub.n, pub.key.rsaPub.nLen, uio) != 0) {
        BSL_SAL_Free(pub.key.rsaPub.n);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_MODULUS);
        return CRYPT_DECODE_PRINT_MODULUS;
    }
    if (BSL_PRINT_Number(layer, "Exponent", pub.key.rsaPub.e, pub.key.rsaPub.eLen, uio) != 0) {
        BSL_SAL_Free(pub.key.rsaPub.n);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_EXPONENT);
        return CRYPT_DECODE_PRINT_EXPONENT;
    }
    BSL_SAL_Free(pub.key.rsaPub.n);

    return PrintRsaPssPara(layer, pkey, uio);
}
#endif // HITLS_CRYPTO_RSA

int32_t CRYPT_EAL_PrintPubkey(uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio)
{
    if (uio == NULL) {
        return CRYPT_INVALID_ARG;
    }

    CRYPT_PKEY_AlgId algId = CRYPT_EAL_PkeyGetId(pkey);
    switch (algId) {
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PKEY_RSA:
            return PrintRsaPubkey(layer, pkey, uio);
#endif
#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
        case CRYPT_PKEY_ECDSA:
        case CRYPT_PKEY_SM2:
            return PrintEccPubkey(layer, pkey, uio);
#endif
        default:
            return CRYPT_DECODE_PRINT_UNSUPPORT_ALG;
    }
}

#ifdef HITLS_CRYPTO_RSA
static inline int32_t PrintPrikeyBits(bool isEcc, uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio)
{
    if (!isEcc) {
        return BSL_PRINT_Fmt(layer, uio, "Private-Key: (%d bit)\n", CRYPT_EAL_PkeyGetKeyBits(pkey));
    }
    uint32_t bits = 0;
    int32_t ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_ECC_ORDER_BITS, &bits, sizeof(uint32_t));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return BSL_PRINT_Fmt(layer, uio, "Private-Key: (%d bit)\n", bits);
}

static int32_t PrintRsaPrikey(uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio)
{
    RETURN_RET_IF(PrintPrikeyBits(false, layer, pkey, uio) != 0, CRYPT_DECODE_PRINT_KEYBITS);

    int32_t ret;
    /* pri key */
    CRYPT_EAL_PkeyPrv pri = {0};
    ret = CRYPT_EAL_InitRsaPrv(pkey, CRYPT_PKEY_RSA, &pri);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_PkeyGetPrv(pkey, &pri);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        return ret;
    }
    if (BSL_PRINT_Fmt(layer, uio, "Modulus:\n") != 0 ||
        BSL_PRINT_Hex(layer + 1, false, pri.key.rsaPrv.n, pri.key.rsaPrv.nLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_MODULUS);
        return CRYPT_DECODE_PRINT_MODULUS;
    }
    if (BSL_PRINT_Number(layer, "PublicExponent", pri.key.rsaPrv.e, pri.key.rsaPrv.eLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_EXPONENT);
        return CRYPT_DECODE_PRINT_EXPONENT;
    }
    if (BSL_PRINT_Fmt(layer, uio, "PrivateExponent:\n") != 0 ||
        BSL_PRINT_Hex(layer + 1, false, pri.key.rsaPrv.d, pri.key.rsaPrv.dLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_MODULUS);
        return CRYPT_DECODE_PRINT_MODULUS;
    }
    if (BSL_PRINT_Fmt(layer, uio, "Prime1:\n") != 0 ||
        BSL_PRINT_Hex(layer + 1, false, pri.key.rsaPrv.p, pri.key.rsaPrv.pLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_MODULUS);
        return CRYPT_DECODE_PRINT_MODULUS;
    }
    if (BSL_PRINT_Fmt(layer, uio, "Prime2:\n") != 0 ||
        BSL_PRINT_Hex(layer + 1, false, pri.key.rsaPrv.q, pri.key.rsaPrv.qLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_MODULUS);
        return CRYPT_DECODE_PRINT_MODULUS;
    }
    if (BSL_PRINT_Fmt(layer, uio, "Exponent1:\n") != 0 ||
        BSL_PRINT_Hex(layer + 1, false, pri.key.rsaPrv.dP, pri.key.rsaPrv.dPLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_MODULUS);
        return CRYPT_DECODE_PRINT_MODULUS;
    }
    if (BSL_PRINT_Fmt(layer, uio, "Exponent2:\n") != 0 ||
        BSL_PRINT_Hex(layer + 1, false, pri.key.rsaPrv.dQ, pri.key.rsaPrv.dQLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_MODULUS);
        return CRYPT_DECODE_PRINT_MODULUS;
    }
    if (BSL_PRINT_Fmt(layer, uio, "Coefficient:\n") != 0 ||
        BSL_PRINT_Hex(layer + 1, false, pri.key.rsaPrv.qInv, pri.key.rsaPrv.qInvLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_MODULUS);
        return CRYPT_DECODE_PRINT_MODULUS;
    }
    CRYPT_EAL_DeinitRsaPrv(&pri);
    return CRYPT_SUCCESS;
}
#endif

int32_t CRYPT_EAL_PrintPrikey(uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio)
{
    if (uio == NULL) {
        return CRYPT_INVALID_ARG;
    }

    CRYPT_PKEY_AlgId algId = CRYPT_EAL_PkeyGetId(pkey);
    switch (algId) {
#ifdef HITLS_CRYPTO_RSA
        case CRYPT_PKEY_RSA:
            return PrintRsaPrikey(layer, pkey, uio);
#endif
        default:
            return CRYPT_DECODE_PRINT_UNSUPPORT_ALG;
    }
}

#endif  // HITLS_CRYPTO_KEY_INFO
