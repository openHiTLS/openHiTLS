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
#include "crypt_codecskey_local.h"
#include "crypt_codecskey.h"

#define CRYPT_UNKOWN_STRING "Unknown\n"
#define CRYPT_UNSUPPORT_ALG "Unsupported alg\n"
#define CRYPT_PUB_KEY_BITS_FMT "Public-Key: (%d bit)\n"
#define CRYPT_PRV_KEY_BITS_FMT "Private-Key: (%d bit)\n"

static int32_t PrintKeyBits(bool isEcc, bool isPrv, uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio)
{
    int32_t ret;
    uint32_t bits = 0;
    if (isEcc == true) {
        ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_GET_ECC_ORDER_BITS, &bits, sizeof(uint32_t));
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    } else {
        bits = CRYPT_EAL_PkeyGetKeyBits(pkey);
    }
    return BSL_PRINT_Fmt(layer, uio, isPrv == true ? CRYPT_PRV_KEY_BITS_FMT : CRYPT_PUB_KEY_BITS_FMT, bits);
}

#if defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2)
static int32_t PrintEccPubkey(uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio)
{
    RETURN_RET_IF(PrintKeyBits(true, false, layer, pkey, uio) != 0, CRYPT_DECODE_PRINT_KEYBITS);

    /* pub key */
    CRYPT_EAL_PkeyPub pub = {0};
    int32_t ret = GetCommonPubKey(pkey, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    (void)BSL_PRINT_Fmt(layer, uio, "Pub:\n");
    (void)BSL_PRINT_Hex(layer + 1, false, pub.key.eccPub.data, pub.key.eccPub.len, uio);
    BSL_SAL_Free(pub.key.eccPub.data);

    /* ASN1 OID */
    CRYPT_PKEY_ParaId paraId =
        CRYPT_EAL_PkeyGetId(pkey) == CRYPT_PKEY_SM2 ? CRYPT_ECC_SM2 : CRYPT_EAL_PkeyGetParaId(pkey);
    const char *name = BSL_OBJ_GetOidNameFromCID((BslCid)paraId);
    (void)BSL_PRINT_Fmt(layer, uio, "ANS1 OID: %s\n", name == NULL ? CRYPT_UNKOWN_STRING : name);
    return CRYPT_SUCCESS;
}
#endif // HITLS_CRYPTO_ECDSA || HITLS_CRYPTO_SM2

#ifdef HITLS_CRYPTO_RSA
int32_t CRYPT_EAL_PrintRsaPssPara(uint32_t layer, CRYPT_RSA_PssPara *para, BSL_UIO *uio)
{
    if (para == NULL || uio == NULL) {
        return CRYPT_INVALID_ARG;
    }
    /* hash */
    const char *name = BSL_OBJ_GetOidNameFromCID((BslCid)para->mdId);
    (void)BSL_PRINT_Fmt(layer, uio, "Hash Algorithm: %s%s\n",
        name == NULL ? CRYPT_UNKOWN_STRING : name, para->mdId == CRYPT_MD_SHA1 ? " (default)" : "");
    /* mgf */
    name = BSL_OBJ_GetOidNameFromCID((BslCid)para->mgfId);
    (void)BSL_PRINT_Fmt(layer, uio, "Mask Algorithm: %s%s\n",
        name == NULL ? CRYPT_UNKOWN_STRING : name, para->mgfId == CRYPT_MD_SHA1 ? " (default)" : "");
    /* saltLen */
    (void)BSL_PRINT_Fmt(layer, uio, "Salt Length: 0x%x%s\n", para->saltLen, para->saltLen == 20 ? " (default)" : "");
    /* trailer is not supported */
    return CRYPT_SUCCESS;
}

static int32_t PrintRsaPssPara(uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio)
{
    int32_t padType = 0;
    CRYPT_RSA_PssPara para;
    int32_t ret = CRYPT_EAL_GetRsaPssPara(pkey, &para, &padType);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (padType != CRYPT_EMSA_PSS) {
        return CRYPT_SUCCESS;
    }
    if (para.saltLen <= 0 && para.mdId == 0 && para.mgfId == 0) {
        return BSL_PRINT_Fmt(layer, uio, "No PSS parameter restrictions\n");
    }

    (void)BSL_PRINT_Fmt(layer, uio, "PSS parameter restrictions:\n");
    return CRYPT_EAL_PrintRsaPssPara(layer + 1, &para, uio);
}

static int32_t PrintRsaPubkey(uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio)
{
    RETURN_RET_IF(PrintKeyBits(false, false, layer, pkey, uio) != 0, CRYPT_DECODE_PRINT_KEYBITS);

    /* pub key */
    CRYPT_EAL_PkeyPub pub;
    int32_t ret = GetRsaPubKey(pkey, &pub);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    (void)BSL_PRINT_Fmt(layer, uio, "Modulus:\n");
    (void)BSL_PRINT_Hex(layer + 1, false, pub.key.rsaPub.n, pub.key.rsaPub.nLen, uio);
    (void)BSL_PRINT_Number(layer, "Exponent", pub.key.rsaPub.e, pub.key.rsaPub.eLen, uio);
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
static int32_t PrintRsaPrikey(uint32_t layer, CRYPT_EAL_PkeyCtx *pkey, BSL_UIO *uio)
{
    RETURN_RET_IF(PrintKeyBits(false, true, layer, pkey, uio) != 0, CRYPT_DECODE_PRINT_KEYBITS);

    /* pri key */
    CRYPT_EAL_PkeyPrv pri = {0};
    int32_t ret = CRYPT_EAL_InitRsaPrv(pkey, &pri);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_EAL_PkeyGetPrv(pkey, &pri);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        return ret;
    }
    (void)BSL_PRINT_Fmt(layer, uio, "Modulus:\n");
    if (BSL_PRINT_Hex(layer + 1, false, pri.key.rsaPrv.n, pri.key.rsaPrv.nLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_MODULUS);
        return CRYPT_DECODE_PRINT_MODULUS;
    }
    if (BSL_PRINT_Number(layer, "PublicExponent", pri.key.rsaPrv.e, pri.key.rsaPrv.eLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_EXPONENT);
        return CRYPT_DECODE_PRINT_EXPONENT;
    }
    (void)BSL_PRINT_Fmt(layer, uio, "PrivateExponent:\n");
    if (BSL_PRINT_Hex(layer + 1, false, pri.key.rsaPrv.d, pri.key.rsaPrv.dLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_MODULUS);
        return CRYPT_DECODE_PRINT_MODULUS;
    }
    (void)BSL_PRINT_Fmt(layer, uio, "Prime1:\n");
    if (BSL_PRINT_Hex(layer + 1, false, pri.key.rsaPrv.p, pri.key.rsaPrv.pLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_MODULUS);
        return CRYPT_DECODE_PRINT_MODULUS;
    }
    (void)BSL_PRINT_Fmt(layer, uio, "Prime2:\n");
    if (BSL_PRINT_Hex(layer + 1, false, pri.key.rsaPrv.q, pri.key.rsaPrv.qLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_MODULUS);
        return CRYPT_DECODE_PRINT_MODULUS;
    }
    (void)BSL_PRINT_Fmt(layer, uio, "Exponent1:\n");
    if (BSL_PRINT_Hex(layer + 1, false, pri.key.rsaPrv.dP, pri.key.rsaPrv.dPLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_MODULUS);
        return CRYPT_DECODE_PRINT_MODULUS;
    }
    (void)BSL_PRINT_Fmt(layer, uio, "Exponent2:\n");
    if (BSL_PRINT_Hex(layer + 1, false, pri.key.rsaPrv.dQ, pri.key.rsaPrv.dQLen, uio) != 0) {
        CRYPT_EAL_DeinitRsaPrv(&pri);
        BSL_ERR_PUSH_ERROR(CRYPT_DECODE_PRINT_MODULUS);
        return CRYPT_DECODE_PRINT_MODULUS;
    }
    (void)BSL_PRINT_Fmt(layer, uio, "Coefficient:\n");
    if (BSL_PRINT_Hex(layer + 1, false, pri.key.rsaPrv.qInv, pri.key.rsaPrv.qInvLen, uio) != 0) {
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
