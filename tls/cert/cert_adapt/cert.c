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
#include "securec.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_sal.h"
#include "bsl_list.h"
#include "hitls_error.h"
#include "hitls_cert_reg.h"
#include "hitls_security.h"
#include "tls.h"
#ifdef HITLS_TLS_FEATURE_SECURITY
#include "security.h"
#endif
#include "cert_mgr_ctx.h"
#include "cert_method.h"
#include "cert_mgr.h"
#include "cert.h"
#include "config_type.h"
#include "pack.h"
#include "custom_extensions.h"

#ifdef HITLS_TLS_FEATURE_SECURITY
static int32_t CheckKeySecbits(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, HITLS_CERT_Key *key)
{
    int32_t ret;
    int32_t secBits = 0;
    HITLS_Config *config = &ctx->config.tlsConfig;

    ret = SAL_CERT_KeyCtrl(config, key, CERT_KEY_CTRL_GET_SECBITS, NULL, (void *)&secBits);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16303, "GET_SECBITS fail");
    }
    ret = SECURITY_SslCheck((HITLS_Ctx *)ctx, HITLS_SECURITY_SECOP_EE_KEY, secBits, 0, cert);
    if (ret != SECURITY_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16304, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "SslCheck fail, ret %d", ret, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_EE_KEY_WITH_INSECURE_SECBITS);
        ctx->method.sendAlert((TLS_Ctx *)ctx, ALERT_LEVEL_FATAL, ALERT_INSUFFICIENT_SECURITY);
        return HITLS_CERT_ERR_EE_KEY_WITH_INSECURE_SECBITS;
    }

    return HITLS_SUCCESS;
}
#endif

CERT_Type CertKeyType2CertType(HITLS_CERT_KeyType keyType)
{
    switch (keyType) {
        case TLS_CERT_KEY_TYPE_RSA:
        case TLS_CERT_KEY_TYPE_RSA_PSS:
            return CERT_TYPE_RSA_SIGN;
        case TLS_CERT_KEY_TYPE_DSA:
            return CERT_TYPE_DSS_SIGN;
        case TLS_CERT_KEY_TYPE_SM2:
        case TLS_CERT_KEY_TYPE_ECDSA:
        case TLS_CERT_KEY_TYPE_ED25519:
            return CERT_TYPE_ECDSA_SIGN;
        default:
            break;
    }
    return CERT_TYPE_UNKNOWN;
}

HITLS_CERT_KeyType SAL_CERT_SignScheme2CertKeyType(const HITLS_Ctx *ctx, HITLS_SignHashAlgo signScheme)
{
    const TLS_SigSchemeInfo *info = ConfigGetSignatureSchemeInfo(&ctx->config.tlsConfig, signScheme);
    if (info == NULL) {
        return TLS_CERT_KEY_TYPE_UNKNOWN;
    }
    return info->keyType;
}

HITLS_SignHashAlgo SAL_CERT_GetDefaultSignHashAlgo(HITLS_CERT_KeyType keyType)
{
    switch (keyType) {
        case TLS_CERT_KEY_TYPE_RSA:
            return CERT_SIG_SCHEME_RSA_PKCS1_SHA1;
        case TLS_CERT_KEY_TYPE_RSA_PSS:
            return CERT_SIG_SCHEME_RSA_PSS_PSS_SHA256;
        case TLS_CERT_KEY_TYPE_DSA:
            return CERT_SIG_SCHEME_DSA_SHA1;
        case TLS_CERT_KEY_TYPE_ECDSA:
            return CERT_SIG_SCHEME_ECDSA_SHA1;
        case TLS_CERT_KEY_TYPE_ED25519:
            return CERT_SIG_SCHEME_ED25519;
#if defined(HITLS_TLS_PROTO_TLCP11) || defined(HITLS_TLS_FEATURE_SM_TLS13)
        case TLS_CERT_KEY_TYPE_SM2:
            return CERT_SIG_SCHEME_SM2_SM3;
#endif
        default:
            break;
    }
    return CERT_SIG_SCHEME_UNKNOWN;
}

int32_t CheckCertType(CERT_Type expectCertType, HITLS_CERT_KeyType checkedKeyType)
{
    if (expectCertType == CERT_TYPE_UNKNOWN) {
        /* The certificate type is not specified. This check is not required. */
        return HITLS_SUCCESS;
    }
    /* Convert the key type to the certificate type. */
    CERT_Type checkedCertType = CertKeyType2CertType(checkedKeyType);
    if (expectCertType != checkedCertType) {
        BSL_ERR_PUSH_ERROR(HITLS_MSG_HANDLE_UNSUPPORT_CERT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15034, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "unexpect cert: expect cert type = %u, checked key type = %u.", expectCertType, checkedKeyType, 0, 0);
        return HITLS_MSG_HANDLE_UNSUPPORT_CERT;
    }

    return HITLS_SUCCESS;
}

static bool IsSignSchemeExist(const uint16_t *signSchemeList, uint32_t signSchemeNum, HITLS_SignHashAlgo signScheme)
{
    for (uint32_t i = 0; i < signSchemeNum; i++) {
        if (signSchemeList[i] == signScheme) {
            return true;
        }
    }
    return false;
}
typedef struct {
    uint32_t baseSignAlgorithmsSize;
    const uint16_t *baseSignAlgorithms;
    uint32_t selectSignAlgorithmsSize;
    const uint16_t *selectSignAlgorithms;
} SelectSignAlgorithms;

static int32_t CheckSelectSignAlgorithms(TLS_Ctx *ctx, const SelectSignAlgorithms *select,
    HITLS_CERT_KeyType checkedKeyType, HITLS_CERT_Key *pubkey, bool isNegotiateSignAlgo)
{
    uint32_t baseSignAlgorithmsSize = select->baseSignAlgorithmsSize;
    const uint16_t *baseSignAlgorithms = select->baseSignAlgorithms;
    uint32_t selectSignAlgorithmsSize = select->selectSignAlgorithmsSize;
    const uint16_t *selectSignAlgorithms = select->selectSignAlgorithms;
    const TLS_SigSchemeInfo *info = NULL;
    (void)pubkey;
#ifdef HITLS_TLS_PROTO_TLS13
    int32_t paraId = 0;
    (void)SAL_CERT_KeyCtrl(&ctx->config.tlsConfig, pubkey, CERT_KEY_CTRL_GET_PARAM_ID, NULL, (void *)&paraId);
#endif
    for (uint32_t i = 0; i < baseSignAlgorithmsSize; i++) {
        info = ConfigGetSignatureSchemeInfo(&ctx->config.tlsConfig, baseSignAlgorithms[i]);
        if (info == NULL || info->keyType != (int32_t)checkedKeyType) {
            continue;
        }
#ifdef HITLS_TLS_PROTO_TLS13
        if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13 && info->paraId != 0 && info->paraId != paraId) {
            continue;
        }
#endif
        if (!IsSignSchemeExist(selectSignAlgorithms, selectSignAlgorithmsSize, baseSignAlgorithms[i])) {
            /* The signature algorithm must be the same as the algorithm configured on the peer end. */
            continue;
        }
        if (info->keyType == TLS_CERT_KEY_TYPE_RSA_PSS) {
            HITLS_HashAlgo hashAlgId = HITLS_HASH_BUTT;
            (void)SAL_CERT_KeyCtrl(&ctx->config.tlsConfig, pubkey, CERT_KEY_CTRL_GET_PSS_MD, NULL, (void *)&hashAlgId);
            if (hashAlgId != HITLS_HASH_BUTT && (int32_t)hashAlgId != info->hashAlgId) {
                continue;
            }
        }
#ifdef HITLS_TLS_FEATURE_SECURITY
        if (SECURITY_SslCheck(ctx, HITLS_SECURITY_SECOP_SIGALG_CHECK, 0, baseSignAlgorithms[i],
            NULL) != SECURITY_SUCCESS) {
            continue;
        }
#endif
        if (!isNegotiateSignAlgo) {
            /* Only the signature algorithm in the certificate is checked.
               The signature algorithm in the handshake message is not negotiated. */
            return HITLS_SUCCESS;
        }

#ifdef HITLS_TLS_PROTO_TLS13
        const uint32_t rsaPkcsv15Mask = 0x01;
        const uint32_t dsaMask = 0x02;
        const uint32_t sha1Mask = 0x0200;
        const uint32_t sha224Mask = 0x0300;
        /* rfc8446 4.2.3.  Signature Algorithms */
        if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
            if (((baseSignAlgorithms[i] & 0xff) == rsaPkcsv15Mask) ||
                ((baseSignAlgorithms[i] & 0xff) == dsaMask) ||
                ((baseSignAlgorithms[i] & 0xff00) == sha1Mask) ||
                ((baseSignAlgorithms[i] & 0xff00) == sha224Mask)) {
                /* not defined for use in signed TLS handshake messages in TLS1.3 */
                continue;
            }
        }
#endif
#ifdef HITLS_TLS_FEATURE_SM_TLS13
        if (IS_SM_TLS13(ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite)) {
            if (baseSignAlgorithms[i] != CERT_SIG_SCHEME_SM2_SM3) {
                continue;
            }
        }
#endif
        ctx->negotiatedInfo.signScheme = baseSignAlgorithms[i];
        return HITLS_SUCCESS;
    }
    BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_NO_SIGN_SCHEME_MATCH);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15981, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "unexpect cert: no available signature scheme, key type = %u.", checkedKeyType, 0, 0, 0);
    return HITLS_CERT_ERR_NO_SIGN_SCHEME_MATCH;
}

static int32_t CheckSignScheme(TLS_Ctx *ctx, const uint16_t *signSchemeList, uint32_t signSchemeNum,
    HITLS_CERT_KeyType checkedKeyType, HITLS_CERT_Key *pubkey, bool isNegotiateSignAlgo)
{
    if (signSchemeList == NULL) {
        if (!isNegotiateSignAlgo) {
            /* Do not save the signature algorithm used for sending handshake messages. */
            return HITLS_SUCCESS;
        }
        /* No signature algorithm is specified.
           The default signature algorithm is used when handshake messages are sent. */
        HITLS_SignHashAlgo signScheme = SAL_CERT_GetDefaultSignHashAlgo(checkedKeyType);
        if (signScheme == CERT_SIG_SCHEME_UNKNOWN
#ifdef HITLS_TLS_FEATURE_SECURITY
            || SECURITY_SslCheck(ctx, HITLS_SECURITY_SECOP_SIGALG_CHECK, 0, signScheme, NULL) != SECURITY_SUCCESS
#endif
            ) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16074, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
                "unexpect key type: no available signature scheme, key type = %u.", checkedKeyType, 0, 0, 0);
            return HITLS_CERT_ERR_NO_SIGN_SCHEME_MATCH;
        }
        ctx->negotiatedInfo.signScheme = signScheme;
        return HITLS_SUCCESS;
    }

    SelectSignAlgorithms select = { 0 };
    bool supportServer = ctx->config.tlsConfig.isSupportServerPreference;
    select.baseSignAlgorithmsSize = supportServer ? ctx->config.tlsConfig.signAlgorithmsSize : signSchemeNum;
    select.baseSignAlgorithms = supportServer ? ctx->config.tlsConfig.signAlgorithms : signSchemeList;
    select.selectSignAlgorithmsSize = supportServer ? signSchemeNum : ctx->config.tlsConfig.signAlgorithmsSize;
    select.selectSignAlgorithms = supportServer ? signSchemeList : ctx->config.tlsConfig.signAlgorithms;

    return CheckSelectSignAlgorithms(ctx, &select, checkedKeyType, pubkey, isNegotiateSignAlgo);
}

int32_t CheckCurveName(HITLS_Config *config, const uint16_t *curveList, uint32_t curveNum, HITLS_CERT_Key *pubkey)
{
    uint32_t curveName = HITLS_NAMED_GROUP_BUTT;
    int32_t ret = SAL_CERT_KeyCtrl(config, pubkey, CERT_KEY_CTRL_GET_CURVE_NAME, NULL, (void *)&curveName);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15036, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "internal error: unable to get curve name.", 0, 0, 0, 0);
        return ret;
    }
    for (uint32_t i = 0; i < curveNum; i++) {
        if (curveName == curveList[i]) {
            return HITLS_SUCCESS;
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_NO_CURVE_MATCH);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15037, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "unexpect cert: no curve match, which used %u.", curveName, 0, 0, 0);
    return HITLS_CERT_ERR_NO_CURVE_MATCH;
}

int32_t CheckPointFormat(HITLS_Config *config, const uint8_t *ecPointFormatList, uint32_t listSize,
    HITLS_CERT_Key *pubkey)
{
    uint32_t ecPointFormat = HITLS_POINT_FORMAT_BUTT;
    int32_t ret = SAL_CERT_KeyCtrl(config, pubkey, CERT_KEY_CTRL_GET_POINT_FORMAT, NULL, (void *)&ecPointFormat);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15038, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "internal error: unable to get point format.", 0, 0, 0, 0);
        return ret;
    }
    for (uint32_t i = 0; i < listSize; i++) {
        if (ecPointFormat == ecPointFormatList[i]) {
            return HITLS_SUCCESS;
        }
    }
    BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_NO_POINT_FORMAT_MATCH);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15039, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "unexpect cert: no point format match, which used %u.", ecPointFormat, 0, 0, 0);
    return HITLS_CERT_ERR_NO_POINT_FORMAT_MATCH;
}

int32_t IsEcParamCompatible(HITLS_Config *config, const CERT_ExpectInfo *info, HITLS_CERT_Key *pubkey)
{
    int32_t ret;

    /* If the client has used a Supported Elliptic Curves Extension, the public key in the server's certificate MUST
    respect the client's choice of elliptic curves */
    if (info->ellipticCurveNum != 0) {
        ret = CheckCurveName(config, info->ellipticCurveList, info->ellipticCurveNum, pubkey);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    if (info->ecPointFormatNum != 0) {
        ret = CheckPointFormat(config, info->ecPointFormatList, info->ecPointFormatNum, pubkey);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    return HITLS_SUCCESS;
}

static int32_t CheckCertTypeAndSignScheme(HITLS_Ctx *ctx, const CERT_ExpectInfo *expectCertInfo, HITLS_CERT_Key *pubkey,
    bool isNegotiateSignAlgo, bool signCheck)
{
    HITLS_Config *config = &ctx->config.tlsConfig;
    uint32_t keyType = TLS_CERT_KEY_TYPE_UNKNOWN;
    int32_t ret = SAL_CERT_KeyCtrl(config, pubkey, CERT_KEY_CTRL_GET_TYPE, NULL, (void *)&keyType);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15041, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
            "check certificate error: pubkey type unknown.", 0, 0, 0, 0);
        return ret;
    }

    ret = CheckCertType(expectCertInfo->certType, keyType);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    if (signCheck == true) {
        ret = CheckSignScheme(ctx, expectCertInfo->signSchemeList, expectCertInfo->signSchemeNum,
            keyType, pubkey, isNegotiateSignAlgo);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
    }

    /* ECDSA certificate. The curve ID and point format must be checked.
    TLS_CERT_KEY_TYPE_SM2 does not check the curve ID and point format. TLCP curves is sm2 and is not compressed. */
    if (keyType == TLS_CERT_KEY_TYPE_ECDSA && ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
        ret = IsEcParamCompatible(config, expectCertInfo, pubkey);
    }

    return ret;
}

int32_t SAL_CERT_CheckCertInfo(HITLS_Ctx *ctx, const CERT_ExpectInfo *expectCertInfo, HITLS_CERT_X509 *cert,
    bool isNegotiateSignAlgo, bool signCheck)
{
    HITLS_Config *config = &ctx->config.tlsConfig;
    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    HITLS_CERT_Key *pubkey = NULL;
    int32_t ret = SAL_CERT_X509Ctrl(config, cert, CERT_CTRL_GET_PUB_KEY, NULL, (void *)&pubkey);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID15040, "get pubkey fail");
    }

    do {
#ifdef HITLS_TLS_FEATURE_SECURITY
        ret = CheckKeySecbits(ctx, cert, pubkey);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16307, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "CheckKeySecbits fail", 0, 0, 0, 0);
            break;
        }
#endif

        ret = CheckCertTypeAndSignScheme(ctx, expectCertInfo, pubkey, isNegotiateSignAlgo, signCheck);
        if (ret != HITLS_SUCCESS) {
            break;
        }
    } while (false);

    SAL_CERT_KeyFree(mgrCtx, pubkey);
    return ret;
}

/*
 * Server: Currently, two certificates are required for either of the two cipher suites supported.
 * If the ECDHE cipher suite is used, the client needs to obtain the encrypted certificate to generate the premaster key
 * and the signature certificate authenticates the identity.
 * If the ECC cipher suite is used, the server public key is required to encrypt the premaster key
 * and the signature certificate authentication is required.
 * Client: Only the ECDHE cipher suite requires the client encryption certificate.
 * In this case, the value of isNeedClientCert is true and may not be two-way authentication. (The specific value
 * depends on the server configuration.)
 * Therefore, the client does not verify any certificate and only sets the index.
 * */
#ifdef HITLS_TLS_PROTO_TLCP11
static int32_t TlcpSelectCertByInfo(HITLS_Ctx *ctx, CERT_ExpectInfo *info)
{
    int32_t encCertKeyType = TLS_CERT_KEY_TYPE_SM2;
    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    CERT_Pair *certPair =  NULL;
    int32_t ret = BSL_HASH_At(mgrCtx->certPairs, (uintptr_t)encCertKeyType, (uintptr_t *)&certPair);
    if (ret != HITLS_SUCCESS || certPair == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CERT_ERR_SELECT_CERTIFICATE, BINLOG_ID17336,
            "The certificate required by TLCP is not loaded");
    }
    HITLS_CERT_X509 *cert = certPair->cert;
    HITLS_CERT_X509 *encCert = certPair->encCert;
    if (ctx->isClient == false || ctx->negotiatedInfo.cipherSuiteInfo.kxAlg == HITLS_KEY_EXCH_ECDHE) {
        if (cert == NULL || encCert == NULL) {
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_CERT_ERR_SELECT_CERTIFICATE, BINLOG_ID15042,
                "The certificate required by TLCP is not loaded");
        }

        ret = SAL_CERT_CheckCertInfo(ctx, info, cert, true, true);
        if (ret != HITLS_SUCCESS) {
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16308, "CheckCertInfo fail");
        }

        ret = SAL_CERT_CheckCertInfo(ctx, info, encCert, true, false);
        if (ret != HITLS_SUCCESS) {
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16309, "CheckCertInfo fail");
        }
    } else {
        /* Check whether the certificate is missing when the client sends the certificate
           or sends it to the server for processing. Check whether the authentication-related signature certificate
           or derived encryption certificate exists when the client uses the certificate. */
        if (cert != NULL) {
            ret = SAL_CERT_CheckCertInfo(ctx, info, cert, true, true);
            if (ret != HITLS_SUCCESS) {
                return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16310, "CheckCertInfo fail");
            }
        }
        if (encCert != NULL) {
            ret = SAL_CERT_CheckCertInfo(ctx, info, encCert, true, false);
            if (ret != HITLS_SUCCESS) {
                return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16311, "CheckCertInfo fail");
            }
        }
    }
    mgrCtx->currentCertKeyType = TLS_CERT_KEY_TYPE_SM2;
    return HITLS_SUCCESS;
}
#endif

static int32_t SelectCertByInfo(HITLS_Ctx *ctx, CERT_ExpectInfo *info)
{
    int32_t ret;
    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_UNREGISTERED_CALLBACK, BINLOG_ID16312, "unregistered callback");
    }

    BSL_HASH_Hash *certPairs = mgrCtx->certPairs;
    BSL_HASH_Iterator it = BSL_HASH_IterBegin(certPairs);
    while (it != BSL_HASH_IterEnd(certPairs)) {
        uint32_t keyType = (uint32_t)BSL_HASH_HashIterKey(certPairs, it);
        CERT_Pair *certPair = (CERT_Pair *)BSL_HASH_IterValue(certPairs, it);
        if (certPair == NULL || certPair->cert == NULL || certPair->privateKey == NULL) {
            it = BSL_HASH_IterNext(certPairs, it);
            continue;
        }
        ret = SAL_CERT_CheckCertInfo(ctx, info, certPair->cert, true, true);
        if (ret != HITLS_SUCCESS) {
            it = BSL_HASH_IterNext(certPairs, it);
            continue;
        }
        /* Find a proper certificate and record the corresponding subscript. */
        mgrCtx->currentCertKeyType = keyType;
        return HITLS_SUCCESS;
    }
    return HITLS_CERT_ERR_SELECT_CERTIFICATE;
}

int32_t SAL_CERT_SelectCertByInfo(HITLS_Ctx *ctx, CERT_ExpectInfo *info)
{
    int32_t ret = HITLS_SUCCESS;
    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    if (mgrCtx == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_UNREGISTERED_CALLBACK, BINLOG_ID16313, "unregistered callback");
    }
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11) {
#ifdef HITLS_TLS_PROTO_TLCP11
        ret = TlcpSelectCertByInfo(ctx, info);
#endif
    } else {
        ret = SelectCertByInfo(ctx, info);
    }
    if (ret == HITLS_SUCCESS) {
        return ret;
    }
    BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_SELECT_CERTIFICATE);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16151, BSL_LOG_LEVEL_INFO, BSL_LOG_BINLOG_TYPE_RUN,
        "select certificate fail. ret %d", ret, 0, 0, 0);
    mgrCtx->currentCertKeyType = TLS_CERT_KEY_TYPE_UNKNOWN;
    return HITLS_CERT_ERR_SELECT_CERTIFICATE;
}

int32_t EncodeCertificate(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, PackPacket *pkt, uint32_t certIndex)
{
    if (ctx == NULL || pkt == NULL || cert == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16314, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    (void)certIndex;
    int32_t ret;
    HITLS_Config *config = &ctx->config.tlsConfig;
    uint32_t certLen = 0;
    ret = SAL_CERT_X509Ctrl(config, cert, CERT_CTRL_GET_ENCODE_LEN, NULL, (void *)&certLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15043, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode certificate error: unable to get encode length.", 0, 0, 0, 0);
        return ret;
    }
    if (certLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_ENCODE_CERT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15044, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "cert encode len is 0", 0, 0, 0, 0);
        return HITLS_CERT_ERR_ENCODE_CERT;
    }

    /* Write the length of the certificate data (3 bytes). */
    ret = PackAppendUint24ToBuf(pkt, certLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    /* Reserve space for certificate data and encode directly */
    uint8_t *certBuf = NULL;
    ret = PackReserveBytes(pkt, certLen, &certBuf);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    uint32_t usedLen = 0;
    /* Write the certificate data using the low-level encoding function */
    ret = SAL_CERT_X509Encode(ctx, cert, certBuf, certLen, &usedLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16315, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "X509Encode err", 0, 0, 0, 0);
        return ret;
    }

    ret = PackSkipBytes(pkt, usedLen);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

#ifdef HITLS_TLS_PROTO_TLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        /* If an extension applies to the entire chain, it SHOULD be included in the first CertificateEntry. */
        /* Start length field for extensions */
        uint32_t exLenPos = 0;
        ret = PackStartLengthField(pkt, sizeof(uint16_t), &exLenPos);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
#ifdef HITLS_TLS_FEATURE_CUSTOM_EXTENSION
        if (IsPackNeedCustomExtensions(CUSTOM_EXT_FROM_CTX(ctx), HITLS_EX_TYPE_TLS1_3_CERTIFICATE)) {
            ret = PackCustomExtensions(ctx, pkt, HITLS_EX_TYPE_TLS1_3_CERTIFICATE, cert, certIndex);
            if (ret != HITLS_SUCCESS) {
                return ret;
            }
        }
#endif /* HITLS_TLS_FEATURE_CUSTOM_EXTENSION */
        /* Close extension length field */
        PackCloseUint16Field(pkt, exLenPos);
    }
#endif
    return HITLS_SUCCESS;
}

void FreeCertList(HITLS_CERT_X509 **certList, uint32_t certNum)
{
    if (certList == NULL) {
        return;
    }
    for (uint32_t i = 0; i < certNum; i++) {
        SAL_CERT_X509Free(certList[i]);
    }
}

static int32_t EncodeEECert(HITLS_Ctx *ctx, PackPacket *pkt, HITLS_CERT_X509 **cert)
{
    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    CERT_Pair *currentCertPair =  NULL;
    int32_t ret = BSL_HASH_At(mgrCtx->certPairs, (uintptr_t)mgrCtx->currentCertKeyType, (uintptr_t *)&currentCertPair);
    if (ret != HITLS_SUCCESS || currentCertPair == NULL || currentCertPair->cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_EXP_CERT);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CERT_ERR_EXP_CERT, BINLOG_ID16152, "first cert is null");
    }
    HITLS_CERT_X509 *tmpCert = currentCertPair->cert;

#ifdef HITLS_TLS_FEATURE_SECURITY
    HITLS_CERT_Key *key = currentCertPair->privateKey;
    ret = CheckKeySecbits(ctx, tmpCert, key);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16317, "check key fail");
    }
#endif

    /* Write the first device certificate. */
    ret = EncodeCertificate(ctx, tmpCert, pkt, 0);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16153, "encode fail");
    }
#ifdef HITLS_TLS_PROTO_TLCP11
    /* If the TLCP algorithm is used and the encryption certificate is required, write the
    second encryption certificate. */
    HITLS_CERT_X509 *certEnc = currentCertPair->encCert;
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11 && certEnc != NULL) {
#ifdef HITLS_TLS_FEATURE_SECURITY
        HITLS_CERT_Key *keyEnc = currentCertPair->encPrivateKey;
        ret = CheckKeySecbits(ctx, certEnc, keyEnc);
        if (ret != HITLS_SUCCESS) {
            return ret;
        }
#endif
        ret = EncodeCertificate(ctx, certEnc, pkt, 1);
        if (ret != HITLS_SUCCESS) {
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16154, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "TLCP encode device certificate error.", 0, 0, 0, 0);
            return ret;
        }
    }
#endif
    *cert = tmpCert;
    return HITLS_SUCCESS;
}

#ifdef HITLS_TLS_FEATURE_SECURITY
static int32_t CheckCertChainFromStore(HITLS_Config *config, HITLS_CERT_X509 *cert)
{
    HITLS_CERT_Key *pubkey = NULL;
    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    int32_t ret = SAL_CERT_X509Ctrl(config, cert, CERT_CTRL_GET_PUB_KEY, NULL, (void *)&pubkey);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CFG_ERR_LOAD_CERT_FILE, BINLOG_ID16318, "GET_PUB_KEY fail");
    }

    int32_t secBits = 0;
    ret = SAL_CERT_KeyCtrl(config, pubkey, CERT_KEY_CTRL_GET_SECBITS, NULL, (void *)&secBits);
    SAL_CERT_KeyFree(mgrCtx, pubkey);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16319, "GET_SECBITS fail");
    }

    ret = SECURITY_CfgCheck(config, HITLS_SECURITY_SECOP_CA_KEY, secBits, 0, cert);  // cert key
    if (ret != SECURITY_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16320, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CfgCheck fail, ret %d", ret, 0, 0, 0);
        return HITLS_CERT_ERR_CA_KEY_WITH_INSECURE_SECBITS;
    }

    int32_t signAlg = 0;
    ret = SAL_CERT_X509Ctrl(config, cert, CERT_CTRL_GET_SIGN_ALGO, NULL, (void *)&signAlg);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16321, "GET_SIGN_ALGO fail");
    }

    ret = SECURITY_CfgCheck(config, HITLS_SECURITY_SECOP_SIGALG_CHECK, 0, signAlg, NULL);
    if (ret != SECURITY_SUCCESS) {
        return HITLS_CERT_ERR_INSECURE_SIG_ALG ;
    }
    return HITLS_SUCCESS;
}
#endif

static int32_t EncodeCertificateChain(HITLS_Ctx *ctx, PackPacket *pkt)
{
    HITLS_CERT_X509 *tempCert = NULL;
    HITLS_Config *config = &ctx->config.tlsConfig;
    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    CERT_Pair *currentCertPair =  NULL;
    int32_t ret = BSL_HASH_At(mgrCtx->certPairs, (uintptr_t)mgrCtx->currentCertKeyType, (uintptr_t *)&currentCertPair);
    if (ret != HITLS_SUCCESS || currentCertPair == NULL) {
        return HITLS_SUCCESS;
    }
    HITLS_CERT_Chain *chain = NULL;
    if (BSL_LIST_COUNT(currentCertPair->chain) > 0) {
        chain = currentCertPair->chain;
    } else {
        chain = mgrCtx->extraChain;
    }
    tempCert = (HITLS_CERT_X509 *)BSL_LIST_GET_FIRST(chain);
    uint32_t certIndex = 1;
    while (tempCert != NULL) {
        ret = EncodeCertificate(ctx, tempCert, pkt, certIndex);
        if (ret != HITLS_SUCCESS) {
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID15048, "encode cert chain err");
        }
        certIndex++;
        tempCert = BSL_LIST_GET_NEXT(chain);
    }
    return HITLS_SUCCESS;
}

static int32_t EncodeCertStore(HITLS_Ctx *ctx, PackPacket *pkt, HITLS_CERT_X509 *cert)
{
    HITLS_Config *config = &ctx->config.tlsConfig;
    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    HITLS_CERT_Store *store = (mgrCtx->chainStore != NULL) ? mgrCtx->chainStore : mgrCtx->certStore;
    HITLS_CERT_X509 *certList[TLS_DEFAULT_VERIFY_DEPTH] = {0};
    uint32_t certNum = TLS_DEFAULT_VERIFY_DEPTH;
    if (store != NULL) {
        int32_t ret = SAL_CERT_BuildChain(config, store, cert, certList, &certNum);
        if (ret != HITLS_SUCCESS) {
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16322, "BuildChain fail");
        }
        /* The first device certificate has been written. The certificate starts from the second one. */
        for (uint32_t i = 1; i < certNum; i++) {
#ifdef HITLS_TLS_FEATURE_SECURITY
            ret = CheckCertChainFromStore(config, certList[i]);
            if (ret != HITLS_SUCCESS) {
                FreeCertList(certList, certNum);
                return ret;
            }
#endif
            ret = EncodeCertificate(ctx, certList[i], pkt, i);
            if (ret != HITLS_SUCCESS) {
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16155, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "encode cert chain error in No.%u.", i, 0, 0, 0);
                FreeCertList(certList, certNum);
                return ret;
            }
        }
    }
    FreeCertList(certList, certNum);
    return HITLS_SUCCESS;
}
/*
 * The constructed certificate chain is incomplete (excluding the root certificate).
 * Therefore, in the buildCertChain callback, the return value is ignored, even if the error returned by this call.
 * In fact, certificates are not verified but chains are constructed as many as possible.
 * So do not need to invoke buildCertChain if the certificate is encrypted using the TLCP.
 * If the TLCP is used, the server has checked that the two certificates are not empty.
 * The client does not check, the message is sent based on the configuration.
 * If the message will be sent, the signature certificate must exist.
 * */
int32_t SAL_CERT_EncodeCertChain(HITLS_Ctx *ctx, PackPacket *pkt)
{
    if (ctx == NULL || pkt == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_NULL_INPUT, BINLOG_ID16323, "input null");
    }
    HITLS_CERT_X509 *cert = NULL;
    HITLS_Config *config = &ctx->config.tlsConfig;
    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    if (mgrCtx == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_UNREGISTERED_CALLBACK, BINLOG_ID16324, "unregistered callback");
    }

    CERT_Pair *currentCertPair =  NULL;
    int32_t ret = BSL_HASH_At(mgrCtx->certPairs, (uintptr_t)mgrCtx->currentCertKeyType, (uintptr_t *)&currentCertPair);
    if (ret != HITLS_SUCCESS || currentCertPair == NULL) {
        /* No certificate needs to be sent at the local end. */
        return HITLS_SUCCESS;
    }
    ret = EncodeEECert(ctx, pkt, &cert);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID15046, "encode device cert err");
    }
    // Check the size. If a certificate exists in the chain, directly put the data in the chain into the buf and return.
    if (BSL_LIST_COUNT(currentCertPair->chain) > 0 || BSL_LIST_COUNT(mgrCtx->extraChain) > 0) {
        return EncodeCertificateChain(ctx, pkt);
    }
    return EncodeCertStore(ctx, pkt, cert);
}

#ifdef HITLS_TLS_PROTO_TLS13
// rfc8446 4.4.2.4. Receiving a Certificate Message
// Any endpoint receiving any certificate which it would need to validate using any signature algorithm using an MD5
// hash MUST abort the handshake with a "bad_certificate" alert.
// Currently, the MD5 signature algorithm is not available, but it is still an unknown one.
int32_t CheckCertSignature(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert)
{
    HITLS_Config *config = &ctx->config.tlsConfig;
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        HITLS_SignHashAlgo signAlg = CERT_SIG_SCHEME_UNKNOWN;
        const uint32_t md5Mask = 0x0100;
        (void)SAL_CERT_X509Ctrl(config, cert, CERT_CTRL_GET_SIGN_ALGO, NULL, (void *)&signAlg);
        if ((signAlg == CERT_SIG_SCHEME_UNKNOWN) || (((uint32_t)signAlg & 0xff00) == md5Mask)) {
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_CERT_CTRL_ERR_GET_SIGN_ALGO, BINLOG_ID16325, "signAlg unknow");
        }
    }
    return HITLS_SUCCESS;
}
#endif

static void DestoryParseChain(HITLS_CERT_X509 *encCert, HITLS_CERT_X509 *cert, HITLS_CERT_Chain *newChain)
{
    SAL_CERT_X509Free(encCert);
    SAL_CERT_X509Free(cert);
    SAL_CERT_ChainFree(newChain);
}

#ifdef HITLS_TLS_PROTO_TLCP11
static bool TlcpCheckSignCertKeyUsage(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert)
{
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11) {
        return SAL_CERT_CheckCertKeyUsage(ctx, cert, CERT_KEY_CTRL_IS_DIGITAL_SIGN_USAGE) ||
                SAL_CERT_CheckCertKeyUsage(ctx, cert, CERT_KEY_CTRL_IS_NON_REPUDIATION_USAGE);
    }
    return true;
}

static bool TlcpCheckEncCertKeyUsage(HITLS_Ctx *ctx, HITLS_CERT_X509 *encCert)
{
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11) {
        return SAL_CERT_CheckCertKeyUsage(ctx, encCert, CERT_KEY_CTRL_IS_KEYENC_USAGE) ||
                SAL_CERT_CheckCertKeyUsage(ctx, encCert, CERT_KEY_CTRL_IS_DATA_ENC_USAGE) ||
                SAL_CERT_CheckCertKeyUsage(ctx, encCert, CERT_KEY_CTRL_IS_KEY_AGREEMENT_USAGE);
    }
    return false;
}
#endif

int32_t ParseChain(HITLS_Ctx *ctx, CERT_Item *item, HITLS_CERT_Chain **chain, HITLS_CERT_X509 **encCert)
{
    if (ctx == NULL || chain == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_NULL_INPUT, BINLOG_ID16326, "input null");
    }
    HITLS_CERT_X509 *encCertLocal = NULL;
    HITLS_Config *config = &ctx->config.tlsConfig;
    HITLS_CERT_Chain *newChain = SAL_CERT_ChainNew();
    if (newChain == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID15049, "ChainNew fail");
    }

    CERT_Item *listNode = item;
    while (listNode != NULL) {
        HITLS_CERT_X509 *cert = SAL_CERT_X509Parse(LIBCTX_FROM_CONFIG(config),
            ATTRIBUTE_FROM_CONFIG(config), config, listNode->data, listNode->dataSize,
            TLS_PARSE_TYPE_BUFF, TLS_PARSE_FORMAT_ASN1);
        if (cert == NULL) {
            DestoryParseChain(encCertLocal, NULL, newChain);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_CERT_ERR_PARSE_MSG, BINLOG_ID15050, "parse cert chain err");
        }
#ifdef HITLS_TLS_PROTO_TLS13
        if (CheckCertSignature(ctx, cert) != HITLS_SUCCESS) {
            DestoryParseChain(encCertLocal, cert, newChain);
            return HITLS_CERT_CTRL_ERR_GET_SIGN_ALGO;
        }
#endif

#ifdef HITLS_TLS_PROTO_TLCP11
        if ((encCert != NULL) && (TlcpCheckEncCertKeyUsage(ctx, cert) == true)) {
            SAL_CERT_X509Free(encCertLocal);
            encCertLocal = cert;
            listNode = listNode->next;
            continue;
        }
#endif
        /* Add a certificate to the certificate chain. */
        if (SAL_CERT_ChainAppend(newChain, cert) != HITLS_SUCCESS) {
            DestoryParseChain(encCertLocal, cert, newChain);
            return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID15051, "ChainAppend fail");
        }
        listNode = listNode->next;
    }
    if (encCert != NULL) {
        *encCert = encCertLocal;
    }
    *chain = newChain;
    return HITLS_SUCCESS;
}

int32_t SAL_CERT_ParseCertChain(HITLS_Ctx *ctx, CERT_Item *item, CERT_Pair **certPair)
{
    if (ctx == NULL || item == NULL || certPair == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_NULL_INPUT, BINLOG_ID16327, "input null");
    }
    HITLS_CERT_X509 *encCert = NULL;
    HITLS_Config *config = &ctx->config.tlsConfig;
    if (config->certMgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_UNREGISTERED_CALLBACK, BINLOG_ID16328, "unregistered callback");
    }

    /* Parse the first device certificate. */
    HITLS_CERT_X509 *cert = SAL_CERT_X509Parse(LIBCTX_FROM_CONFIG(config),
        ATTRIBUTE_FROM_CONFIG(config), config, item->data, item->dataSize,
        TLS_PARSE_TYPE_BUFF, TLS_PARSE_FORMAT_ASN1);
    if (cert == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CERT_ERR_PARSE_MSG, BINLOG_ID15052, "X509Parse fail");
    }
#ifdef HITLS_TLS_PROTO_TLS13
    if (CheckCertSignature(ctx, cert) != HITLS_SUCCESS) {
        SAL_CERT_X509Free(cert);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CERT_CTRL_ERR_GET_SIGN_ALGO, BINLOG_ID16329, "check signature fail");
    }
#endif

#ifdef HITLS_TLS_PROTO_TLCP11
    if (!TlcpCheckSignCertKeyUsage(ctx, cert)) {
        SAL_CERT_X509Free(cert);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CERT_ERR_KEYUSAGE, BINLOG_ID15341, "check sign cert keyusage fail");
    }
#endif

    /* Parse other certificates in the certificate chain. */
    HITLS_CERT_Chain *chain = NULL;
    HITLS_CERT_X509 **inParseEnc = ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11 ? &encCert : NULL;
    int32_t ret = ParseChain(ctx, item->next, &chain, inParseEnc);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_X509Free(cert);
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16330, "ParseChain fail");
    }

    CERT_Pair *newCertPair = BSL_SAL_Calloc(1u, sizeof(CERT_Pair));
    if (newCertPair == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        SAL_CERT_X509Free(cert);
        SAL_CERT_X509Free(encCert);
        SAL_CERT_ChainFree(chain);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID15053, "Calloc fail");
    }
    newCertPair->cert = cert;
#ifdef HITLS_TLS_PROTO_TLCP11
    newCertPair->encCert = encCert;
#endif
    newCertPair->chain = chain;
    *certPair = newCertPair;
    return HITLS_SUCCESS;
}

int32_t SAL_CERT_VerifyCertChain(HITLS_Ctx *ctx, CERT_Pair *certPair, bool isTlcpEncCert)
{
    (void)isTlcpEncCert;
    if (ctx == NULL || certPair == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_NULL_INPUT, BINLOG_ID16331, "input null");
    }
    int32_t ret;
    uint32_t i = 0;
    HITLS_Config *config = &ctx->config.tlsConfig;
    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_UNREGISTERED_CALLBACK, BINLOG_ID16332, "mgrCtx null");
    }

    HITLS_CERT_Chain *chain = certPair->chain;
    /* Obtain the number of certificates. The first device certificate must also be included. */
    uint32_t certNum = (uint32_t)(BSL_LIST_COUNT(chain) + 1);

    HITLS_CERT_X509 **certList = (HITLS_CERT_X509 **)BSL_SAL_Calloc(1u, sizeof(HITLS_CERT_X509 *) * certNum);
    if (certList == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_MEMALLOC_FAIL);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_MEMALLOC_FAIL, BINLOG_ID15054, "Calloc fail");
    }
    certList[i++] =
#ifdef HITLS_TLS_PROTO_TLCP11
        isTlcpEncCert ? certPair->encCert :
#endif
        certPair->cert;
    HITLS_CERT_X509 *currCert = NULL;
    for (currCert = BSL_LIST_GET_FIRST(chain); currCert != NULL; currCert = BSL_LIST_GET_NEXT(chain)) {
        certList[i++] = currCert;
    }

    /* Verify the certificate chain. */
    HITLS_CERT_Store *store = (mgrCtx->verifyStore != NULL) ? mgrCtx->verifyStore : mgrCtx->certStore;
    if (store == NULL) {
        BSL_SAL_FREE(certList);
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_CERT_ERR_VERIFY_CERT_CHAIN, BINLOG_ID16333, "Calloc fail");
    }

    ret = SAL_CERT_VerifyChain(ctx, store, certList, i);
    BSL_SAL_FREE(certList);
    return ret;
}

uint32_t SAL_CERT_GetSignMaxLen(HITLS_Config *config, HITLS_CERT_Key *key)
{
    uint32_t len = 0;
    int32_t ret = SAL_CERT_KeyCtrl(config, key, CERT_KEY_CTRL_GET_SIGN_LEN, NULL, &len);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID15056, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get signature length error: callback ret = 0x%x.", ret, 0, 0, 0);
        return 0;
    }
    return len;
}

#ifdef HITLS_TLS_CONFIG_CERT_CALLBACK
int32_t HITLS_CFG_SetCheckPriKeyCb(HITLS_Config *config, CERT_CheckPrivateKeyCallBack checkPrivateKey)
{
    if (config == NULL || config->certMgrCtx == NULL || checkPrivateKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

#ifndef HITLS_TLS_FEATURE_PROVIDER
    config->certMgrCtx->method.checkPrivateKey = checkPrivateKey;
#endif
    return HITLS_SUCCESS;
}

CERT_CheckPrivateKeyCallBack HITLS_CFG_GetCheckPriKeyCb(HITLS_Config *config)
{
    if (config == NULL || config->certMgrCtx == NULL) {
        return NULL;
    }
#ifndef HITLS_TLS_FEATURE_PROVIDER
    return config->certMgrCtx->method.checkPrivateKey;
#else
    return NULL;
#endif
}
#endif /* HITLS_TLS_CONFIG_CERT_CALLBACK */

#ifdef HITLS_TLS_PROTO_TLCP11
static uint8_t *EncodeEncCert(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, uint32_t *useLen)
{
    if (ctx == NULL || cert == NULL || useLen == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16336, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return NULL;
    }
    uint32_t certLen;
    HITLS_Config *config = &ctx->config.tlsConfig;
    int32_t ret = SAL_CERT_X509Ctrl(config, cert, CERT_CTRL_GET_ENCODE_LEN, NULL, (void *)&certLen);
    if (ret != HITLS_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16157, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode gm enc certificate error: unable to get encode length.", 0, 0, 0, 0);
        return NULL;
    }

    uint8_t *data = BSL_SAL_Calloc(1u, certLen);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16158, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "signature data memory alloc fail.", 0, 0, 0, 0);
        return NULL;
    }

    ret = SAL_CERT_X509Encode(ctx, cert, data, certLen, useLen);
    if (ret != HITLS_SUCCESS) {
        BSL_SAL_FREE(data);
        BSL_ERR_PUSH_ERROR(HITLS_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16232, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "encode cert error: callback ret = 0x%x.", (uint32_t)ret, 0, 0, 0);
        return NULL;
    }
    return data;
}

uint8_t *SAL_CERT_SrvrGmEncodeEncCert(HITLS_Ctx *ctx, uint32_t *useLen)
{
    if (ctx == NULL || useLen == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16337, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return NULL;
    }
    int keyType = TLS_CERT_KEY_TYPE_SM2;

    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    CERT_Pair *currentCertPair =  NULL;
    int32_t ret = BSL_HASH_At(mgrCtx->certPairs, (uintptr_t)keyType, (uintptr_t *)&currentCertPair);
    if (ret != HITLS_SUCCESS || currentCertPair == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17337, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "encCert null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return NULL;
    }
    HITLS_CERT_X509 *cert = currentCertPair->encCert;

    return EncodeEncCert(ctx, cert, useLen);
}

uint8_t *SAL_CERT_ClntGmEncodeEncCert(HITLS_Ctx *ctx, CERT_Pair *peerCert, uint32_t *useLen)
{
    return EncodeEncCert(ctx, peerCert->encCert, useLen);
}

#endif

#if defined(HITLS_TLS_PROTO_TLCP11) || defined(HITLS_TLS_CONFIG_KEY_USAGE)
bool SAL_CERT_CheckCertKeyUsage(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, HITLS_CERT_CtrlCmd keyusage)
{
    if (ctx == NULL || cert == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16338, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "input null", 0, 0, 0, 0);
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    uint8_t isUsage = false;
    if (keyusage != CERT_KEY_CTRL_IS_KEYENC_USAGE && keyusage != CERT_KEY_CTRL_IS_DIGITAL_SIGN_USAGE &&
        keyusage != CERT_KEY_CTRL_IS_KEY_CERT_SIGN_USAGE && keyusage != CERT_KEY_CTRL_IS_KEY_AGREEMENT_USAGE &&
        keyusage != CERT_KEY_CTRL_IS_DATA_ENC_USAGE && keyusage != CERT_KEY_CTRL_IS_NON_REPUDIATION_USAGE) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16339, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "keyusage err", 0, 0, 0, 0);
        return (bool)isUsage;
    }
    HITLS_Config *config = &ctx->config.tlsConfig;
    int32_t ret = SAL_CERT_X509Ctrl(config, cert, keyusage, NULL, (void *)&isUsage);
    if (ret != HITLS_SUCCESS) {
        if (keyusage == CERT_KEY_CTRL_IS_KEYENC_USAGE || keyusage == CERT_KEY_CTRL_IS_DATA_ENC_USAGE ||
            keyusage == CERT_KEY_CTRL_IS_KEY_AGREEMENT_USAGE) {
            return false;
        }
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID16340, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN, "%d fail", keyusage, 0, 0, 0);
        return false;
    }

    return (bool)isUsage;
}
#endif