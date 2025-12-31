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

#include "bsl_err_internal.h"
#include "bsl_hash.h"

#include "tls_binlog_id.h"
#include "tls_config.h"
#include "hitls_error.h"
#include "cipher_suite.h"
#include "config_type.h"
#include "cert_method.h"
#include "cert.h"
#include "security.h"

#include "hs_cert.h"

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
            return CERT_TYPE_UNKNOWN;
    }
}

static int32_t CheckCertType(CERT_Type expectCertType, HITLS_CERT_KeyType checkedKeyType)
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
        // Check algorithm in allow list, protocol version and security policy restrictions
        if (!SAL_CERT_IsSignAlgorithmAllowed(ctx, baseSignAlgorithms[i],
            selectSignAlgorithms, selectSignAlgorithmsSize)) {
            continue;
        }
        if (info->keyType == TLS_CERT_KEY_TYPE_RSA_PSS) {
            HITLS_HashAlgo hashAlgId = HITLS_HASH_BUTT;
            (void)SAL_CERT_KeyCtrl(&ctx->config.tlsConfig, pubkey, CERT_KEY_CTRL_GET_PSS_MD, NULL, (void *)&hashAlgId);

            if (hashAlgId != HITLS_HASH_BUTT && (int32_t)hashAlgId != info->hashAlgId) {
                continue;
            }
        }
        if (!isNegotiateSignAlgo) {
            /* Only the signature algorithm in the certificate is checked.
               The signature algorithm in the handshake message is not negotiated. */
            return HITLS_SUCCESS;
        }

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

static int32_t CheckCurveName(HITLS_Config *config, const uint16_t *curveList, uint32_t curveNum,
    HITLS_CERT_Key *pubkey)
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

static int32_t CheckPointFormat(HITLS_Config *config, const uint8_t *ecPointFormatList, uint32_t listSize,
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

static int32_t IsEcParamCompatible(HITLS_Config *config, const CERT_ExpectInfo *info, HITLS_CERT_Key *pubkey)
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
    /* Check the certificate type. */
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
        TLS_CERT_KEY_TYPE_SM2 does not check the curve ID and point format.
        TLCP curves is sm2 and is not compressed. */
    if (keyType == TLS_CERT_KEY_TYPE_ECDSA && ctx->negotiatedInfo.version != HITLS_VERSION_TLS13) {
        ret = IsEcParamCompatible(config, expectCertInfo, pubkey);
    }

    return ret;
}

int32_t HS_CheckCertInfo(HITLS_Ctx *ctx, const CERT_ExpectInfo *expectCertInfo, HITLS_CERT_X509 *cert,
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
        ret = SAL_CERT_CheckKeySecbits(ctx, cert, pubkey);
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

        ret = HS_CheckCertInfo(ctx, info, cert, true, true);
        if (ret != HITLS_SUCCESS) {
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16308, "CheckCertInfo fail");
        }

        ret = HS_CheckCertInfo(ctx, info, encCert, true, false);
        if (ret != HITLS_SUCCESS) {
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16309, "CheckCertInfo fail");
        }
    } else {
        /* Check whether the certificate is missing when the client sends the certificate
           or sends it to the server for processing. Check whether the authentication-related signature certificate
           or derived encryption certificate exists when the client uses the certificate. */
        if (cert != NULL) {
            ret = HS_CheckCertInfo(ctx, info, cert, true, true);
            if (ret != HITLS_SUCCESS) {
                return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16310, "CheckCertInfo fail");
            }
        }
        if (encCert != NULL) {
            ret = HS_CheckCertInfo(ctx, info, encCert, true, false);
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

    bool supportServer = ctx->config.tlsConfig.isSupportServerPreference;
    uint32_t baseSignAlgorithmsSize = supportServer ? ctx->config.tlsConfig.signAlgorithmsSize : info->signSchemeNum;
    const uint16_t *baseSignAlgorithms = supportServer ? ctx->config.tlsConfig.signAlgorithms : info->signSchemeList;
    for (uint32_t i = 0; i < baseSignAlgorithmsSize; i++) {
        const TLS_SigSchemeInfo *signInfo = ConfigGetSignatureSchemeInfo(&ctx->config.tlsConfig, baseSignAlgorithms[i]);
        if (signInfo == NULL || CheckCertType(info->certType, signInfo->keyType) != HITLS_SUCCESS) {
            continue;
        }
        CERT_Pair *certPair =  NULL;
        ret = BSL_HASH_At(mgrCtx->certPairs, (uintptr_t)signInfo->keyType, (uintptr_t *)&certPair);
        if (ret != HITLS_SUCCESS || certPair == NULL || certPair->cert == NULL || certPair->privateKey == NULL) {
            continue;
        }
        ret = HS_CheckCertInfo(ctx, info, certPair->cert, true, true);
        if (ret != HITLS_SUCCESS) {
            continue;
        }
        mgrCtx->currentCertKeyType = signInfo->keyType;
        return HITLS_SUCCESS;
    }

    BSL_HASH_Hash *certPairs = mgrCtx->certPairs;
    BSL_HASH_Iterator it = BSL_HASH_IterBegin(certPairs);
    while (it != BSL_HASH_IterEnd(certPairs)) {
        uint32_t keyType = (uint32_t)BSL_HASH_HashIterKey(certPairs, it);
        uintptr_t ptr = BSL_HASH_IterValue(certPairs, it);
        CERT_Pair *certPair = (CERT_Pair *)ptr;
        if (certPair == NULL || certPair->cert == NULL || certPair->privateKey == NULL ||
            CheckCertType(info->certType, keyType) != HITLS_SUCCESS) {
            it = BSL_HASH_IterNext(certPairs, it);
            continue;
        }
        ret = HS_CheckCertInfo(ctx, info, certPair->cert, true, true);
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

int32_t HS_SelectCertByInfo(HITLS_Ctx *ctx, CERT_ExpectInfo *info)
{
    int32_t ret = HITLS_SUCCESS;
    CERT_MgrCtx *mgrCtx = ctx->config.tlsConfig.certMgrCtx;
    if (mgrCtx == NULL) {
        return RETURN_ERROR_NUMBER_PROCESS(HITLS_UNREGISTERED_CALLBACK, BINLOG_ID16313, "unregistered callback");
    }
#ifdef HITLS_TLS_PROTO_TLCP11
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11) {
        ret = TlcpSelectCertByInfo(ctx, info);
    } else
#endif
    {
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
