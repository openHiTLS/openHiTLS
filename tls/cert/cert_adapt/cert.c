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
int32_t SAL_CERT_CheckKeySecbits(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, HITLS_CERT_Key *key)
{
    int32_t secBits = 0;
    HITLS_Config *config = &ctx->config.tlsConfig;

    int32_t ret = SAL_CERT_KeyCtrl(config, key, CERT_KEY_CTRL_GET_SECBITS, NULL, (void *)&secBits);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16303, "GET_SECBITS fail");
    }
    ret = SECURITY_CfgCheck(config, HITLS_SECURITY_SECOP_EE_KEY, secBits, 0, cert);
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

bool SAL_CERT_IsSignAlgorithmAllowed(const TLS_Ctx *ctx, uint16_t signScheme,
    const uint16_t *allowList, uint32_t allowListSize)
{
    (void)ctx;
    if (allowList != NULL) {
        bool found = false;
        for (uint32_t i = 0; i < allowListSize; i++) {
            if (allowList[i] == signScheme) {
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }

#ifdef HITLS_TLS_FEATURE_SECURITY
    if (SECURITY_SslCheck(ctx, HITLS_SECURITY_SECOP_SIGALG_CHECK, 0, signScheme, NULL) != SECURITY_SUCCESS) {
        return false;
    }
#endif

#ifdef HITLS_TLS_PROTO_TLS13
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLS13) {
        const uint32_t rsaPkcsv15Mask = 0x01;
        const uint32_t dsaMask = 0x02;
        const uint32_t sha1Mask = 0x0200;
        const uint32_t sha224Mask = 0x0300;

        // These algorithms are not defined for use in signed TLS handshake messages in TLS 1.3
        if (((signScheme & 0xff) == rsaPkcsv15Mask) ||
            ((signScheme & 0xff) == dsaMask) ||
            ((signScheme & 0xff00) == sha1Mask) ||
            ((signScheme & 0xff00) == sha224Mask)) {
            return false;
        }
    }
#endif

#ifdef HITLS_TLS_FEATURE_SM_TLS13
    if (IS_SM_TLS13(ctx->negotiatedInfo.cipherSuiteInfo.cipherSuite)) {
        if (signScheme != CERT_SIG_SCHEME_SM2_SM3) {
            return false;
        }
    }
#endif

    return true;
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
    /* Reserve at least 3 bytes length + data length. */
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

        /* Valid extensions for server certificates at present include the OCSP Status extension [RFC6066]
        and the SignedCertificateTimestamp extension [RFC6962] */
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
    ret = SAL_CERT_CheckKeySecbits(ctx, tmpCert, key);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16317, "check key fail");
    }
    ret = CheckCertChainFromStore(&ctx->config.tlsConfig, tmpCert);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID15111, "check ee cert fail");
    }
#endif

    /* Write the first device certificate. */
    ret = EncodeCertificate(ctx, tmpCert, pkt, 0);
    if (ret != HITLS_SUCCESS) {
        return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID16153, "encode fail");
    }
#ifdef HITLS_TLS_PROTO_TLCP11
    /* If the TLCP algorithm is used and the encryption certificate is required,
       write the second encryption certificate. */
    HITLS_CERT_X509 *certEnc = currentCertPair->encCert;
    if (ctx->negotiatedInfo.version == HITLS_VERSION_TLCP_DTLCP11 && certEnc != NULL) {
#ifdef HITLS_TLS_FEATURE_SECURITY
        HITLS_CERT_Key *keyEnc = currentCertPair->encPrivateKey;
        ret = SAL_CERT_CheckKeySecbits(ctx, certEnc, keyEnc);
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
#ifdef HITLS_TLS_FEATURE_SECURITY
        ret = CheckCertChainFromStore(config, tempCert);
        if (ret != HITLS_SUCCESS) {
            return RETURN_ERROR_NUMBER_PROCESS(ret, BINLOG_ID15115, "check chain cert fail");
        }
#endif
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