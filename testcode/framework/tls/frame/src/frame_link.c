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
#include "bsl_sal.h"
#include "uio_base.h"
#include "uio_abstraction.h"
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"
#include "hitls_error.h"
#include "hlt_type.h"
#include "cert_callback.h"
#include "frame_tls.h"
#include "frame_io.h"
#include "frame_link.h"
#include "rec_wrapper.h"

#define MAX_CERT_PATH_LENGTH (1024)

HITLS_Ctx *FRAME_CreateDefaultDtlsObj(void)
{
    HITLS_Config *config = HITLS_CFG_NewDTLS12Config();
    if (config == NULL) {
        return NULL;
    }

    char verifyPath[MAX_CERT_PATH_LENGTH] = {0};
    char chainPath[MAX_CERT_PATH_LENGTH] = {0};
    char certPath[MAX_CERT_PATH_LENGTH] = {0};
    char keyPath[MAX_CERT_PATH_LENGTH] = {0};
    if (sprintf_s(verifyPath, MAX_CERT_PATH_LENGTH, "%s:%s", RSA_SHA_CA_PATH, ECDSA_SHA_CA_PATH) <= 0) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }

    if (sprintf_s(chainPath, MAX_CERT_PATH_LENGTH, "%s:%s", RSA_SHA_CHAIN_PATH, ECDSA_SHA_CHAIN_PATH) <= 0) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }

    if (sprintf_s(certPath, MAX_CERT_PATH_LENGTH, "%s:%s", RSA_SHA256_EE_PATH3, ECDSA_SHA256_EE_PATH) <= 0) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }

    if (sprintf_s(keyPath, MAX_CERT_PATH_LENGTH, "%s:%s", RSA_SHA256_PRIV_PATH3, ECDSA_SHA256_PRIV_PATH) <= 0) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }

    int32_t ret = HiTLS_X509_LoadCertAndKey(config, verifyPath, chainPath, certPath, NULL, keyPath, NULL);
    if (ret != HITLS_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }

    HITLS_Ctx *ctx = HITLS_New(config);
    if (ctx == NULL) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }

    HITLS_CFG_FreeConfig(config);
    return ctx;
}

FRAME_LinkObj *CreateLink(HITLS_Config *config, BSL_UIO_TransportType type)
{
    BSL_UIO_Method method = {0};
    BSL_UIO *io = NULL;
    FrameUioUserData *ioUserdata = NULL;
    const BSL_UIO_Method *ori = NULL;
    switch (type) {
        case BSL_UIO_TCP:
#ifdef HITLS_BSL_UIO_TCP
            ori = BSL_UIO_TcpMethod();
#endif
            break;
        case BSL_UIO_UDP:
#ifdef HITLS_BSL_UIO_UDP
            ori = BSL_UIO_UdpMethod();
#endif
            break;
        default:
#ifdef HITLS_BSL_UIO_SCTP
            ori = BSL_UIO_SctpMethod();
#endif
            break;
    }
    if (memcpy_s(&method, sizeof(BSL_UIO_Method), ori, sizeof(method)) != EOK) {
        return NULL;
    }

    FRAME_LinkObj *linkObj = BSL_SAL_Calloc(1u, sizeof(FRAME_LinkObj));
    if (linkObj == NULL) {
        return NULL;
    }
    HITLS_CFG_SetReadAhead(config, 1);
#ifdef HITLS_TLS_FEATURE_FLIGHT
    HITLS_CFG_SetFlightTransmitSwitch(config, false);
#endif
    HITLS_Ctx *sslObj = HITLS_New(config);
    if (sslObj == NULL) {
        goto ERR;
    }
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP)
    if (type == BSL_UIO_UDP) {
        HITLS_SetMtu(sslObj, 16384);
    }
#endif
    INIT_IO_METHOD(method, type, FRAME_Write, FRAME_Read, FRAME_Ctrl);
    io = BSL_UIO_New(&method);
    if (io == NULL) {
        goto ERR;
    }

    ioUserdata = FRAME_IO_CreateUserData();
    if (ioUserdata == NULL) {
        goto ERR;
    }

    uint32_t ret = BSL_UIO_SetUserData(io, ioUserdata);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }

    int32_t fd = 666;
    // Set any fd as the value of the underlying transfer I/O
    ret = BSL_UIO_Ctrl(io, BSL_UIO_SET_FD, (int32_t)sizeof(fd), &fd);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }
    BSL_UIO_SetInit(io, true);
    // must return success
    ret = HITLS_SetUio(sslObj, io);
    if (ret != HITLS_SUCCESS) {
        goto ERR;
    }
    linkObj->io = io;
    linkObj->ssl = sslObj;

    // Register connection for late wrapper application
    // This enables RegisterWrapper to apply wrappers to connections
    // that were created before the wrapper was registered
    RegisterConnection(sslObj);

    return linkObj;
ERR:
    FRAME_IO_FreeUserData(ioUserdata);
    BSL_UIO_Free(io);
    HITLS_Free(sslObj);
    BSL_SAL_FREE(linkObj);
    return NULL;
}
#ifdef HITLS_TLS_PROTO_TLCP11
FRAME_LinkObj *FRAME_CreateTLCPLink(HITLS_Config *config, BSL_UIO_TransportType type, bool isClient)
{
#ifdef HITLS_TLS_CONFIG_KEY_USAGE
    HITLS_CFG_SetCheckKeyUsage(config, false);
#endif

#ifdef HITLS_TLS_FEATURE_SECURITY
    HITLS_CFG_SetSecurityLevel(config, HITLS_SECURITY_LEVEL_ZERO);
#endif /* HITLS_TLS_FEATURE_SECURITY */
    int32_t ret;
    if (isClient) {
        ret = HiTLS_X509_LoadCertAndKey(config, SM2_VERIFY_PATH, SM2_CHAIN_PATH, SM2_CLIENT_ENC_CERT_PATH,
                                     SM2_CLIENT_SIGN_CERT_PATH, SM2_CLIENT_ENC_KEY_PATH, SM2_CLIENT_SIGN_KEY_PATH);
    } else {
        ret = HiTLS_X509_LoadCertAndKey(config, SM2_VERIFY_PATH, SM2_CHAIN_PATH, SM2_SERVER_ENC_CERT_PATH,
                                     SM2_SERVER_SIGN_CERT_PATH, SM2_SERVER_ENC_KEY_PATH, SM2_SERVER_SIGN_KEY_PATH);
    }
    if (ret != HITLS_SUCCESS) {
        return NULL;
    }

    return CreateLink(config, type);
}
#endif /* HITLS_TLS_PROTO_TLCP11 */
//Set certificate and creating a connection
FRAME_LinkObj *FRAME_CreateLinkBase(HITLS_Config *config, BSL_UIO_TransportType type, bool setCertFlag)
{
    int32_t ret;
    if (setCertFlag) {
        char verifyPath[MAX_CERT_PATH_LENGTH] = {0};
        char chainPath[MAX_CERT_PATH_LENGTH] = {0};
        char certPath[MAX_CERT_PATH_LENGTH] = {0};
        char keyPath[MAX_CERT_PATH_LENGTH] = {0};
        sprintf_s(verifyPath, MAX_CERT_PATH_LENGTH, "%s:%s", ECDSA_SHA_CA_PATH, RSA_SHA_CA_PATH);
        sprintf_s(chainPath,
            MAX_CERT_PATH_LENGTH,
            "%s:%s",
            ECDSA_SHA_CHAIN_PATH,
            RSA_SHA_CHAIN_PATH);
        sprintf_s(
            certPath, MAX_CERT_PATH_LENGTH, "%s:%s", ECDSA_SHA256_EE_PATH, RSA_SHA256_EE_PATH3);
        sprintf_s(keyPath,
            MAX_CERT_PATH_LENGTH,
            "%s:%s",
            ECDSA_SHA256_PRIV_PATH,
            RSA_SHA256_PRIV_PATH3);
        ret = HiTLS_X509_LoadCertAndKey(config, verifyPath, chainPath, certPath, NULL, keyPath, NULL);
        if (ret != HITLS_SUCCESS) {
            return NULL;
        }
    }

    return CreateLink(config, type);
}

FRAME_LinkObj *FRAME_CreateLink(HITLS_Config *config, BSL_UIO_TransportType type)
{
#ifdef HITLS_TLS_CONFIG_KEY_USAGE
    HITLS_CFG_SetCheckKeyUsage(config, false);
#endif /* HITLS_TLS_CONFIG_KEY_USAGE */

#ifdef HITLS_TLS_FEATURE_SECURITY
    HITLS_CFG_SetSecurityLevel(config, HITLS_SECURITY_LEVEL_ZERO);
#endif /* HITLS_TLS_FEATURE_SECURITY */
    return FRAME_CreateLinkBase(config, type, true);
}

FRAME_LinkObj *FRAME_CreateLinkEx(HITLS_Config *config, BSL_UIO_TransportType type)
{
#ifdef HITLS_TLS_CONFIG_KEY_USAGE
    HITLS_CFG_SetCheckKeyUsage(config, false);
#endif /* HITLS_TLS_CONFIG_KEY_USAGE */

#ifdef HITLS_TLS_FEATURE_SECURITY
    HITLS_CFG_SetSecurityLevel(config, HITLS_SECURITY_LEVEL_ZERO);
#endif /* HITLS_TLS_FEATURE_SECURITY */
    return FRAME_CreateLinkBase(config, type, false);
}

FRAME_LinkObj *FRAME_CreateLinkWithCert(HITLS_Config *config, BSL_UIO_TransportType type, const FRAME_CertInfo* certInfo)
{
#ifdef HITLS_TLS_CONFIG_KEY_USAGE
    HITLS_CFG_SetCheckKeyUsage(config, false);
#endif /* HITLS_TLS_CONFIG_KEY_USAGE */

#ifdef HITLS_TLS_FEATURE_SECURITY
    if (config->securityLevel == HITLS_SECURITY_LEVEL_ONE) {
        HITLS_CFG_SetSecurityLevel(config, HITLS_SECURITY_LEVEL_ZERO);
    }
#endif /* HITLS_TLS_FEATURE_SECURITY */
    int32_t ret;
    ret = HiTLS_X509_LoadCertAndKey(config,
        certInfo->caFile,
        certInfo->chainFile,
        certInfo->endEquipmentFile,
        certInfo->signFile,
        certInfo->privKeyFile,
        certInfo->signPrivKeyFile);
    if (ret != HITLS_SUCCESS) {
        return NULL;
    }
    return CreateLink(config, type);
}

FRAME_LinkObj *FRAME_CreateLinkWithCerts(HITLS_Config *config, BSL_UIO_TransportType type, const FRAME_CertInfo* certInfo, size_t certInfoLen)
{
#ifdef HITLS_TLS_CONFIG_KEY_USAGE
    HITLS_CFG_SetCheckKeyUsage(config, false);
#endif /* HITLS_TLS_CONFIG_KEY_USAGE */

#ifdef HITLS_TLS_FEATURE_SECURITY
    if (config->securityLevel == HITLS_SECURITY_LEVEL_ONE) {
        HITLS_CFG_SetSecurityLevel(config, HITLS_SECURITY_LEVEL_ZERO);
    }
#endif /* HITLS_TLS_FEATURE_SECURITY */
    int32_t ret;
    for (size_t i = 0; i < certInfoLen; i++) {
        ret = HiTLS_X509_LoadCertAndKey(config,
        certInfo[i].caFile,
        certInfo[i].chainFile,
        certInfo[i].endEquipmentFile,
        certInfo[i].signFile,
        certInfo[i].privKeyFile,
        certInfo[i].signPrivKeyFile);
        if (ret != HITLS_SUCCESS) {
            return NULL;
        }
    }
    
    return CreateLink(config, type);
}

void FRAME_FreeLink(FRAME_LinkObj *linkObj)
{
    if (linkObj == NULL) {
        return;
    }

    // Unregister connection from global tracking before freeing
    if (linkObj->ssl != NULL) {
        UnregisterConnection(linkObj->ssl);
        RemoveWrapperFromConnection(linkObj->ssl);
    }

    FRAME_IO_FreeUserData(BSL_UIO_GetUserData(linkObj->io));
    // BSL_UIO_Free is automatically invoked twice in HITLS_Free
#ifdef HITLS_TLS_FEATURE_FLIGHT
    if (linkObj->io != NULL && linkObj->io->references.count >= 2) {
        while (linkObj->io->references.count > 2) {
            BSL_UIO_Free(linkObj->io);
        }
    } else {
#endif
        BSL_UIO_Free(linkObj->io);
#ifdef HITLS_TLS_FEATURE_FLIGHT
    }
#endif
    HITLS_Free(linkObj->ssl);
    BSL_SAL_FREE(linkObj);
    return;
}

HITLS_Ctx *FRAME_GetTlsCtx(const FRAME_LinkObj *linkObj)
{
    if (linkObj == NULL) {
        return NULL;
    }
    return linkObj->ssl;
}
