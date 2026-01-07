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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include "securec.h"

#include "logger.h"
#include "process.h"
#include "handle_cmd.h"
#include "hlt.h"
#include "tls_res.h"
#include "common_func.h"
#include "hitls_func.h"
#include "sctp_channel.h"
#include "tcp_channel.h"
#include "udp_channel.h"
#include "socket_common.h"
#include "cert_callback.h"
#include "sctp_channel.h"
#include "frame_tls.h"
#include "rec_wrapper.h"

#define DOMAIN_PATH_LEN (128)
#define CMD_MAX_LEN 1024
#define SUCCESS 0
#define ERROR (-1)

int g_acceptFd;

void* HLT_TlsNewCtx(TLS_VERSION tlsVersion)
{
    int ret;
    void *ctx = NULL;
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS:
            ctx = HitlsNewCtx(tlsVersion);
            break;
        default:
            ctx = NULL;
    }
    if ((process->remoteFlag == 0) && (ctx != NULL)) {
        // If the value is LocalProcess, insert it to the CTX linked list.
        ret =  InsertCtxToList(ctx);
        if (ret == ERROR) {
            LOG_ERROR("InsertCtxToList ERROR");
            return NULL;
        }
    }
    return ctx;
}

#ifdef HITLS_TLS_FEATURE_PROVIDER
void* HLT_TlsProviderNewCtx(char *providerPath, char (*providerNames)[MAX_PROVIDER_NAME_LEN], int *providerLibFmts,
    int providerCnt, char *attrName, TLS_VERSION tlsVersion)
{
    int ret;
    void *ctx = NULL;
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS:
            ctx = HitlsProviderNewCtx(providerPath, providerNames, providerLibFmts, providerCnt,
                attrName, tlsVersion);
            break;
        default:
            ctx = NULL;
    }
    if ((process->remoteFlag == 0) && (ctx != NULL)) {
        // If the value is LocalProcess, insert it to the CTX linked list.
        ret =  InsertCtxToList(ctx);
        if (ret == ERROR) {
            LOG_ERROR("InsertCtxToList ERROR");
            return NULL;
        }
    }
    return ctx;
}
#endif
void* HLT_TlsNewSsl(void *ctx)
{
    int ret;
    void *ssl = NULL;
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS:
            LOG_DEBUG("Hitls New Ssl");
            ssl = HitlsNewSsl(ctx);
            break;
        default:
            ssl = NULL;
    }
    if ((process->remoteFlag == 0) && (ssl != NULL)) {
        // If the value is LocalProcess, insert it to the SSL linked list.
        ret = InsertSslToList(ctx, ssl);
        if (ret == ERROR) {
            LOG_ERROR("InsertSslToList ERROR");
            return NULL;
        }
    }
    return ssl;
}

int HLT_TlsSetCtx(void *ctx, HLT_Ctx_Config *ctxConfig)
{
    int ret;
    Process *process = GetProcess();
    switch (process->tlsType) {
        case HITLS:
            LOG_DEBUG("HiTLS Set Ctx's Config");
            ret = HitlsSetCtx(ctx, ctxConfig);
            break;
        default:
            ret = ERROR;
    }
    return ret;
}

int HLT_TlsSetSsl(void *ssl, HLT_Ssl_Config *sslConfig)
{
    int ret = ERROR;
    Process *process = GetProcess();
    switch (process->tlsType) {
        case HITLS:
            LOG_DEBUG("HiTLS Set Ssl's Config");
            ret = HitlsSetSsl(ssl, sslConfig);
            break;
        default:
            LOG_DEBUG("Unknown tls type");
            break;
    }
    return ret;
}

// listen non-blocking interface
pthread_t HLT_TlsListen(void *ssl)
{
    (void)ssl;
    Process *process = GetProcess();
    switch (process->tlsType) {
        case HITLS : {
            return 0; // Hitls does not support the listen function.
        }
        default:
            return 0;
    }
}

// listen blocking interface
int HLT_TlsListenBlock(void* ssl)
{
    (void)ssl;
    Process *process = GetProcess();
    switch (process->tlsType) {
        case HITLS : return ERROR; // Hitls does not support the listen function.
        default:
            return ERROR;
    }
}

// Non-blocking interface
pthread_t HLT_TlsAccept(void *ssl)
{
    (void)ssl;
    int ret;
    Process *process = GetProcess();
    pthread_t t_id;
    switch (process->tlsType) {
        case HITLS :
            ret = pthread_create(&t_id, NULL, (void*)HitlsAccept, (void*)ssl);
            break;
        default:
            return 0;
    }

    if (ret != 0) {
        return 0;
    }
    return t_id;
}

int HLT_TlsAcceptBlock(void *ssl)
{
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS:
            return *(int *)HitlsAccept(ssl);
        default:
            return ERROR;
    }
}

int HLT_GetTlsAcceptResultFromId(pthread_t threadId)
{
    pthread_join(threadId, NULL);
    return SUCCESS;
}

int HLT_GetTlsAcceptResult(HLT_Tls_Res* tlsRes)
{
    static int ret;
    if (tlsRes->acceptId == 0) {
        LOG_ERROR("This Res Has Not acceptId");
        return ERROR;
    }
    if (tlsRes->ctx == NULL) {
        // Indicates that the remote process accepts the request.
        // acceptId stores RPC command ID (int) cast to pthread_t, cast it back
        ret = HLT_RpcGetTlsAcceptResult((int)(uintptr_t)tlsRes->acceptId);
    } else {
        // Indicates that the local process accepts the request.
        int *tmp = NULL;
        pthread_join(tlsRes->acceptId, (void**)&tmp);
        if (tmp == NULL) {
            return ERROR;
        }
        ret = *tmp;
        tlsRes->acceptId = 0;
        return ret;
    }
    tlsRes->acceptId = 0;
    return ret;
}

int HLT_TlsConnect(void *ssl)
{
    Process *process;
    process = GetProcess();

    // For local connections, register connection for wrapper tracking
    if (process->remoteFlag == 0) {
        RegisterConnection((TLS_Ctx *)ssl);

        // If wrapper already enabled, apply it now
        if (IsWrapperEnabled()) {
            ApplyWrapperToConnectionEarly((TLS_Ctx *)ssl);
        }
    }

    switch (process->tlsType) {
        case HITLS:
            return HitlsConnect(ssl);
        default:
            return ERROR;
    }
}

int HLT_TlsWrite(void *ssl, uint8_t *data, uint32_t dataLen)
{
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS : {
            LOG_DEBUG("Hitls Write Ing...");
            return HitlsWrite(ssl, data, dataLen);
        }
        default:
            return ERROR;
    }
}

int HLT_TLSWriteExportMaterial(void* ssl, ExportMaterialParam *param)
{
    int ret = 0;
    Process *process = GetProcess();
    uint32_t dataLen = param->outLen;
    uint8_t *data = calloc(dataLen, 1);
    if (data == NULL) {
        return ERROR;
    }
    uint8_t nullData[MAX_EXPORT_MATERIAL_BUF] = {0};
    const char *label = param->label;
    if (memcmp(label, nullData, MAX_EXPORT_MATERIAL_BUF) == 0) {
        label = NULL;
    }
    size_t labelLen = param->labelLen;
    const uint8_t *context = (const uint8_t *)param->context;
    if (memcmp(context, nullData, MAX_EXPORT_MATERIAL_BUF) == 0) {
        context = NULL;
    }
    size_t contextLen = param->contextLen;
    int32_t useContext = param->useContext;
    switch (process->tlsType) {
        case HITLS : {
#ifdef HITLS_TLS_FEATURE_EXPORT_KEY_MATERIAL
            ret = HITLS_ExportKeyingMaterial(ssl, data, dataLen, label, labelLen, context, contextLen, useContext);
            if (ret != 0) {
                free(data);
                return ret;
            }
            LOG_DEBUG("Hitls Write Ing...");
            ret = HitlsWrite(ssl, data, dataLen);
            free(data);
            return ret;
#else
            (void)useContext;
            (void)contextLen;
            (void)labelLen;
            (void)ret;
            (void)ssl;
            free(data);
            return -1;
#endif
        }
        default:
            free(data);
            return ERROR;
    }
}

int HLT_TlsRead(void *ssl, uint8_t *data, uint32_t bufSize, uint32_t *readLen)
{
    Process *process;
    process = GetProcess();

    switch (process->tlsType) {
        case HITLS: {
            LOG_DEBUG("Hitls Read Ing...");
            return HitlsRead(ssl, data, bufSize, readLen);
        }
        default:
            return ERROR;
    }
}

int HLT_TlsRenegotiate(void *ssl)
{
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS:
            return HitlsRenegotiate(ssl);
        default:
            return ERROR;
    }
}

int HLT_TlsVerifyClientPostHandshake(void *ssl)
{
#ifdef HITLS_TLS_FEATURE_PHA
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS: return HITLS_VerifyClientPostHandshake(ssl);
        default:
            return ERROR;
    }
#else
    (void)ssl;
#endif
    return ERROR;
}

int HLT_TlsClose(void *ssl)
{
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS: return HitlsClose(ssl);
        default:
            return ERROR;
    }
}

int HLT_TlsSetSession(void *ssl, void *session)
{
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS: return (HitlsSetSession(ssl, session) == 0) ? 1 : 0;
        default:
            return ERROR;
    }
}

int HLT_TlsSessionReused(void *ssl)
{
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS:
            return HitlsSessionReused(ssl);
        default:
            return ERROR;
    }
}

void *HLT_TlsGet1Session(void *ssl)
{
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS:
            return HitlsGet1Session(ssl);
        default:
            return NULL;
    }
}

int32_t HLT_SetSessionCacheMode(HLT_Ctx_Config* config, HITLS_SESS_CACHE_MODE mode)
{
    config->setSessionCache = mode;
    return SUCCESS;
}

int32_t HLT_SetSessionTicketSupport(HLT_Ctx_Config* config, bool issupport)
{
    config->isSupportSessionTicket = issupport;
    return SUCCESS;
}

int HLT_TlsSessionHasTicket(void *session)
{
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS:
            return HitlsSessionHasTicket(session);
        default:
            return ERROR;
    }
}

int HLT_TlsSessionIsResumable(void *session)
{
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS:
            return HitlsSessionIsResumable(session);
        default:
            return ERROR;
    }
}

void HLT_TlsFreeSession(void *session)
{
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS:
            HitlsFreeSession(session);
            break;
		default:
		    break;
	}
}

int RunDataChannelBind(void *param)
{
    int sockFd  = -1;
    LOG_DEBUG("RunDataChannelBind Ing...\n");
    DataChannelParam *channelParam = (DataChannelParam*)param;
    switch (channelParam->type) {
#ifdef HITLS_BSL_UIO_TCP
        case TCP: sockFd = TcpBind(channelParam->port); break;
#endif
#ifdef HITLS_BSL_UIO_UDP
        case UDP: sockFd = UdpBind(channelParam->port); break;
#endif
        default:
            return ERROR;
    }
    struct sockaddr_in add;
    socklen_t len = sizeof(add);
    getsockname(sockFd, (struct sockaddr *)&add, &len);
    channelParam->port = ntohs(add.sin_port);
    channelParam->bindFd = sockFd;
    g_acceptFd = sockFd;
    return sockFd;
}

int RunDataChannelAccept(void *param)
{
    int sockFd = -1;
    LOG_DEBUG("RunDataChannelAccept Ing...\n");
    DataChannelParam *channelParam = (DataChannelParam *)param;
    switch (channelParam->type) {
#ifdef HITLS_BSL_UIO_TCP
        case TCP:
            sockFd = TcpAccept(channelParam->ip, channelParam->bindFd, channelParam->isBlock, true);
            break;
#endif
#ifdef HITLS_BSL_UIO_UDP
        case UDP:
            sockFd = UdpAccept(channelParam->bindFd, (struct sockaddr *)&channelParam->sockAddr);
#endif
            break;
        default:
            return ERROR;
    }
    g_acceptFd = sockFd;
    return sockFd;
}

pthread_t HLT_DataChannelAccept(DataChannelParam *channelParam)
{
    pthread_t t_id;
    if (pthread_create(&t_id, NULL, (void*)RunDataChannelAccept, (void*)channelParam) != 0) {
        LOG_ERROR("Create Thread HLT_RpcDataChannelAccept Error ...");
        return 0;
    }
    return t_id;
}

int HLT_DataChannelBind(DataChannelParam *channelParam)
{
    return RunDataChannelBind(channelParam);
}


int HLT_DataChannelConnect(DataChannelParam *dstChannelParam)
{
    switch (dstChannelParam->type) {
#ifdef HITLS_BSL_UIO_TCP
        case TCP: return TcpConnect(dstChannelParam->ip, dstChannelParam->port);
#endif
#ifdef HITLS_BSL_UIO_UDP
        case UDP: return UdpConnect(dstChannelParam->ip, dstChannelParam->port);
#endif
        default:
            return ERROR;
    }
    return ERROR;
}

int HLT_GetAcceptFd(pthread_t threadId)
{
    pthread_join(threadId, NULL);
    return g_acceptFd;
}

HLT_FD HLT_CreateDataChannel(HLT_Process *process1, HLT_Process *process2, DataChannelParam channelParam)
{
    int acceptId;
    int bindFd;
    pthread_t pthreadId;
    HLT_FD sockFd;
    char *userPort = getenv("FIXED_PORT");
    if (userPort == NULL) {
        channelParam.port = 0; // The system randomly allocates available ports.
    }

    if (process2->remoteFlag == 1) {
        bindFd = HLT_RpcDataChannelBind(process2, &channelParam);
    } else {
        bindFd = HLT_DataChannelBind(&channelParam);
    }
    channelParam.bindFd = bindFd;
    // Start Accept again.
    if (process2->remoteFlag == 1) {
        acceptId = HLT_RpcDataChannelAccept(process2, &channelParam);
    } else {
        pthreadId = HLT_DataChannelAccept(&channelParam);
    }

    // In Connect
    if (process1->remoteFlag == 1) {
        sockFd.srcFd = HLT_RpcDataChannelConnect(process1, &channelParam);
    } else {
        sockFd.srcFd = HLT_DataChannelConnect(&channelParam);
    }

    if (process2->remoteFlag == 1) {
        if (sockFd.srcFd > 0) {
            // Indicates that the CONNECT is successful.
            sockFd.peerFd = HLT_RpcGetAcceptFd(acceptId);
        } else {
            sockFd.peerFd = -1;
        }
    } else {
        if (sockFd.srcFd > 0) {
            // Indicates that the CONNECT is successful.
            sockFd.peerFd = HLT_GetAcceptFd(pthreadId);
            sockFd.sockAddr = channelParam.sockAddr;
            sockFd.connPort = channelParam.port;
        } else {
            // If the SCTP link fails to be established, delete the thread to avoid congestion.
            pthread_cancel(pthreadId);
            pthread_join(pthreadId, NULL);
        }
    }

    return sockFd;
}

void HLT_CloseFd(int fd, int linkType)
{
    switch (linkType) {
#ifdef HITLS_BSL_UIO_TCP
        case TCP: TcpClose(fd); break;
#endif
#ifdef HITLS_BSL_UIO_UDP
        case UDP: UdpClose(fd); break;
#endif
        default:
            /* Unknown fd type */
            break;
    }
}

HLT_Ctx_Config* HLT_NewCtxConfigTLCP(char *setFile, const char *key, bool isClient)
{
    (void)setFile;
    Process *localProcess;

    HLT_Ctx_Config *ctxConfig = (HLT_Ctx_Config*)calloc(1u, sizeof(HLT_Ctx_Config));
    if (ctxConfig == NULL) {
        return NULL;
    }
    ctxConfig->isSupportRenegotiation = false;
    ctxConfig->allowClientRenegotiate = false;
    ctxConfig->allowLegacyRenegotiate = false;
    ctxConfig->isSupportClientVerify = false;
    ctxConfig->isSupportNoClientCert = false;
    ctxConfig->isSupportExtendedMasterSecret = false;
    ctxConfig->isClient = isClient;
    ctxConfig->setSessionCache = HITLS_SESS_CACHE_SERVER;
    HLT_SetGroups(ctxConfig, "NULL");
    HLT_SetCipherSuites(ctxConfig, "NULL");
    HLT_SetTls13CipherSuites(ctxConfig, "NULL");
    HLT_SetSignature(ctxConfig, "NULL");
    HLT_SetEcPointFormats(ctxConfig, "NULL");
    HLT_SetPassword(ctxConfig, "NULL");
    HLT_SetPsk(ctxConfig, "NULL");
    HLT_SetTicketKeyCb(ctxConfig, "NULL");

    if (strncmp("SERVER", key, strlen(key)) == 0) {
        HLT_SetCertPath(ctxConfig, SM2_VERIFY_PATH, SM2_CHAIN_PATH, SM2_SERVER_ENC_CERT_PATH, SM2_SERVER_ENC_KEY_PATH,
                        SM2_SERVER_SIGN_CERT_PATH, SM2_SERVER_SIGN_KEY_PATH);
    } else if (strncmp("CLIENT", key, strlen(key)) == 0) {
        HLT_SetCertPath(ctxConfig, SM2_VERIFY_PATH, SM2_CHAIN_PATH, SM2_CLIENT_ENC_CERT_PATH, SM2_CLIENT_ENC_KEY_PATH,
                        SM2_CLIENT_SIGN_CERT_PATH, SM2_CLIENT_SIGN_KEY_PATH);
    } else {
        free(ctxConfig);
        ctxConfig = NULL;
        return NULL;
    }
    // Store CTX configuration resources and release them later.
    localProcess = GetProcess();
    localProcess->tlsResArray[localProcess->tlsResNum] = ctxConfig;
    localProcess->tlsResNum++;
    return ctxConfig;
}

HLT_Ctx_Config* HLT_NewCtxConfig(char *setFile, const char *key)
{
    (void)setFile;
    HLT_Ctx_Config *ctxConfig;
    Process *localProcess;

    ctxConfig = (HLT_Ctx_Config*)malloc(sizeof(HLT_Ctx_Config));
    if (ctxConfig == NULL) {
        return NULL;
    }

    (void)memset_s(ctxConfig, sizeof(HLT_Ctx_Config), 0, sizeof(HLT_Ctx_Config));
    ctxConfig->needCheckKeyUsage = false;
    ctxConfig->isSupportRenegotiation = false;
    ctxConfig->allowClientRenegotiate = false;
    ctxConfig->allowLegacyRenegotiate = false;
    ctxConfig->isSupportClientVerify = false;
    ctxConfig->isSupportNoClientCert = false;
    ctxConfig->isSupportVerifyNone = false;
    ctxConfig->isSupportPostHandshakeAuth = false;
    ctxConfig->isSupportExtendedMasterSecret = true;
    ctxConfig->isSupportSessionTicket = false;
    ctxConfig->isSupportDhAuto = true;
	ctxConfig->isEncryptThenMac = true;
    ctxConfig->isMiddleBoxCompat = true;
    ctxConfig->keyExchMode = TLS13_KE_MODE_PSK_WITH_DHE;
    ctxConfig->setSessionCache = HITLS_SESS_CACHE_SERVER;
    ctxConfig->mtu = 0;
    ctxConfig->infoCb = NULL;
	ctxConfig->securitylevel = HITLS_SECURITY_LEVEL_ZERO;
	ctxConfig->SupportType = 0;
    ctxConfig->readAhead = 1;
    ctxConfig->emptyRecordsNum = 32;
    HLT_SetGroups(ctxConfig, "NULL");
    HLT_SetCipherSuites(ctxConfig, "NULL");
    HLT_SetTls13CipherSuites(ctxConfig, "NULL");
    HLT_SetSignature(ctxConfig, "NULL");
    HLT_SetEcPointFormats(ctxConfig, "HITLS_POINT_FORMAT_UNCOMPRESSED");
    HLT_SetPassword(ctxConfig, "NULL");
    HLT_SetPsk(ctxConfig, "NULL");
    HLT_SetTicketKeyCb(ctxConfig, "NULL");
    HLT_SetServerName(ctxConfig, "NULL");
    HLT_SetServerNameCb(ctxConfig, "NULL");
    HLT_SetServerNameArg(ctxConfig, "NULL");
    HLT_SetAlpnProtos(ctxConfig, "NULL");
    HLT_SetAlpnProtosSelectCb(ctxConfig, "NULL", "NULL");

    if (strncmp("SERVER", key, strlen(key)) == 0) {
        HLT_SetCertPath(ctxConfig, ECDSA_SHA256_CA_PATH,
            ECDSA_SHA256_CHAIN_PATH, ECDSA_SHA256_EE_PATH1, ECDSA_SHA256_PRIV_PATH1, "NULL", "NULL");
    } else if (strncmp("CLIENT", key, strlen(key)) == 0) {
        HLT_SetCertPath(ctxConfig, ECDSA_SHA256_CA_PATH,
            ECDSA_SHA256_CHAIN_PATH, ECDSA_SHA256_EE_PATH2, ECDSA_SHA256_PRIV_PATH2, "NULL", "NULL");
    } else {
        free(ctxConfig);
        ctxConfig = NULL;
        return NULL;
    }
    // Store CTX configuration resources and release them later.
    localProcess = GetProcess();
    localProcess->tlsResArray[localProcess->tlsResNum] = ctxConfig;
    localProcess->tlsResNum++;
    return ctxConfig;
}

HLT_Ssl_Config *HLT_NewSslConfig(char *setFile)
{
    (void)setFile;
    HLT_Ssl_Config *sslConfig;
    Process *localProcess;

    sslConfig = (HLT_Ssl_Config*)malloc(sizeof(HLT_Ssl_Config));
    if (sslConfig == NULL) {
        return NULL;
    }

    (void)memset_s(sslConfig, sizeof(HLT_Ssl_Config), 0, sizeof(HLT_Ssl_Config));

    // Store SSL configuration resources and release them later.
    localProcess = GetProcess();
    localProcess->tlsResArray[localProcess->tlsResNum] = sslConfig;
    localProcess->tlsResNum++;
    return sslConfig;
}

int HLT_LibraryInit(TLS_TYPE tlsType)
{
    switch (tlsType) {
        case HITLS: return HitlsInit(); break;
        default:
            /* Unknown type */
            break;
    }
    return ERROR;
}

int HLT_TlsRegCallback(TlsCallbackType type)
{
    switch (type) {
        case HITLS_CALLBACK_DEFAULT:
		    FRAME_Init();
            break;
        default:
            return SUCCESS;
    }
    return SUCCESS;
}

void HLT_FreeAllProcess(void)
{
    int ret;
    HLT_Tls_Res* tlsRes;
    Process *remoteProcess;
    Process *localProcess = GetProcess();

    if (localProcess == NULL) {
        return;
    }

    if (localProcess->remoteFlag != 0) {
        LOG_ERROR("Only Local Process Can Call HLT_FreeAllProcess");
        return;
    }

    // Clearing HLT_Tls_Res and Threads
    for (int i = 0; i < localProcess->hltTlsResNum; i++) {
        tlsRes = localProcess->hltTlsResArray[i];
        alarm(60); // Avoid long waits
        if ((tlsRes->acceptId != 0) && (tlsRes->ctx != NULL)) {
            pthread_join(tlsRes->acceptId, NULL);
        }
        free(tlsRes);
    }

    // Sends a signal for the peer process to exit.
    remoteProcess = GetProcessFromList();
    while (remoteProcess != NULL) {
        ret = HLT_RpcProcessExit(remoteProcess);
        if (ret != SUCCESS) {
            LOG_ERROR("HLT_RpcProcessExit Error");
        }
        free(remoteProcess);
        remoteProcess = GetProcessFromList();
    }

    // Clearing Local Resources
    // Clearing Ports
    if (localProcess->connFd > 0) {
        close(localProcess->connFd);
    }
    // Clear wrapper state BEFORE freeing SSL objects to prevent use-after-free
    ClearWrapper();
    // Clear the TlsRes linked list.
    FreeTlsResList();
    // Clear CTX SSL configuration resources.
    for (int i = 0; i < localProcess->tlsResNum; i++) {
        free(localProcess->tlsResArray[i]);
    }
    // Clear the linked list of the remote process.
    FreeProcessResList();
    // Clear local control connection resources
    FreeControlChannelRes();
    // Clear local processes.
    FreeProcess();
    // Clear connection tracking list to prevent state leakage between tests
    ClearConnectionList();
    return;
}

int HLT_FreeResFromSsl(const void *ssl)
{
    return FreeResFromSsl(ssl);
}

static int LocalProcessTlsInit(HLT_Process *process, TLS_VERSION tlsVersion,
                               HLT_Ctx_Config *ctxConfig, HLT_Ssl_Config *sslConfig, HLT_Tls_Res *tlsRes)
{
    void *ctx, *ssl;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ctx = HLT_TlsProviderNewCtx(ctxConfig->providerPath, ctxConfig->providerNames, ctxConfig->providerLibFmts,
        ctxConfig->providerCnt, ctxConfig->attrName, tlsVersion);
#else
    ctx = HLT_TlsNewCtx(tlsVersion);
#endif
    if (ctx == NULL) {
        LOG_ERROR("HLT_TlsNewCtx or HLT_TlsProviderNewCtx ERROR");
        return ERROR;
    }
    if (HLT_TlsSetCtx(ctx, ctxConfig) != SUCCESS) {
        LOG_ERROR("HLT_TlsSetCtx ERROR");
        return ERROR;
    }
    ssl = HLT_TlsNewSsl(ctx);
    if (ssl == NULL) {
        LOG_ERROR("HLT_TlsNewSsl ERROR");
        return ERROR;
    }
    // When FD is 0, the default configuration is used.
    if (sslConfig->sockFd == 0) {
        sslConfig->sockAddr = process->sockAddr;
        sslConfig->sockFd = process->connFd;
        sslConfig->connType = process->connType;
    }
    if (HLT_TlsSetSsl(ssl, sslConfig) != SUCCESS) {
        LOG_ERROR("HLT_TlsSetSsl ERROR");
        return ERROR;
    }
    if (ctxConfig->mtu > 0) {
        if (HLT_TlsSetMtu(ssl, ctxConfig->mtu) != SUCCESS) {
            LOG_ERROR("HLT_TlsSetMtu ERROR");
            return ERROR;
        }
    }
    tlsRes->ctx = ctx;
    tlsRes->ssl = ssl;
    tlsRes->ctxId = -1; // -1 indicates that the field is discarded.
    tlsRes->sslId = -1; // -1 indicates that the field is discarded.

    // Register connection for wrapper tracking
    RegisterConnection((TLS_Ctx *)ssl);

    return SUCCESS;
}

static int RemoteProcessTlsInit(HLT_Process *process, TLS_VERSION tlsVersion,
                                HLT_Ctx_Config *ctxConfig, HLT_Ssl_Config *sslConfig, HLT_Tls_Res *tlsRes)
{
    int ctxId;
    int sslId;
#ifdef HITLS_TLS_FEATURE_PROVIDER
    ctxId = HLT_RpcProviderTlsNewCtx(process, tlsVersion, ctxConfig->isClient, ctxConfig->providerPath,
        ctxConfig->providerNames, ctxConfig->providerLibFmts, ctxConfig->providerCnt, ctxConfig->attrName);
#else
    ctxId = HLT_RpcTlsNewCtx(process, tlsVersion, ctxConfig->isClient);
#endif
    if (ctxId < 0) {
        LOG_ERROR("HLT_RpcTlsNewCtx ERROR");
        return ERROR;
    }
    if (HLT_RpcTlsSetCtx(process, ctxId, ctxConfig) != SUCCESS) {
        LOG_ERROR("HLT_RpcTlsSetCtx ERROR");
        return ERROR;
    }
    sslId = HLT_RpcTlsNewSsl(process, ctxId);
    if (sslId < 0) {
        LOG_ERROR("HLT_RpcTlsNewSsl ERROR");
        return ERROR;
    }
    // When FD is 0, the default configuration is used.
    if (sslConfig->sockFd == 0) {
        sslConfig->connPort = process->connPort;
        sslConfig->sockFd = process->connFd;
        sslConfig->connType = process->connType;
    }
    if (HLT_RpcTlsSetSsl(process, sslId, sslConfig) != SUCCESS) {
        LOG_ERROR("HLT_RpcTlsSetSsl ERROR");
        return ERROR;
    }
    if (ctxConfig->mtu > 0) {
        if (HLT_RpcTlsSetMtu(process, sslId, ctxConfig->mtu) != SUCCESS) {
            LOG_ERROR("HLT_RpcTlsSetMtu ERROR");
            return ERROR;
        }
    }

    tlsRes->ctx = NULL;
    tlsRes->ssl = NULL;
    tlsRes->ctxId = ctxId;
    tlsRes->sslId = sslId;
    return SUCCESS;
}

HLT_Tls_Res *HLT_ProcessTlsInit(HLT_Process *process, TLS_VERSION tlsVersion,
    HLT_Ctx_Config *ctxConfig, HLT_Ssl_Config *sslConfig)
{
    int ret;
    HLT_Tls_Res *tlsRes = (HLT_Tls_Res*)malloc(sizeof(HLT_Tls_Res));
    if (tlsRes == NULL) {
        LOG_ERROR("Malloc TlsRes ERROR");
        return NULL;
    }

    // Checking Configuration Parameters
    if (ctxConfig == NULL) {
        ctxConfig = HLT_NewCtxConfig(NULL, "SERVER");
    }
    if (sslConfig == NULL) {
        sslConfig = HLT_NewSslConfig(NULL);
    }
    if ((ctxConfig == NULL) || (sslConfig == NULL)) {
        LOG_ERROR("ctxConfig or sslConfig is NULL");
        goto ERR;
    }
    sslConfig->SupportType = ctxConfig->SupportType;
    // Check whether the call is invoked by the local process or by the RPC.
    if (process->remoteFlag == 0) {
        ret = LocalProcessTlsInit(process, tlsVersion, ctxConfig, sslConfig, tlsRes);
        if (ret == ERROR) {
            LOG_ERROR("LocalProcessTlsInit ERROR");
            goto ERR;
        }
    } else {
        ret = RemoteProcessTlsInit(process, tlsVersion, ctxConfig, sslConfig, tlsRes);
        if (ret == ERROR) {
            LOG_ERROR("RemoteProcessTlsInit ERROR");
            goto ERR;
        }
    }
    // The configuration resources of the HLT_Tls_Res table are stored and will be released later.
    Process *localProcess = GetProcess();
    tlsRes->acceptId = 0;
    localProcess->hltTlsResArray[localProcess->hltTlsResNum] = tlsRes;
    localProcess->hltTlsResNum++;
    return tlsRes;
ERR:
    free(tlsRes);
    return NULL;
}

int HLT_TlsSetMtu(void *ssl, uint16_t mtu)
{
    Process *process;
    process = GetProcess();
    switch (process->tlsType) {
        case HITLS:
            return HitlsSetMtu(ssl, mtu);
        default:
            break;
    }
    return ERROR;
}

int HLT_TlsGetErrorCode(void *ssl)
{
    return HitlsGetErrorCode(ssl);
}

HLT_Tls_Res* HLT_ProcessTlsAccept(HLT_Process *process, TLS_VERSION tlsVersion,
                                  HLT_Ctx_Config *ctxConfig, HLT_Ssl_Config *sslConfig)
{
    HLT_Tls_Res *tlsRes = NULL;

    tlsRes = HLT_ProcessTlsInit(process, tlsVersion, ctxConfig, sslConfig);
    if (tlsRes == NULL) {
        LOG_ERROR("HLT_ProcessTlsInit ERROR");
        return NULL;
    }
    // Check whether the call is invoked by the local process or by the RPC.
    if (process->remoteFlag == 0) {
        pthread_t acceptId = HLT_TlsAccept(tlsRes->ssl);
        if (acceptId == 0) {
            LOG_ERROR("HLT_TlsAccept ERROR");
            return NULL;
        }
        tlsRes->acceptId = acceptId;
    } else {
        int rpcAcceptId = HLT_RpcTlsAccept(process, tlsRes->sslId);
        if (rpcAcceptId == ERROR) {
            LOG_ERROR("HLT_TlsAccept ERROR");
            return NULL;
        }
        // Store RPC command ID in acceptId (safe to cast int to pthread_t for storage)
        tlsRes->acceptId = (pthread_t)(uintptr_t)rpcAcceptId;
    }
    return tlsRes;
}

HLT_Tls_Res* HLT_ProcessTlsConnect(HLT_Process *process, TLS_VERSION tlsVersion,
                                   HLT_Ctx_Config *ctxConfig, HLT_Ssl_Config *sslConfig)
{
    int ret;

    HLT_Tls_Res *tlsRes = (HLT_Tls_Res*)malloc(sizeof(HLT_Tls_Res));
    if (tlsRes == NULL) {
        LOG_ERROR("Malloc TlsRes ERROR");
        return NULL;
    }
    (void)memset_s(tlsRes, sizeof(HLT_Tls_Res), 0, sizeof(HLT_Tls_Res));
    // Checking Configuration Parameters
    if (ctxConfig == NULL) {
        ctxConfig = HLT_NewCtxConfig(NULL, "CLIENT");
    }
    if (sslConfig == NULL) {
        sslConfig = HLT_NewSslConfig(NULL);
    }
    if ((ctxConfig == NULL) || (sslConfig == NULL)) {
        LOG_ERROR("ctxConfig or sslConfig is NULL");
        goto ERR;
    }
    // Check whether the call is invoked by the local process or by the RPC.
    if (process->remoteFlag == 0) {
        ret = LocalProcessTlsInit(process, tlsVersion, ctxConfig, sslConfig, tlsRes);
        if (ret == ERROR) {
            LOG_ERROR("LocalProcessTlsInit ERROR");
            goto ERR;
        }
        ret = HLT_TlsConnect(tlsRes->ssl);
        if (ret != SUCCESS) {
            LOG_ERROR("HLT_TlsConnect ERROR is %d", ret);
            goto ERR;
        }
    } else {
        ret = RemoteProcessTlsInit(process, tlsVersion, ctxConfig, sslConfig, tlsRes);
        if (ret == ERROR) {
            LOG_ERROR("Retmote Process Init Tls  ERROR");
            goto ERR;
        }
        ret = HLT_RpcTlsConnect(process, tlsRes->sslId);
        if (ret != SUCCESS) {
            LOG_ERROR("HLT_RpcTlsConnect ERROR is %d", ret);
            goto ERR;
        }
    }

    // The configuration resources of the HLT_Tls_Res table are stored and will be released later.
    Process *localProcess = GetProcess();
    localProcess->hltTlsResArray[localProcess->hltTlsResNum] = tlsRes;
    localProcess->hltTlsResNum++;
    return tlsRes;
ERR:
    free(tlsRes);
    return NULL;
}

int HLT_ProcessTlsWrite(HLT_Process *process, HLT_Tls_Res *tlsRes, uint8_t *data, uint32_t dataLen)
{
    if (process == NULL) {
        LOG_ERROR("Process is NULL");
        return ERROR;
    }
    if (process->remoteFlag == 0) {
        return HLT_TlsWrite(tlsRes->ssl, data, dataLen);
    } else {
        return HLT_RpcTlsWrite(process, tlsRes->sslId, data, dataLen);
    }
}

int HLT_ProcessTlsRead(HLT_Process *process, HLT_Tls_Res *tlsRes, uint8_t *data, uint32_t bufSize, uint32_t *dataLen)
{
    if (process == NULL) {
        LOG_ERROR("Process is NULL");
        return ERROR;
    }
    if (process->remoteFlag == 0) {
        return HLT_TlsRead(tlsRes->ssl, data, bufSize, dataLen);
    } else {
        return HLT_RpcTlsRead(process, tlsRes->sslId, data, bufSize, dataLen);
    }
}

int HLT_SetVersion(HLT_Ctx_Config *ctxConfig, uint16_t minVersion, uint16_t maxVersion)
{
    ctxConfig->minVersion = minVersion;
    ctxConfig->maxVersion = maxVersion;
    return SUCCESS;
}

int HLT_SetSecurityLevel(HLT_Ctx_Config *ctxConfig, int32_t level)
{
    ctxConfig->securitylevel = level;
    return SUCCESS;
}

int HLT_SetRenegotiationSupport(HLT_Ctx_Config *ctxConfig, bool support)
{
    ctxConfig->isSupportRenegotiation = support;
    return SUCCESS;
}

int HLT_SetLegacyRenegotiateSupport(HLT_Ctx_Config *ctxConfig, bool support)
{
    ctxConfig->allowLegacyRenegotiate = support;
    return SUCCESS;
}

int HLT_SetClientRenegotiateSupport(HLT_Ctx_Config *ctxConfig, bool support)
{
    ctxConfig->allowClientRenegotiate = support;
    return SUCCESS;
}

int HLT_SetEmptyRecordsNum(HLT_Ctx_Config *ctxConfig, uint32_t emptyNum)
{
    ctxConfig->emptyRecordsNum = emptyNum;
    return SUCCESS;
}

int HLT_SetKeyLogCb(HLT_Ctx_Config *ctxConfig, char *SetKeyLogCb)
{
    (void)memset_s(ctxConfig->keyLogCb, KEY_LOG_CB_LEN, 0, KEY_LOG_CB_LEN);
    if (strcpy_s(ctxConfig->keyLogCb, KEY_LOG_CB_LEN, SetKeyLogCb) != EOK) {
        LOG_ERROR("HLT_SetKeyLogCb failed.");
        return -1;
    }
    return SUCCESS;
}

int HLT_SetEncryptThenMac(HLT_Ctx_Config *ctxConfig, int support)
{
    ctxConfig->isEncryptThenMac = support;
    return SUCCESS;
}

int HLT_SetRecordSizeLimit(HLT_Ctx_Config *ctxConfig, uint16_t recordSize)
{
    ctxConfig->recordSizeLimit = recordSize;
    return SUCCESS;
}

int HLT_SetMiddleBoxCompat(HLT_Ctx_Config *ctxConfig, int support)
{
    ctxConfig->isMiddleBoxCompat = support;
    return SUCCESS;
}

int HLT_SetFlightTransmitSwitch(HLT_Ctx_Config *ctxConfig, bool support)
{
    ctxConfig->isFlightTransmitEnable = support;
    return SUCCESS;
}

int HLT_SetClientVerifySupport(HLT_Ctx_Config *ctxConfig, bool support)
{
    ctxConfig->isSupportClientVerify = support;
    return SUCCESS;
}

int HLT_SetPostHandshakeAuth(HLT_Ctx_Config *ctxConfig, bool support)
{
    ctxConfig->isSupportPostHandshakeAuth = support;
    return SUCCESS;
}

int HLT_SetPostHandshakeAuthSupport(HLT_Ctx_Config *ctxConfig, bool support)
{
    ctxConfig->isSupportPostHandshakeAuth = support;
    return SUCCESS;
}

int HLT_SetNoClientCertSupport(HLT_Ctx_Config *ctxConfig, bool support)
{
    ctxConfig->isSupportNoClientCert = support;
    return SUCCESS;
}

int HLT_SetExtendedMasterSecretSupport(HLT_Ctx_Config *ctxConfig, bool support)
{
    ctxConfig->isSupportExtendedMasterSecret = support;
    return SUCCESS;
}

int HLT_SetModeSupport(HLT_Ctx_Config *ctxConfig, uint32_t mode)
{
    ctxConfig->modeSupport = mode;
    return SUCCESS;
}

int HLT_SetCipherSuites(HLT_Ctx_Config *ctxConfig, const char *cipherSuites)
{
    int ret;
    (void)memset_s(ctxConfig->cipherSuites, sizeof(ctxConfig->cipherSuites), 0, sizeof(ctxConfig->cipherSuites));
    ret = sprintf_s(ctxConfig->cipherSuites, sizeof(ctxConfig->cipherSuites), cipherSuites);
    if (ret <= 0) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetProviderPath(HLT_Ctx_Config *ctxConfig, char *providerPath)
{
    if (strcpy_s(ctxConfig->providerPath, sizeof(ctxConfig->providerPath), providerPath) != EOK) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetProviderAttrName(HLT_Ctx_Config *ctxConfig, char *attrName)
{
    if (strcpy_s(ctxConfig->attrName, sizeof(ctxConfig->attrName), attrName) != EOK) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_AddProviderInfo(HLT_Ctx_Config *ctxConfig, char *providerName, int providerLibFmt)
{
    if (providerName != NULL) {
        if (strcpy_s(ctxConfig->providerNames[ctxConfig->providerCnt], MAX_PROVIDER_NAME_LEN, providerName) != EOK) {
            return ERROR;
        }
        ctxConfig->providerLibFmts[ctxConfig->providerCnt] = providerLibFmt;
        ctxConfig->providerCnt += 1;
    }
    return SUCCESS;
}

int HLT_SetTls13CipherSuites(HLT_Ctx_Config *ctxConfig, const char *cipherSuites)
{
    int ret;
    (void)memset_s(ctxConfig->tls13CipherSuites, sizeof(ctxConfig->tls13CipherSuites), 0,
        sizeof(ctxConfig->tls13CipherSuites));
    ret = sprintf_s(ctxConfig->tls13CipherSuites, sizeof(ctxConfig->tls13CipherSuites), cipherSuites);
    if (ret <= 0) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetEcPointFormats(HLT_Ctx_Config *ctxConfig, const char *pointFormat)
{
    int ret;
    (void)memset_s(ctxConfig->pointFormats, sizeof(ctxConfig->pointFormats), 0, sizeof(ctxConfig->pointFormats));
    ret = sprintf_s(ctxConfig->pointFormats, sizeof(ctxConfig->pointFormats), pointFormat);
    if (ret <= 0) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetGroups(HLT_Ctx_Config *ctxConfig, const char *groups)
{
    int ret;
    (void)memset_s(ctxConfig->groups, sizeof(ctxConfig->groups), 0, sizeof(ctxConfig->groups));
    ret = sprintf_s(ctxConfig->groups, sizeof(ctxConfig->groups), groups);
    if (ret <= 0) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetSignature(HLT_Ctx_Config *ctxConfig, const char *signature)
{
    int ret;
    (void)memset_s(ctxConfig->signAlgorithms, sizeof(ctxConfig->signAlgorithms), 0, sizeof(ctxConfig->signAlgorithms));
    ret = sprintf_s(ctxConfig->signAlgorithms, sizeof(ctxConfig->signAlgorithms), signature);
    if (ret <= 0) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetPsk(HLT_Ctx_Config *ctxConfig, char *psk)
{
    (void)memset_s(ctxConfig->psk, PSK_MAX_LEN, 0, PSK_MAX_LEN);
    if (strcpy_s(ctxConfig->psk, PSK_MAX_LEN, psk) != EOK) {
        LOG_ERROR("HLT_SetPsk failed.");
        return -1;
    }
    return SUCCESS;
}

int HLT_SetKeyExchMode(HLT_Ctx_Config *config, uint32_t mode)
{
    config->keyExchMode = mode;
    return SUCCESS;
}

int HLT_SetTicketKeyCb(HLT_Ctx_Config *ctxConfig, char *ticketKeyCbName)
{
    (void)memset_s(ctxConfig->ticketKeyCb, TICKET_KEY_CB_NAME_LEN, 0, TICKET_KEY_CB_NAME_LEN);
    if (strcpy_s(ctxConfig->ticketKeyCb, TICKET_KEY_CB_NAME_LEN, ticketKeyCbName) != EOK) {
        LOG_ERROR("HLT_SetTicketKeyCb failed.");
        return -1;
    }
    return SUCCESS;
}

int HLT_SetCaCertPath(HLT_Ctx_Config *ctxConfig, const char *caCertPath)
{
    int ret;
    (void)memset_s(ctxConfig->caCert, sizeof(ctxConfig->caCert), 0, sizeof(ctxConfig->caCert));
    ret = sprintf_s(ctxConfig->caCert, sizeof(ctxConfig->caCert), caCertPath);
    if (ret <= 0) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetChainCertPath(HLT_Ctx_Config *ctxConfig, const char *chainCertPath)
{
    int ret;
    (void)memset_s(ctxConfig->chainCert, sizeof(ctxConfig->chainCert), 0, sizeof(ctxConfig->chainCert));
    ret = sprintf_s(ctxConfig->chainCert, sizeof(ctxConfig->chainCert), chainCertPath);
    if (ret <= 0) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetEeCertPath(HLT_Ctx_Config *ctxConfig, const char *eeCertPath)
{
    int ret;
    (void)memset_s(ctxConfig->eeCert, sizeof(ctxConfig->eeCert), 0, sizeof(ctxConfig->eeCert));
    ret = sprintf_s(ctxConfig->eeCert, sizeof(ctxConfig->eeCert), eeCertPath);
    if (ret <= 0) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetPrivKeyPath(HLT_Ctx_Config *ctxConfig, const char *privKeyPath)
{
    int ret;
    (void)memset_s(ctxConfig->privKey, sizeof(ctxConfig->privKey), 0, sizeof(ctxConfig->privKey));
    ret = sprintf_s(ctxConfig->privKey, sizeof(ctxConfig->privKey), privKeyPath);
    if (ret <= 0) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetSignCertPath(HLT_Ctx_Config *ctxConfig, const char *signCertPath)
{
    int ret;
    (void)memset_s(ctxConfig->signCert, sizeof(ctxConfig->signCert), 0, sizeof(ctxConfig->signCert));
    ret = sprintf_s(ctxConfig->signCert, sizeof(ctxConfig->signCert), signCertPath);
    if (ret <= 0) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetSignPrivKeyPath(HLT_Ctx_Config *ctxConfig, const char *signPrivKeyPath)
{
    int ret;
    (void)memset_s(ctxConfig->signPrivKey, sizeof(ctxConfig->signPrivKey), 0, sizeof(ctxConfig->signPrivKey));
    ret = sprintf_s(ctxConfig->signPrivKey, sizeof(ctxConfig->signPrivKey), signPrivKeyPath);
    if (ret <= 0) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetPassword(HLT_Ctx_Config* ctxConfig, const char* password)
{
    int ret;
    (void)memset_s(ctxConfig->password, sizeof(ctxConfig->password), 0, sizeof(ctxConfig->password));
    ret = sprintf_s(ctxConfig->password, sizeof(ctxConfig->password), password);
    if (ret <= 0) {
        return ERROR;
    }
    return SUCCESS;
}

void HLT_SetCertPath(HLT_Ctx_Config *ctxConfig, const char *caPath, const char *chainPath, const char *EePath,
                     const char *PrivPath, const char *signCert, const char *signPrivKey)
{
    HLT_SetCaCertPath(ctxConfig, caPath);
    if (ctxConfig->isNoSetCert) {
        return;
    }
    HLT_SetChainCertPath(ctxConfig, chainPath);
    HLT_SetEeCertPath(ctxConfig, EePath);
    HLT_SetPrivKeyPath(ctxConfig, PrivPath);
    HLT_SetSignCertPath(ctxConfig, signCert);
    HLT_SetSignPrivKeyPath(ctxConfig, signPrivKey);
}

int HLT_SetServerName(HLT_Ctx_Config *ctxConfig, const char *serverName)
{
    (void)memset_s(ctxConfig->serverName, sizeof(ctxConfig->serverName), 0, sizeof(ctxConfig->serverName));
    int ret = sprintf_s(ctxConfig->serverName, sizeof(ctxConfig->serverName), serverName);
    if (ret <= 0) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetServerNameArg(HLT_Ctx_Config *ctxConfig, char *arg)
{
    (void)memset_s(ctxConfig->sniArg, SERVER_NAME_ARG_NAME_LEN, 0, SERVER_NAME_ARG_NAME_LEN);
    if (strcpy_s(ctxConfig->sniArg, SERVER_NAME_ARG_NAME_LEN, arg) != EOK) {
        LOG_ERROR("HLT_SetServerNameArg failed.");
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetServerNameCb(HLT_Ctx_Config *ctxConfig, char *sniCbName)
{
    (void)memset_s(ctxConfig->sniDealCb, SERVER_NAME_CB_NAME_LEN, 0, SERVER_NAME_CB_NAME_LEN);
    if (strcpy_s(ctxConfig->sniDealCb, SERVER_NAME_CB_NAME_LEN, sniCbName) != EOK) {
        LOG_ERROR("HLT_SetServerNameCb failed.");
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetAlpnProtos(HLT_Ctx_Config *ctxConfig, const char *alpnProtos)
{
    (void)memset_s(ctxConfig->alpnList, sizeof(ctxConfig->alpnList), 0, sizeof(ctxConfig->alpnList));
    int ret = sprintf_s(ctxConfig->alpnList, sizeof(ctxConfig->alpnList), alpnProtos);
    if (ret <= 0) {
        return ERROR;
    }
    return SUCCESS;
}

int HLT_SetAlpnProtosSelectCb(HLT_Ctx_Config *ctxConfig, char *callback, char *userData)
{
    (void)memset_s(ctxConfig->alpnSelectCb, ALPN_CB_NAME_LEN, 0, ALPN_CB_NAME_LEN);
    if (strcpy_s(ctxConfig->alpnSelectCb, ALPN_CB_NAME_LEN, callback) != EOK) {
        LOG_ERROR("HLT_SetAlpnCb failed.");
        return ERROR;
    }
    (void)memset_s(ctxConfig->alpnUserData, ALPN_DATA_NAME_LEN, 0, ALPN_DATA_NAME_LEN);
    if (strcpy_s(ctxConfig->alpnUserData, ALPN_DATA_NAME_LEN, userData) != EOK) {
        LOG_ERROR("HLT_SetAlpnDataCb failed.");
        return ERROR;
    }
    return SUCCESS;
}


int HLT_SetClientHelloCb(HLT_Ctx_Config *ctxConfig, HITLS_ClientHelloCb callback, void *arg)
{
    ctxConfig->clientHelloCb = callback;
    ctxConfig->clientHelloArg = arg;
    return SUCCESS;
}

int HLT_SetCertCb(HLT_Ctx_Config *ctxConfig, HITLS_CertCb certCb, void *arg)
{
    ctxConfig->certCb = certCb;
    ctxConfig->certArg = arg;
    return SUCCESS;
}

int HLT_SetCAList(HLT_Ctx_Config *ctxConfig, HITLS_TrustedCAList *caList)
{
    ctxConfig->caList = caList;
    return SUCCESS;
}

int HLT_SetDtlsCookieExchangeSupport(HLT_Ctx_Config *ctxConfig, bool isSupport)
{
    ctxConfig->isSupportDtlsCookieExchange = isSupport;
    return SUCCESS;
}

int HLT_SetFrameHandle(HLT_FrameHandle *frameHandle)
{
    return SetFrameHandle(frameHandle);
}

void HLT_CleanFrameHandle(void)
{
    CleanFrameHandle();
}

bool IsEnableSctpAuth(void)
{
    return false;
}

void HLT_ConfigTimeOut(const char* timeout)
{
    setenv("SSL_TIMEOUT", timeout, 1);
}

void HLT_UnsetTimeOut()
{
    unsetenv("SSL_TIMEOUT");
}
