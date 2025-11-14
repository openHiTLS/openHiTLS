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

#ifndef HLT_H
#define HLT_H

#include <stddef.h>
#include "hlt_type.h"

#ifdef __cplusplus
extern "C" {
#endif


// Create a process
HLT_Process* InitSrcProcess(TLS_TYPE tlsType, char* srcDomainPath);
HLT_Process* InitPeerProcess(TLS_TYPE tlsType, HILT_TransportType connType, int port, bool isBlock);
#define HLT_InitLocalProcess(tlsType) InitSrcProcess(tlsType, __FILE__)
#define HLT_CreateRemoteProcess(tlsType) InitPeerProcess(tlsType, NONE_TYPE, 0, 0)
#define HLT_LinkRemoteProcess(tlsType, connType, port, isBlock) InitPeerProcess(tlsType, connType, port, isBlock)

// Clear all process resources
void HLT_FreeAllProcess(void);
int HLT_FreeResFormSsl(const void *ssl);

// Create a local data connection
HLT_FD HLT_CreateDataChannel(HLT_Process* process1, HLT_Process* process2, DataChannelParam channelParam);
int HLT_DataChannelConnect(DataChannelParam* dstChannelParam);
pthread_t HLT_DataChannelAccept(DataChannelParam* channelParam);
void HLT_CloseFd(int fd, int linkType);

// Interface for setting connection information
int HLT_SetVersion(HLT_Ctx_Config* ctxConfig, uint16_t minVersion, uint16_t maxVersion);
int HLT_SetSecurityLevel(HLT_Ctx_Config *ctxConfig, int32_t level);
int HLT_SetRenegotiationSupport(HLT_Ctx_Config* ctxConfig, bool support);
int HLT_SetLegacyRenegotiateSupport(HLT_Ctx_Config* ctxConfig, bool support);
int HLT_SetClientRenegotiateSupport(HLT_Ctx_Config* ctxConfig, bool support);
int HLT_SetEmptyRecordsNum(HLT_Ctx_Config *ctxConfig, uint32_t emptyNum);
int HLT_SetFlightTransmitSwitch(HLT_Ctx_Config *ctxConfig, bool support);
int HLT_SetClientVerifySupport(HLT_Ctx_Config* ctxConfig, bool support);
int HLT_SetNoClientCertSupport(HLT_Ctx_Config* ctxConfig, bool support);
int HLT_SetPostHandshakeAuth(HLT_Ctx_Config *ctxConfig, bool support);
int HLT_SetExtenedMasterSecretSupport(HLT_Ctx_Config* ctxConfig, bool support);
int HLT_SetEncryptThenMac(HLT_Ctx_Config *ctxConfig, int support);
int HLT_SetDtlsCookieExchangeSupport(HLT_Ctx_Config *ctxConfig, bool isSupport);
int HLT_SetModeSupport(HLT_Ctx_Config *ctxConfig, uint32_t mode);
int HLT_SetCipherSuites(HLT_Ctx_Config* ctxConfig, const char* cipherSuites);
int HLT_SetProviderPath(HLT_Ctx_Config *ctxConfig, char *providerPath);
int HLT_SetProviderAttrName(HLT_Ctx_Config *ctxConfig, char *attrName);
int HLT_AddProviderInfo(HLT_Ctx_Config *ctxConfig, char *providerName, int providerLibFmt);
int HLT_SetTls13CipherSuites(HLT_Ctx_Config *ctxConfig, const char *cipherSuites);
int HLT_SetEcPointFormats(HLT_Ctx_Config* ctxConfig, const char* pointFormat);
int HLT_SetGroups(HLT_Ctx_Config* ctxConfig, const char* groups);
int HLT_SetSignature(HLT_Ctx_Config* ctxConfig, const char* signature);
int HLT_SetCaCertPath(HLT_Ctx_Config* ctxConfig, const char* caCertPath);
int HLT_SetChainCertPath(HLT_Ctx_Config* ctxConfig, const char* chainCertPath);
int HLT_SetEeCertPath(HLT_Ctx_Config* ctxConfig, const char* eeCertPath);
int HLT_SetPrivKeyPath(HLT_Ctx_Config* ctxConfig, const char* privKeyPath);
int HLT_SetPassword(HLT_Ctx_Config* ctxConfig, const char* password);
void HLT_SetCertPath(HLT_Ctx_Config* ctxConfig, const char *caPath,
    const char *chainPath, const char *EePath, const char *PrivPath, const char *signCert, const char *signPrivKey);

int HLT_SetPsk(HLT_Ctx_Config *ctxConfig, char *psk);
int HLT_SetKeyExchMode(HLT_Ctx_Config *config, uint32_t mode);
int HLT_SetTicketKeyCb(HLT_Ctx_Config *ctxConfig, char *ticketKeyCbName);

int HLT_SetServerName(HLT_Ctx_Config *ctxConfig, const char *serverName);
int HLT_SetServerNameArg(HLT_Ctx_Config *ctxConfig, char *arg);
int HLT_SetServerNameCb(HLT_Ctx_Config *ctxConfig, char *sniCbName);

int HLT_SetAlpnProtos(HLT_Ctx_Config *ctxConfig, const char *alpnProtos);
int HLT_SetAlpnProtosSelectCb(HLT_Ctx_Config *ctxConfig, char *callback, char *userData);

// Interface for setting abnormal message operations
int HLT_SetFrameHandle(HLT_FrameHandle *frameHandle);
void HLT_CleanFrameHandle(void);
int HLT_FreeResFromSsl(const void *ssl);

// General initialization interface
int HLT_LibraryInit(TLS_TYPE tlsType);

// The local process invokes TLS functions
HLT_Tls_Res* HLT_ProcessTlsInit(HLT_Process *process, TLS_VERSION tlsVersion,
    HLT_Ctx_Config *ctxConfig, HLT_Ssl_Config *sslConfig);
void* HLT_TlsNewCtx(TLS_VERSION tlsVersion);
void* HLT_TlsProviderNewCtx(char *providerPath, char (*providerNames)[MAX_PROVIDER_NAME_LEN], int *providerLibFmts,
    int providerCnt, char *attrName, TLS_VERSION tlsVersion);
HLT_Ctx_Config* HLT_NewCtxConfig(char* setFile, const char* key);
HLT_Ctx_Config* HLT_NewCtxConfigTLCP(char *setFile, const char *key, bool isClient);
int HLT_TlsSetCtx(void* ctx, HLT_Ctx_Config* config);
HLT_Ssl_Config* HLT_NewSslConfig(char* setFile);
void* HLT_TlsNewSsl(void* ctx);
int HLT_TlsSetSsl(void* ssl, HLT_Ssl_Config* config);
unsigned long int HLT_TlsListen(void *ssl);
unsigned long int HLT_TlsAccept(void* ssl);
int HLT_TlsListenBlock(void* ssl);
int HLT_TlsAcceptBlock(void* ssl);
int HLT_GetTlsAcceptResultFromId(unsigned long int threadId);
int HLT_GetTlsAcceptResult(HLT_Tls_Res* tlsRes);
int HLT_TlsConnect(void* ssl);
int HLT_TlsRead(void* ssl,  uint8_t *data, uint32_t bufSize, uint32_t *readLen);
int HLT_TlsWrite(void* ssl,  uint8_t *data, uint32_t dataLen);
int HLT_TlsRegCallback(TlsCallbackType type);
int HLT_TlsRenegotiate(void *ssl);
int HLT_TlsVerifyClientPostHandshake(void *ssl);
int HLT_TlsClose(void *ssl);
int HLT_TlsSetSession(void *ssl, void *session);
int HLT_TlsSessionReused(void *ssl);
void *HLT_TlsGet1Session(void *ssl);
int32_t HLT_SetSessionCacheMode(HLT_Ctx_Config* config, HITLS_SESS_CACHE_MODE mode);
int32_t HLT_SetSessionTicketSupport(HLT_Ctx_Config* config, bool issupport);
int HLT_TlsSessionHasTicket(void *session);
int HLT_TlsSessionIsResumable(void *session);
void HLT_TlsFreeSession(void *session);

// The RPC controls the remote process to invoke TLS functions
int HLT_RpcTlsNewCtx(HLT_Process* peerProcess, TLS_VERSION tlsVersion, bool isClient);
int HLT_RpcProviderTlsNewCtx(HLT_Process *peerProcess, TLS_VERSION tlsVersion, bool isClient, char *providerPath,
    char (*providerNames)[MAX_PROVIDER_NAME_LEN], int32_t *providerLibFmts, int32_t providerCnt, char *attrName);
int HLT_RpcTlsSetCtx(HLT_Process* peerProcess, int ctxId, HLT_Ctx_Config* config);
int HLT_RpcTlsNewSsl(HLT_Process* peerProcess, int ctxId);
int HLT_RpcTlsSetSsl(HLT_Process* peerProcess, int sslId, HLT_Ssl_Config* config);
int HLT_RpcTlsListen(HLT_Process* peerProcess, int sslId);
int HLT_RpcTlsAccept(HLT_Process* peerProcess, int sslId);
int HLT_RpcGetTlsListenResult(int acceptId);
int HLT_RpcGetTlsAcceptResult(int acceptId);
int HLT_RpcTlsConnect(HLT_Process* peerProcess, int sslId);
int HLT_RpcTlsConnectUnBlock(HLT_Process *peerProcess, int sslId);
int HLT_RpcGetTlsConnectResult(int cmdIndex);
int HLT_RpcTlsRead(HLT_Process* peerProcess, int sslId,  uint8_t *data, uint32_t bufSize, uint32_t *readLen);
int HLT_RpcTlsReadUnBlock(HLT_Process *peerProcess, int sslId,  uint8_t *data, uint32_t bufSize, uint32_t *readLen);
int HLT_RpcGetTlsReadResult(int cmdIndex, uint8_t *data, uint32_t bufSize, uint32_t *readLen);
int HLT_RpcTlsWrite(HLT_Process* peerProcess, int sslId,  uint8_t *data, uint32_t bufSize);
int HLT_RpcTlsWriteUnBlock(HLT_Process *peerProcess, int sslId,  uint8_t *data, uint32_t bufSize);
int HLT_RpcGetTlsWriteResult(int cmdIndex);
int HLT_RpcTlsRenegotiate(HLT_Process *peerProcess, int sslId);
int HLT_RpcTlsVerifyClientPostHandshake(HLT_Process *peerProcess, int sslId);
int HLT_RpcTlsRegCallback(HLT_Process* peerProcess, TlsCallbackType type);
int HLT_RpcProcessExit(HLT_Process* peerProcess);
int HLT_RpcDataChannelBind(HLT_Process *peerProcess, DataChannelParam *channelParam);
int HLT_RpcDataChannelAccept(HLT_Process* peerProcess, DataChannelParam* channelParam);
int HLT_RpcGetAcceptFd(int acceptId);
int HLT_RpcDataChannelConnect(HLT_Process* peerProcess, DataChannelParam* channelParam);
int HLT_RpcTlsGetStatus(HLT_Process *peerProcess, int sslId);
int HLT_RpcTlsGetAlertFlag(HLT_Process *peerProcess, int sslId);
int HLT_RpcTlsGetAlertLevel(HLT_Process *peerProcess, int sslId);
int HLT_RpcTlsGetAlertDescription(HLT_Process *peerProcess, int sslId);
int HLT_RpcTlsClose(HLT_Process *peerProcess, int sslId);
int HLT_RpcFreeResFormSsl(HLT_Process *peerProcess, int sslId);
int HLT_RpcSctpClose(HLT_Process *peerProcess, int fd);
int HLT_RpcCloseFd(HLT_Process *peerProcess, int fd, int linkType);
int HLT_RpcTlsSetMtu(HLT_Process *peerProcess, int sslId, uint16_t mtu);
int HLT_RpcTlsGetErrorCode(HLT_Process *peerProcess, int sslId);

// TLS connection establishment encapsulation interface
HLT_Tls_Res* HLT_ProcessTlsAccept(HLT_Process *process, TLS_VERSION tlsVersion,
    HLT_Ctx_Config *ctxConfig, HLT_Ssl_Config *sslConfig);
HLT_Tls_Res* HLT_ProcessTlsConnect(HLT_Process *process, TLS_VERSION tlsVersion,
    HLT_Ctx_Config *ctxConfig, HLT_Ssl_Config *sslConfig);
int HLT_ProcessTlsRead(HLT_Process *process, HLT_Tls_Res* tlsRes, uint8_t *data, uint32_t bufSize, uint32_t *dataLen);
int HLT_ProcessTlsWrite(HLT_Process *process, HLT_Tls_Res* tlsRes, uint8_t *data, uint32_t dataLen);

int HLT_TlsSetMtu(void *ssl, uint16_t mtu);
int HLT_TlsGetErrorCode(void *ssl);

bool IsEnableSctpAuth(void);
#ifdef __cplusplus
}
#endif

#endif // HLT_H