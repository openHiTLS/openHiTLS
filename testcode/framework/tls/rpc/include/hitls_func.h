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

#ifndef HITLS_FUNC_H
#define HITLS_FUNC_H

#include "hitls_config.h"
#include "bsl_uio.h"
#include "hlt_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief Hitls initialization
*/
int HitlsInit(void);

/**
* @brief HiTLS Create connection management resources.
*/
void* HitlsNewCtx(TLS_VERSION tlsVersion);

HITLS_Config *HitlsProviderNewCtx(char *providerPath, char (*providerNames)[MAX_PROVIDER_NAME_LEN], int *providerLibFmts,
    int providerCnt, char *attrName, TLS_VERSION tlsVersion);

/**
* @brief HiTLS Releases connection management resources.
*/
void HitlsFreeCtx(void *ctx);

/**
* @brief HiTLS Setting connection information
*/
int HitlsSetCtx(HITLS_Config *config, HLT_Ctx_Config *ctxConfig);

/**
* @brief HiTLS Creating an SSL resource
*/
void* HitlsNewSsl(void *ctx);

/**
* @brief HiTLS Releases SSL resources.
*/
void HitlsFreeSsl(void *ssl);

/**
* @brief HiTLS Set TLS information.
*/
int HitlsSetSsl(void *ssl, HLT_Ssl_Config *sslConfig);

/**
* @brief HiTLS waits for a TLS connection.
*/
int HitlsAccept(void *ssl);

/**
* @brief The HiTLS initiates a TLS connection.
*/
int HitlsConnect(void *ssl);

/**
* @brief HiTLS writes data through the TLS connection.
*/
int HitlsWrite(void *ssl, uint8_t *data, uint32_t dataLen);

/**
* @brief HiTLS reads data through the TLS connection.
*/
int HitlsRead(void *ssl, uint8_t *data, uint32_t bufSize, uint32_t *readLen);

/**
* @brief HiTLS Disables the TLS connection.
*/
int HitlsClose(void *ssl);

/**
* @brief HiTLS supports renegotiation through TLS connection.
*/
int HitlsRenegotiate(void *ssl);

int HitlsSetMtu(void *ssl, uint16_t mtu);

int HitlsSetSession(void *ssl, void *session);
int HitlsSessionReused(void *ssl);
void *HitlsGet1Session(void *ssl);
int HitlsSessionHasTicket(void *session);
int HitlsSessionIsResumable(void *session);
void HitlsFreeSession(void *session);
int HitlsGetErrorCode(void *ssl);

/**
* @brief Obtaining method based on the connection type
*/
BSL_UIO_Method *GetDefaultMethod(BSL_UIO_TransportType type);

#ifdef __cplusplus
}
#endif

#endif // HITLS_FUNC_H
