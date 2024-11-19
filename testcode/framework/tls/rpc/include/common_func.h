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

#ifndef COMMON_FUNC_H
#define COMMON_FUNC_H

#include <stdatomic.h>
#include "hlt_type.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EE_CERT,
    PRIVE_KEY,
    CA_CERT,
    CHAIN_CERT
} CERT_TYPE;

typedef struct {
    atomic_int mallocCnt;
    atomic_int freeCnt;
    atomic_int mallocSize;
    atomic_int freeSize;
    atomic_int maxMemSize;
} MemCnt;

/**
* @brief Load a certificate from a file.
*/
int LoadCertFromFile(void *ctx, char *pCert, CERT_TYPE certType);

/**
* @brief Memory application that contains the count
*/
void *CountMalloc(uint32_t len);

/**
* @brief Memory release that contains the count
*/
void CountFree(void *addr);

/**
* @brief Clear the memory count.
*/
void ClearMemCntData(void);

/**
* @brief Obtain the memory count.
*/
MemCnt *GetMemCntData(void);

int32_t ExampleSetPsk(char *psk);

uint32_t ExampleClientCb(HITLS_Ctx *ctx, const uint8_t *hint, uint8_t *identity, uint32_t maxIdentityLen,
    uint8_t *psk, uint32_t maxPskLen);

uint32_t ExampleServerCb(HITLS_Ctx *ctx, const uint8_t *identity, uint8_t *psk, uint32_t maxPskLen);

int32_t ExampleTicketKeySuccessCb(uint8_t *keyName, uint32_t keyNameSize, void *cipher, uint8_t isEncrypt);
int32_t ExampleTicketKeyRenewCb(uint8_t *keyName, uint32_t keyNameSize, void *cipher, uint8_t isEncrypt);
void *GetTicketKeyCb(char *str);

void *GetExtensionCb(const char *str);
void *GetExampleData(const char *str);

#ifdef __cplusplus
}
#endif

#endif // COMMON_FUNC_H