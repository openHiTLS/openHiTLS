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

#ifndef TLS_RES_H
#define TLS_RES_H

#include <stdint.h>
#include "lock.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Res {
    void *tlsRes; // Indicates the CTX or SSL resource.
    int  ctxId; // This field is used only in sslList, indicating the ctx from which the SSL is generated.
    struct Res *next;
    uint8_t id; // Indicates the sequence number of a resource, that is, the number of times that the resource
                // is created. The value starts from 0.
} Res;

typedef struct {
    Res *res;
    uint8_t num;
    Lock *resListLock;
} ResList;

/**
* @brief  Initializing the TLS Resource Linked List
*/
int InitTlsResList(void);

/**
* @brief  Releasing the TLS Resource Linked List
*/
void FreeTlsResList(void);

/**
* @brief  Releases CTX and SSL resources in the linked list based on CTX resources.
*/
int FreeResFromSsl(const void *ctx);

/**
* @brief  Insert CTX resources into the linked list.
*/
int InsertCtxToList(void *ctx);

/**
* @brief  Insert SSL resources into the linked list.
*/
int InsertSslToList(void* ctx, void *ssl);

/**
* @brief  Obtains the CTX linked list from the linked list.
*/
ResList* GetCtxList(void);

/**
* @brief  Obtains the SSL linked list from the linked list.
*/
ResList* GetSslList(void);

/**
* @brief  Obtain the CTX from the CTX linked list based on the ID.
*/
int GetCtxIdFromSsl(const void* tls);

/**
* @brief  Obtains the TLS RES in the linked list.
*/
Res* GetResFromTlsResList(ResList *resList, const void* tlsRes);

/**
* @brief  Obtains TLS RES from the linked list based on the ID.
*/
void* GetTlsResFromId(ResList *resList, int id);

#ifdef __cplusplus
}
#endif

#endif // TLS_RES_H
