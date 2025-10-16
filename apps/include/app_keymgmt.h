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

#ifndef HITLS_APP_KEYMGMT_H
#define HITLS_APP_KEYMGMT_H
#include <stdint.h>
#include "app_sm.h"
#include "crypt_eal_pkey.h"

#ifdef __cplusplus
extern "C" {
#endif
#ifdef HITLS_APP_SM_MODE
#define HITLS_APP_MAX_KEY_LEN 64
#define HITLS_APP_UUID_LEN 32

typedef struct {
    int32_t version;
    uint8_t uuid[HITLS_APP_UUID_LEN];
    int32_t algId;
    int64_t createTime;
    int64_t expireTime;
} HITLS_APP_KeyAttr;

typedef struct {
    uint8_t key[HITLS_APP_MAX_KEY_LEN];
    uint32_t keyLen;
    CRYPT_EAL_PkeyCtx *pkeyCtx;
    HITLS_APP_KeyAttr attr;
} HITLS_APP_KeyInfo;

/**
 * @ingroup app_keymgmt
 * @brief   The function type to send the key.
 *
 * @param   ctx [IN] The context of the function.
 * @param   buf [IN] The buffer to send the key.
 * @param   len [IN] The length of the buffer.
 *
 * @retval  #HITLS_APP_SUCCESS.
 *          For other error codes, see app_errno.h.
 */
typedef int32_t (*HITLS_APP_SendFunc)(void *ctx, const void *buf, uint32_t len);

/**
 * @ingroup app_keymgmt
 * @brief   The function type to receive the key.
 *
 * @param   ctx [IN] The context of the function.
 * @param   buf [OUT] The buffer to receive.
 * @param   len [IN] The length of the buffer.
 *
 * @retval  #HITLS_APP_SUCCESS.
 *          For other error codes, see app_errno.h.
 */
typedef int32_t (*HITLS_APP_RecvFunc)(void *ctx, void *buf, uint32_t len);

/**
 * @ingroup app_keymgmt
 * @brief   The main function of the key management module.
 *
 * @param   argc [IN] The number of arguments.
 * @param   argv [IN] The arguments.
 *
 * @retval  #HITLS_APP_SUCCESS.
 *          For other error codes, see app_errno.h.
 */
int32_t HITLS_KeyMgmtMain(int argc, char *argv[]);

/**
 * @ingroup app_keymgmt
 * @brief   Find the key from the key file.
 *
 * @param   provider [IN] The provider of the application.
 * @param   smParam [IN] The parameter of the SM mode.
 * @param   algId [IN] The algorithm ID of the key.
 * @param   keyInfo [OUT] The key information.
 *
 * @retval  #HITLS_APP_SUCCESS.
 *          For other error codes, see app_errno.h.
 */
int32_t HITLS_APP_FindKey(AppProvider *provider, HITLS_APP_SM_Param *smParam, int32_t algId,
    HITLS_APP_KeyInfo *keyInfo);

/**
 * @ingroup app_keymgmt
 * @brief   Send the key to the remote device.
 *
 * @param   provider [IN] The provider of the application.
 * @param   smParam [IN] The parameter of the SM mode.
 * @param   sendFunc [IN] The function to send the key.
 * @param   ctx [IN] The context of the function.
 *
 * @retval  #HITLS_APP_SUCCESS.
 *          For other error codes, see app_errno.h.
 */
int32_t HITLS_APP_SendKey(AppProvider *provider, HITLS_APP_SM_Param *smParam, HITLS_APP_SendFunc sendFunc, void *ctx);

/**
 * @ingroup app_keymgmt
 * @brief   Receive the key from the remote device.
 *
 * @param   provider [IN] The provider of the application.
 * @param   smParam [IN] The parameter of the SM mode, don't need uuid.
 * @param   iter [IN] The iteration times for pkcs12 encryption.
 * @param   saltLen [IN] The salt length for pkcs12 encryption.
 * @param   recvFunc [IN] The function to receive the key.
 * @param   ctx [IN] The context of the function.
 *
 * @retval  #HITLS_APP_SUCCESS.
 *          For other error codes, see app_errno.h.
 */
int32_t HITLS_APP_ReceiveKey(AppProvider *provider, HITLS_APP_SM_Param *smParam, int32_t iter, int32_t saltLen,
    HITLS_APP_RecvFunc recvFunc, void *ctx);
#endif
#ifdef __cplusplus
}
#endif
#endif