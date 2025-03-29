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
#ifndef CONFIG_TYPE_H
#define CONFIG_TYPE_H

#include <stdint.h>
#include <stdbool.h>
#include "hitls_type.h"
#include "tls_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Load group information
 * @param config: config context
 * @return HITLS_SUCCESS: success, other: error
 */
int32_t ConfigLoadGroupInfo(HITLS_Config *config);

/**
 * @brief Get group information
 * @param config: config context
 * @param groupId: group id
 * @return group information
 */
const TLS_GroupInfo *ConfigGetGroupInfo(const HITLS_Config *config, uint16_t groupId);

/**
 * @brief Get group information list
 * @param config: config context
 * @param size: size of group information list
 * @return group information list
 */
const TLS_GroupInfo *ConfigGetGroupInfoList(const HITLS_Config *config, uint32_t *size);

/**
 * @brief Load signature scheme information
 * @param config: config context
 * @return HITLS_SUCCESS: success, other: error
 */
int32_t ConfigLoadSignatureSchemeInfo(HITLS_Config *config);

/**
 * @brief Get signature scheme information
 * @param config: config context
 * @param signatureScheme: signature scheme
 * @return signature scheme information
 */
const TLS_SigSchemeInfo *ConfigGetSignatureSchemeInfo(const HITLS_Config *config, uint16_t signatureScheme);

/**
 * @brief Get signature scheme information list
 * @param config: config context
 * @param size: size of signature scheme information list
 * @return signature scheme information list
 */
const TLS_SigSchemeInfo *ConfigGetSignatureSchemeInfoList(const HITLS_Config *config, uint32_t *size);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_TYPE_H */
