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

#ifndef CONFIG_CHECK_H
#define CONFIG_CHECK_H

#include <stdint.h>
#include "tls.h"
#include "hitls_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/** check the version */
int32_t CheckVersion(uint16_t minVersion, uint16_t maxVersion);

/** check whether the TLS configuration is valid */
int32_t CheckConfig(const HITLS_Config *config);

uint32_t MapVersion2VersionBit(bool isDatagram, uint16_t version);

void ChangeMinMaxVersion(uint32_t versionMask, uint32_t originVersionMask, uint16_t *minVersion, uint16_t *maxVersion);

int32_t CheckRenegotiatedVersion(TLS_Ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif