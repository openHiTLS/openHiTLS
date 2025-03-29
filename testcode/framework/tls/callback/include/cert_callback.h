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

#ifndef CERT_CALLBACK_H
#define CERT_CALLBACK_H

#include "hlt_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief  Certificate callback
*/
int32_t RegCertCallback(CertCallbackType type);

/**
* @brief  Memory callback
*/
int32_t RegMemCallback(MemCallbackType type);

/**
* @brief  Loading Certificates and Private Keys by hitls x509
*/
int32_t HiTLS_X509_LoadCertAndKey(HITLS_Config *tlsCfg, const char *caFile, const char *chainFile,
    const char *eeFile, const char *signFile, const char *privateKeyFile, const char *signPrivateKeyFile);

void BinLogFixLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para1, void *para2, void *para3, void *para4);

void BinLogVarLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para);

void RegDefaultMemCallback(void);
	
#ifdef __cplusplus
}
#endif

#endif // CERT_CALLBACK_H