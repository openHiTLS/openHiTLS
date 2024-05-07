/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
	
#ifdef __cplusplus
}
#endif

#endif // CERT_CALLBACK_H