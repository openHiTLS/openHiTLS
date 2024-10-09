/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HITLS_CMS_LOCAL_H
#define HITLS_CMS_LOCAL_H

#include "bsl_type.h"
#include "bsl_obj.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

// parse PKCS7-Data
int32_t CRYPT_EAL_ParseAsn1PKCS7Data(BSL_Buffer *encode, BSL_Buffer *dataValue);

// parse PKCS7-DigestInfo：only support hash.
int32_t CRYPT_EAL_ParseAsn1PKCS7DigestInfo(BSL_Buffer *encode, BslCid *cid, BSL_Buffer *digest);

// encode PKCS7-DigestInfo：only support hash.
int32_t CRYPT_EAL_EncodePKCS7DigestInfoBuff(BslCid cid, BSL_Buffer *in, BSL_Buffer **encode);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CMS_LOCAL_H
