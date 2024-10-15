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
int32_t CRYPT_EAL_EncodePKCS7DigestInfoBuff(BslCid cid, BSL_Buffer *in, BSL_Buffer *encode);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CMS_LOCAL_H
