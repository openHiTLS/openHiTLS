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

#ifndef REC_CRYPTO_TLS13_HMAC_H
#define REC_CRYPTO_TLS13_HMAC_H

#include "rec_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

const RecCryptoFunc *RecGetTls13IntegrityCryptoFuncs(DecryptPostProcess decryptPostProcess,
    EncryptPreProcess encryptPreProcess);

#ifdef __cplusplus
}
#endif

#endif /* REC_CRYPTO_TLS13_HMAC_H */
