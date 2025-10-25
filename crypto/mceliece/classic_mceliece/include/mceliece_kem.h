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

#ifndef MCELIECE_KEM_H
#define MCELIECE_KEM_H

#include "mceliece_types.h"
#include "mceliece_shake.h"
#include "mceliece_decode.h"
#include "mceliece_encode.h"
#include "mceliece_keygen.h"
#include "mceliece_poly.h"
#include "mceliece_controlbits.h"
#include "mceliece_rng.h"

#ifdef __cplusplus
extern "C" {
#endif

McElieceError McElieceKeygen(CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params);
// SeededKeyGen variant producing semi-systematic public key; stores pivots in sk->c
McElieceError McElieceKeygenSemi(CMPublicKey *pk, CMPrivateKey *sk, const McelieceParams *params);

McElieceError McElieceEncaps(uint8_t *ciphertext, const CMPublicKey *pk, uint8_t *sessionKey, const McelieceParams *params);
McElieceError McElieceEncapsPC(uint8_t *ciphertext, const CMPublicKey *pk, uint8_t *sessionKey, const McelieceParams *params);

McElieceError McElieceDecaps(const uint8_t *ciphertext, const CMPrivateKey *sk, uint8_t *sessionKey, const McelieceParams *params);
McElieceError McElieceDecapPC(const uint8_t *ciphertext, const CMPrivateKey *sk, uint8_t *sessionKey, const McelieceParams *params);

#ifdef __cplusplus
}
#endif

#endif // MCELIECE_KEM_H
