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

#ifndef CRYPT_ASCON_LOCAL_H
#define CRYPT_ASCON_LOCAL_H

#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "bsl_sal.h"
#include "bsl_bytes.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_asconaead.h"
#include "crypt_asconhash.h"

#if defined(HITLS_CRYPTO_ASCONAEAD) || defined(HITLS_CRYPTO_ASCONHASH) 

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* ============ struct ============ */
typedef struct {
    uint64_t x0, x1, x2, x3, x4;
} state_t;

/* ============ word ============ */
typedef uint64_t word_t;

/* get byte from 64-bit Ascon word */
#define GETBYTE(x, i) ((uint8_t)((uint64_t)(x) >> (56 - 8 * (i))))

/* set byte in 64-bit Ascon word */
#define SETBYTE(b, i) ((uint64_t)(b) << (56 - 8 * (i)))

/* set padding byte in 64-bit Ascon word */
#define PAD(i) SETBYTE(0x80, i)

/* load bytes into 64-bit Ascon word */
static inline uint64_t LOADBYTES(const uint8_t* bytes, int n) 
{
    uint64_t x = 0;
    for (int i = 0; i < n; ++i) x |= SETBYTE(bytes[i], i);
    return x;
}

/* store bytes from 64-bit Ascon word */
static inline void STOREBYTES(uint8_t* bytes, uint64_t x, int n) 
{
    for (int i = 0; i < n; ++i) bytes[i] = GETBYTE(x, i);
}

/* clear bytes in 64-bit Ascon word */
static inline uint64_t CLEARBYTES(uint64_t x, int n) 
{
    for (int i = 0; i < n; ++i) x &= ~SETBYTE(0xff, i);
    return x;
}

/* ============ round ============ */
static inline uint64_t ROR(uint64_t x, int n) 
{
    return (x << (64 - n)) | (x >> n);
}

static inline void ROUND(state_t* s, uint8_t C) 
{
    state_t t;
    /* addition of round constant */
    s->x2 ^= C;
    /* substitution layer */
    s->x0 ^= s->x4;
    s->x4 ^= s->x3;
    s->x2 ^= s->x1;
    /* start of keccak s-box */
    t.x0 = s->x0 ^ (~s->x1 & s->x2);
    t.x1 = s->x1 ^ (~s->x2 & s->x3);
    t.x2 = s->x2 ^ (~s->x3 & s->x4);
    t.x3 = s->x3 ^ (~s->x4 & s->x0);
    t.x4 = s->x4 ^ (~s->x0 & s->x1);
    /* end of keccak s-box */
    t.x1 ^= t.x0;
    t.x0 ^= t.x4;
    t.x3 ^= t.x2;
    t.x2 = ~t.x2;
    /* linear diffusion layer */
    s->x0 = t.x0 ^ ROR(t.x0, 19) ^ ROR(t.x0, 28);
    s->x1 = t.x1 ^ ROR(t.x1, 61) ^ ROR(t.x1, 39);
    s->x2 = t.x2 ^ ROR(t.x2, 1) ^ ROR(t.x2, 6);
    s->x3 = t.x3 ^ ROR(t.x3, 10) ^ ROR(t.x3, 17);
    s->x4 = t.x4 ^ ROR(t.x4, 7) ^ ROR(t.x4, 41);
} 

/* ============ permutation ============ */
#define ASCON_128_KEYBYTES 16
#define ASCON_128A_KEYBYTES 16
#define ASCON_80PQ_KEYBYTES 20

#define ASCON_128_RATE 8
#define ASCON_128A_RATE 16
#define ASCON_HASH_RATE 8

#define ASCON_128_PA_ROUNDS 12
#define ASCON_128_PB_ROUNDS 6

#define ASCON_128A_PA_ROUNDS 12
#define ASCON_128A_PB_ROUNDS 8

#define ASCON_HASH_PA_ROUNDS 12
#define ASCON_HASH_PB_ROUNDS 12

#define ASCON_HASHA_PA_ROUNDS 12
#define ASCON_HASHA_PB_ROUNDS 8

#define ASCON_HASH_BYTES 32

#define ASCON_128_IV                            \
    (((uint64_t)(ASCON_128_KEYBYTES * 8) << 56) | \
    ((uint64_t)(ASCON_128_RATE * 8) << 48) |     \
    ((uint64_t)(ASCON_128_PA_ROUNDS) << 40) |    \
    ((uint64_t)(ASCON_128_PB_ROUNDS) << 32))

#define ASCON_128A_IV                            \
    (((uint64_t)(ASCON_128A_KEYBYTES * 8) << 56) | \
    ((uint64_t)(ASCON_128A_RATE * 8) << 48) |     \
    ((uint64_t)(ASCON_128A_PA_ROUNDS) << 40) |    \
    ((uint64_t)(ASCON_128A_PB_ROUNDS) << 32))

#define ASCON_80PQ_IV                            \
    (((uint64_t)(ASCON_80PQ_KEYBYTES * 8) << 56) | \
    ((uint64_t)(ASCON_128_RATE * 8) << 48) |      \
    ((uint64_t)(ASCON_128_PA_ROUNDS) << 40) |     \
    ((uint64_t)(ASCON_128_PB_ROUNDS) << 32))

#define ASCON_HASH_IV                                                \
    (((uint64_t)(ASCON_HASH_RATE * 8) << 48) |                         \
    ((uint64_t)(ASCON_HASH_PA_ROUNDS) << 40) |                        \
    ((uint64_t)(ASCON_HASH_PA_ROUNDS - ASCON_HASH_PB_ROUNDS) << 32) | \
    ((uint64_t)(ASCON_HASH_BYTES * 8) << 0))

#define ASCON_HASHA_IV                                                 \
    (((uint64_t)(ASCON_HASH_RATE * 8) << 48) |                           \
    ((uint64_t)(ASCON_HASHA_PA_ROUNDS) << 40) |                         \
    ((uint64_t)(ASCON_HASHA_PA_ROUNDS - ASCON_HASHA_PB_ROUNDS) << 32) | \
    ((uint64_t)(ASCON_HASH_BYTES * 8) << 0))


static inline void P12(state_t* s) 
{
    ROUND(s, 0xf0);
    ROUND(s, 0xe1);
    ROUND(s, 0xd2);
    ROUND(s, 0xc3);
    ROUND(s, 0xb4);
    ROUND(s, 0xa5);
    ROUND(s, 0x96);
    ROUND(s, 0x87);
    ROUND(s, 0x78);
    ROUND(s, 0x69);
    ROUND(s, 0x5a);
    ROUND(s, 0x4b);
}

static inline void P8(state_t* s) 
{
    ROUND(s, 0xb4);
    ROUND(s, 0xa5);
    ROUND(s, 0x96);
    ROUND(s, 0x87);
    ROUND(s, 0x78);
    ROUND(s, 0x69);
    ROUND(s, 0x5a);
    ROUND(s, 0x4b);
}

static inline void P6(state_t* s) 
{
    ROUND(s, 0x96);
    ROUND(s, 0x87);
    ROUND(s, 0x78);
    ROUND(s, 0x69);
    ROUND(s, 0x5a);
    ROUND(s, 0x4b);
}


#ifdef __cplusplus
}
#endif // __cplusplus

#endif /* HITLS_CRYPTO_ASCONAEAD || HITLS_CRYPTO_ASCONHASH */

#endif /* CRYPT_ASCON_LOCAL_H */
