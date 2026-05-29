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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ASCONAEAD

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_asconaead.h"
#include "ascon_core.h"

/* ============ Ctrl Command ============ */
#define CRYPT_CTRL_SET_ASCON_VARIANT  0x1001
#define CRYPT_CTRL_GET_ASCON_VARIANT  0x1002

/* ===== Unified internal encrypt (called by all three public encrypt functions) ===== */
static int ascon_aead_encrypt_internal(uint8_t* c, uint64_t* clen,
    const uint8_t* m, uint64_t mlen,
    const uint8_t* ad, uint64_t adlen,
    const uint8_t* nsec, const uint8_t* npub,
    const uint8_t* k, ASCON_VARIANT_E variant)
{
    (void)nsec;

    const uint8_t CRYPTO_ABYTES = 16;   /* same for all three variants */

    if (c == NULL || clen == NULL || npub == NULL || k == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (mlen > 0 && m == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (adlen > 0 && ad == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (mlen > ULLONG_MAX - CRYPTO_ABYTES) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CRYPTLEN_OVERFLOW);
        return CRYPT_MODES_CRYPTLEN_OVERFLOW;
    }

    /* set ciphertext size */
    *clen = mlen + CRYPTO_ABYTES;

    uint64_t K0 = 0;
    uint64_t K1 = 0;
    uint64_t K2 = 0;   /* only used by 80PQ */
    int ret = CRYPT_SUCCESS;

    /* load key and nonce */
    if (variant == ASCON_VARIANT_80PQ) {
        K0 = LOADBYTES(k + 0, 4) >> 32;
        K1 = LOADBYTES(k + 4, 8);
        K2 = LOADBYTES(k + 12, 8);
    } else {
        K0 = LOADBYTES(k, 8);
        K1 = LOADBYTES(k + 8, 8);
    }
    const uint64_t N0 = LOADBYTES(npub, 8);
    const uint64_t N1 = LOADBYTES(npub + 8, 8);

    /* initialize */
    state_t s;
    if (variant == ASCON_VARIANT_128) {
        s.x0 = ASCON_128_IV;  s.x1 = K0; s.x2 = K1;
    } else if (variant == ASCON_VARIANT_128A) {
        s.x0 = ASCON_128A_IV; s.x1 = K0; s.x2 = K1;
    } else { /* ASCON_VARIANT_80PQ */
        s.x0 = ASCON_80PQ_IV | K0; s.x1 = K1; s.x2 = K2;
    }
    s.x3 = N0;
    s.x4 = N1;
    P12(&s);
    if (variant == ASCON_VARIANT_80PQ) {
        s.x2 ^= K0; s.x3 ^= K1; s.x4 ^= K2;
    } else {
        s.x3 ^= K0; s.x4 ^= K1;
    }

    if (adlen) {
        if (variant == ASCON_VARIANT_128A) {
            /* full associated data blocks */
            while (adlen >= ASCON_128A_RATE) {
                s.x0 ^= LOADBYTES(ad, 8);
                s.x1 ^= LOADBYTES(ad + 8, 8);
                P8(&s);
                ad += ASCON_128A_RATE;
                adlen -= ASCON_128A_RATE;
            }
            /* final associated data block */
            if (adlen >= 8) {
                s.x0 ^= LOADBYTES(ad, 8);
                s.x1 ^= LOADBYTES(ad + 8, adlen - 8);
                s.x1 ^= PAD(adlen - 8);
            } else {
                s.x0 ^= LOADBYTES(ad, adlen);
                s.x0 ^= PAD(adlen);
            }
            P8(&s);
        } else {
            /* full associated data blocks */
            while (adlen >= ASCON_128_RATE) {
                s.x0 ^= LOADBYTES(ad, 8);
                P6(&s);
                ad += ASCON_128_RATE;
                adlen -= ASCON_128_RATE;
            }
            /* final associated data block */
            s.x0 ^= LOADBYTES(ad, adlen);
            s.x0 ^= PAD(adlen);
            P6(&s);
        }
    }
    /* domain separation */
    s.x4 ^= 1;

    if (variant == ASCON_VARIANT_128A) {
        /* full plaintext blocks */
        while (mlen >= ASCON_128A_RATE) {
            s.x0 ^= LOADBYTES(m, 8);
            s.x1 ^= LOADBYTES(m + 8, 8);
            STOREBYTES(c, s.x0, 8);
            STOREBYTES(c + 8, s.x1, 8);
            P8(&s);
            m += ASCON_128A_RATE;
            c += ASCON_128A_RATE;
            mlen -= ASCON_128A_RATE;
        }
        /* final plaintext block */
        if (mlen >= 8) {
            s.x0 ^= LOADBYTES(m, 8);
            s.x1 ^= LOADBYTES(m + 8, mlen - 8);
            STOREBYTES(c, s.x0, 8);
            STOREBYTES(c + 8, s.x1, mlen - 8);
            s.x1 ^= PAD(mlen - 8);
        } else {
            s.x0 ^= LOADBYTES(m, mlen);
            STOREBYTES(c, s.x0, mlen);
            s.x0 ^= PAD(mlen);
        }
    } else {
        /* full plaintext blocks */
        while (mlen >= ASCON_128_RATE) {
            s.x0 ^= LOADBYTES(m, 8);
            STOREBYTES(c, s.x0, 8);
            P6(&s);
            m += ASCON_128_RATE;
            c += ASCON_128_RATE;
            mlen -= ASCON_128_RATE;
        }
        /* final plaintext block */
        s.x0 ^= LOADBYTES(m, mlen);
        STOREBYTES(c, s.x0, mlen);
        s.x0 ^= PAD(mlen);
    }
    c += mlen;

    /* finalize */
    if (variant == ASCON_VARIANT_128) {
        s.x1 ^= K0; s.x2 ^= K1;
        P12(&s);
        s.x3 ^= K0; s.x4 ^= K1;
    } else if (variant == ASCON_VARIANT_128A) {
        s.x2 ^= K0; s.x3 ^= K1;
        P12(&s);
        s.x3 ^= K0; s.x4 ^= K1;
    } else { /* ASCON_VARIANT_80PQ */
        s.x1 ^= K0 << 32 | K1 >> 32;
        s.x2 ^= K1 << 32 | K2 >> 32;
        s.x3 ^= K2 << 32;
        P12(&s);
        s.x3 ^= K1; s.x4 ^= K2;
    }

    /* set tag */
    STOREBYTES(c, s.x3, 8);
    STOREBYTES(c + 8, s.x4, 8);

    goto cleanup;

cleanup:
    BSL_SAL_CleanseData(&s, sizeof(s));
    BSL_SAL_CleanseData(&K0, sizeof(K0));
    BSL_SAL_CleanseData(&K1, sizeof(K1));
    BSL_SAL_CleanseData(&K2, sizeof(K2));
    return ret;
}


/* ===== Unified internal decrypt (called by all three public decrypt functions) ===== */
static int ascon_aead_decrypt_internal(uint8_t* m, uint64_t* mlen,
    uint8_t* nsec, const uint8_t* c,
    uint64_t clen, const uint8_t* ad,
    uint64_t adlen, const uint8_t* npub,
    const uint8_t* k, ASCON_VARIANT_E variant)
{
    (void)nsec;

    const uint8_t CRYPTO_ABYTES = 16;   /* same for all three variants */

    if (m == NULL || mlen == NULL || c == NULL || npub == NULL || k == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (adlen > 0 && ad == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (clen < CRYPTO_ABYTES) {
        return CRYPT_INVALID_ARG;
    }

    /* set plaintext size */
    *mlen = clen - CRYPTO_ABYTES;

    uint64_t K0 = 0;
    uint64_t K1 = 0;
    uint64_t K2 = 0;   /* only used by 80PQ */
    uint8_t t[16];     /* CRYPTO_ABYTES = 16 for all variants */
    uint64_t c0 = 0;
    uint64_t c1 = 0;   /* only used by 128A */
    int ret = CRYPT_SUCCESS;

    /* load key and nonce */
    if (variant == ASCON_VARIANT_80PQ) {
        K0 = LOADBYTES(k + 0, 4) >> 32;
        K1 = LOADBYTES(k + 4, 8);
        K2 = LOADBYTES(k + 12, 8);
    } else {
        K0 = LOADBYTES(k, 8);
        K1 = LOADBYTES(k + 8, 8);
    }
    const uint64_t N0 = LOADBYTES(npub, 8);
    const uint64_t N1 = LOADBYTES(npub + 8, 8);

    /* initialize */
    state_t s;
    if (variant == ASCON_VARIANT_128) {
        s.x0 = ASCON_128_IV;  s.x1 = K0; s.x2 = K1;
    } else if (variant == ASCON_VARIANT_128A) {
        s.x0 = ASCON_128A_IV; s.x1 = K0; s.x2 = K1;
    } else { /* ASCON_VARIANT_80PQ */
        s.x0 = ASCON_80PQ_IV | K0; s.x1 = K1; s.x2 = K2;
    }
    s.x3 = N0;
    s.x4 = N1;
    P12(&s);
    if (variant == ASCON_VARIANT_80PQ) {
        s.x2 ^= K0; s.x3 ^= K1; s.x4 ^= K2;
    } else {
        s.x3 ^= K0; s.x4 ^= K1;
    }

    if (adlen) {
        if (variant == ASCON_VARIANT_128A) {
            /* full associated data blocks */
            while (adlen >= ASCON_128A_RATE) {
                s.x0 ^= LOADBYTES(ad, 8);
                s.x1 ^= LOADBYTES(ad + 8, 8);
                P8(&s);
                ad += ASCON_128A_RATE;
                adlen -= ASCON_128A_RATE;
            }
            /* final associated data block */
            if (adlen >= 8) {
                s.x0 ^= LOADBYTES(ad, 8);
                s.x1 ^= LOADBYTES(ad + 8, adlen - 8);
                s.x1 ^= PAD(adlen - 8);
            } else {
                s.x0 ^= LOADBYTES(ad, adlen);
                s.x0 ^= PAD(adlen);
            }
            P8(&s);
        } else {
            /* full associated data blocks */
            while (adlen >= ASCON_128_RATE) {
                s.x0 ^= LOADBYTES(ad, 8);
                P6(&s);
                ad += ASCON_128_RATE;
                adlen -= ASCON_128_RATE;
            }
            /* final associated data block */
            s.x0 ^= LOADBYTES(ad, adlen);
            s.x0 ^= PAD(adlen);
            P6(&s);
        }
    }
    /* domain separation */
    s.x4 ^= 1;

    /* full/final ciphertext blocks */
    clen -= CRYPTO_ABYTES;
    if (variant == ASCON_VARIANT_128A) {
        /* full ciphertext blocks */
        while (clen >= ASCON_128A_RATE) {
            c0 = LOADBYTES(c, 8);
            c1 = LOADBYTES(c + 8, 8);
            STOREBYTES(m, s.x0 ^ c0, 8);
            STOREBYTES(m + 8, s.x1 ^ c1, 8);
            s.x0 = c0;
            s.x1 = c1;
            P8(&s);
            m += ASCON_128A_RATE;
            c += ASCON_128A_RATE;
            clen -= ASCON_128A_RATE;
        }
        /* final ciphertext block */
        if (clen >= 8) {
            c0 = LOADBYTES(c, 8);
            c1 = LOADBYTES(c + 8, clen - 8);
            STOREBYTES(m, s.x0 ^ c0, 8);
            STOREBYTES(m + 8, s.x1 ^ c1, clen - 8);
            s.x0 = c0;
            s.x1 = CLEARBYTES(s.x1, clen - 8);
            s.x1 |= c1;
            s.x1 ^= PAD(clen - 8);
            m += clen;
        } else {
            c0 = LOADBYTES(c, clen);
            STOREBYTES(m, s.x0 ^ c0, clen);
            s.x0 = CLEARBYTES(s.x0, clen);
            s.x0 |= c0;
            s.x0 ^= PAD(clen);
            m += clen;
        }
    } else {
        /* full ciphertext blocks */
        while (clen >= ASCON_128_RATE) {
            c0 = LOADBYTES(c, 8);
            STOREBYTES(m, s.x0 ^ c0, 8);
            s.x0 = c0;
            P6(&s);
            m += ASCON_128_RATE;
            c += ASCON_128_RATE;
            clen -= ASCON_128_RATE;
        }
        /* final ciphertext block */
        c0 = LOADBYTES(c, clen);
        STOREBYTES(m, s.x0 ^ c0, clen);
        s.x0 = CLEARBYTES(s.x0, clen);
        s.x0 |= c0;
        s.x0 ^= PAD(clen);
        m += clen;
    }
    c += clen;

    /* finalize */
    if (variant == ASCON_VARIANT_128) {
        s.x1 ^= K0; s.x2 ^= K1;
        P12(&s);
        s.x3 ^= K0; s.x4 ^= K1;
    } else if (variant == ASCON_VARIANT_128A) {
        s.x2 ^= K0; s.x3 ^= K1;
        P12(&s);
        s.x3 ^= K0; s.x4 ^= K1;
    } else { /* ASCON_VARIANT_80PQ */
        s.x1 ^= K0 << 32 | K1 >> 32;
        s.x2 ^= K1 << 32 | K2 >> 32;
        s.x3 ^= K2 << 32;
        P12(&s);
        s.x3 ^= K1; s.x4 ^= K2;
    }

    /* set tag */
    STOREBYTES(t, s.x3, 8);
    STOREBYTES(t + 8, s.x4, 8);

    if (ConstTimeMemcmp(c, t, CRYPTO_ABYTES) == 0) {
        BSL_SAL_CleanseData(m - (*mlen), *mlen);
        ret = CRYPT_HPKE_ERR_AEAD_TAG;
        goto cleanup;
    }

cleanup:
    BSL_SAL_CleanseData(t, sizeof(t));
    BSL_SAL_CleanseData(&c0, sizeof(c0));
    BSL_SAL_CleanseData(&c1, sizeof(c1));
    BSL_SAL_CleanseData(&s, sizeof(s));
    BSL_SAL_CleanseData(&K0, sizeof(K0));
    BSL_SAL_CleanseData(&K1, sizeof(K1));
    BSL_SAL_CleanseData(&K2, sizeof(K2));
    return ret;
}


/* ============ ASCON_AEAD128 Encryption / Decryption ============ */
#ifdef HITLS_CRYPTO_ASCON_AEAD128
static int crypt_ascon_aead128_encrypt(uint8_t* c, uint64_t* clen,
    const uint8_t* m, uint64_t mlen,
    const uint8_t* ad, uint64_t adlen,
    const uint8_t* nsec, const uint8_t* npub,
    const uint8_t* k) 
{
    return ascon_aead_encrypt_internal(c, clen, m, mlen, ad, adlen,
                                       nsec, npub, k, ASCON_VARIANT_128);
}

static int crypt_ascon_aead128_decrypt(uint8_t* m, uint64_t* mlen,
    uint8_t* nsec, const uint8_t* c,
    uint64_t clen, const uint8_t* ad,
    uint64_t adlen, const uint8_t* npub,
    const uint8_t* k) 
{
    return ascon_aead_decrypt_internal(m, mlen, nsec, c, clen, ad,
                                       adlen, npub, k, ASCON_VARIANT_128);
}
#endif /* HITLS_CRYPTO_ASCON_AEAD128 */


/* ============ ASCON_AEAD128A Encryption / Decryption ============ */
#ifdef HITLS_CRYPTO_ASCON_AEAD128A
static int crypt_ascon_aead128a_encrypt(uint8_t* c, uint64_t* clen,
    const uint8_t* m, uint64_t mlen,
    const uint8_t* ad, uint64_t adlen,
    const uint8_t* nsec, const uint8_t* npub,
    const uint8_t* k) 
{
    return ascon_aead_encrypt_internal(c, clen, m, mlen, ad, adlen,
                                       nsec, npub, k, ASCON_VARIANT_128A);
}

static int crypt_ascon_aead128a_decrypt(uint8_t* m, uint64_t* mlen,
    uint8_t* nsec, const uint8_t* c,
    uint64_t clen, const uint8_t* ad,
    uint64_t adlen, const uint8_t* npub,
    const uint8_t* k) 
{
    return ascon_aead_decrypt_internal(m, mlen, nsec, c, clen, ad,
                                       adlen, npub, k, ASCON_VARIANT_128A);
}
#endif /* HITLS_CRYPTO_ASCON_AEAD128A */


/* ============ ASCON_AEAD80PQ Encryption / Decryption ============ */
#ifdef HITLS_CRYPTO_ASCON_AEAD80PQ
static int crypt_ascon_aead80pq_encrypt(uint8_t* c, uint64_t* clen,
    const uint8_t* m, uint64_t mlen,
    const uint8_t* ad, uint64_t adlen,
    const uint8_t* nsec, const uint8_t* npub,
    const uint8_t* k) 
{
    return ascon_aead_encrypt_internal(c, clen, m, mlen, ad, adlen,
                                       nsec, npub, k, ASCON_VARIANT_80PQ);
}

static int crypt_ascon_aead80pq_decrypt(uint8_t* m, uint64_t* mlen,
    uint8_t* nsec, const uint8_t* c,
    uint64_t clen, const uint8_t* ad,
    uint64_t adlen, const uint8_t* npub,
    const uint8_t* k) 
{
    return ascon_aead_decrypt_internal(m, mlen, nsec, c, clen, ad,
                                       adlen, npub, k, ASCON_VARIANT_80PQ);
}
#endif /* HITLS_CRYPTO_ASCON_AEAD80PQ */


/* ============ ASCONAEAD VariantConfig ============ */
static const ASCON_VariantConfig g_asconConfigs[ASCON_VARIANT_MAX] = {
#ifdef HITLS_CRYPTO_ASCON_AEAD128
    [ASCON_VARIANT_128] = {
        .variant = ASCON_VARIANT_128, .keyLen = 16, .nonceLen = 16, .tagLen = 16,
        .rate = 8, .rounds_ad = 6, .rounds_init = 12, .iv_const = ASCON_128_IV,
        .encrypt = crypt_ascon_aead128_encrypt, .decrypt = crypt_ascon_aead128_decrypt
    },
#endif
#ifdef HITLS_CRYPTO_ASCON_AEAD128A
    [ASCON_VARIANT_128A] = {
        .variant = ASCON_VARIANT_128A, .keyLen = 16, .nonceLen = 16, .tagLen = 16,
        .rate = 16, .rounds_ad = 8, .rounds_init = 12, .iv_const = ASCON_128A_IV,
        .encrypt = crypt_ascon_aead128a_encrypt, .decrypt = crypt_ascon_aead128a_decrypt
    },
#endif
#ifdef HITLS_CRYPTO_ASCON_AEAD80PQ
    [ASCON_VARIANT_80PQ] = {
        .variant = ASCON_VARIANT_80PQ, .keyLen = 20, .nonceLen = 16, .tagLen = 16,
        .rate = 8, .rounds_ad = 6, .rounds_init = 12, .iv_const = ASCON_80PQ_IV,
        .encrypt = crypt_ascon_aead80pq_encrypt, .decrypt = crypt_ascon_aead80pq_decrypt
    },
#endif
};


/* ============ Helper: append data to a growable buffer ============ */
static int32_t buffer_append(CRYPT_ASCONAEAD_Ctx *ctx, const uint8_t *data, uint32_t dataLen)
{
    if (dataLen == 0) {
        return CRYPT_SUCCESS;
    }
    if (dataLen > UINT32_MAX - ctx->inLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CRYPTLEN_OVERFLOW);
        return CRYPT_MODES_CRYPTLEN_OVERFLOW;
    }
    uint32_t newLen = ctx->inLen + dataLen;
    if (newLen > ctx->inCap) {
        size_t newCapSize = ((size_t)newLen + 1023U) & ~(size_t)1023U;
        if (newCapSize > UINT32_MAX) {
            BSL_ERR_PUSH_ERROR(CRYPT_MODES_CRYPTLEN_OVERFLOW);
            return CRYPT_MODES_CRYPTLEN_OVERFLOW;
        }
        uint32_t newCap = (uint32_t)newCapSize;
        uint8_t *newBuf = (uint8_t *)BSL_SAL_Realloc(ctx->in, newCap, ctx->inCap);
        if (newBuf == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        ctx->in = newBuf;
        ctx->inCap = newCap;
    }
    memcpy(ctx->in + ctx->inLen, data, dataLen);
    ctx->inLen = newLen;
    return CRYPT_SUCCESS;
}


/* ============ API Implementation ============ */
CRYPT_ASCONAEAD_Ctx *CRYPT_ASCONAEAD_NewCtx(int32_t algId)
{
    CRYPT_ASCONAEAD_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_ASCONAEAD_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    /*
     * Map EAL cipher algorithm IDs to ASCON variant indices.
     * Note: algId is the EAL cipher AlgId (e.g., CRYPT_CIPHER_ASCON_AEAD128 = 2501),
     * NOT the ASCON_Variant_E enum value. We must translate it.
     */
    int32_t variant = 0; /* will be set by switch; default case returns NULL before use */
    switch (algId) {
#ifdef HITLS_CRYPTO_ASCON_AEAD128
        case CRYPT_CIPHER_ASCON_AEAD128:
            variant = ASCON_VARIANT_128;
            break;
#endif
#ifdef HITLS_CRYPTO_ASCON_AEAD128A
        case CRYPT_CIPHER_ASCON_AEAD128A:
            variant = ASCON_VARIANT_128A;
            break;
#endif
#ifdef HITLS_CRYPTO_ASCON_AEAD80PQ
        case CRYPT_CIPHER_ASCON_AEAD80PQ:
            variant = ASCON_VARIANT_80PQ;
            break;
#endif
        default:
            BSL_SAL_Free(ctx);
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return NULL;
    }
    ctx->config = &g_asconConfigs[variant];
    return ctx;
}

CRYPT_ASCONAEAD_Ctx *CRYPT_ASCONAEAD_NewCtxEx(void *libCtx, int32_t algId)
{
    (void)libCtx;
    return CRYPT_ASCONAEAD_NewCtx(algId);
}

int32_t CRYPT_ASCONAEAD_InitCtx(CRYPT_ASCONAEAD_Ctx *ctx, const uint8_t *key, uint32_t keyLen,
    const uint8_t *iv, uint32_t ivLen, void *param, bool enc)
{
    if (ctx == NULL || key == NULL || iv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (keyLen != ctx->config->keyLen || ivLen != ctx->config->nonceLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    (void)param;

    memcpy(ctx->key, key, keyLen);
    memcpy(ctx->nonce, iv, ivLen);
    ctx->enc = enc;
    ctx->initialized = true;
    ctx->aadSet = false;
    ctx->tagValid = false;
    ctx->vfyTagLen = 0;

    if (ctx->aad != NULL) {
        BSL_SAL_CleanseData(ctx->aad, ctx->aadLen);
        BSL_SAL_Free(ctx->aad);
        ctx->aad = NULL;
        ctx->aadLen = 0;
    }
    if (ctx->in != NULL) {
        BSL_SAL_CleanseData(ctx->in, ctx->inCap);
        BSL_SAL_Free(ctx->in);
        ctx->in = NULL;
        ctx->inLen = 0;
        ctx->inCap = 0;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ASCONAEAD_Update(CRYPT_ASCONAEAD_Ctx *ctx, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (!ctx->initialized) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
    *outLen = 0;
    if (inLen == 0) {
        return CRYPT_SUCCESS;
    }
    if (in == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    return buffer_append(ctx, in, inLen);
}

int32_t CRYPT_ASCONAEAD_Final(CRYPT_ASCONAEAD_Ctx *ctx, uint8_t *out, uint32_t *outLen)
{
    if (ctx == NULL || out == NULL || outLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (!ctx->initialized) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    const ASCON_VariantConfig *cfg = ctx->config;
    uint64_t outLen64 = 0;
    int32_t ret = CRYPT_SUCCESS;
    uint32_t tagLen = cfg->tagLen;

    if (ctx->enc) {
        /* Encrypt: output = ciphertext || tag, written from out[0] */
        if (ctx->inLen > UINT32_MAX - tagLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_MODES_CRYPTLEN_OVERFLOW);
            return CRYPT_MODES_CRYPTLEN_OVERFLOW;
        }
        if (*outLen < ctx->inLen + tagLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
            return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
        }
        ret = cfg->encrypt(out, &outLen64, ctx->in, ctx->inLen,
                           ctx->aad, ctx->aadLen, NULL, ctx->nonce, ctx->key);
        if (ret == CRYPT_SUCCESS) {
            /* Save tag to tagBuf for CRYPT_CTRL_GET_TAG */
            uint64_t ctLen = outLen64 - tagLen;
            if (ctLen <= UINT32_MAX) {
                memcpy(ctx->tagBuf, out + (uint32_t)ctLen, tagLen);
                ctx->tagValid = true;
            }
            *outLen = (uint32_t)outLen64;
        } else {
            *outLen = 0;
            BSL_ERR_PUSH_ERROR(ret);
        }
    } else {
        /* Decrypt: output = plaintext, written from out[0], verifies tag internally */
        if (ctx->vfyTagLen > 0) {
            /* Tag was set via CRYPT_CTRL_SET_TAG: append vfyTag to ciphertext and call
               decrypt which performs constant-time tag verification internally,
               consistent with GCM's tag verification approach */
            if (ctx->vfyTagLen != tagLen) {
                BSL_ERR_PUSH_ERROR(CRYPT_MODES_TAGLEN_ERROR);
                return CRYPT_MODES_TAGLEN_ERROR;
            }
            if (ctx->inLen > UINT32_MAX - tagLen) {
                BSL_ERR_PUSH_ERROR(CRYPT_MODES_CRYPTLEN_OVERFLOW);
                return CRYPT_MODES_CRYPTLEN_OVERFLOW;
            }
            uint32_t packedLen = ctx->inLen + tagLen;
            if (*outLen < ctx->inLen) {
                BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
                return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
            }
            uint8_t *packed = (uint8_t *)BSL_SAL_Malloc(packedLen);
            if (packed == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            memcpy(packed, ctx->in, ctx->inLen);
            memcpy(packed + ctx->inLen, ctx->vfyTag, tagLen);
            ret = cfg->decrypt(out, &outLen64, NULL, packed, packedLen,
                               ctx->aad, ctx->aadLen, ctx->nonce, ctx->key);
            BSL_SAL_ClearFree(packed, packedLen);
        } else {
            /* Tag is appended to ctx->in already */
            if (ctx->inLen < tagLen || *outLen < (ctx->inLen - tagLen)) {
                BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
                return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
            }
            ret = cfg->decrypt(out, &outLen64, NULL, ctx->in, ctx->inLen,
                               ctx->aad, ctx->aadLen, ctx->nonce, ctx->key);
        }
        if (ret == CRYPT_SUCCESS) {
            *outLen = (uint32_t)outLen64;
        } else {
            *outLen = 0;
            BSL_ERR_PUSH_ERROR(ret);
        }
    }

    /* Clean up buffers */
    if (ctx->aad != NULL) {
        BSL_SAL_CleanseData(ctx->aad, ctx->aadLen);
        BSL_SAL_Free(ctx->aad);
        ctx->aad = NULL;
        ctx->aadLen = 0;
        ctx->aadSet = false;
    }
    if (ctx->in != NULL) {
        BSL_SAL_CleanseData(ctx->in, ctx->inCap);
        BSL_SAL_Free(ctx->in);
        ctx->in = NULL;
        ctx->inLen = 0;
        ctx->inCap = 0;
    }
    ctx->initialized = false;
    return ret;
}

int32_t CRYPT_ASCONAEAD_DeInitCtx(CRYPT_ASCONAEAD_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->aad != NULL) {
        BSL_SAL_CleanseData(ctx->aad, ctx->aadLen);
        BSL_SAL_Free(ctx->aad);
        ctx->aad = NULL;
        ctx->aadLen = 0;
    }
    if (ctx->in != NULL) {
        BSL_SAL_CleanseData(ctx->in, ctx->inCap);
        BSL_SAL_Free(ctx->in);
        ctx->in = NULL;
        ctx->inLen = 0;
        ctx->inCap = 0;
    }
    BSL_SAL_CleanseData(ctx->key, sizeof(ctx->key));
    BSL_SAL_CleanseData(ctx->nonce, sizeof(ctx->nonce));
    BSL_SAL_CleanseData(ctx->tagBuf, sizeof(ctx->tagBuf));
    BSL_SAL_CleanseData(ctx->vfyTag, sizeof(ctx->vfyTag));
    ctx->vfyTagLen = 0;
    ctx->initialized = false;
    ctx->aadSet = false;
    ctx->tagValid = false;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ASCONAEAD_Ctrl(CRYPT_ASCONAEAD_Ctx *ctx, int32_t cmd, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    switch (cmd) {
        case CRYPT_CTRL_SET_AAD: {
            if (ctx->aadSet || ctx->inLen > 0) {
                BSL_ERR_PUSH_ERROR(CRYPT_MODES_AAD_REPEAT_SET_ERROR);
                return CRYPT_MODES_AAD_REPEAT_SET_ERROR;
            }
            if (val == NULL && len > 0) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            if (len == 0) {
                return CRYPT_SUCCESS;
            }
            ctx->aad = BSL_SAL_Malloc(len);
            if (ctx->aad == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            memcpy(ctx->aad, val, len);
            ctx->aadLen = len;
            ctx->aadSet = true;
            return CRYPT_SUCCESS;
        }
        case CRYPT_CTRL_SET_TAG:
            /* Consistent with MODES_SetVfyTag: val must be non-NULL and len > 0 */
            if (val == NULL || len == 0) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            if (len > sizeof(ctx->vfyTag)) {
                BSL_ERR_PUSH_ERROR(CRYPT_MODES_TAGLEN_ERROR);
                return CRYPT_MODES_TAGLEN_ERROR;
            }
            memcpy(ctx->vfyTag, val, len);
            ctx->vfyTagLen = len;
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_GET_TAG:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            if (len == 0 || len > ctx->config->tagLen) {
                BSL_ERR_PUSH_ERROR(CRYPT_MODES_TAGLEN_ERROR);
                return CRYPT_MODES_TAGLEN_ERROR;
            }
            /* Tag is only available after encryption Final */
            if (!ctx->tagValid) {
                BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
                return CRYPT_EAL_ERR_STATE;
            }
            memcpy(val, ctx->tagBuf, len);
            return CRYPT_SUCCESS;
        case CRYPT_CTRL_REINIT_STATUS: {
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            if (len != ctx->config->nonceLen) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            memcpy(ctx->nonce, val, len);
            ctx->initialized = true;
            ctx->aadSet = false;
            ctx->tagValid = false;
            /* Clear vfyTag on reinit, consistent with GCM MODES_ClearVfyTag */
            BSL_SAL_CleanseData(ctx->vfyTag, sizeof(ctx->vfyTag));
            ctx->vfyTagLen = 0;
            
            if (ctx->aad != NULL) {
                BSL_SAL_CleanseData(ctx->aad, ctx->aadLen);
                BSL_SAL_Free(ctx->aad);
                ctx->aad = NULL;
                ctx->aadLen = 0;
            }
            if (ctx->in != NULL) {
                BSL_SAL_CleanseData(ctx->in, ctx->inCap);
                BSL_SAL_Free(ctx->in);
                ctx->in = NULL;
                ctx->inLen = 0;
                ctx->inCap = 0;
            }
            return CRYPT_SUCCESS;
        }
        case CRYPT_CTRL_SET_ASCON_VARIANT: {
            if (ctx->initialized) {
                BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
                return CRYPT_EAL_ERR_STATE;
            }
            if (val == NULL || len != sizeof(int32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            int32_t variant = *(int32_t *)val;
            if (variant < 0 || variant >= ASCON_VARIANT_MAX) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            ctx->config = &g_asconConfigs[variant];
            return CRYPT_SUCCESS;
        }
        case CRYPT_CTRL_GET_ASCON_VARIANT: {
            if (val == NULL || len != sizeof(int32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            *(int32_t *)val = (int32_t)ctx->config->variant;
            return CRYPT_SUCCESS;
        }
        default:
            return CRYPT_INVALID_ARG;
    }
}

void CRYPT_ASCONAEAD_FreeCtx(CRYPT_ASCONAEAD_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    if (ctx->aad != NULL) {
        BSL_SAL_CleanseData(ctx->aad, ctx->aadLen);
        BSL_SAL_Free(ctx->aad);
    }
    if (ctx->in != NULL) {
        BSL_SAL_CleanseData(ctx->in, ctx->inCap);
        BSL_SAL_Free(ctx->in);
    }
    BSL_SAL_CleanseData(ctx->key, sizeof(ctx->key));
    BSL_SAL_CleanseData(ctx->nonce, sizeof(ctx->nonce));
    BSL_SAL_Free(ctx);
}

CRYPT_ASCONAEAD_Ctx *CRYPT_ASCONAEAD_DupCtx(const CRYPT_ASCONAEAD_Ctx *src)
{
    if (src == NULL) {
        return NULL;
    }
    CRYPT_ASCONAEAD_Ctx *dst = BSL_SAL_Malloc(sizeof(CRYPT_ASCONAEAD_Ctx));
    if (dst == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    memcpy(dst, src, sizeof(CRYPT_ASCONAEAD_Ctx));

    dst->aad = NULL;
    dst->in = NULL;
    dst->aadLen = 0;
    dst->inLen = 0;
    dst->inCap = 0;

    if (src->aadLen > 0 && src->aad != NULL) {
        dst->aad = BSL_SAL_Malloc(src->aadLen);
        if (dst->aad == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            BSL_SAL_Free(dst);
            return NULL;
        }
        memcpy(dst->aad, src->aad, src->aadLen);
        dst->aadLen = src->aadLen;
    }

    if (src->inLen > 0 && src->in != NULL) {
        dst->in = BSL_SAL_Malloc(src->inCap);
        if (dst->in == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            if (dst->aad != NULL) {
                BSL_SAL_CleanseData(dst->aad, dst->aadLen);
                BSL_SAL_Free(dst->aad);
            }
            BSL_SAL_Free(dst);
            return NULL;
        }
        memcpy(dst->in, src->in, src->inCap);
        dst->inLen = src->inLen;
        dst->inCap = src->inCap;
    }
    return dst;
}

#endif /* HITLS_CRYPTO_ASCONAEAD */