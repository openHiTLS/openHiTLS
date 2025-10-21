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

#ifndef CRYPT_UTILS_H
#define CRYPT_UTILS_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_local_types.h"
#include "bsl_params.h"
#include "crypt_params_key.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define BITS_PER_BYTE   8
#define SHIFTS_PER_BYTE 3
#define BITSIZE(t)      (sizeof(t) * BITS_PER_BYTE)

#if defined(__GNUC__) || defined(__clang__)
    #define LIKELY(x) __builtin_expect(!!(x), 1)
    #define UNLIKELY(x) __builtin_expect(!!(x), 0)
    #define ALIGN32     __attribute__((aligned(32)))
    #define ALIGN64     __attribute__((aligned(64)))
#else
    #define LIKELY(x) x
    #define UNLIKELY(x) x
    #define ALIGN32
    #define ALIGN64
#endif

#define FORCE_ADDR_ALIGN 1
#if defined(__x86_64) || defined(__x86_64__) || defined(__aarch64__)
    #undef FORCE_ADDR_ALIGN
#endif

#define PUT_UINT32_BE(v, p, i)               \
do {                                         \
    (p)[(i) + 0] = (uint8_t)((v) >> 24);     \
    (p)[(i) + 1] = (uint8_t)((v) >> 16);     \
    (p)[(i) + 2] = (uint8_t)((v) >>  8);     \
    (p)[(i) + 3] = (uint8_t)((v) >>  0);     \
} while (0)

#define PUT_UINT64_BE(v, p, i)               \
do {                                         \
    (p)[(i) + 0] = (uint8_t)((v) >> 56);     \
    (p)[(i) + 1] = (uint8_t)((v) >> 48);     \
    (p)[(i) + 2] = (uint8_t)((v) >> 40);     \
    (p)[(i) + 3] = (uint8_t)((v) >> 32);     \
    (p)[(i) + 4] = (uint8_t)((v) >> 24);     \
    (p)[(i) + 5] = (uint8_t)((v) >> 16);     \
    (p)[(i) + 6] = (uint8_t)((v) >>  8);     \
    (p)[(i) + 7] = (uint8_t)((v) >>  0);     \
} while (0)

#define GET_UINT32_BE(p, i)                  \
(                                            \
    ((uint32_t)(p)[(i) + 0] << 24) |         \
    ((uint32_t)(p)[(i) + 1] << 16) |         \
    ((uint32_t)(p)[(i) + 2] <<  8) |         \
    ((uint32_t)(p)[(i) + 3] <<  0)           \
)

#define PUT_UINT32_LE(v, p, i)               \
do {                                         \
    (p)[(i) + 3] = (uint8_t)((v) >> 24);     \
    (p)[(i) + 2] = (uint8_t)((v) >> 16);     \
    (p)[(i) + 1] = (uint8_t)((v) >>  8);     \
    (p)[(i) + 0] = (uint8_t)((v) >>  0);     \
} while (0)

#define PUT_UINT64_LE(v, p, i) do {          \
    (p)[(i) + 7] = (uint8_t)((v) >> 56);     \
    (p)[(i) + 6] = (uint8_t)((v) >> 48);     \
    (p)[(i) + 5] = (uint8_t)((v) >> 40);     \
    (p)[(i) + 4] = (uint8_t)((v) >> 32);     \
    (p)[(i) + 3] = (uint8_t)((v) >> 24);     \
    (p)[(i) + 2] = (uint8_t)((v) >> 16);     \
    (p)[(i) + 1] = (uint8_t)((v) >>  8);     \
    (p)[(i) + 0] = (uint8_t)((v) >>  0);     \
} while (0)

#define GET_UINT64_LE(p, i)                                            \
(                                                                      \
    ((uint64_t)(p)[(i) + 7] << 56) | ((uint64_t)(p)[(i) + 6] << 48) |  \
    ((uint64_t)(p)[(i) + 5] << 40) | ((uint64_t)(p)[(i) + 4] << 32) |  \
    ((uint64_t)(p)[(i) + 3] << 24) | ((uint64_t)(p)[(i) + 2] << 16) |  \
    ((uint64_t)(p)[(i) + 1] <<  8) | ((uint64_t)(p)[(i) + 0] <<  0)    \
)

/**
 * Check whether conditions are met. If yes, an error code is returned.
 */

/**
 * If the return value of func is not CRYPT_SUCCESS, go to the label ERR.
 */
#define GOTO_ERR_IF(func, ret) do { \
        (ret) = (func); \
        if ((ret) != CRYPT_SUCCESS) { \
            BSL_ERR_PUSH_ERROR((ret)); \
            goto ERR; \
        } \
    } while (0)

#define GOTO_ERR_IF_EX(func, ret) do { \
        (ret) = (func); \
        if ((ret) != CRYPT_SUCCESS) { \
            goto ERR; \
        } \
    } while (0)

#define GOTO_ERR_IF_TRUE(condition, ret) do { \
        if (condition) { \
            BSL_ERR_PUSH_ERROR((ret)); \
            goto ERR; \
        } \
    } while (0)

/**
 * Check whether conditions are met. If yes, an error code is returned.
 */
#define RETURN_RET_IF(condition, ret) \
    do {                              \
        if (condition) {              \
            BSL_ERR_PUSH_ERROR(ret);  \
            return ret;               \
        }                             \
    } while (0)


#define RETURN_RET_IF_ERR(func, ret)   \
    do {                               \
        (ret) = (func);                \
        if ((ret) != CRYPT_SUCCESS) {  \
            BSL_ERR_PUSH_ERROR((ret)); \
            return ret;                \
        }                              \
    } while (0)

#define RETURN_RET_IF_ERR_EX(func, ret)   \
    do {                               \
        (ret) = (func);                \
        if ((ret) != CRYPT_SUCCESS) {  \
            return ret;                \
        }                              \
    } while (0)

#define BREAK_IF(condition) \
        if (condition) {    \
            break;          \
        }

/**
 * If src is not NULL, then execute the fun function. If the operation fails, go to the label ERR.
 */
#define GOTO_ERR_IF_SRC_NOT_NULL(dest, src, func, ret)                  \
    do {                                                    \
        if ((src) != NULL) {                                \
            (dest) = (func);                                \
            if ((dest) == NULL) {                           \
                BSL_ERR_PUSH_ERROR((ret));                           \
                goto ERR;                                   \
            }                                               \
        }                                                   \
    } while (0)

/**
 * @brief Perform the XOR operation on the data of two arrays.
 *
 * @param a [IN] Input data a
 * @param b [IN] Input data b
 * @param r [out] Output the result data.
 * @param len [IN] Output result data length
 */
#define DATA_XOR(a, b, r, len)       \
    do {                             \
        uint32_t subscript;          \
        for (subscript = 0; subscript < (len); subscript++) { \
            (r)[subscript] = (a)[subscript] ^ (b)[subscript]; \
        }                             \
    } while (0)

/**
 * @brief Perform the XOR operation on the data of 32 bits in two arrays each time.
 * Ensure that the input and output are integer multiples of 32 bits.
 * Type conversion is performed only when the address is 4-byte aligned.
 *
 * @param a [IN] Input data a
 * @param b [IN] Input data b
 * @param r [out] Output the result data.
 * @param len [IN] Output result data length
 */
#ifdef FORCE_ADDR_ALIGN
#define DATA32_XOR(a, b, r, len)                  \
    do {                                          \
        for (uint32_t ii = 0; ii < (len); ii++) { \
            (r)[ii] = (a)[ii] ^ (b)[ii];          \
        }                                         \
    } while (0)
#else
#define DATA32_XOR(a, b, r, len)                                                                         \
    do {                                                                                                 \
        for (uint32_t ii = 0; ii < (len); ii += 4) {                                                     \
            *(uint32_t *)((uintptr_t)(r) + ii) =                                                         \
                (*(const uint32_t *)((uintptr_t)(a) + ii)) ^ (*(const uint32_t *)((uintptr_t)(b) + ii)); \
        }                                                                                                \
    } while (0)
#endif
/**
 * @brief Perform the XOR operation on 64 bits of data in two arrays each time.
 * Ensure that the input and output are integer multiples of 64 bits.
 * Type conversion is performed only when the address is 8-byte aligned.
 *
 * @param a [IN] Input data a
 * @param b [IN] Input data b
 * @param r [out] Output the result data.
 * @param len [IN] Output result data length
 */
#define DATA64_XOR(a, b, r, len)                                \
    do {                                                        \
        uint32_t ii;                                            \
        uintptr_t aPtr = (uintptr_t)(a);                        \
        uintptr_t bPtr = (uintptr_t)(b);                        \
        uintptr_t rPtr = (uintptr_t)(r);                        \
        if (((aPtr & 0x7) != 0) || ((bPtr & 0x7) != 0) || ((rPtr & 0x7) != 0)) {     \
            for (ii = 0; ii < (len); ii++) {                    \
                (r)[ii] = (a)[ii] ^ (b)[ii];                    \
            }                                                   \
        } else {                                                \
            for (ii = 0; ii < (len); ii += 8) {                 \
                *(uint64_t *)((rPtr) + ii) = (*(const uint64_t *)((aPtr) + ii)) ^ (*(const uint64_t *)((bPtr) + ii)); \
            }                                                   \
        }                                                       \
    } while (0)

/**
 * @brief Calculate the hash value of the input data.
 *
 * @param provCtx [IN] Provider context
 * @param hashMethod [IN] Hash method
 * @param hashData [IN] Hash data
 * @param size [IN] Size of hash data
 * @param out [OUT] Output hash value
 */
int32_t CRYPT_CalcHash(void *provCtx, const EAL_MdMethod *hashMethod, const CRYPT_ConstData *hashData, uint32_t size,
    uint8_t *out, uint32_t *outlen);

/**
 * @ingroup rsa
 * @brief mgf1 of PKCS1
 *
 * @param provCtx [IN] Provider context
 * @param hashMethod [IN] Hash method
 * @param seed [IN] Seed
 * @param seedLen [IN] Seed length
 * @param mask [OUT] Mask
 * @param maskLen [IN] Mask length
 *
 * @retval CRYPT_SUCCESS on success
 */
int32_t CRYPT_Mgf1(void *provCtx, const EAL_MdMethod *hashMethod, const uint8_t *seed, const uint32_t seedLen,
    uint8_t *mask, uint32_t maskLen);

/**
 * @brief Retrieves the process function callback and its arguments from a parameter list.
 *
 * @param params A pointer to the BSL_Param list containing the parameters.
 * @param processCb A pointer to a pointer to the process function callback.
 * @param args A pointer to a pointer to the process function arguments.
 * @return int32_t Returns CRYPT_SUCCESS if the operation is successful, otherwise an error code.
 */
int32_t CRYPT_GetPkeyProcessParams(BSL_Param *params, CRYPT_EAL_ProcessFuncCb *processCb, void **args);

#if (defined(HITLS_CRYPTO_DH_CHECK) || defined(HITLS_CRYPTO_DSA_CHECK))
/**
 * @brief check the key pair consistency
 *
 * @param x [IN] FFC private key
 * @param y [IN] FFC public key
 * @param p [IN] FFC prime
 * @param g [IN] FFC generator
 *
 * @retval CRYPT_SUCCESS    check success.
 * Others. For details, see error code in errno.
 */
int32_t CRYPT_FFC_KeyPairCheck(const void *x, const void *y, const void *p, const void *g);

/**
 * @brief check the private key
 *
 * @param x [IN] FFC private key
 * @param p [IN] FFC prime
 * @param q [IN] FFC subprime
 *
 * @retval CRYPT_SUCCESS    check success.
 * Others. For details, see error code in errno.
 */
int32_t CRYPT_FFC_PrvCheck(const void *x, const void *p, const void *q);

#endif // HITLS_CRYPTO_DH_CHECK || HITLS_CRYPTO_DSA_CHECK

#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_MD)
/**
 * @brief Control the MD context.
 *
 * @param mdSize [IN] MD size
 * @param mdBlockSize [IN] MD block size
 * @param opt [IN] Option
 * @param val [IN] Value
 * @param len [IN] Length
 *
 * @retval #CRYPT_SUCCESS       initialization succeeded.
 * @retval #CRYPT_NULL_INPUT    Pointer ctx is NULL
 * @retval #CRYPT_NOT_SUPPORT   Option is not supported
 */
int32_t CRYPT_MdCommonGetParam(uint16_t mdSize, uint16_t mdBlockSize, BSL_Param *param);
#endif

#if defined(HITLS_CRYPTO_PROVIDER) && (defined(HITLS_CRYPTO_RSA) || defined(HITLS_CRYPTO_ECDSA) || \
    defined(HITLS_CRYPTO_DSA))
/**
 * @brief Set the MD attribute.
 *
 * @param mdAttr [IN] MD attribute
 * @param len [IN] MD attribute length
 * @param pkeyMdAttr [OUT] Output pkey MD attribute
 */
int32_t CRYPT_PkeySetMdAttr(const char *mdAttr, uint32_t len, char **pkeyMdAttr);
#endif

/* Assumes that x is uint32_t and 0 < n < 32 */
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define ROTR64(x, n) (((x) << (64 - (n))) | ((x) >> (n))) // Assumes that x is uint64_t and 0 < n < 64

#define IS_BUF_NON_ZERO(out, outLen)  (((out) != NULL) && ((outLen) > 0))
#define CRYPT_IS_BUF_NON_ZERO(out, outLen)  (((out) != NULL) && ((outLen) > 0))
#define CRYPT_CHECK_DATA_INVALID(d) (((d)->data == NULL && (d)->len != 0))
#define CRYPT_IsDataNull(d) ((d) == NULL || (d)->data == NULL || (d)->len == 0)
#define CRYPT_IN_RANGE(x, range) ((x) >= (range)->min && (x) <= (range)->max)
#define CRYPT_CHECK_BUF_INVALID(buf, len) (((buf) == NULL && (len) != 0))
#define CRYPT_SWAP32(x) ((((x) & 0xff000000) >> 24) | \
                         (((x) & 0x00ff0000) >> 8) | \
                         (((x) & 0x0000ff00) << 8) | \
                         (((x) & 0x000000ff) << 24))
#ifdef HITLS_BIG_ENDIAN

#define CRYPT_HTONL(x) (x)

// Interpret p + i as little endian order. The type of p must be uint8_t *.
#define GET_UINT32_LE(p, i)                                            \
(                                                                      \
    ((uint32_t)((const uint8_t *)(p))[(i) + 3] << 24) |             \
    ((uint32_t)((const uint8_t *)(p))[(i) + 2] << 16) |             \
    ((uint32_t)((const uint8_t *)(p))[(i) + 1] <<  8) |             \
    ((uint32_t)((const uint8_t *)(p))[(i) + 0] <<  0)               \
)

// Convert little-endian order to host order
#define CRYPT_LE32TOH(x)    CRYPT_SWAP32(x)
// Convert host order to little-endian order
#define CRYPT_HTOLE32(x)    CRYPT_SWAP32(x)

#else

#define CRYPT_HTONL(x) CRYPT_SWAP32(x)

// Interpret p + i as little endian.
#define GET_UINT32_LE(p, i)         \
(                                   \
    (((uintptr_t)(p) & 0x7) != 0) ? ((uint32_t)((const uint8_t *)(p))[(i) + 3] << 24) | /* 24: 4th byte */      \
                                    ((uint32_t)((const uint8_t *)(p))[(i) + 2] << 16) | /* 16: 3rd byte */      \
                                    ((uint32_t)((const uint8_t *)(p))[(i) + 1] <<  8) | /*  8: 2nd byte */      \
                                    ((uint32_t)((const uint8_t *)(p))[(i) + 0] <<  0)   /*  0: 1st byte */      \
                                  : (*(uint32_t *)((uintptr_t)(p) + (i)))                                       \
)
// Convert little-endian order to host order
#define CRYPT_LE32TOH(x)    (x)
// Convert host order to little-endian order
#define CRYPT_HTOLE32(x)    (x)

#endif

#ifdef HITLS_BIG_ENDIAN

// Interpret p + i as little endian. The type of p must be uint8_t *.
#define GET_UINT16_LE(p, i)                                            \
(                                                                      \
    ((uint16_t)((const uint8_t *)(p))[(i) + 1] <<  8) |                \
    ((uint16_t)((const uint8_t *)(p))[(i) + 0] <<  0)                  \
)
#else
// Interpret p + i as little endian.
#define GET_UINT16_LE(p, i)         \
(                                   \
    (((uintptr_t)(p) & 0x7) != 0) ? ((uint16_t)((const uint8_t *)(p))[(i) + 1] <<  8) |     \
                                    ((uint16_t)((const uint8_t *)(p))[(i) + 0] <<  0)       \
                                  : (*(uint16_t *)((uint8_t *)(uintptr_t)(p) + (i)))        \
)
#endif

#define PUT_UINT16_LE(v, p, i)                                \
    do                                                        \
    {                                                         \
        (p)[(i) + 1] = (uint8_t)((v) >> 8);                   \
        (p)[(i) + 0] = (uint8_t)((v) >> 0);                   \
    } while (0)

/**
 * 64-bit integer manipulation functions (big endian)
 */
static inline uint64_t Uint64FromBeBytes(const uint8_t *bytes)
{
    return (((uint64_t)bytes[0] << 56) |
            ((uint64_t)bytes[1] << 48) |
            ((uint64_t)bytes[2] << 40) |
            ((uint64_t)bytes[3] << 32) |
            ((uint64_t)bytes[4] << 24) |
            ((uint64_t)bytes[5] << 16) |
            ((uint64_t)bytes[6] << 8) |
            (uint64_t)bytes[7]);
}

static inline void Uint64ToBeBytes(uint64_t v, uint8_t *bytes)
{
    bytes[0] = (uint8_t)(v >> 56);
    bytes[1] = (uint8_t)(v >> 48);
    bytes[2] = (uint8_t)(v >> 40);
    bytes[3] = (uint8_t)(v >> 32);
    bytes[4] = (uint8_t)(v >> 24);
    bytes[5] = (uint8_t)(v >> 16);
    bytes[6] = (uint8_t)(v >> 8);
    bytes[7] = (uint8_t)(v & 0xffu);
}

#if defined(HITLS_CRYPTO_RSA_VERIFY) || defined(HITLS_CRYPTO_RSA_SIGN) || defined(HITLS_CRYPTO_DSA) || \
    defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2_SIGN)
uint32_t CRYPT_GetMdSizeById(CRYPT_MD_AlgId id);
#endif

#if defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_ECDSA) || defined(HITLS_CRYPTO_SM2_SIGN)
typedef int32_t (*CheckSignMdCallBack)(void *val);
int32_t CRYPT_SetSignMdCtrl(CRYPT_MD_AlgId *signMdId, void *val, uint32_t len, CheckSignMdCallBack checkSignMdIdCb);
#endif

static inline bool ParamIdIsValid(uint32_t id, const uint32_t *list, uint32_t num)
{
    for (uint32_t i = 0; i < num; i++) {
        if (id == list[i]) {
            return true;
        }
    }
    return false;
}

const BSL_Param *EAL_FindConstParam(const BSL_Param *param, int32_t key);

BSL_Param *EAL_FindParam(BSL_Param *param, int32_t key);

static inline const BSL_Param *GetConstParamValue(const BSL_Param *params, int32_t type,
    uint8_t **value, uint32_t *valueLen)
{
    const BSL_Param *temp = EAL_FindConstParam(params, type);
    if (temp != NULL) {
        *value = temp->value;
        if (valueLen != NULL) {
            *valueLen = temp->valueLen;
        }
    }
    return temp;
}

static inline BSL_Param *GetParamValue(BSL_Param *params, int32_t type, uint8_t **value, uint32_t *valueLen)
{
    BSL_Param *temp = EAL_FindParam(params, type);
    if (temp != NULL) {
        *value = temp->value;
        if (valueLen != NULL) {
            *valueLen = temp->valueLen;
        }
    }
    return temp;
}

void GetCpuInstrSupportState(void);

#ifdef __x86_64__
#define CPU_ID_OUT_U32_CNT      4
#define EAX_OUT_IDX             0
#define EBX_OUT_IDX             1
#define ECX_OUT_IDX             2
#define EDX_OUT_IDX             3

/* %eax */
#define XCR0_BIT_SSE            (1ULL << 1)
#define XCR0_BIT_AVX            (1ULL << 2)
#define XCR0_BIT_OPMASK         (1ULL << 5)
#define XCR0_BIT_ZMM_LOW        (1ULL << 6)
#define XCR0_BIT_ZMM_HIGH       (1ULL << 7)

typedef struct {
    uint32_t code1Out[CPU_ID_OUT_U32_CNT];
    uint32_t code7Out[CPU_ID_OUT_U32_CNT];
    bool osSupportAVX;      /* input ecx = 0, output edx:eax bit 2 */
    bool osSupportAVX512;   /* input ecx = 0, output edx:eax bit 6 */
} CpuInstrSupportState;

bool IsSupportAES(void);
bool IsSupportBMI1(void);
bool IsSupportBMI2(void);
bool IsSupportADX(void);
bool IsSupportAVX(void);
bool IsSupportAVX2(void);
bool IsSupportSSE(void);
bool IsSupportSSE2(void);
bool IsSupportSSE3(void);
bool IsSupportMOVBE(void);
bool IsSupportAVX512F(void);
bool IsSupportAVX512VL(void);
bool IsSupportAVX512BW(void);
bool IsSupportAVX512DQ(void);
bool IsSupportXSAVE(void);
bool IsSupportOSXSAVE(void);
bool IsOSSupportAVX(void);
bool IsOSSupportAVX512(void);

void GetCpuId(uint32_t eax, uint32_t ecx, uint32_t cpuId[CPU_ID_OUT_U32_CNT]);

#elif defined(__arm__) || defined(__arm) || defined(__aarch64__)

bool IsSupportAES(void);
bool IsSupportPMULL(void);
bool IsSupportSHA1(void);
bool IsSupportSHA256(void);
bool IsSupportNEON(void);

#if defined(__aarch64__)
bool IsSupportSM4(void);
bool IsSupportSHA512(void);
#endif // __aarch64__

#endif // __arm__ || __arm || __aarch64__

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_UTILS_H
