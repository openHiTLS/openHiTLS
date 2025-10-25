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

/**
 * @defgroup crypt_eal_provider
 * @ingroup crypt
 * @brief using during provider development
 */

#ifndef CRYPT_EAL_IMPLPROVIDER_H
#define CRYPT_EAL_IMPLPROVIDER_H

#include <stdint.h>
#include "bsl_params.h"
#include "crypt_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define CRYPT_EAL_FUNC_END     {0, NULL}
#define CRYPT_EAL_ALGINFO_END  {0, NULL, NULL}

typedef struct {
    int32_t algId; // implemented algorithm id, such as aes128cbc, rsa sign
    const CRYPT_EAL_Func *implFunc; // implemented algorithm callback
    const char *attr; // implemented algorithm attribute
} CRYPT_EAL_AlgInfo;

typedef void (CRYPT_EAL_CvtVoid)(void);

/* capFuncs */
#define CRYPT_EAL_CAP_GETENTROPY   1 // Callback definition CRYPT_EAL_GetEntropyCb, in crypt_types.h
#define CRYPT_EAL_CAP_CLEANENTROPY 2 // Callback definition CRYPT_EAL_CleanEntropyCb
#define CRYPT_EAL_CAP_GETNONCE     3 // Callback definition CRYPT_EAL_GetNonceCb
#define CRYPT_EAL_CAP_CLEANNONCE   4 // Callback definition CRYPT_EAL_CleanNonceCb

/* get information from mgrCtx, such as entropy source context */
#define CRYPT_EAL_CAP_MGRCTXCTRL   5
/* load dynamic library functions */
#define BSL_SAL_CAP_LOAD_LIB       6
#define BSL_SAL_CAP_GET_FUNC_ADDR  7
#define BSL_SAL_CAP_UNLOAD_LIB     8

typedef int32_t (*CRYPT_EAL_ProvMgrCtrlCb)(void *mgrCtx, int32_t cmd, void *val, uint32_t valLen);

typedef enum {
    CRYPT_EAL_MGR_GETSEEDCTX,
    CRYPT_EAL_MGR_GETLIBCTX,
} CRYPT_EAL_PROVMGRCTRL;

/* outFuncs */
#define CRYPT_EAL_PROVCB_FREE       1
#define CRYPT_EAL_PROVCB_QUERY      2
#define CRYPT_EAL_PROVCB_CTRL       3
#define CRYPT_EAL_PROVCB_GETCAPS    4


typedef void (*CRYPT_EAL_ProvFreeCb)(void *provCtx);

#define CRYPT_EAL_OPERAID_SYMMCIPHER  1
#define CRYPT_EAL_OPERAID_KEYMGMT     2
#define CRYPT_EAL_OPERAID_SIGN        3
#define CRYPT_EAL_OPERAID_ASYMCIPHER  4
#define CRYPT_EAL_OPERAID_KEYEXCH     5
#define CRYPT_EAL_OPERAID_KEM         6
#define CRYPT_EAL_OPERAID_HASH        7
#define CRYPT_EAL_OPERAID_MAC         8
#define CRYPT_EAL_OPERAID_KDF         9
#define CRYPT_EAL_OPERAID_RAND        10
#define CRYPT_EAL_OPERAID_DECODER     11
#define CRYPT_EAL_OPERAID_SELFTEST    12

typedef int32_t (*CRYPT_EAL_ProvQueryCb)(void *provCtx, int32_t operaId, CRYPT_EAL_AlgInfo **algInfos);
/* Used for obtaining provider information through the eal layer interface */
typedef int32_t (*CRYPT_EAL_ProvCtrlCb)(void *provCtx, int32_t cmd, void *val, uint32_t valLen);

#define CRYPT_EAL_GET_GROUP_CAP 1
#define CRYPT_EAL_GET_SIGALG_CAP 2

/**
 * @brief Callback function type for processing provider capabilities
 *
 * @param params [IN] Parameters containing capability information
 * @param args [IN] User-provided arguments for capability processing
 *
 * @retval #CRYPT_SUCCESS if processing succeeds
 *         Other error codes see the crypt_errno.h
 */
typedef int32_t (*CRYPT_EAL_ProcessFuncCb)(const BSL_Param *params, void *args);

/* Used for obtaining the capabilities of provider through the eal layer interface */
typedef int32_t (*CRYPT_EAL_ProvGetCapsCb)(void *provCtx, int32_t cmd, CRYPT_EAL_ProcessFuncCb cb, void *args);

/**
 * @ingroup crypt_eal_provider
 * @brief Provider initialization function prototype,
 *
 * @param mgrCtx [IN] framework generates context for each provider, for provider, it is opaque
 * @param param [IN] parameters passed transparently when loading the provider interface
 * @param capFuncs [IN] The ability passed from the framework to provider, such as entropy source
 * @param outFuncs [OUT] The callback returned by provider, such as entropy source
 * @param provCtx [OUT] provider context
 *
 * @retval #CRYPT_SUCCESS, if success.
 *         Other error codes see the crypt_errno.h
*/
typedef int32_t (*CRYPT_EAL_ImplProviderInit)(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param,
    CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx);

// CRYPT_EAL_OPERAID_SYMMCIPHER
#define CRYPT_EAL_IMPLCIPHER_NEWCTX      1
#define CRYPT_EAL_IMPLCIPHER_INITCTX     2
#define CRYPT_EAL_IMPLCIPHER_UPDATE      3
#define CRYPT_EAL_IMPLCIPHER_FINAL       4
#define CRYPT_EAL_IMPLCIPHER_DEINITCTX   5
#define CRYPT_EAL_IMPLCIPHER_CTRL        6
#define CRYPT_EAL_IMPLCIPHER_FREECTX     7

typedef void *(*CRYPT_EAL_ImplCipherNewCtx)(void *provCtx, int32_t algId);
typedef int32_t (*CRYPT_EAL_ImplCipherInitCtx)(void *ctx, const uint8_t *key, uint32_t keyLen,
    const uint8_t *iv, uint32_t ivLen, BSL_Param *param, bool enc);
typedef int32_t (*CRYPT_EAL_ImplCipherUpdate)(void *ctx, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);
typedef int32_t (*CRYPT_EAL_ImplCipherFinal)(void *ctx, uint8_t *out, uint32_t *outLen);
typedef int32_t (*CRYPT_EAL_ImplCipherDeinitCtx)(void *ctx);
typedef int32_t (*CRYPT_EAL_ImplCipherCtrl)(void *ctx, int32_t cmd, void *val, uint32_t valLen);
typedef void (*CRYPT_EAL_ImplCipherFreeCtx)(void *ctx);


// CRYPT_EAL_OPERAID_KEYMGMT
#define CRYPT_EAL_IMPLPKEYMGMT_NEWCTX     1
#define CRYPT_EAL_IMPLPKEYMGMT_SETPARAM   2
#define CRYPT_EAL_IMPLPKEYMGMT_GETPARAM   3
#define CRYPT_EAL_IMPLPKEYMGMT_GENKEY     4
#define CRYPT_EAL_IMPLPKEYMGMT_SETPRV     5
#define CRYPT_EAL_IMPLPKEYMGMT_SETPUB     6
#define CRYPT_EAL_IMPLPKEYMGMT_GETPRV     7
#define CRYPT_EAL_IMPLPKEYMGMT_GETPUB     8
#define CRYPT_EAL_IMPLPKEYMGMT_DUPCTX     9
#define CRYPT_EAL_IMPLPKEYMGMT_CHECK     10
#define CRYPT_EAL_IMPLPKEYMGMT_COMPARE   11
#define CRYPT_EAL_IMPLPKEYMGMT_CTRL      12
#define CRYPT_EAL_IMPLPKEYMGMT_FREECTX   13
#define CRYPT_EAL_IMPLPKEYMGMT_COPYPARAM 14
#define CRYPT_EAL_IMPLPKEYMGMT_IMPORT    15
#define CRYPT_EAL_IMPLPKEYMGMT_EXPORT    16

typedef void *(*CRYPT_EAL_ImplPkeyMgmtNewCtx)(void *provCtx, int32_t algId);
typedef int32_t (*CRYPT_EAL_ImplPkeyMgmtSetParam)(void *ctx, const BSL_Param *param);
typedef int32_t (*CRYPT_EAL_ImplPkeyMgmtGetParam)(void *ctx, BSL_Param *param);
typedef int32_t (*CRYPT_EAL_ImplPkeyMgmtGenKey)(void *ctx);
typedef int32_t (*CRYPT_EAL_ImplPkeyMgmtSetPrv)(void *ctx, const BSL_Param *param);
typedef int32_t (*CRYPT_EAL_ImplPkeyMgmtSetPub)(void *ctx, const BSL_Param *param);
typedef int32_t (*CRYPT_EAL_ImplPkeyMgmtGetPrv)(const void *ctx, BSL_Param *param);
typedef int32_t (*CRYPT_EAL_ImplPkeyMgmtGetPub)(const void *ctx, BSL_Param *param);
typedef void *(*CRYPT_EAL_ImplPkeyMgmtDupCtx)(const void *ctx);
typedef int32_t (*CRYPT_EAL_ImplPkeyMgmtCheck)(uint32_t checkType, const void *ctx1, const void *ctx2);
typedef int32_t (*CRYPT_EAL_ImplPkeyMgmtCompare)(const void *ctx1, const void *ctx2);
typedef int32_t (*CRYPT_EAL_ImplPkeyMgmtCtrl)(void *ctx, int32_t cmd, void *val, uint32_t valLen);
typedef void (*CRYPT_EAL_ImplPkeyMgmtFreeCtx)(void *ctx);
typedef int32_t (*CRYPT_EAL_ImplPkeyMgmtImport)(void *ctx, const BSL_Param *param);
typedef int32_t (*CRYPT_EAL_ImplPkeyMgmtExport)(const void *ctx, BSL_Param *param);

// CRYPT_EAL_OPERAID_SIGN
#define CRYPT_EAL_IMPLPKEYSIGN_SIGN       1
#define CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA   2
#define CRYPT_EAL_IMPLPKEYSIGN_VERIFY     3
#define CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA 4
#define CRYPT_EAL_IMPLPKEYSIGN_RECOVER    5
#define CRYPT_EAL_IMPLPKEYSIGN_BLIND      6
#define CRYPT_EAL_IMPLPKEYSIGN_UNBLIND    7

typedef int32_t (*CRYPT_EAL_ImplPkeySign)(void *ctx, int32_t mdAlgId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen);
typedef int32_t (*CRYPT_EAL_ImplPkeySignData)(void *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen);
typedef int32_t (*CRYPT_EAL_ImplPkeyVerify)(const void *ctx, int32_t mdAlgId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t signLen);
typedef int32_t (*CRYPT_EAL_ImplPkeyVerifyData)(const void *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t signLen);
typedef int32_t (*CRYPT_EAL_ImplPkeyRecover)(const void *ctx, uint8_t *sign, uint32_t signLen,
    uint8_t *data, uint32_t *dataLen);
typedef int32_t (*CRYPT_EAL_ImplPkeyBlind)(void *ctx, int32_t mdAlgId, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen);
typedef int32_t (*CRYPT_EAL_ImplPkeyUnBlind)(const void *ctx, const uint8_t *input, uint32_t inputLen,
    uint8_t *out, uint32_t *outLen);

// CRYPT_EAL_OPERAID_ASYMCIPHER
#define CRYPT_EAL_IMPLPKEYCIPHER_ENCRYPT  1
#define CRYPT_EAL_IMPLPKEYCIPHER_DECRYPT  2
#define CRYPT_EAL_IMPLPKEYCIPHER_HEADD    3
#define CRYPT_EAL_IMPLPKEYCIPHER_HEMUL    4

typedef int32_t (*CRYPT_EAL_ImplPkeyEncrypt)(void *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen);
typedef int32_t (*CRYPT_EAL_ImplPkeyDecrypt)(void *ctx, const uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen);
typedef int32_t (*CRYPT_EAL_ImplPkeyHEAdd)(const void *ctx, const BSL_Param *input, uint8_t *out, uint32_t *outLen);
typedef int32_t (*CRYPT_EAL_ImplPkeyHEMul)(const void *ctx, const BSL_Param *input, uint8_t *out, uint32_t *outLen);

// CRYPT_EAL_OPERAID_KEYEXCH
#define CRYPT_EAL_IMPLPKEYEXCH_EXCH  1
typedef int32_t (*CRYPT_EAL_ImplPkeyExch)(const void *ctx, const void *pubCtx, uint8_t *out, uint32_t *outLen);

// CRYPT_EAL_OPERAID_KEM
#define CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE_INIT  1
#define CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE_INIT  2
#define CRYPT_EAL_IMPLPKEYKEM_ENCAPSULATE       3
#define CRYPT_EAL_IMPLPKEYKEM_DECAPSULATE       4

typedef int32_t (*CRYPT_EAL_ImplPkeyEncapsInit)(const void *ctx, BSL_Param *params);
typedef int32_t (*CRYPT_EAL_ImplPkeyDecapsInit)(const void *ctx, BSL_Param *params);
typedef int32_t (*CRYPT_EAL_ImplPkeyKemEncapsulate)(const void *ctx, uint8_t *cipher, uint32_t *cipherLen,
    uint8_t *out, uint32_t *outLen);
typedef int32_t (*CRYPT_EAL_ImplPkeyKemDecapsulate)(const void *ctx, uint8_t *data, uint32_t dataLen,
    uint8_t *out, uint32_t *outLen);

// CRYPT_EAL_OPERAID_HASH
#define CRYPT_EAL_IMPLMD_NEWCTX      1
#define CRYPT_EAL_IMPLMD_INITCTX     2
#define CRYPT_EAL_IMPLMD_UPDATE      3
#define CRYPT_EAL_IMPLMD_FINAL       4
#define CRYPT_EAL_IMPLMD_DEINITCTX   5
#define CRYPT_EAL_IMPLMD_DUPCTX      6
#define CRYPT_EAL_IMPLMD_CTRL        7 // not support
#define CRYPT_EAL_IMPLMD_FREECTX     8
#define CRYPT_EAL_IMPLMD_SQUEEZE     9
#define CRYPT_EAL_IMPLMD_COPYCTX     10
#define CRYPT_EAL_IMPLMD_GETPARAM    11

typedef void *(*CRYPT_EAL_ImplMdNewCtx)(void *provCtx, int32_t algId);
typedef int32_t (*CRYPT_EAL_ImplMdInitCtx)(void *ctx, BSL_Param *param);
typedef int32_t (*CRYPT_EAL_ImplMdUpdate)(void *ctx, const uint8_t *input, uint32_t len);
typedef int32_t (*CRYPT_EAL_ImplMdFinal)(void *ctx, uint8_t *out, uint32_t *outLen);
typedef int32_t (*CRYPT_EAL_ImplMdDeInitCtx)(void *ctx);
typedef void *(*CRYPT_EAL_ImplMdDupCtx)(const void *ctx);
typedef int32_t (*CRYPT_EAL_ImplMdCtrl)(void *ctx, int32_t cmd, void *val, uint32_t valLen);  // not support
typedef void (*CRYPT_EAL_ImplMdFreeCtx)(void *ctx);
typedef int32_t (*CRYPT_EAL_ImplMdSqueeze)(void *ctx, uint8_t *out, uint32_t len);
typedef int32_t (*CRYPT_EAL_ImplMdCopyCtx)(void *dst, const void *src);
typedef int32_t (*CRYPT_EAL_ImplMdGetParam)(void *ctx, BSL_Param *param);

// CRYPT_EAL_OPERAID_MAC
#define CRYPT_EAL_IMPLMAC_NEWCTX      1
#define CRYPT_EAL_IMPLMAC_INIT        2
#define CRYPT_EAL_IMPLMAC_UPDATE      3
#define CRYPT_EAL_IMPLMAC_FINAL       4
#define CRYPT_EAL_IMPLMAC_DEINITCTX   5
#define CRYPT_EAL_IMPLMAC_REINITCTX   6
#define CRYPT_EAL_IMPLMAC_CTRL        7
#define CRYPT_EAL_IMPLMAC_FREECTX     8
#define CRYPT_EAL_IMPLMAC_SETPARAM    9

typedef void *(*CRYPT_EAL_ImplMacNewCtx)(void *provCtx, int32_t algId);
typedef int32_t (*CRYPT_EAL_ImplMacInit)(void *ctx, const uint8_t *key, uint32_t len, BSL_Param *param);
typedef int32_t (*CRYPT_EAL_ImplMacUpdate)(void *ctx, const uint8_t *input, uint32_t len);
typedef int32_t (*CRYPT_EAL_ImplMacFinal)(void *ctx, uint8_t *out, uint32_t *outLen);
typedef int32_t (*CRYPT_EAL_ImplMacDeInitCtx)(void *ctx);
typedef int32_t (*CRYPT_EAL_ImplMacReInitCtx)(void *ctx);
typedef int32_t (*CRYPT_EAL_ImplMacCtrl)(void *ctx, int32_t cmd, void *val, uint32_t valLen);
typedef void (*CRYPT_EAL_ImplMacFreeCtx)(void *ctx);
typedef int32_t (*CRYPT_EAL_ImplMacSetParam)(void *ctx, const BSL_Param *param);

// CRYPT_EAL_OPERAID_KDF
#define CRYPT_EAL_IMPLKDF_NEWCTX      1
#define CRYPT_EAL_IMPLKDF_SETPARAM    2
#define CRYPT_EAL_IMPLKDF_DERIVE      3
#define CRYPT_EAL_IMPLKDF_DEINITCTX   4
#define CRYPT_EAL_IMPLKDF_CTRL        5 // not support
#define CRYPT_EAL_IMPLKDF_FREECTX     6

typedef void *(*CRYPT_EAL_ImplKdfNewCtx)(void *provCtx, int32_t algId);
typedef int32_t (*CRYPT_EAL_ImplKdfSetParam)(void *ctx, BSL_Param *param);
typedef int32_t (*CRYPT_EAL_ImplKdfDerive)(void *ctx, uint8_t *key, uint32_t keyLen);
typedef int32_t (*CRYPT_EAL_ImplKdfDeInitCtx)(void *ctx);
typedef int32_t (*CRYPT_EAL_ImplKdfCtrl)(void *ctx, int32_t cmd, void *val, uint32_t valLen); // not support
typedef void (*CRYPT_EAL_ImplKdfFreeCtx)(void *ctx);

// CRYPT_EAL_OPERAID_RAND
#define CRYPT_EAL_IMPLRAND_DRBGNEWCTX   1
#define CRYPT_EAL_IMPLRAND_DRBGINST     2
#define CRYPT_EAL_IMPLRAND_DRBGUNINST   3
#define CRYPT_EAL_IMPLRAND_DRBGGEN      4
#define CRYPT_EAL_IMPLRAND_DRBGRESEED   5
#define CRYPT_EAL_IMPLRAND_DRBGCTRL     6
#define CRYPT_EAL_IMPLRAND_DRBGFREECTX  7

typedef void *(*CRYPT_EAL_ImplRandDrbgNewCtx)(void *provCtx, int32_t algId, BSL_Param *param);
typedef int32_t (*CRYPT_EAL_ImplRandDrbgInst)(void *ctx, const uint8_t *pers, uint32_t persLen, BSL_Param *param);
typedef int32_t (*CRYPT_EAL_ImplRandDrbgUnInst)(void *ctx);
typedef int32_t (*CRYPT_EAL_ImplRandDrbgGen)(void *ctx, uint8_t *out, uint32_t outLen, const uint8_t *adin,
    uint32_t adinLen, BSL_Param *param);
typedef int32_t (*CRYPT_EAL_ImplRandDrbgReSeed)(void *ctx, const uint8_t *addin, uint32_t addinLen, BSL_Param *param);
typedef int32_t (*CRYPT_EAL_ImplRandDrbgCtrl)(void *ctx, int32_t cmd, void *val, uint32_t valLen);
typedef void (*CRYPT_EAL_ImplRandDrbgFreeCtx)(void *ctx);

// CRYPT_EAL_OPERAID_DECODER
#define CRYPT_DECODER_IMPL_NEWCTX           1
#define CRYPT_DECODER_IMPL_SETPARAM         2
#define CRYPT_DECODER_IMPL_GETPARAM         3
#define CRYPT_DECODER_IMPL_DECODE           4
#define CRYPT_DECODER_IMPL_FREEOUTDATA      5
#define CRYPT_DECODER_IMPL_FREECTX          6

typedef void *(*CRYPT_DECODER_IMPL_NewCtx)(void *provCtx);
typedef int32_t (*CRYPT_DECODER_IMPL_SetParam)(void *ctx, const BSL_Param *param);
typedef int32_t (*CRYPT_DECODER_IMPL_GetParam)(void *ctx, BSL_Param *param);
typedef int32_t (*CRYPT_DECODER_IMPL_Decode)(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
typedef void (*CRYPT_DECODER_IMPL_FreeOutData)(void *ctx, BSL_Param *outData);
typedef void (*CRYPT_DECODER_IMPL_FreeCtx)(void *ctx);

// CRYPT_EAL_OPERAID_SELFTEST
#define CRYPT_EAL_IMPLSELFTEST_NEWCTX           1
#define CRYPT_EAL_IMPLSELFTEST_GETVERSION       2
#define CRYPT_EAL_IMPLSELFTEST_SELFTEST         3
#define CRYPT_EAL_IMPLSELFTEST_FREECTX          4

typedef void *(*CRYPT_EAL_ImplSelftestNewCtx)(void *provCtx);
typedef const char *(*CRYPT_EAL_ImplSelftestGetVersion)(void *ctx);
typedef int32_t (*CRYPT_EAL_ImplSelftestSelftest)(void *ctx, const BSL_Param *param);
typedef void (*CRYPT_EAL_ImplSelftestFreeCtx)(void *ctx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_IMPLPROVIDER_H
