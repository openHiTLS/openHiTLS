#ifndef EAL_KDF_LOCAL_H
#define EAL_KDF_LOCAL_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_KDF)

#include <stdint.h>
#include "crypt_algid.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

struct EalKdfCtx {
    bool isProvider;
    EAL_KdfUnitaryMethod *method;  /* algorithm operation entity */
    void *data;
    CRYPT_KDF_AlgId id;
};

const EAL_KdfMethod *EAL_KdfFindMethod(CRYPT_KDF_AlgId id);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // HITLS_CRYPTO_KDF

#endif // EAL_KDF_LOCAL_H
