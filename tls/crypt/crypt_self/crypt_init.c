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
#include "hitls_crypt_reg.h"
#include "crypt_default.h"

void HITLS_CryptMethodInit(void)
{
#ifdef HITLS_TLS_CALLBACK_CRYPT
    HITLS_CRYPT_BaseMethod baseMethod = {0};
    baseMethod.randBytes = (CRYPT_RandBytesCallback)CRYPT_DEFAULT_RandomBytes;
    baseMethod.hmacSize = (CRYPT_HmacSizeCallback)CRYPT_DEFAULT_HMAC_Size;
#ifdef HITLS_TLS_CALLBACK_CRYPT_HMAC_PRIMITIVES
    baseMethod.hmacInit = (CRYPT_HmacInitCallback)CRYPT_DEFAULT_HMAC_Init;
    baseMethod.hmacReinit = (CRYPT_HmacReInitCallback)CRYPT_DEFAULT_HMAC_ReInit;
    baseMethod.hmacFree = (CRYPT_HmacFreeCallback)CRYPT_DEFAULT_HMAC_Free;
    baseMethod.hmacUpdate = (CRYPT_HmacUpdateCallback)CRYPT_DEFAULT_HMAC_Update;
    baseMethod.hmacFinal = (CRYPT_HmacFinalCallback)CRYPT_DEFAULT_HMAC_Final;
#endif
    baseMethod.hmac = (CRYPT_HmacCallback)CRYPT_DEFAULT_HMAC;
    baseMethod.digestSize = (CRYPT_DigestSizeCallback)CRYPT_DEFAULT_DigestSize;
    baseMethod.digestInit = (CRYPT_DigestInitCallback)CRYPT_DEFAULT_DigestInit;
    baseMethod.digestCopy = (CRYPT_DigestCopyCallback)CRYPT_DEFAULT_DigestCopy;
    baseMethod.digestFree = (CRYPT_DigestFreeCallback)CRYPT_DEFAULT_DigestFree;
    baseMethod.digestUpdate = (CRYPT_DigestUpdateCallback)CRYPT_DEFAULT_DigestUpdate;
    baseMethod.digestFinal = (CRYPT_DigestFinalCallback)CRYPT_DEFAULT_DigestFinal;
    baseMethod.digest = (CRYPT_DigestCallback)CRYPT_DEFAULT_Digest;
    baseMethod.encrypt = (CRYPT_EncryptCallback)CRYPT_DEFAULT_Encrypt;
    baseMethod.decrypt = (CRYPT_DecryptCallback)CRYPT_DEFAULT_Decrypt;
    baseMethod.cipherFree = (CRYPT_CipherFreeCallback)CRYPT_DEFAULT_CipherFree;
    HITLS_CRYPT_RegisterBaseMethod(&baseMethod);

    HITLS_CRYPT_EcdhMethod ecdhMethod = {0};
    ecdhMethod.generateEcdhKeyPair = (CRYPT_GenerateEcdhKeyPairCallback)CRYPT_DEFAULT_GenerateEcdhKey;
    ecdhMethod.freeEcdhKey = (CRYPT_FreeEcdhKeyCallback)CRYPT_DEFAULT_FreeKey;
    ecdhMethod.getEcdhPubKey = (CRYPT_GetEcdhEncodedPubKeyCallback)CRYPT_DEFAULT_GetPubKey;
    ecdhMethod.calcEcdhSharedSecret = (CRYPT_CalcEcdhSharedSecretCallback)CRYPT_DEFAULT_EcdhCalcSharedSecret;
#ifdef HITLS_TLS_PROTO_TLCP11
    ecdhMethod.sm2CalEcdhSharedSecret = (CRYPT_Sm2CalcEcdhSharedSecretCallback)CRYPT_DEFAULT_CalcSM2SharedSecret;
#endif /* HITLS_TLS_PROTO_TLCP11 */
#ifdef HITLS_TLS_FEATURE_KEM
    ecdhMethod.kemEncapsulate = (CRYPT_KemEncapsulateCallback)CRYPT_DEFAULT_KemEncapsulate;
    ecdhMethod.kemDecapsulate = (CRYPT_KemDecapsulateCallback)CRYPT_DEFAULT_KemDecapsulate;
#endif /* HITLS_TLS_FEATURE_KEM */
    HITLS_CRYPT_RegisterEcdhMethod(&ecdhMethod);

#ifdef HITLS_TLS_SUITE_KX_DHE
    HITLS_CRYPT_DhMethod dhMethod = {0};
    dhMethod.generateDhKeyBySecbits = (CRYPT_GenerateDhKeyBySecbitsCallback)CRYPT_DEFAULT_GenerateDhKeyBySecbits;
    dhMethod.generateDhKeyByParams = (CRYPT_GenerateDhKeyByParamsCallback)CRYPT_DEFAULT_GenerateDhKeyByParameters;
#ifdef HITLS_TLS_CONFIG_MANUAL_DH
    dhMethod.dupDhKey = (CRYPT_DupDhKeyCallback)CRYPT_DEFAULT_DupKey;
#endif /* HITLS_TLS_CONFIG_MANUAL_DH */
    dhMethod.freeDhKey = (CRYPT_FreeDhKeyCallback)CRYPT_DEFAULT_FreeKey;
    dhMethod.getDhParameters = (CRYPT_DHGetParametersCallback)CRYPT_DEFAULT_GetDhParameters;
    dhMethod.getDhPubKey = (CRYPT_GetDhEncodedPubKeyCallback)CRYPT_DEFAULT_GetPubKey;
    dhMethod.calcDhSharedSecret = (CRYPT_CalcDhSharedSecretCallback)CRYPT_DEFAULT_DhCalcSharedSecret;
    HITLS_CRYPT_RegisterDhMethod(&dhMethod);
#endif /* HITLS_TLS_SUITE_KX_DHE */

#ifdef HITLS_TLS_PROTO_TLS13
    HITLS_CRYPT_KdfMethod hkdfMethod = {0};
    hkdfMethod.hkdfExtract = (CRYPT_HkdfExtractCallback)CRYPT_DEFAULT_HkdfExtract;
    hkdfMethod.hkdfExpand = (CRYPT_HkdfExpandCallback)CRYPT_DEFAULT_HkdfExpand;
    HITLS_CRYPT_RegisterHkdfMethod(&hkdfMethod);
#endif
#endif /* HITLS_TLS_CALLBACK_CRYPT */
}