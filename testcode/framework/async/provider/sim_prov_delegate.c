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

/* Simulation provider: delegate layer (built-in implementations, NULL libCtx) */

#include "sim_prov_internal.h"
#include "crypt_eal_codecs.h"

#ifdef HITLS_CRYPTO_PROVIDER

int32_t SimRunOperation(SimOpCtx *op)
{
    CRYPT_EAL_PkeyCtx *pkey = op->pkey;
    const CRYPT_EAL_PkeyCtx *peer = op->peer;
    uint32_t len = op->outCap;
    uint32_t len2 = op->outCap2;
    int32_t ret;
    switch (op->kind) {
        case SIM_OP_KIND_SIGN:
            ret = CRYPT_EAL_PkeySign(pkey, (CRYPT_MD_AlgId)op->mdId, op->data, op->dataLen, op->out, &len);
            break;
        case SIM_OP_KIND_VERIFY:
            return CRYPT_EAL_PkeyVerify(pkey, (CRYPT_MD_AlgId)op->mdId, op->data, op->dataLen, op->out, op->outCap);
        case SIM_OP_KIND_EXCH:
            ret = CRYPT_EAL_PkeyComputeShareKey(pkey, peer, op->out, &len);
            break;
        case SIM_OP_KIND_GEN:
            return CRYPT_EAL_PkeyGen(op->pkey);
        case SIM_OP_KIND_DECODE: {
            BSL_Buffer encode = {(uint8_t *)(uintptr_t)op->data, op->dataLen};
            return CRYPT_EAL_DecodeBuffKey(op->decodeFormat, op->decodeType, &encode, op->password, op->passwordLen,
                                           &op->decoded);
        }
        case SIM_OP_KIND_KEM_ENC:
            ret = CRYPT_EAL_PkeyEncaps(pkey, op->out, &len, op->out2, &len2);
            break;
        case SIM_OP_KIND_KEM_DEC:
            ret = CRYPT_EAL_PkeyDecaps(pkey, op->data, op->dataLen, op->out, &len);
            break;
        default:
            return CRYPT_EAL_ALG_NOT_SUPPORT;
    }
    if (ret == CRYPT_SUCCESS) {
        if (op->kind != SIM_OP_KIND_SIGN || op->out != NULL) {
            op->outLen = len;
        }
        if (op->kind == SIM_OP_KIND_KEM_ENC) {
            op->outLen2 = len2;
        }
    }
    return ret;
}

#endif /* HITLS_CRYPTO_PROVIDER */
