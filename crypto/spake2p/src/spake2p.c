/*
 *  Copyright (C) 2024, Your Name or Company
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  SPAKE2+ implementation (RFC 9383)
 */

#include "crypt_spake2p.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_kdf.h"
#include "crypt_ecc.h"
#include "crypt_bn.h"
#include "bsl_sal.h"
#include "securec.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_algid.h"
#include "crypt_utils.h" // For CRYPT_MEM_FREE_NONULL, CRYPT_VerifyMacsConstantTime
// #include "eal_pkey_local.h" // May not be needed directly if not using pkey methods

/* Ed25519 M and N points from RFC 9383, Appendix A.1 (compressed form) */
static const char *ED25519_M_HEX = "02731a40556b52479369d62fc62c75142de018328820d55350733648932942391b";
static const char *ED25519_N_HEX = "02a2a6686825880495d8116a18af5f6103f1002e4e007c33658178109147026b92";

/* Helper: Free MPI and zeroize */
static void spake2p_mpi_clear_free(CRYPT_MPI *mpi)
{
    if (mpi != NULL && mpi->s != NULL) { // Check if MPI was initialized
        CRYPT_MPI_ClearFree(mpi);
    }
}

/* Helper: Free ECC Point and zeroize */
static void spake2p_point_clear_free(CRYPT_ECC_Point *pt)
{
    if (pt != NULL && pt->X.s != NULL) { // Check if Point was initialized
        CRYPT_ECC_ClearPoint(pt);
    }
}

/* Helper: Securely allocate and copy data */
static int32_t spake2p_secure_alloc_copy(uint8_t **dst, size_t *dst_len, const uint8_t *src, size_t src_len)
{
    if (dst == NULL || dst_len == NULL || src == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_NULL_PARAM, "Null parameter in secure_alloc_copy");
        return CRYPT_ERR_NULL_PARAM;
    }
    if (src_len == 0) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_INVALID_PARAM, "Source length is 0 in secure_alloc_copy");
        return CRYPT_ERR_INVALID_PARAM;
    }

    CRYPT_MEM_FREE_NONULL(*dst);
    *dst = (uint8_t *)BSL_TRD_MALLOC_PARA(src_len);
    if (*dst == NULL) {
        *dst_len = 0;
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_MALLOC_FAIL, "Malloc fail in secure_alloc_copy");
        return CRYPT_ERR_MALLOC_FAIL;
    }

    if (BSL_SRE_MEMCPY_S(*dst, src_len, src, src_len) != EOK) {
        CRYPT_MEM_FREE_NONULL(*dst);
        *dst = NULL;
        *dst_len = 0;
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_MEMCPY_FAIL, "Memcpy fail in secure_alloc_copy");
        return CRYPT_ERR_MEMCPY_FAIL;
    }
    *dst_len = src_len;
    return CRYPT_SUCCESS;
}

/* Helper: Append data to transcript buffer, reallocating as needed */
static int32_t transcript_append(CRYPT_SPAKE2P_Ctx *ctx, const uint8_t *data, size_t data_len)
{
    if (ctx == NULL || data == NULL) {
        return CRYPT_ERR_NULL_PARAM;
    }
    if (data_len == 0) {
        return CRYPT_SUCCESS; // Nothing to append
    }

    uint8_t *new_transcript = (uint8_t *)BSL_TRD_MALLOC_PARA(ctx->transcript_TT_len + data_len);
    if (new_transcript == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_MALLOC_FAIL, "Transcript append malloc fail");
        return CRYPT_ERR_MALLOC_FAIL;
    }

    if (ctx->transcript_TT != NULL) {
        if (BSL_SRE_MEMCPY_S(new_transcript, ctx->transcript_TT_len, ctx->transcript_TT, ctx->transcript_TT_len) != EOK) {
            BSL_TRD_FREE(new_transcript);
            BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_MEMCPY_FAIL, "Transcript append memcpy old data fail");
            return CRYPT_ERR_MEMCPY_FAIL;
        }
    }
    if (BSL_SRE_MEMCPY_S(new_transcript + ctx->transcript_TT_len, data_len, data, data_len) != EOK) {
        BSL_TRD_FREE(new_transcript);
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_MEMCPY_FAIL, "Transcript append memcpy new data fail");
        return CRYPT_ERR_MEMCPY_FAIL;
    }

    CRYPT_MEM_FREE_NONULL(ctx->transcript_TT);
    ctx->transcript_TT = new_transcript;
    ctx->transcript_TT_len += data_len;
    return CRYPT_SUCCESS;
}

/* Helper: Append length-prefixed data to transcript */
static int32_t transcript_append_L(CRYPT_SPAKE2P_Ctx *ctx, const uint8_t *data, size_t data_len)
{
    if (ctx == NULL) return CRYPT_ERR_NULL_PARAM;

    // Using a fixed-size length prefix (e.g., 2 bytes for lengths up to 65535)
    // RFC 9383 does not specify encoding for these lengths, but a fixed size is simplest.
    // Let's assume lengths are reasonable and use 1 byte for simplicity if data_len < 256,
    // or require specific encoding if larger lengths are common.
    // For now, let's assume data_len fits in uint8_t for simplicity of example.
    // A robust implementation would use varints or fixed multi-byte lengths.
    if (data_len > 0xFF) { // Example check, adjust as needed
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_INVALID_PARAM, "Data length too large for simple L-prefix");
        return CRYPT_ERR_INVALID_PARAM;
    }
    uint8_t len_byte = (uint8_t)data_len;
    int32_t ret = transcript_append(ctx, &len_byte, 1);
    if (ret != CRYPT_SUCCESS) return ret;
    if (data_len > 0 && data != NULL) {
        ret = transcript_append(ctx, data, data_len);
    }
    return ret;
}


CRYPT_SPAKE2P_Ctx *CRYPT_SPAKE2P_NewCtx(void)
{
    CRYPT_SPAKE2P_Ctx *ctx = (CRYPT_SPAKE2P_Ctx *)BSL_TRD_MALLOC_PARA(sizeof(CRYPT_SPAKE2P_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_MALLOC_FAIL, "Failed to allocate SPAKE2P context");
        return NULL;
    }

    if (BSL_SRE_MEMSET_S(ctx, sizeof(CRYPT_SPAKE2P_Ctx), 0, sizeof(CRYPT_SPAKE2P_Ctx)) != EOK) {
        BSL_TRD_FREE(ctx);
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_MEMSET_FAIL, "Failed to zeroize SPAKE2P context");
        return NULL;
    }

    CRYPT_ECC_InitGrp(&ctx->grp);
    CRYPT_ECC_InitPoint(&ctx->P_generator);
    CRYPT_ECC_InitPoint(&ctx->M);
    CRYPT_ECC_InitPoint(&ctx->N);
    CRYPT_MPI_Init(&ctx->pw_scalar);
    CRYPT_MPI_Init(&ctx->w0);
    CRYPT_MPI_Init(&ctx->w1);
    CRYPT_MPI_Init(&ctx->w0_peer);
    CRYPT_MPI_Init(&ctx->w1_peer);
    CRYPT_MPI_Init(&ctx->k_private);
    CRYPT_ECC_InitPoint(&ctx->P_our_msg);
    CRYPT_ECC_InitPoint(&ctx->P_peer_msg);
    CRYPT_MPI_Init(&ctx->temp_bn1);
    CRYPT_MPI_Init(&ctx->temp_bn2);
    CRYPT_ECC_InitPoint(&ctx->temp_point1);
    CRYPT_ECC_InitPoint(&ctx->temp_point2);
    CRYPT_ECC_InitPoint(&ctx->temp_point3);

    /* Defaults, can be overridden by InitGroup */
    ctx->hashId = CRYPT_MD_SHA256;
    ctx->macId = CRYPT_MAC_HMAC_SHA256; /* For HKDF and confirmation MACs */
    /* curveId will be set by InitGroup */

    return ctx;
}

void CRYPT_SPAKE2P_FreeCtx(CRYPT_SPAKE2P_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    CRYPT_MEM_FREE_NONULL(ctx->pwd_buf);
    CRYPT_MEM_FREE_NONULL(ctx->our_id_buf);
    CRYPT_MEM_FREE_NONULL(ctx->peer_id_buf);
    CRYPT_MEM_FREE_NONULL(ctx->transcript_TT);
    CRYPT_MEM_FREE_NONULL(ctx->Ke_derived);
    CRYPT_MEM_FREE_NONULL(ctx->KcA_derived);
    CRYPT_MEM_FREE_NONULL(ctx->KcB_derived);

    CRYPT_ECC_ClearGrp(&ctx->grp);
    spake2p_point_clear_free(&ctx->P_generator);
    spake2p_point_clear_free(&ctx->M);
    spake2p_point_clear_free(&ctx->N);
    spake2p_mpi_clear_free(&ctx->pw_scalar);
    spake2p_mpi_clear_free(&ctx->w0);
    spake2p_mpi_clear_free(&ctx->w1);
    spake2p_mpi_clear_free(&ctx->w0_peer);
    spake2p_mpi_clear_free(&ctx->w1_peer);
    spake2p_mpi_clear_free(&ctx->k_private);
    spake2p_point_clear_free(&ctx->P_our_msg);
    spake2p_point_clear_free(&ctx->P_peer_msg);
    spake2p_mpi_clear_free(&ctx->temp_bn1);
    spake2p_mpi_clear_free(&ctx->temp_bn2);
    spake2p_point_clear_free(&ctx->temp_point1);
    spake2p_point_clear_free(&ctx->temp_point2);
    spake2p_point_clear_free(&ctx->temp_point3);

    (void)BSL_SRE_MEMSET_S(ctx, sizeof(CRYPT_SPAKE2P_Ctx), 0, sizeof(CRYPT_SPAKE2P_Ctx));
    BSL_TRD_FREE(ctx);
}

int32_t CRYPT_SPAKE2P_SetPassword(CRYPT_SPAKE2P_Ctx *ctx, const uint8_t *password, uint32_t passwordLen)
{
    if (ctx == NULL) return CRYPT_ERR_NULL_PARAM;
    return spake2p_secure_alloc_copy(&ctx->pwd_buf, &ctx->pwd_len, password, (size_t)passwordLen);
}

int32_t CRYPT_SPAKE2P_SetOurIdentity(CRYPT_SPAKE2P_Ctx *ctx, const uint8_t *identity, uint32_t identityLen)
{
    if (ctx == NULL) return CRYPT_ERR_NULL_PARAM;
    return spake2p_secure_alloc_copy(&ctx->our_id_buf, &ctx->our_id_len, identity, (size_t)identityLen);
}

int32_t CRYPT_SPAKE2P_SetPeerIdentity(CRYPT_SPAKE2P_Ctx *ctx, const uint8_t *identity, uint32_t identityLen)
{
    if (ctx == NULL) return CRYPT_ERR_NULL_PARAM;
    return spake2p_secure_alloc_copy(&ctx->peer_id_buf, &ctx->peer_id_len, identity, (size_t)identityLen);
}

int32_t CRYPT_SPAKE2P_SetRole(CRYPT_SPAKE2P_Ctx *ctx, CRYPT_SPAKE2P_Role role)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_NULL_PARAM, "Context is NULL");
        return CRYPT_ERR_NULL_PARAM;
    }
    if (role != CRYPT_SPAKE2P_ROLE_CLIENT && role != CRYPT_SPAKE2P_ROLE_SERVER) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_INVALID_PARAM, "Invalid role specified");
        return CRYPT_ERR_INVALID_PARAM;
    }
    ctx->role = role;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SPAKE2P_InitGroup(CRYPT_SPAKE2P_Ctx *ctx, CRYPT_PKEY_ParaId curveId,
                               CRYPT_MD_AlgId hashId, CRYPT_MAC_AlgId macId)
{
    if (ctx == NULL) return CRYPT_ERR_NULL_PARAM;
    int32_t ret;

    ctx->curveId = curveId;
    ctx->hashId = hashId;
    ctx->macId = macId;

    ret = CRYPT_ECC_NewParaById(&ctx->grp, curveId);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to load ECC group parameters");
        return ret;
    }

    ret = CRYPT_ECC_GetGenerator(&ctx->P_generator, &ctx->grp);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to get group generator P");
        goto cleanup_grp;
    }

    // Load M and N (specific to ciphersuite, e.g., Ed25519)
    // RFC 9383, Section 4.1: SPAKE2+-Ed25519-SHA256-HKDF-HMAC-SHA256
    if (curveId == CRYPT_PKEY_PARAID_SPAKE2P_EDWARDS25519_SHA256_HKDF_HMAC_SHA256 ||
        curveId == CRYPT_ECC_NISTP256) { // Assuming Ed25519 for now
        // CRYPT_ECC_HexToPoint is not standard, need to use CRYPT_ECC_PointFromOctet
        // Convert hex string to octet string first.
        uint8_t m_oct[CRYPT_MAX_POINT_LEN];
        uint8_t n_oct[CRYPT_MAX_POINT_LEN];
        uint32_t m_oct_len, n_oct_len;

        m_oct_len = (uint32_t)CRYPT_UTILS_HexToBin(ED25519_M_HEX, (uint32_t)strlen(ED25519_M_HEX), m_oct, sizeof(m_oct));
        if (m_oct_len == 0) {
            BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_CONVERT_FAIL, "Failed to convert M_HEX to octet");
            ret = CRYPT_ERR_CONVERT_FAIL;
            goto cleanup_gen;
        }
        ret = CRYPT_ECC_PointFromOctet(&ctx->M, &ctx->grp, m_oct, m_oct_len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to load M point from octet");
            goto cleanup_gen;
        }

        n_oct_len = (uint32_t)CRYPT_UTILS_HexToBin(ED25519_N_HEX, (uint32_t)strlen(ED25519_N_HEX), n_oct, sizeof(n_oct));
         if (n_oct_len == 0) {
            BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_CONVERT_FAIL, "Failed to convert N_HEX to octet");
            ret = CRYPT_ERR_CONVERT_FAIL;
            goto cleanup_m;
        }
        ret = CRYPT_ECC_PointFromOctet(&ctx->N, &ctx->grp, n_oct, n_oct_len);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to load N point from octet");
            goto cleanup_m;
        }
    } else {
        // TODO: Handle other curves or return error if M, N not defined
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_INVALID_PARAM, "Curve not supported or M,N not defined for it");
        ret = CRYPT_ERR_INVALID_PARAM;
        goto cleanup_gen;
    }
    return CRYPT_SUCCESS;

cleanup_m:
    CRYPT_ECC_ClearPoint(&ctx->M);
cleanup_gen:
    CRYPT_ECC_ClearPoint(&ctx->P_generator);
cleanup_grp:
    CRYPT_ECC_ClearGrp(&ctx->grp);
    return ret;
}

int32_t CRYPT_SPAKE2P_ComputePw(CRYPT_SPAKE2P_Ctx *ctx)
{
    if (ctx == NULL || ctx->pwd_buf == NULL || ctx->pwd_len == 0) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_NULL_PARAM, "Context or password not set for ComputePw");
        return CRYPT_ERR_NULL_PARAM;
    }

    int32_t ret;
    uint8_t hashed_pwd[CRYPT_MAX_MD_SIZE];
    uint32_t hashed_pwd_len = 0;
    CRYPT_EAL_MD_ImpCtx md_ctx_s;
    CRYPT_EAL_MD_HANDLE md_handle = &md_ctx_s;

    ret = CRYPT_EAL_HashNew(md_handle, ctx->hashId);
    if (ret != CRYPT_SUCCESS) return ret;

    ret = CRYPT_EAL_HashUpdate(md_handle, ctx->pwd_buf, (uint32_t)ctx->pwd_len);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_HashFree(md_handle);
        return ret;
    }
    ret = CRYPT_EAL_HashFinal(md_handle, hashed_pwd, &hashed_pwd_len);
    CRYPT_EAL_HashFree(md_handle);
    if (ret != CRYPT_SUCCESS) return ret;

    ret = CRYPT_MPI_ReadBin(&ctx->pw_scalar, hashed_pwd, hashed_pwd_len);
    if (ret != CRYPT_SUCCESS) return ret;

    /* Reduce pw_scalar modulo group order n */
    ret = CRYPT_MPI_Mod(&ctx->pw_scalar, &ctx->pw_scalar, &ctx->grp.n);
    if (ret != CRYPT_SUCCESS) return ret;

    /* Compute w0 and w1 based on role (RFC 9383 Section 3.3.1) */
    if (ctx->role == CRYPT_SPAKE2P_ROLE_CLIENT) {
        ret = CRYPT_MPI_Copy(&ctx->w0, &ctx->pw_scalar);
        if (ret != CRYPT_SUCCESS) return ret;
        ret = CRYPT_MPI_Zero(&ctx->w1);
    } else { /* Server role */
        ret = CRYPT_MPI_Zero(&ctx->w0);
        if (ret != CRYPT_SUCCESS) return ret;
        ret = CRYPT_MPI_Copy(&ctx->w1, &ctx->pw_scalar);
    }
    return ret;
}

int32_t CRYPT_SPAKE2P_GenerateExchangeMessage(CRYPT_SPAKE2P_Ctx *ctx, uint8_t *msg_out, uint32_t *msg_out_len)
{
    if (ctx == NULL || msg_out == NULL || msg_out_len == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_NULL_PARAM, "Null param for GenExchangeMsg");
        return CRYPT_ERR_NULL_PARAM;
    }
    if (ctx->grp.n.s == NULL) { // Check if group is initialized
         BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_INVALID_STATE, "Group not initialized for GenExchangeMsg");
        return CRYPT_ERR_INVALID_STATE;
    }

    int32_t ret;

    /* Compute pw, w0, w1 if not already done (e.g. if SetPassword was called again) */
    /* Assuming ComputePw is called separately or once after SetPassword and SetRole */
    if (ctx->pw_scalar.s == NULL || (CRYPT_MPI_IsZero(&ctx->w0) && CRYPT_MPI_IsZero(&ctx->w1))) {
         ret = CRYPT_SPAKE2P_ComputePw(ctx);
         if (ret != CRYPT_SUCCESS) {
             BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "ComputePw failed in GenExchangeMsg");
             return ret;
         }
    }


    /* 1. Generate random scalar k_private (x for client, y for server) in [0, n-1] */
    ret = CRYPT_BN_RandRange(&ctx->k_private, &ctx->grp.n);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to generate random k_private");
        return ret;
    }

    /* 2. Compute T = k_private * P_generator */
    ret = CRYPT_ECC_PointScalarMul(&ctx->temp_point1, &ctx->P_generator, &ctx->k_private, &ctx->grp);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to compute T = k*P");
        return ret;
    }

    /* 3. Compute P_our_msg = T + w0 * M (Client) or P_our_msg = T + w1 * N (Server) */
    if (ctx->role == CRYPT_SPAKE2P_ROLE_CLIENT) {
        /* temp_point2 = w0 * M */
        ret = CRYPT_ECC_PointScalarMul(&ctx->temp_point2, &ctx->M, &ctx->w0, &ctx->grp);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to compute w0*M for client");
            return ret;
        }
    } else { /* Server role */
        /* temp_point2 = w1 * N */
        ret = CRYPT_ECC_PointScalarMul(&ctx->temp_point2, &ctx->N, &ctx->w1, &ctx->grp);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to compute w1*N for server");
            return ret;
        }
    }

    /* P_our_msg = temp_point1 (T) + temp_point2 (w0M or w1N) */
    ret = CRYPT_ECC_PointAdd(&ctx->P_our_msg, &ctx->temp_point1, &ctx->temp_point2, &ctx->grp);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to compute P_our_msg = T + wM/N");
        return ret;
    }

    /* 4. Serialize P_our_msg to msg_out */
    ret = CRYPT_ECC_PointToOctet(&ctx->P_our_msg, &ctx->grp, CRYPT_POINT_UNCOMPRESSED, msg_out, msg_out_len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to serialize P_our_msg");
    }
    return ret;
}

int32_t CRYPT_SPAKE2P_ComputeSharedSecretAndConfirmationMacs(CRYPT_SPAKE2P_Ctx *ctx,
                                                           const uint8_t *peer_msg_in, uint32_t peer_msg_in_len)
{
    if (ctx == NULL || peer_msg_in == NULL || peer_msg_in_len == 0) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_NULL_PARAM, "Null param for ComputeSharedSecret");
        return CRYPT_ERR_NULL_PARAM;
    }
    if (ctx->k_private.s == NULL || CRYPT_MPI_IsZero(&ctx->k_private)) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_INVALID_STATE, "Private key k not generated");
        return CRYPT_ERR_INVALID_STATE;
    }

    int32_t ret;
    uint32_t point_len;

    /* 1. Deserialize peer_msg_in to P_peer_msg */
    ret = CRYPT_ECC_OctetToPoint(&ctx->P_peer_msg, &ctx->grp, peer_msg_in, peer_msg_in_len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to deserialize P_peer_msg");
        return ret;
    }

    /* 2. Determine peer's w0_peer, w1_peer based on OUR role */
    /* If I am client, peer is server: w0_peer = 0, w1_peer = pw_scalar (derived from my password) */
    /* If I am server, peer is client: w0_peer = pw_scalar, w1_peer = 0 */
    if (ctx->role == CRYPT_SPAKE2P_ROLE_CLIENT) { /* Peer is server */
        ret = CRYPT_MPI_Zero(&ctx->w0_peer);
        if (ret != CRYPT_SUCCESS) return ret;
        ret = CRYPT_MPI_Copy(&ctx->w1_peer, &ctx->pw_scalar);
    } else { /* Peer is client */
        ret = CRYPT_MPI_Copy(&ctx->w0_peer, &ctx->pw_scalar);
        if (ret != CRYPT_SUCCESS) return ret;
        ret = CRYPT_MPI_Zero(&ctx->w1_peer);
    }
    if (ret != CRYPT_SUCCESS) {
         BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to set peer w0/w1");
         return ret;
    }


    /* 3. Compute Z_point or V_point (shared secret point K in RFC) */
    /* K = k_private * (P_peer_msg - (w0_peer * M + w1_peer * N)) */
    /* temp_point1 = w0_peer * M */
    ret = CRYPT_ECC_PointScalarMul(&ctx->temp_point1, &ctx->M, &ctx->w0_peer, &ctx->grp);
    if (ret != CRYPT_SUCCESS) return ret;
    /* temp_point2 = w1_peer * N */
    ret = CRYPT_ECC_PointScalarMul(&ctx->temp_point2, &ctx->N, &ctx->w1_peer, &ctx->grp);
    if (ret != CRYPT_SUCCESS) return ret;
    /* temp_point3 = w0_peer * M + w1_peer * N */
    ret = CRYPT_ECC_PointAdd(&ctx->temp_point3, &ctx->temp_point1, &ctx->temp_point2, &ctx->grp);
    if (ret != CRYPT_SUCCESS) return ret;
    /* temp_point1 = P_peer_msg - temp_point3 */
    ret = CRYPT_ECC_PointSub(&ctx->temp_point1, &ctx->P_peer_msg, &ctx->temp_point3, &ctx->grp);
    if (ret != CRYPT_SUCCESS) return ret;

    /* temp_point2 (K) = k_private * temp_point1 */
    ret = CRYPT_ECC_PointScalarMul(&ctx->temp_point2, &ctx->temp_point1, &ctx->k_private, &ctx->grp);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to compute shared secret point K");
        return ret;
    }


    /* 4. Construct Transcript TT (RFC 9383 Section 3.3) */
    /* TT = Context || A || B || G || M || N || X || Y || Z || V || w */
    /* For this implementation, Context is empty. A=our_id, B=peer_id. */
    /* X, Y are P_our_msg, P_peer_msg in order of exchange. */
    /* Z, V are derived from K (temp_point2) based on role. */
    /* w is pw_scalar. */

    CRYPT_MEM_FREE_NONULL(ctx->transcript_TT); // Clear previous transcript
    ctx->transcript_TT = NULL;
    ctx->transcript_TT_len = 0;

    uint8_t point_buf[CRYPT_MAX_POINT_LEN];
    uint8_t mpi_buf[CRYPT_MAX_MPI_LEN]; // Assuming CRYPT_MAX_MPI_LEN is sufficient for pw_scalar
    uint32_t buf_len;

    // ID_A (our ID), ID_B (peer ID) - order depends on role for TT
    const uint8_t *id_A = (ctx->role == CRYPT_SPAKE2P_ROLE_CLIENT) ? ctx->our_id_buf : ctx->peer_id_buf;
    size_t id_A_len = (ctx->role == CRYPT_SPAKE2P_ROLE_CLIENT) ? ctx->our_id_len : ctx->peer_id_len;
    const uint8_t *id_B = (ctx->role == CRYPT_SPAKE2P_ROLE_CLIENT) ? ctx->peer_id_buf : ctx->our_id_buf;
    size_t id_B_len = (ctx->role == CRYPT_SPAKE2P_ROLE_CLIENT) ? ctx->peer_id_len : ctx->our_id_len;

    ret = transcript_append_L(ctx, id_A, id_A_len); if (ret != CRYPT_SUCCESS) return ret;
    ret = transcript_append_L(ctx, id_B, id_B_len); if (ret != CRYPT_SUCCESS) return ret;

    // G (P_generator)
    buf_len = sizeof(point_buf);
    ret = CRYPT_ECC_PointToOctet(&ctx->P_generator, &ctx->grp, CRYPT_POINT_UNCOMPRESSED, point_buf, &buf_len);
    if (ret != CRYPT_SUCCESS) return ret;
    ret = transcript_append_L(ctx, point_buf, buf_len); if (ret != CRYPT_SUCCESS) return ret;

    // M
    buf_len = sizeof(point_buf);
    ret = CRYPT_ECC_PointToOctet(&ctx->M, &ctx->grp, CRYPT_POINT_UNCOMPRESSED, point_buf, &buf_len);
    if (ret != CRYPT_SUCCESS) return ret;
    ret = transcript_append_L(ctx, point_buf, buf_len); if (ret != CRYPT_SUCCESS) return ret;

    // N
    buf_len = sizeof(point_buf);
    ret = CRYPT_ECC_PointToOctet(&ctx->N, &ctx->grp, CRYPT_POINT_UNCOMPRESSED, point_buf, &buf_len);
    if (ret != CRYPT_SUCCESS) return ret;
    ret = transcript_append_L(ctx, point_buf, buf_len); if (ret != CRYPT_SUCCESS) return ret;

    // pU (Client's message), pV (Server's message)
    const CRYPT_ECC_Point *pU_point = (ctx->role == CRYPT_SPAKE2P_ROLE_CLIENT) ? &ctx->P_our_msg : &ctx->P_peer_msg;
    const CRYPT_ECC_Point *pV_point = (ctx->role == CRYPT_SPAKE2P_ROLE_CLIENT) ? &ctx->P_peer_msg : &ctx->P_our_msg;

    buf_len = sizeof(point_buf);
    ret = CRYPT_ECC_PointToOctet(pU_point, &ctx->grp, CRYPT_POINT_UNCOMPRESSED, point_buf, &buf_len);
    if (ret != CRYPT_SUCCESS) return ret;
    ret = transcript_append_L(ctx, point_buf, buf_len); if (ret != CRYPT_SUCCESS) return ret;

    buf_len = sizeof(point_buf);
    ret = CRYPT_ECC_PointToOctet(pV_point, &ctx->grp, CRYPT_POINT_UNCOMPRESSED, point_buf, &buf_len);
    if (ret != CRYPT_SUCCESS) return ret;
    ret = transcript_append_L(ctx, point_buf, buf_len); if (ret != CRYPT_SUCCESS) return ret;

    // Z (Client's shared secret point), V (Server's shared secret point)
    // Both are derived from K (ctx->temp_point2)
    buf_len = sizeof(point_buf);
    ret = CRYPT_ECC_PointToOctet(&ctx->temp_point2, &ctx->grp, CRYPT_POINT_UNCOMPRESSED, point_buf, &buf_len);
    if (ret != CRYPT_SUCCESS) return ret;

    if (ctx->role == CRYPT_SPAKE2P_ROLE_CLIENT) { // Z then V
        ret = transcript_append_L(ctx, point_buf, buf_len); if (ret != CRYPT_SUCCESS) return ret; // Z
        ret = transcript_append_L(ctx, NULL, 0); // V is empty for client if we take Z as the single shared secret point repr.
                                                // Or, more correctly, Z and V are the same point K.
                                                // RFC9383: "The transcript TT is constructed ... || Z || V || w"
                                                // Z = Ka, V = Kb. If K is the shared secret point:
                                                // Client computes Ka = x(Y - w0*M), Server computes Kb = y(X - w1*N)
                                                // Both Ka and Kb should be the same point if math is correct.
                                                // So, append K twice.
        ret = transcript_append_L(ctx, point_buf, buf_len); if (ret != CRYPT_SUCCESS) return ret; // V
    } else { // V then Z
        ret = transcript_append_L(ctx, point_buf, buf_len); if (ret != CRYPT_SUCCESS) return ret; // V
        ret = transcript_append_L(ctx, point_buf, buf_len); if (ret != CRYPT_SUCCESS) return ret; // Z
    }


    // w (pw_scalar)
    buf_len = (uint32_t)CRYPT_MPI_GetSize(&ctx->pw_scalar);
    if (buf_len > sizeof(mpi_buf)) return CRYPT_ERR_BUF_TOO_SMALL;
    ret = CRYPT_MPI_WriteBin(&ctx->pw_scalar, mpi_buf, buf_len);
    if (ret != CRYPT_SUCCESS) return ret;
    ret = transcript_append_L(ctx, mpi_buf, buf_len); if (ret != CRYPT_SUCCESS) return ret;


    /* 5. Derive Ke, KcA, KcB using HKDF */
    // Lengths: hash_len for Ke, hash_len for KcA, hash_len for KcB
    // For SHA256, each is 32 bytes. Total 96 bytes.
    uint32_t hash_output_len_bits = CRYPT_MD_GetOutputBits(ctx->hashId);
    if (hash_output_len_bits == 0) return CRYPT_ERR_INVALID_ALG;
    uint32_t key_material_len = (hash_output_len_bits / 8) * 3;
    uint8_t *derived_key_material = (uint8_t *)BSL_TRD_MALLOC_PARA(key_material_len);
    if (derived_key_material == NULL) return CRYPT_ERR_MALLOC_FAIL;

    CRYPT_KDF_Params kdf_params;
    kdf_params.kdfAlgId = CRYPT_KDF_HKDF;
    kdf_params.hkdf.hashId = ctx->hashId;
    kdf_params.hkdf.salt = NULL; // No salt for SPAKE2+ HKDF
    kdf_params.hkdf.saltLen = 0;
    kdf_params.hkdf.ikm = ctx->transcript_TT;
    kdf_params.hkdf.ikmLen = (uint32_t)ctx->transcript_TT_len;
    kdf_params.hkdf.info = (const uint8_t *)"SPAKE2P Key Establishment"; // From RFC 9383
    kdf_params.hkdf.infoLen = (uint32_t)strlen("SPAKE2P Key Establishment");
    kdf_params.hkdf.okm = derived_key_material;
    kdf_params.hkdf.okmLen = key_material_len;

    ret = CRYPT_EAL_KdfDerive(&kdf_params);
    if (ret != CRYPT_SUCCESS) {
        BSL_TRD_FREE(derived_key_material);
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "HKDF key derivation failed");
        return ret;
    }

    uint32_t single_key_len = hash_output_len_bits / 8;
    ret = spake2p_secure_alloc_copy(&ctx->Ke_derived, &ctx->Ke_derived_len, derived_key_material, single_key_len);
    if (ret != CRYPT_SUCCESS) { BSL_TRD_FREE(derived_key_material); return ret; }
    ret = spake2p_secure_alloc_copy(&ctx->KcA_derived, &ctx->KcA_derived_len, derived_key_material + single_key_len, single_key_len);
    if (ret != CRYPT_SUCCESS) { BSL_TRD_FREE(derived_key_material); return ret; }
    ret = spake2p_secure_alloc_copy(&ctx->KcB_derived, &ctx->KcB_derived_len, derived_key_material + (2 * single_key_len), single_key_len);
    BSL_TRD_FREE(derived_key_material);
    if (ret != CRYPT_SUCCESS) return ret;


    /* 6. Compute ConfirmationMACs */
    CRYPT_EAL_MAC_ImpCtx mac_ctx_s;
    CRYPT_EAL_MAC_HANDLE mac_handle = &mac_ctx_s;
    const uint8_t *our_mac_key = (ctx->role == CRYPT_SPAKE2P_ROLE_CLIENT) ? ctx->KcA_derived : ctx->KcB_derived;
    size_t our_mac_key_len = (ctx->role == CRYPT_SPAKE2P_ROLE_CLIENT) ? ctx->KcA_derived_len : ctx->KcB_derived_len;
    const uint8_t *peer_mac_key = (ctx->role == CRYPT_SPAKE2P_ROLE_CLIENT) ? ctx->KcB_derived : ctx->KcA_derived;
    size_t peer_mac_key_len = (ctx->role == CRYPT_SPAKE2P_ROLE_CLIENT) ? ctx->KcB_derived_len : ctx->KcA_derived_len;

    /* Our MAC */
    ret = CRYPT_EAL_MacNew(mac_handle, ctx->macId, our_mac_key, (uint32_t)our_mac_key_len);
    if (ret != CRYPT_SUCCESS) return ret;
    ret = CRYPT_EAL_MacUpdate(mac_handle, ctx->transcript_TT, (uint32_t)ctx->transcript_TT_len);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_MacFree(mac_handle); return ret; }
    ctx->our_mac_len = sizeof(ctx->our_mac); // Set max buffer size
    ret = CRYPT_EAL_MacFinal(mac_handle, ctx->our_mac, (uint32_t*)&ctx->our_mac_len);
    CRYPT_EAL_MacFree(mac_handle);
    if (ret != CRYPT_SUCCESS) return ret;

    /* Peer's Expected MAC */
    ret = CRYPT_EAL_MacNew(mac_handle, ctx->macId, peer_mac_key, (uint32_t)peer_mac_key_len);
    if (ret != CRYPT_SUCCESS) return ret;
    ret = CRYPT_EAL_MacUpdate(mac_handle, ctx->transcript_TT, (uint32_t)ctx->transcript_TT_len);
    if (ret != CRYPT_SUCCESS) { CRYPT_EAL_MacFree(mac_handle); return ret; }
    ctx->peer_expected_mac_len = sizeof(ctx->peer_expected_mac); // Set max buffer size
    ret = CRYPT_EAL_MacFinal(mac_handle, ctx->peer_expected_mac, (uint32_t*)&ctx->peer_expected_mac_len);
    CRYPT_EAL_MacFree(mac_handle);

    return ret;
}

int32_t CRYPT_SPAKE2P_GetOurConfirmationMac(CRYPT_SPAKE2P_Ctx *ctx, uint8_t *mac_out, uint32_t *mac_out_len)
{
    if (ctx == NULL || mac_out == NULL || mac_out_len == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_NULL_PARAM, "Null param for GetOurConfMac");
        return CRYPT_ERR_NULL_PARAM;
    }
    if (ctx->our_mac_len == 0) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_INVALID_STATE, "Our MAC not computed");
        return CRYPT_ERR_INVALID_STATE;
    }
    if (*mac_out_len < ctx->our_mac_len) {
        *mac_out_len = (uint32_t)ctx->our_mac_len;
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_BUF_TOO_SMALL, "Output buffer too small for MAC");
        return CRYPT_ERR_BUF_TOO_SMALL;
    }

    if (BSL_SRE_MEMCPY_S(mac_out, *mac_out_len, ctx->our_mac, ctx->our_mac_len) != EOK) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_MEMCPY_FAIL, "Memcpy failed for GetOurConfMac");
        return CRYPT_ERR_MEMCPY_FAIL;
    }
    *mac_out_len = (uint32_t)ctx->our_mac_len;
    return CRYPT_SUCCESS;
}

/*
 * Internal function to set the ephemeral private key 'k_private' from a hex string.
 * This is primarily for RFC test vector validation.
 */
static int32_t spake2p_set_ephemeral_private_key_from_hex(CRYPT_SPAKE2P_Ctx *ctx, const char *hex_key)
{
    if (ctx == NULL || hex_key == NULL) {
        return CRYPT_ERR_NULL_PARAM;
    }

    uint8_t key_bin[CRYPT_MAX_MPI_LEN]; // Assuming private key fits
    uint32_t key_bin_len = (uint32_t)CRYPT_UTILS_HexToBin(hex_key, (uint32_t)strlen(hex_key), key_bin, sizeof(key_bin));

    if (key_bin_len == 0 && strlen(hex_key) != 0) { // Allow empty hex for zero key if that's a test case
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_CONVERT_FAIL, "Failed to convert hex private key to binary");
        return CRYPT_ERR_CONVERT_FAIL;
    }
    
    // Free existing k_private before re-reading.
    // CRYPT_MPI_ClearFree(&ctx->k_private); // Not needed as ReadBin will overwrite
    // CRYPT_MPI_Init(&ctx->k_private);      // Ensure it's initialized if it wasn't

    int32_t ret = CRYPT_MPI_ReadBin(&ctx->k_private, key_bin, key_bin_len);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to read binary private key into MPI");
        return ret;
    }
    
    // Ensure k_private is < n (order of the group)
    if (ctx->grp.n.s != NULL && CRYPT_MPI_Cmp(&ctx->k_private, &ctx->grp.n) >= 0) {
        ret = CRYPT_MPI_Mod(&ctx->k_private, &ctx->k_private, &ctx->grp.n);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, ret, "Failed to reduce k_private modulo n");
            return ret;
        }
    }
    return CRYPT_SUCCESS;
}


/* Internal helper to get MPI as octet string */
static int32_t spake2p_get_mpi_as_octets(const CRYPT_MPI *mpi, CRYPT_SPAKE2P_BUFFER_PARAM *params)
{
    if (mpi == NULL || mpi->s == NULL || params == NULL || params->bufferLen == NULL) {
        return CRYPT_ERR_NULL_PARAM;
    }
    uint32_t mpi_byte_len = (uint32_t)CRYPT_MPI_GetSize(mpi);
    if (*(params->bufferLen) < mpi_byte_len) {
        *(params->bufferLen) = mpi_byte_len;
        return CRYPT_ERR_BUF_TOO_SMALL;
    }
    int32_t ret = CRYPT_MPI_WriteBin(mpi, params->buffer, mpi_byte_len);
    if (ret == CRYPT_SUCCESS) {
        *(params->bufferLen) = mpi_byte_len;
    }
    return ret;
}

/* Internal helper to get ECC Point as octet string */
static int32_t spake2p_get_point_as_octets(const CRYPT_ECC_Point *pt, const CRYPT_ECC_Grp *grp, CRYPT_SPAKE2P_BUFFER_PARAM *params)
{
    if (pt == NULL || pt->X.s == NULL || grp == NULL || params == NULL || params->bufferLen == NULL) {
        return CRYPT_ERR_NULL_PARAM;
    }
    // CRYPT_ECC_PointToOctet will fill in actual length.
    // Caller must ensure params->bufferLen initially holds buffer capacity.
    return CRYPT_ECC_PointToOctet(pt, grp, CRYPT_POINT_UNCOMPRESSED, params->buffer, params->bufferLen);
}

/* Internal helper to get raw buffer */
static int32_t spake2p_get_buffer_data(const uint8_t *src_buf, size_t src_len, CRYPT_SPAKE2P_BUFFER_PARAM *params)
{
    if (src_buf == NULL || params == NULL || params->bufferLen == NULL) {
        return CRYPT_ERR_NULL_PARAM;
    }
    if (src_len == 0) { // Nothing to copy, report 0 length
        *(params->bufferLen) = 0;
        return CRYPT_SUCCESS;
    }
    if (*(params->bufferLen) < src_len) {
        *(params->bufferLen) = (uint32_t)src_len;
        return CRYPT_ERR_BUF_TOO_SMALL;
    }
    if (BSL_SRE_MEMCPY_S(params->buffer, *(params->bufferLen), src_buf, src_len) != EOK) {
        return CRYPT_ERR_MEMCPY_FAIL;
    }
    *(params->bufferLen) = (uint32_t)src_len;
    return CRYPT_SUCCESS;
}


int32_t CRYPT_SPAKE2P_VerifyPeerConfirmationMac(CRYPT_SPAKE2P_Ctx *ctx, const uint8_t *peer_mac_in, uint32_t peer_mac_in_len)
{
    if (ctx == NULL || peer_mac_in == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_NULL_PARAM, "Null param for VerifyPeerConfMac");
        return CRYPT_ERR_NULL_PARAM;
    }
    if (ctx->peer_expected_mac_len == 0) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_INVALID_STATE, "Peer expected MAC not computed");
        return CRYPT_ERR_INVALID_STATE;
    }
    if (peer_mac_in_len != ctx->peer_expected_mac_len) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_MAC_VERIFY_FAIL, "Peer MAC length mismatch");
        return CRYPT_ERR_MAC_VERIFY_FAIL;
    }

    // Use a constant-time comparison
    if (CRYPT_VerifyMacsConstantTime(peer_mac_in, ctx->peer_expected_mac, ctx->peer_expected_mac_len) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_MAC_VERIFY_FAIL, "Peer MAC verification failed");
        return CRYPT_ERR_MAC_VERIFY_FAIL;
    }
    return CRYPT_SUCCESS;
}

/*
 * Centralized control function for SPAKE2P specific operations,
 * particularly for test vector verification.
 */
int32_t CRYPT_SPAKE2P_Ctrl(CRYPT_SPAKE2P_Ctx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        // Allow certain ops if ctx is NULL? For now, require valid ctx.
        // Example: if opt is for getting default M/N points, ctx might not be needed.
        // However, most GET operations need a populated context.
        BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_NULL_PARAM, "SPAKE2P context is NULL for Ctrl operation");
        return CRYPT_ERR_NULL_PARAM;
    }
    if (val == NULL &&
        opt != CRYPT_CTRL_SPAKE2P_GENERATE_EXCHANGE_MSG && /* Some GET might not need val if len implies what to get */
        opt != CRYPT_CTRL_SPAKE2P_PROCESS_PEER_MSG_AND_CONFIRM /* these are handled by EAL Ctrl which wraps this */
        /* Add other ops that might not use val or len directly */
       ) {
        // More fine-grained checks for val/len per opt needed.
        // This is a generic check.
    }


    switch (opt) {
        case CRYPT_CTRL_SPAKE2P_SET_EPHEMERAL_PRIVATE_KEY:
        {
            if (val == NULL) return CRYPT_ERR_NULL_PARAM;
            CRYPT_SPAKE2P_DATA_PARAM *params = (CRYPT_SPAKE2P_DATA_PARAM *)val;
            // Assuming params->data is a null-terminated hex string for the private key
            return spake2p_set_ephemeral_private_key_from_hex(ctx, (const char *)params->data);
        }
        case CRYPT_CTRL_SPAKE2P_GET_COMPUTED_W0:
            if (val == NULL) return CRYPT_ERR_NULL_PARAM;
            return spake2p_get_mpi_as_octets(&ctx->w0, (CRYPT_SPAKE2P_BUFFER_PARAM *)val);
        case CRYPT_CTRL_SPAKE2P_GET_COMPUTED_W1:
            if (val == NULL) return CRYPT_ERR_NULL_PARAM;
            return spake2p_get_mpi_as_octets(&ctx->w1, (CRYPT_SPAKE2P_BUFFER_PARAM *)val);
        case CRYPT_CTRL_SPAKE2P_GET_PW_SCALAR:
             if (val == NULL) return CRYPT_ERR_NULL_PARAM;
            return spake2p_get_mpi_as_octets(&ctx->pw_scalar, (CRYPT_SPAKE2P_BUFFER_PARAM *)val);
        case CRYPT_CTRL_SPAKE2P_GET_EXCHANGE_MESSAGE_RAW: /* To get P_our_msg after it's computed */
            if (val == NULL) return CRYPT_ERR_NULL_PARAM;
            return spake2p_get_point_as_octets(&ctx->P_our_msg, &ctx->grp, (CRYPT_SPAKE2P_BUFFER_PARAM *)val);
        case CRYPT_CTRL_SPAKE2P_GET_SHARED_POINT_K: /* K is stored in temp_point2 after ComputeSharedSecret */
            if (val == NULL) return CRYPT_ERR_NULL_PARAM;
            // K = Z = V, which is stored in temp_point2 during ComputeSharedSecretAndConfirmationMacs
            // Ensure this is called after that function.
            if (ctx->temp_point2.X.s == NULL) { // Check if point K is computed
                 BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_INVALID_STATE, "Shared point K not computed yet.");
                return CRYPT_ERR_INVALID_STATE;
            }
            return spake2p_get_point_as_octets(&ctx->temp_point2, &ctx->grp, (CRYPT_SPAKE2P_BUFFER_PARAM *)val);
        case CRYPT_CTRL_SPAKE2P_GET_TRANSCRIPT_TT:
            if (val == NULL) return CRYPT_ERR_NULL_PARAM;
            return spake2p_get_buffer_data(ctx->transcript_TT, ctx->transcript_TT_len, (CRYPT_SPAKE2P_BUFFER_PARAM *)val);
        case CRYPT_CTRL_SPAKE2P_GET_DERIVED_SECRET_KCA:
            if (val == NULL) return CRYPT_ERR_NULL_PARAM;
            return spake2p_get_buffer_data(ctx->KcA_derived, ctx->KcA_derived_len, (CRYPT_SPAKE2P_BUFFER_PARAM *)val);
        case CRYPT_CTRL_SPAKE2P_GET_DERIVED_SECRET_KCB:
            if (val == NULL) return CRYPT_ERR_NULL_PARAM;
            return spake2p_get_buffer_data(ctx->KcB_derived, ctx->KcB_derived_len, (CRYPT_SPAKE2P_BUFFER_PARAM *)val);

        /* Other cases from EAL_SPAKE2P_Ctrl_Internal would be here if this function was the single point of entry.
           However, those are directly calling specific CRYPT_SPAKE2P_* functions.
           This CRYPT_SPAKE2P_Ctrl is primarily for new test-related controls.
           If existing controls like SET_PASSWORD also need to be exposed through this specific Ctrl for some reason,
           they could be added here, but it might be redundant with direct function calls or EAL Ctrl.
        */
        default:
            BSL_ERR_PUSH_ERROR(BSL_MODULE_CRYPTO, CRYPT_ERR_NOT_SUPPORTED_OPT, "Unsupported SPAKE2P internal Ctrl option");
            return CRYPT_ERR_NOT_SUPPORTED_OPT;
    }
}
