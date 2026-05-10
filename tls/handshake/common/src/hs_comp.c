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
#include "hitls_error.h"
#include "bsl_errno.h"
#include "bsl_comp.h"
#include "tls.h"
#include "tls_config.h"
#include "hs_common.h"

#define HITLS_CERT_COMPRESS_MIN_INPUT_LEN 4u

static int32_t HS_MapBslCompRet(int32_t ret, bool isCompress)
{
    if (ret == BSL_SUCCESS) {
        return HITLS_SUCCESS;
    }
    if (ret == BSL_NULL_INPUT) {
        return HITLS_NULL_INPUT;
    }
    if (ret == BSL_INVALID_ARG) {
        return isCompress ? HITLS_MEMCPY_FAIL : HITLS_PARSE_INVALID_MSG_LEN;
    }
    return isCompress ? HITLS_PACK_NOT_ENOUGH_BUF_LENGTH : HITLS_PARSE_CERT_ERR;
}

bool HS_IsCertCompressionEnabled(const TLS_Ctx *ctx)
{
    const TLS_Config *config = &ctx->config.tlsConfig;

    return GET_VERSION_FROM_CTX(ctx) == HITLS_VERSION_TLS13 && config->isSupportCertCompression &&
        config->certCompressionAlgs != NULL && config->certCompressionAlgsSize != 0;
}

bool HS_IsCertCompressionAlgConfigured(const TLS_Ctx *ctx, uint16_t algorithm)
{
    const TLS_Config *config = &ctx->config.tlsConfig;

    if (config->certCompressionAlgs == NULL) {
        return false;
    }
    for (uint32_t i = 0; i < config->certCompressionAlgsSize; i++) {
        if (config->certCompressionAlgs[i] == algorithm) {
            return true;
        }
    }
    return false;
}

int32_t HS_SelectCertCompressionAlg(TLS_Ctx *ctx, const uint16_t *peerAlgs, uint16_t peerAlgCount)
{
    if (!HS_IsCertCompressionEnabled(ctx) || peerAlgs == NULL || peerAlgCount == 0) {
        return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
    }

    for (uint32_t i = 0; i < ctx->config.tlsConfig.certCompressionAlgsSize; i++) {
        uint16_t localAlg = ctx->config.tlsConfig.certCompressionAlgs[i];
        if (!BSL_COMP_IsAlgSupported(localAlg)) {
            continue;
        }
        for (uint16_t j = 0; j < peerAlgCount; j++) {
            if (localAlg == peerAlgs[j]) {
                ctx->negotiatedInfo.certCompressionAlg = peerAlgs[j];
                ctx->negotiatedInfo.isCertCompressionNegotiated = true;
                return HITLS_SUCCESS;
            }
        }
    }
    return HITLS_MSG_HANDLE_UNSUPPORT_EXTENSION_TYPE;
}

bool HS_ShouldSendCompressedCertificate(const TLS_Ctx *ctx, uint32_t certMsgLen)
{
    return ctx->negotiatedInfo.isCertCompressionNegotiated &&
        BSL_COMP_IsAlgSupported(ctx->negotiatedInfo.certCompressionAlg) &&
        certMsgLen >= ctx->config.tlsConfig.certCompressionThreshold;
}

int32_t HS_CompressCertificate(const TLS_Ctx *ctx, uint16_t algorithm, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    (void)ctx;
    if (in == NULL || out == NULL || outLen == NULL || inLen < HITLS_CERT_COMPRESS_MIN_INPUT_LEN) {
        return HITLS_NULL_INPUT;
    }
    if (!BSL_COMP_IsAlgSupported(algorithm)) {
        return HITLS_CONFIG_INVALID_SET;
    }
    return HS_MapBslCompRet(BSL_COMP_Compress(algorithm, in, inLen, out, outLen), true);
}

int32_t HS_DecompressCertificate(const TLS_Ctx *ctx, uint16_t algorithm, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    (void)ctx;
    if (in == NULL || out == NULL || outLen == NULL) {
        return HITLS_NULL_INPUT;
    }
    if (!BSL_COMP_IsAlgSupported(algorithm)) {
        return HITLS_CONFIG_INVALID_SET;
    }
    return HS_MapBslCompRet(BSL_COMP_Decompress(algorithm, in, inLen, out, outLen), false);
}

uint32_t HS_GetCertCompressionBound(uint16_t algorithm, uint32_t inLen)
{
    return BSL_COMP_GetCompressBound(algorithm, inLen);
}
