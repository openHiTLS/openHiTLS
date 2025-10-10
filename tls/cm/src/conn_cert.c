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

#include <stddef.h>
#include "hitls_build.h"
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls_cert_type.h"
#include "hitls_cert.h"
#include "tls.h"

int32_t HITLS_SetVerifyStore(HITLS_Ctx *ctx, HITLS_CERT_Store *store, bool isClone)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetVerifyStore(&(ctx->config.tlsConfig), store, isClone);
}

HITLS_CERT_Store *HITLS_GetVerifyStore(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetVerifyStore(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetChainStore(HITLS_Ctx *ctx, HITLS_CERT_Store *store, bool isClone)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetChainStore(&(ctx->config.tlsConfig), store, isClone);
}

HITLS_CERT_Store *HITLS_GetChainStore(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetChainStore(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetCertStore(HITLS_Ctx *ctx, HITLS_CERT_Store *store, bool isClone)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetCertStore(&(ctx->config.tlsConfig), store, isClone);
}

HITLS_CERT_Store *HITLS_GetCertStore(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetCertStore(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetDefaultPasswordCb(HITLS_Ctx *ctx, HITLS_PasswordCb cb)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetDefaultPasswordCb(&(ctx->config.tlsConfig), cb);
}

HITLS_PasswordCb HITLS_GetDefaultPasswordCb(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetDefaultPasswordCb(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetDefaultPasswordCbUserdata(HITLS_Ctx *ctx, void *userdata)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetDefaultPasswordCbUserdata(&(ctx->config.tlsConfig), userdata);
}

void *HITLS_GetDefaultPasswordCbUserdata(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetDefaultPasswordCbUserdata(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetCertificate(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, bool isClone)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetCertificate(&(ctx->config.tlsConfig), cert, isClone);
}

#ifdef HITLS_TLS_CONFIG_CERT_LOAD_FILE
int32_t HITLS_LoadCertFile(HITLS_Ctx *ctx, const char *file, HITLS_ParseFormat format)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_LoadCertFile(&(ctx->config.tlsConfig), file, format);
}
#endif

int32_t HITLS_LoadCertBuffer(HITLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_LoadCertBuffer(&(ctx->config.tlsConfig), buf, bufLen, format);
}

HITLS_CERT_X509 *HITLS_GetCertificate(const HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetCertificate(&(ctx->config.tlsConfig));
}

int32_t HITLS_SetPrivateKey(HITLS_Ctx *ctx, HITLS_CERT_Key *key, bool isClone)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetPrivateKey(&(ctx->config.tlsConfig), key, isClone);
}

#ifdef HITLS_TLS_CONFIG_CERT_LOAD_FILE
int32_t HITLS_ProviderLoadKeyFile(HITLS_Ctx *ctx, const char *file, const char *format, const char *type)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_ProviderLoadKeyFile(&(ctx->config.tlsConfig), file, format, type);
}

int32_t HITLS_LoadKeyFile(HITLS_Ctx *ctx, const char *file, HITLS_ParseFormat format)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_LoadKeyFile(&(ctx->config.tlsConfig), file, format);
}
#endif /* HITLS_TLS_CONFIG_CERT_LOAD_FILE */

int32_t HITLS_ProviderLoadKeyBuffer(HITLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, const char *format,
    const char *type)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_ProviderLoadKeyBuffer(&(ctx->config.tlsConfig), buf, bufLen, format, type);
}

int32_t HITLS_LoadKeyBuffer(HITLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_LoadKeyBuffer(&(ctx->config.tlsConfig), buf, bufLen, format);
}

HITLS_CERT_Key *HITLS_GetPrivateKey(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetPrivateKey(&(ctx->config.tlsConfig));
}

int32_t HITLS_CheckPrivateKey(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_CheckPrivateKey(&(ctx->config.tlsConfig));
}

int32_t HITLS_RemoveCertAndKey(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_RemoveCertAndKey(&(ctx->config.tlsConfig));
}

#ifdef HITLS_TLS_CONFIG_CERT_CALLBACK
int32_t HITLS_SetVerifyCb(HITLS_Ctx *ctx, HITLS_VerifyCb callback)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_SetVerifyCb(&(ctx->config.tlsConfig), callback);
}

HITLS_VerifyCb HITLS_GetVerifyCb(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    return HITLS_CFG_GetVerifyCb(&(ctx->config.tlsConfig));
}
#endif /* HITLS_TLS_CONFIG_CERT_CALLBACK */

int32_t HITLS_LoadCrlFile(HITLS_Ctx *ctx, const char *file, HITLS_ParseFormat format)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_LoadCrlFile(&(ctx->config.tlsConfig), file, format);
}

int32_t HITLS_LoadCrlBuffer(HITLS_Ctx *ctx, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_LoadCrlBuffer(&(ctx->config.tlsConfig), buf, bufLen, format);
}

int32_t HITLS_ClearVerifyCrls(HITLS_Ctx *ctx)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_ClearVerifyCrls(&(ctx->config.tlsConfig));
}

#ifdef HITLS_TLS_CONFIG_CERT_LOAD_FILE
int32_t HITLS_UseCertificateChainFile(HITLS_Ctx *ctx,  const char *file)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_UseCertificateChainFile(&(ctx->config.tlsConfig), file);
}
#endif /* HITLS_TLS_CONFIG_CERT_LOAD_FILE */

int32_t HITLS_UseCertificateChainBuffer(HITLS_Ctx *ctx, const uint8_t *buf,
    uint32_t bufLen, HITLS_ParseFormat format)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_UseCertificateChainBuffer(&(ctx->config.tlsConfig), buf, bufLen, format);
}

#ifdef HITLS_TLS_CONFIG_CERT_VERIFY_LOCATION
int32_t HITLS_LoadVerifyBuffer(HITLS_Ctx *ctx, const uint8_t *buf,
    uint32_t bufLen, HITLS_ParseFormat format)
{
    if (ctx == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_LoadVerifyBuffer(&(ctx->config.tlsConfig), buf, bufLen, format);
}
#endif /* HITLS_TLS_CONFIG_CERT_VERIFY_LOCATION */