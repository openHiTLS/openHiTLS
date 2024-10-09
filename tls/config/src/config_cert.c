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

#include <stdlib.h>
#include <string.h>
#include "bsl_err_internal.h"
#include "hitls_error.h"
#include "hitls_type.h"
#include "hitls_cert_type.h"
#include "tls_config.h"
#include "cert_method.h"
#include "cert_mgr.h"
#include "cert.h"
#include "security.h"

static int32_t CheckCertSecuritylevel(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isCACert)
{
    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    HITLS_CERT_Key *pubkey = NULL;
    int32_t ret = SAL_CERT_X509Ctrl(config, cert, CERT_CTRL_GET_PUB_KEY, NULL, (void *)&pubkey);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    int32_t secBits = 0;
    ret = SAL_CERT_KeyCtrl(config, pubkey, CERT_KEY_CTRL_GET_SECBITS, NULL, (void *)&secBits);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_KeyFree(mgrCtx, pubkey);
        return ret;
    }

    if (isCACert == true) {
        ret = SECURITY_CfgCheck(config, HITLS_SECURITY_SECOP_CA_KEY, secBits, 0, cert);
        if (ret != SECURITY_SUCCESS) {
            SAL_CERT_KeyFree(mgrCtx, pubkey);
            BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_CA_KEY_WITH_INSECURE_SECBITS);
            return HITLS_CERT_ERR_CA_KEY_WITH_INSECURE_SECBITS;
        }
    } else {
        ret = SECURITY_CfgCheck(config, HITLS_SECURITY_SECOP_EE_KEY, secBits, 0, cert);
        if (ret != SECURITY_SUCCESS) {
            SAL_CERT_KeyFree(mgrCtx, pubkey);
            BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_EE_KEY_WITH_INSECURE_SECBITS);
            return HITLS_CERT_ERR_EE_KEY_WITH_INSECURE_SECBITS;
        }
    }

    int32_t signAlg = 0;
    ret = SAL_CERT_X509Ctrl(config, cert, CERT_CTRL_GET_SIGN_ALGO, NULL, (void *)&signAlg);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_KeyFree(mgrCtx, pubkey);
        return ret;
    }

    ret = SECURITY_CfgCheck(config, HITLS_SECURITY_SECOP_SIGALG_CHECK, 0, signAlg, NULL);
    if (ret != SECURITY_SUCCESS) {
        SAL_CERT_KeyFree(mgrCtx, pubkey);
        BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_INSECURE_SIG_ALG);
        return HITLS_CERT_ERR_INSECURE_SIG_ALG;
    }
    SAL_CERT_KeyFree(mgrCtx, pubkey);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_SetVerifyStore(HITLS_Config *config, HITLS_CERT_Store *store, bool isClone)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Store *newStore = NULL;
    if (isClone && store != NULL) {
        newStore = SAL_CERT_StoreDup(config->certMgrCtx, store);
        if (newStore == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_STORE_DUP);
            return HITLS_CERT_ERR_STORE_DUP;
        }
    } else {
        newStore = store;
    }

    int32_t ret = SAL_CERT_SetVerifyStore(config->certMgrCtx, newStore);
    if (ret != HITLS_SUCCESS) {
        if (isClone && newStore != NULL) {
            SAL_CERT_StoreFree(config->certMgrCtx, newStore);
        }
    }
    return ret;
}

HITLS_CERT_Store *HITLS_CFG_GetVerifyStore(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetVerifyStore(config->certMgrCtx);
}

int32_t HITLS_CFG_SetChainStore(HITLS_Config *config, HITLS_CERT_Store *store, bool isClone)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Store *newStore = NULL;
    if (isClone && store != NULL) {
        newStore = SAL_CERT_StoreDup(config->certMgrCtx, store);
        if (newStore == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_STORE_DUP);
            return HITLS_CERT_ERR_STORE_DUP;
        }
    } else {
        newStore = store;
    }

    int32_t ret = SAL_CERT_SetChainStore(config->certMgrCtx, newStore);
    if (ret != HITLS_SUCCESS) {
        if (isClone && newStore != NULL) {
            SAL_CERT_StoreFree(config->certMgrCtx, newStore);
        }
    }
    return ret;
}

HITLS_CERT_Store *HITLS_CFG_GetChainStore(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetChainStore(config->certMgrCtx);
}

int32_t HITLS_CFG_SetCertStore(HITLS_Config *config, HITLS_CERT_Store *store, bool isClone)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Store *newStore = NULL;
    if (isClone && store != NULL) {
        newStore = SAL_CERT_StoreDup(config->certMgrCtx, store);
        if (newStore == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_STORE_DUP);
            return HITLS_CERT_ERR_STORE_DUP;
        }
    } else {
        newStore = store;
    }

    int32_t ret = SAL_CERT_SetCertStore(config->certMgrCtx, newStore);
    if (ret != HITLS_SUCCESS) {
        if (isClone && newStore != NULL) {
            SAL_CERT_StoreFree(config->certMgrCtx, newStore);
        }
    }
    return ret;
}

HITLS_CERT_Store *HITLS_CFG_GetCertStore(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetCertStore(config->certMgrCtx);
}

int32_t HITLS_CFG_SetVerifyDepth(HITLS_Config *config, uint32_t depth)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return SAL_CERT_SetVerifyDepth(config->certMgrCtx, depth);
}

int32_t HITLS_CFG_GetVerifyDepth(const HITLS_Config *config, uint32_t *depth)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return SAL_CERT_GetVerifyDepth(config->certMgrCtx, depth);
}

int32_t HITLS_CFG_SetDefaultPasswordCb(HITLS_Config *config, HITLS_PasswordCb cb)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return SAL_CERT_SetDefaultPasswordCb(config->certMgrCtx, cb);
}

HITLS_PasswordCb HITLS_CFG_GetDefaultPasswordCb(HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetDefaultPasswordCb(config->certMgrCtx);
}

int32_t HITLS_CFG_SetDefaultPasswordCbUserdata(HITLS_Config *config, void *userdata)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return SAL_CERT_SetDefaultPasswordCbUserdata(config->certMgrCtx, userdata);
}

void *HITLS_CFG_GetDefaultPasswordCbUserdata(HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetDefaultPasswordCbUserdata(config->certMgrCtx);
}

static int32_t CFG_SetCertificate(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone, bool isTlcpEncCert)
{
    if (config == NULL || cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_X509 *newCert = NULL;
    if (isClone) {
        newCert = SAL_CERT_X509Dup(config->certMgrCtx, cert);
        if (newCert == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_X509_DUP);
            return HITLS_CERT_ERR_X509_DUP;
        }
    } else {
        newCert = cert;
    }

    int32_t ret = SAL_CERT_SetCurrentCert(config, newCert, isTlcpEncCert);
    if (ret != HITLS_SUCCESS) {
        if (isClone) {
            SAL_CERT_X509Free(newCert);
        }
    }
    return ret;
}

int32_t HITLS_CFG_SetCertificate(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone)
{
    if (config == NULL || cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    int32_t ret = CheckCertSecuritylevel(config, cert, false);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }
    return CFG_SetCertificate(config, cert, isClone, false);
}

int32_t HITLS_CFG_LoadCertFile(HITLS_Config *config, const char *file, HITLS_ParseFormat format)
{
    if (config == NULL || file == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    CERT_MgrCtx *mgrCtx = config->certMgrCtx;
    if (mgrCtx == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    HITLS_CERT_X509 *cert = SAL_CERT_X509Parse(config, (const uint8_t *)file, (uint32_t)strlen(file),
        TLS_PARSE_TYPE_FILE, format);
    if (cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_ERR_LOAD_CERT_FILE);
        return HITLS_CONFIG_ERR_LOAD_CERT_FILE;
    }

    int32_t ret = CheckCertSecuritylevel(config, cert, false);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_X509Free(cert);
        return ret;
    }

    ret = SAL_CERT_SetCurrentCert(config, cert, false);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_X509Free(cert);
        return ret;
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_LoadCertBuffer(HITLS_Config *config, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format)
{
    if (config == NULL || buf == NULL || bufLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_X509 *newCert = SAL_CERT_X509Parse(config, buf, bufLen, TLS_PARSE_TYPE_BUFF, format);
    if (newCert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_ERR_LOAD_CERT_BUFFER);
        return HITLS_CONFIG_ERR_LOAD_CERT_BUFFER;
    }

    int32_t ret = CheckCertSecuritylevel(config, newCert, false);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_X509Free(newCert);
        return ret;
    }

    ret = SAL_CERT_SetCurrentCert(config, newCert, false);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_X509Free(newCert);
        return ret;
    }

    return HITLS_SUCCESS;
}

HITLS_CERT_X509 *HITLS_CFG_GetCertificate(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetCurrentCert(config->certMgrCtx);
}

static int32_t CFG_SetPrivateKey(HITLS_Config *config, HITLS_CERT_Key *privateKey, bool isClone,
    bool isTlcpEncCertPriKey)
{
    if (config == NULL || privateKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Key *newKey = NULL;
    if (isClone) {
        newKey = SAL_CERT_KeyDup(config->certMgrCtx, privateKey);
        if (newKey == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_X509_DUP);
            return HITLS_CERT_ERR_X509_DUP;
        }
    } else {
        newKey = privateKey;
    }

    int32_t ret = SAL_CERT_SetCurrentPrivateKey(config, newKey, isTlcpEncCertPriKey);
    if (ret != HITLS_SUCCESS) {
        if (isClone) {
            SAL_CERT_KeyFree(config->certMgrCtx, newKey);
        }
    }
    return ret;
}

#ifndef HITLS_NO_TLCP11
int32_t HITLS_CFG_SetTlcpPrivateKey(HITLS_Config *config, HITLS_CERT_Key *privateKey,
    bool isClone, bool isTlcpEncCertPriKey)
{
    return CFG_SetPrivateKey(config, privateKey, isClone, isTlcpEncCertPriKey);
}

int32_t HITLS_CFG_SetTlcpCertificate(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone, bool isTlcpEncCert)
{
    return CFG_SetCertificate(config, cert, isClone, isTlcpEncCert);
}
#endif

int32_t HITLS_CFG_SetPrivateKey(HITLS_Config *config, HITLS_CERT_Key *privateKey, bool isClone)
{
    return CFG_SetPrivateKey(config, privateKey, isClone, false);
}

int32_t HITLS_CFG_LoadKeyFile(HITLS_Config *config, const char *file, HITLS_ParseFormat format)
{
    if (config == NULL || file == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Key *newKey = SAL_CERT_KeyParse(config, (const uint8_t *)file, (uint32_t)strlen(file),
        TLS_PARSE_TYPE_FILE, format);
    if (newKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_ERR_LOAD_KEY_FILE);
        return HITLS_CONFIG_ERR_LOAD_KEY_FILE;
    }

    int32_t ret = SAL_CERT_SetCurrentPrivateKey(config, newKey, false);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_KeyFree(config->certMgrCtx, newKey);
        return ret;
    }

    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_LoadKeyBuffer(HITLS_Config *config, const uint8_t *buf, uint32_t bufLen, HITLS_ParseFormat format)
{
    if (config == NULL || buf == NULL || bufLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Key *newKey = SAL_CERT_KeyParse(config, buf, bufLen, TLS_PARSE_TYPE_BUFF, format);
    if (newKey == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_ERR_LOAD_KEY_BUFFER);
        return HITLS_CONFIG_ERR_LOAD_KEY_BUFFER;
    }

    int32_t ret = SAL_CERT_SetCurrentPrivateKey(config, newKey, false);
    if (ret != HITLS_SUCCESS) {
        SAL_CERT_KeyFree(config->certMgrCtx, newKey);
        return ret;
    }

    return HITLS_SUCCESS;
}

HITLS_CERT_Key *HITLS_CFG_GetPrivateKey(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetCurrentPrivateKey(config->certMgrCtx, false);
}

int32_t HITLS_CFG_CheckPrivateKey(const HITLS_Config *config)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    CERT_MgrCtx *certMgrCtx = config->certMgrCtx;
    if (certMgrCtx == NULL) {
        /* If no certificate callback is registered, the certificate management module will not initialized. */
        BSL_ERR_PUSH_ERROR(HITLS_UNREGISTERED_CALLBACK);
        return HITLS_UNREGISTERED_CALLBACK;
    }

    HITLS_CERT_X509 *cert = SAL_CERT_GetCurrentCert(certMgrCtx);
    if (cert == NULL) {
        /* no certificate is added */
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_NO_CERT);
        return HITLS_CONFIG_NO_CERT;
    }

    HITLS_CERT_Key *privateKey = SAL_CERT_GetCurrentPrivateKey(certMgrCtx, false);
    if (privateKey == NULL) {
        /* no private key is added */
        BSL_ERR_PUSH_ERROR(HITLS_CONFIG_NO_PRIVATE_KEY);
        return HITLS_CONFIG_NO_PRIVATE_KEY;
    }

    return SAL_CERT_CheckPrivateKey(config, cert, privateKey);
}

int32_t HITLS_CFG_AddChainCert(HITLS_Config *config, HITLS_CERT_X509 *cert, bool isClone)
{
    if (config == NULL || cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    int32_t ret = CheckCertSecuritylevel(config, cert, true);
    if (ret != HITLS_SUCCESS) {
        return ret;
    }

    HITLS_CERT_X509 *newCert = NULL;
    if (isClone) {
        newCert = SAL_CERT_X509Dup(config->certMgrCtx, cert);
        if (newCert == NULL) {
            BSL_ERR_PUSH_ERROR(HITLS_CERT_ERR_X509_DUP);
            return HITLS_CERT_ERR_X509_DUP;
        }
    } else {
        newCert = cert;
    }

    ret = SAL_CERT_AddChainCert(config->certMgrCtx, newCert);
    if (ret != HITLS_SUCCESS) {
        if (isClone) {
            SAL_CERT_X509Free(newCert);
        }
        return ret;
    }
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_AddCertToStore(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_StoreType storeType,
    bool isClone)
{
    if (config == NULL || cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    HITLS_CERT_Store *store = NULL;
    switch (storeType) {
        case TLS_CERT_STORE_TYPE_DEFAULT:
            store = SAL_CERT_GetCertStore(config->certMgrCtx);
            break;
        case TLS_CERT_STORE_TYPE_VERIFY:
            store = SAL_CERT_GetVerifyStore(config->certMgrCtx);
            break;
        case TLS_CERT_STORE_TYPE_CHAIN:
            store = SAL_CERT_GetChainStore(config->certMgrCtx);
            break;
        default:
            return HITLS_CERT_ERR_INVALID_STORE_TYPE;
    }

    HITLS_CERT_CtrlCmd cmd = isClone ? CERT_STORE_CTRL_DEEP_COPY_ADD_CERT_LIST :
        CERT_STORE_CTRL_SHALLOW_COPY_ADD_CERT_LIST;
    int32_t ret = SAL_CERT_StoreCtrl(config, store, cmd, cert, NULL);
    if (ret != HITLS_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
    }

    return ret;
}

HITLS_CERT_Chain *HITLS_CFG_GetChainCerts(HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetCurrentChainCerts(config->certMgrCtx);
}

int32_t HITLS_CFG_ClearChainCerts(HITLS_Config *config)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    SAL_CERT_ClearCurrentChainCerts(config->certMgrCtx);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_RemoveCertAndKey(HITLS_Config *config)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }
    SAL_CERT_ClearCertAndKey(config->certMgrCtx);
    return HITLS_SUCCESS;
}

int32_t HITLS_CFG_AddExtraChainCert(HITLS_Config *config, HITLS_CERT_X509 *cert)
{
    if (config == NULL || cert == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return SAL_CERT_AddExtraChainCert(config->certMgrCtx, cert);
}

HITLS_CERT_Chain *HITLS_CFG_GetExtraChainCerts(HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetExtraChainCerts(config->certMgrCtx);
}

int32_t HITLS_CFG_SetVerifyCb(HITLS_Config *config, HITLS_VerifyCb callback)
{
    if (config == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_NULL_INPUT);
        return HITLS_NULL_INPUT;
    }

    return SAL_CERT_SetVerifyCb(config->certMgrCtx, callback);
}

HITLS_VerifyCb HITLS_CFG_GetVerifyCb(const HITLS_Config *config)
{
    if (config == NULL) {
        return NULL;
    }

    return SAL_CERT_GetVerifyCb(config->certMgrCtx);
}