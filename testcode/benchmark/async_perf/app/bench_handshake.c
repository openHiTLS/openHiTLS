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

/* hs-* handshake benchmark: scenario execution and timing */

#include "bench_handshake.h"
#include "affinity.h"
#include "sim_link.h"
#include "bsl_err.h"
#include "hitls.h"
#include "hitls_config.h"
#include "hitls_cert.h"
#include "crypt_eal_provider.h"
#include "sim_prov_ctrl.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static HITLS_Config *PerfBenchNewConfig(const PerfScenario *s, CRYPT_EAL_LibCtx *libCtx)
{
    HITLS_Config *cfg = NULL;
    uint16_t group = HITLS_EC_GROUP_SECP256R1;
    if (s->profile == PERF_PROFILE_TLS12_ECDHE_ECDSA || s->profile == PERF_PROFILE_TLS12_ECDHE_RSA) {
        cfg = HITLS_CFG_ProviderNewTLS12Config(libCtx, PERF_PROVIDER_ATTR);
    } else {
        cfg = HITLS_CFG_ProviderNewTLS13Config(libCtx, PERF_PROVIDER_ATTR);
    }
    if (cfg == NULL) {
        return NULL;
    }
    if (HITLS_CFG_SetGroups(cfg, &group, 1) != HITLS_SUCCESS) {
        HITLS_CFG_FreeConfig(cfg);
        return NULL;
    }
    (void)HITLS_CFG_SetReadAhead(cfg, 1);
#ifdef HITLS_TLS_FEATURE_FLIGHT
    (void)HITLS_CFG_SetFlightTransmitSwitch(cfg, false);
#endif
    return cfg;
}

static int PerfBenchLoadCerts(HITLS_Config *cfg, const PerfScenario *s, const char *certDir)
{
    char caFile[256];
    char chainFile[256];
    char endFile[256];
    char keyFile[256];
    HITLS_CERT_X509 *ca = NULL;
    HITLS_CERT_X509 *end = NULL;
    HITLS_CERT_X509 *chain = NULL;
    HITLS_CERT_Key *key = NULL;
    int ret = -1;

    bool rsa = s->profile == PERF_PROFILE_TLS13_ECDHE_RSA || s->profile == PERF_PROFILE_TLS12_ECDHE_RSA;
    snprintf(caFile, sizeof(caFile), "%s/%s", certDir, rsa ? "ecdsa_rsa_cert/rootCA.der" : "ecdsa/ca-nist521.der");
    snprintf(chainFile, sizeof(chainFile), "%s/%s", certDir,
             rsa ? "ecdsa_rsa_cert/CA1.der" : "ecdsa/inter-nist521.der");
    snprintf(endFile, sizeof(endFile), "%s/%s", certDir, rsa ? "ecdsa_rsa_cert/ee.der" : "ecdsa/end256-sha256.der");
    snprintf(keyFile, sizeof(keyFile), "%s/%s", certDir,
             rsa ? "ecdsa_rsa_cert/ee.key.der" : "ecdsa/end256-sha256.key.der");

    ca = HITLS_CFG_ParseCert(cfg, (const uint8_t *)caFile, (uint32_t)strlen(caFile), TLS_PARSE_TYPE_FILE,
                             TLS_PARSE_FORMAT_ASN1);
    if (ca == NULL) {
        goto EXIT;
    }
    if (HITLS_CFG_AddCertToStore(cfg, ca, TLS_CERT_STORE_TYPE_DEFAULT, false) != HITLS_SUCCESS) {
        goto EXIT;
    }
    ca = NULL;
    end = HITLS_CFG_ParseCert(cfg, (const uint8_t *)endFile, (uint32_t)strlen(endFile), TLS_PARSE_TYPE_FILE,
                              TLS_PARSE_FORMAT_ASN1);
    if (end == NULL) {
        goto EXIT;
    }
    if (HITLS_CFG_SetCertificate(cfg, end, false) != HITLS_SUCCESS) {
        goto EXIT;
    }
    end = NULL;
    chain = HITLS_CFG_ParseCert(cfg, (const uint8_t *)chainFile, (uint32_t)strlen(chainFile), TLS_PARSE_TYPE_FILE,
                                TLS_PARSE_FORMAT_ASN1);
    if (chain == NULL || HITLS_CFG_AddChainCert(cfg, chain, false) != HITLS_SUCCESS) {
        goto EXIT;
    }
    chain = NULL;
    key = HITLS_CFG_ParseKey(cfg, (const uint8_t *)keyFile, (uint32_t)strlen(keyFile), TLS_PARSE_TYPE_FILE,
                             TLS_PARSE_FORMAT_ASN1);
    if (key == NULL) {
        goto EXIT;
    }
    if (HITLS_CFG_SetPrivateKey(cfg, key, false) != HITLS_SUCCESS) {
        goto EXIT;
    }
    key = NULL;
    ret = 0;
EXIT:
    (void)HITLS_CFG_FreeCert(cfg, ca);
    (void)HITLS_CFG_FreeCert(cfg, chain);
    (void)HITLS_CFG_FreeCert(cfg, end);
    (void)HITLS_CFG_FreeKey(cfg, key);
    if (ret != 0) {
        printf("[bench] certificate load failed for profile %s (ca=%s end=%s)\n", PerfProfileName(s->profile), caFile,
               endFile);
    }
    return ret;
}

int PerfBenchHandshake(const PerfOptions *opt, const PerfScenario *s, CRYPT_EAL_LibCtx *libCtx,
                       CRYPT_EAL_ProvMgrCtx *mgr)
{
    HITLS_Config *serverCfg = NULL;
    int listener = -1;
    PerfBatch batch = {0};
    int32_t ret = HITLS_INTERNAL_EXCEPTION;
    if (s->form != PERF_FORM_SYNC && !PerfAsyncSupported()) {
        puts("RESULT,0,0,UNSUPPORTED");
        return 0;
    }
    SIM_PROV_SCENARIO pause = {.action = SIM_PROV_ACTION_PAUSE, .resumeCount = 1};
    SIM_PROV_CTRL_REQ req = {.op = SIM_PROV_OP_SET,
                             .execMode =
                                 opt->execMode == PERF_EXEC_INLINE ? SIM_PROV_EXEC_INLINE : SIM_PROV_EXEC_WORKER,
                             .workers = opt->execMode == PERF_EXEC_INLINE ? 0 : opt->workers,
                             .scenarios = s->form == PERF_FORM_SYNC ? NULL : &pause,
                             .scenarioCount = s->form == PERF_FORM_SYNC ? 0 : 1};
    PerfAffinityConfigure(&req);
    if (CRYPT_EAL_ProviderCtrl(mgr, SIM_PROV_CTRL_CMD, &req, sizeof(req)) != SIM_PROV_SUCCESS) {
        fprintf(stderr, "provider configuration failed\n");
        goto EXIT;
    }
    listener = PerfListen((uint16_t)opt->port);
    if (listener < 0) {
        fprintf(stderr, "cannot listen on 127.0.0.1:%u\n", opt->port);
        goto EXIT;
    }
    serverCfg = PerfBenchNewConfig(s, libCtx);
    if (serverCfg == NULL || PerfBenchLoadCerts(serverCfg, s, opt->certDir) != 0) {
        goto EXIT;
    }
    if (s->form != PERF_FORM_SYNC && HITLS_CFG_SetModeSupport(serverCfg, HITLS_MODE_ASYNC) != HITLS_SUCCESS) {
        goto EXIT;
    }
    ret = PerfBatchCreate(serverCfg, opt->concurrency, s->form, listener, &batch);
    if (ret == HITLS_SUCCESS) {
        ret = PerfRunServer(&batch);
    }
EXIT:
    printf("RESULT,%u,%llu,%s\n", batch.doneServers, (unsigned long long)(batch.doneNs - batch.startNs),
           ret == HITLS_SUCCESS ? "OK" : "INVALID");
    PerfBatchDestroy(&batch);
    HITLS_CFG_FreeConfig(serverCfg);
    if (listener >= 0) {
        close(listener);
    }
    return ret == HITLS_SUCCESS ? 0 : -1;
}
