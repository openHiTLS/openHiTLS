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

#ifndef APP_CLIENT_H
#define APP_CLIENT_H
#include "app_provider.h"
#include "app_sm.h"
#include "bsl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Client parameters structure */
typedef struct {
    /* Connection parameters */
    char *host;
    int port;
    int connectTimeout;
    
    /* Protocol parameters */
    char *protocol;
    char *cipherSuites;
    
    /* Certificate parameters */
    char *caFile;
    char *caChain;
    int verifyDepth;
    bool verifyNone;
    
    /* TLCP parameters */
    char *tlcpEncCert;
    char *tlcpEncKey;
    char *tlcpSignCert;
    char *tlcpSignKey;

    /* Output parameters */
    bool quiet;
    bool state;
    bool prexit;
    
    /* Format parameters */
    BSL_ParseFormat certFormat;
    BSL_ParseFormat keyFormat;
    AppProvider *provider;
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param *smParam;
#endif
} HITLS_ClientParams;

/**
 * @brief Main entry point for s_client tool
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return Application exit code
 */
int HITLS_ClientMain(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

#endif /* APP_CLIENT_H */