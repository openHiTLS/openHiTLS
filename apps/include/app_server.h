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

#ifndef HITLS_APP_SERVER_H
#define HITLS_APP_SERVER_H

#include <stdint.h>
#include "app_provider.h"
#include "app_sm.h"
#include "bsl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Server parameters structure */
typedef struct {
    /* Listen parameters */
    char *bindAddr;
    int port;
    int backlog;
    
    /* Protocol parameters */
    char *protocol;
    char *cipherSuites;
    
    /* Certificate parameters */
    char *caFile;
    char *caChain;
    bool verifyClient;
    int verifyDepth;
    
    /* TLCP parameters */
    char *tlcpEncCert;
    char *tlcpEncKey;
    char *tlcpSignCert;
    char *tlcpSignKey;
    
    /* Service parameters */
    bool acceptOnce;
    int maxConnections;
    
    /* Output parameters */
    bool quiet;
    bool state;
    
    /* Format parameters */
    BSL_ParseFormat certFormat;
    BSL_ParseFormat keyFormat;
    AppProvider *provider;
#ifdef HITLS_APP_SM_MODE
    HITLS_APP_SM_Param *smParam;
#endif
} HITLS_ServerParams;

/**
 * @brief Main entry point for s_server tool
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return Application exit code
 */
int HITLS_ServerMain(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_APP_SERVER_H */