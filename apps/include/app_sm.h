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
#ifndef HITLS_APP_SM_H
#define HITLS_APP_SM_H

#include <stdint.h>
#include <limits.h>
#include "app_provider.h"
#ifdef __cplusplus
extern "C" {
#endif

#ifdef HITLS_APP_SM_MODE
#define HITLS_SM_OPTIONS_ENUM   \
    HITLS_SM_OPT_SM,            \
    HITLS_SM_OPT_UUID,          \
    HITLS_SM_OPT_WORKPATH

#define HITLS_SM_OPTIONS                                                                                \
    {"sm", HITLS_SM_OPT_SM, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Enable SM mode"},                        \
    {"uuid", HITLS_SM_OPT_UUID, HITLS_APP_OPT_VALUETYPE_STRING, "UUID of the key (repeatable)"},        \
    {"workpath", HITLS_SM_OPT_WORKPATH, HITLS_APP_OPT_VALUETYPE_DIR, "Specify the working directory"}

#define HITLS_APP_SM_CASES(optType, smParam)                    \
    switch (optType) {                                          \
        case HITLS_SM_OPT_SM:                                   \
            (smParam)->smTag = 1;                               \
            break;                                              \
        case HITLS_SM_OPT_UUID:                                 \
            (smParam)->uuid = HITLS_APP_OptGetValueStr();       \
            break;                                              \
        case HITLS_SM_OPT_WORKPATH:                             \
            (smParam)->workPath = HITLS_APP_OptGetValueStr();   \
            break;                                              \
        default:                                                \
            break;                                              \
    }

typedef enum {
    HITLS_APP_SM_STATUS_CLOSE = 0,
    HITLS_APP_SM_STATUS_OPEN = 1,
    HITLS_APP_SM_STATUS_INIT = 2,
    HITLS_APP_SM_STATUS_SELFTEST = 3,
    HITLS_APP_SM_STATUS_MANAGER = 4,
    HITLS_APP_SM_STATUS_KEY_PARAMETER_INPUT = 5,
    HITLS_APP_SM_STATUS_APPORVED = 6,
    HITLS_APP_SM_STATUS_ERROR = 7,
} HITLS_APP_SM_Status;

typedef struct {
    char *uuid;
    int32_t smTag;
    char *workPath;
    uint8_t *password;
    uint32_t passwordLen;
    int32_t status;
} HITLS_APP_SM_Param;

/**
 * @ingroup app_sm
 * @brief   Initialize the SM mode.
 * @note    Need to init random number generator before use.
 *
 * @param   provider [IN] The provider of the application.
 * @param   workPath [IN] The working directory.
 * @param   password [OUT] The password.
 *
 * @retval  #HITLS_APP_SUCCESS.
 *          For other error codes, see app_errno.h.
 */
int32_t HITLS_APP_SM_Init(AppProvider *provider, const char *workPath, char **password, int32_t *status);

int32_t HITLS_APP_SM_IntegrityCheck(AppProvider *provider);

int32_t HITLS_APP_SM_PeriodicRandomCheck(AppProvider *provider);

char *HITLS_APP_GetAppPath(void);

int32_t HITLS_APP_SM_RootUserCheck(void);

void HITLS_APP_SM_PrintLog(int32_t ret);

#endif

#ifdef __cplusplus
}
#endif
#endif