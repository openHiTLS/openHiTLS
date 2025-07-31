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
#ifndef HITLS_APP_FUNCTION_H
#define HITLS_APP_FUNCTION_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FUNC_TYPE_NONE,        // default
    FUNC_TYPE_GENERAL,     // general command
} HITLS_CmdFuncType;

typedef struct {
    const char *name;                     // second-class command name
    HITLS_CmdFuncType type;               // type of command
    int (*main)(int argc, char *argv[]);  // second-class entry function
} HITLS_CmdFunc;

int AppGetProgFunc(const char *proName, HITLS_CmdFunc *func);
void AppPrintFuncList(void);

#ifdef __cplusplus
}
#endif
#endif