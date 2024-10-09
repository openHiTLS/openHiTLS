/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef SNI_H
#define SNI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SniArg {
    char  *serverName;
    int32_t alert;
} SNI_Arg;

/* compare whether the host names are the same */
int32_t SNI_StrcaseCmp(const char *s1, const char *s2);

#ifdef __cplusplus
}
#endif
#endif // ALPN_H