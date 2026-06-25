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
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "bsl_version.h"

static const char g_openHiTLSVersion[] = OPENHITLS_VERSION_S;
static const uint64_t g_openHiTLSNumVersion = OPENHITLS_VERSION_I;

const char *HITLS_Version(void)
{
    return g_openHiTLSVersion;
}

uint64_t HITLS_VersionNum(void)
{
    return g_openHiTLSNumVersion;
}
