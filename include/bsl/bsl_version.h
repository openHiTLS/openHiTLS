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

/**
 * @defgroup bsl_version
 * @ingroup bsl
 * @brief version information
 */

#ifndef BSL_VERSION_H
#define BSL_VERSION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OPENHITLS_VERSION_S
#define OPENHITLS_VERSION_S "openHiTLS 0.4.0 31 Mar. 2026"
#endif

#ifndef OPENHITLS_VERSION_I
#define OPENHITLS_VERSION_I 4194304ULL
#endif

/**
 * @ingroup bsl_version
 * @brief   Obtain the openHiTLS version string.
 *
 * @retval  openHiTLS version string.
 */
const char *HITLS_Version(void);

/**
 * @ingroup bsl_version
 * @brief   Obtain the openHiTLS version number.
 *
 * @retval  openHiTLS version number.
 */
uint64_t HITLS_VersionNum(void);

#ifdef __cplusplus
}
#endif

#endif /* BSL_VERSION_H */
