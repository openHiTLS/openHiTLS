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

#ifndef PQCP_PROVIDER_IMPL_H
#define PQCP_PROVIDER_IMPL_H

#include "crypt_eal_provider.h"

extern const CRYPT_EAL_Func g_pqcpKeyMgmtScloudPlus[];
extern const CRYPT_EAL_Func g_pqcpKemScloudPlus[];

extern const CRYPT_EAL_Func g_pqcpKeyMgmtFrodoKem[];
extern const CRYPT_EAL_Func g_pqcpKemFrodoKem[];

extern const CRYPT_EAL_Func g_pqcpKeyMgmtMceliece[];
extern const CRYPT_EAL_Func g_pqcpKemMceliece[];

#endif /* PQCP_PROVIDER_IMPL_H */