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

#ifndef PQCP_ERR_H
#define PQCP_ERR_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    PQCP_SUCCESS = 0,
    PQCP_NULL_INPUT,
    PQCP_MALLOC_FAIL,
    PQCP_MEM_ALLOC_FAIL,
    PQCP_SCLOUDPLUS_INVALID_ARG,
    PQCP_SCLOUDPLUS_CMP_FALSE,
    PQCP_FRODOKEM_INVALID_ARG,
    PQCP_FRODOKEM_CMP_FALSE,
    PQCP_MCELIECE_INVALID_ARG,
    PQCP_MCELIECE_CMP_FALSE,
} CRYPT_ERROR;

#ifdef __cplusplus
}
#endif

#endif /* PQCP_ERR_H */
