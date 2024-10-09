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

#ifndef STUB_CRYPT_H
#define STUB_CRYPT_H
#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief Stub the test framework
*/
void FRAME_RegCryptMethod(void);

void FRAME_DeRegCryptMethod(void);

#ifdef __cplusplus
}
#endif

#endif // STUB_CRYPT_H
