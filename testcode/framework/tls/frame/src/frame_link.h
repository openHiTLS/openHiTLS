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

#ifndef FRAME_LINK_H
#define FRAME_LINK_H

#include "hitls.h"
#include "bsl_uio.h"

#ifdef __cplusplus
extern "C" {
#endif

struct FRAME_LinkObj_ {
    HITLS_Ctx *ssl;
    BSL_UIO *io;
    /* For CCS test, make TRY_RECV_FINISH stop before receiving CCS message */
    bool needStopBeforeRecvCCS;
};

struct FRAME_CertInfo_ {
    const char* caFile;
    const char* chainFile;
    const char* endEquipmentFile;
    const char* signFile;   // used TLCP
    const char* privKeyFile;
    const char* signPrivKeyFile; // used TLCP
};
#define INIT_IO_METHOD(method, tp, pfWrite, pfRead, pfCtrl)   \
    do {                                                      \
        (method).type = tp;                                   \
        (method).read = pfRead;                               \
        (method).write = pfWrite;                             \
        (method).ctrl = pfCtrl;                               \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif // FRAME_LINK_H
