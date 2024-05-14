/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
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
