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

#include "hitls_build.h"
#include "bsl_errno.h"
#include "bsl_sal.h"

#ifdef HITLS_BSL_SAL_NET
#include "sal_netimpl.h"
#endif
#ifdef HITLS_BSL_SAL_TIME
#include "sal_timeimpl.h"
#endif
#ifdef HITLS_BSL_SAL_FILE
#include "sal_fileimpl.h"
#endif
#ifdef HITLS_BSL_SAL_DL
#include "sal_dlimpl.h"
#endif

#include "sal_lockimpl.h"
#include "sal_memimpl.h"

/* The prefix of BSL_SAL_CB_FUNC_TYPE */
#define BSL_SAL_MEM_CB      0x0100
#define BSL_SAL_THREAD_CB   0x0200

#ifdef HITLS_BSL_SAL_NET
#define BSL_SAL_NET_CB      0x0300
#endif

#ifdef HITLS_BSL_SAL_TIME
#define BSL_SAL_TIME_CB     0x0400
#endif

#ifdef HITLS_BSL_SAL_FILE
#define BSL_SAL_FILE_CB     0x0500
#endif

#ifdef HITLS_BSL_SAL_DL
#define BSL_SAL_DL_CB       0x0700
#endif

#ifdef HITLS_BSL_SAL_PID
#define BSL_SAL_PID_CB      0x0800
#endif

int32_t BSL_SAL_CallBack_Ctrl(BSL_SAL_CB_FUNC_TYPE funcType, void *funcCb)
{
    uint32_t type = (uint32_t)funcType & 0xff00;
    switch (type) {
        case BSL_SAL_MEM_CB:
            return SAL_MemCallBack_Ctrl(funcType, funcCb);
        case BSL_SAL_THREAD_CB:
            return SAL_ThreadCallback_Ctrl(funcType, funcCb);
#ifdef HITLS_BSL_SAL_PID
        case BSL_SAL_PID_CB:
            return SAL_PidCallback_Ctrl(funcType, funcCb);
#endif
#ifdef HITLS_BSL_SAL_NET
        case BSL_SAL_NET_CB:
            return SAL_NetCallback_Ctrl(funcType, funcCb);
#endif
#ifdef HITLS_BSL_SAL_TIME
        case BSL_SAL_TIME_CB:
            return SAL_TimeCallback_Ctrl(funcType, funcCb);
#endif
#ifdef HITLS_BSL_SAL_FILE
        case BSL_SAL_FILE_CB:
            return SAL_FileCallback_Ctrl(funcType, funcCb);
#endif
#ifdef HITLS_BSL_SAL_DL
        case BSL_SAL_DL_CB:
            return SAL_DlCallback_Ctrl(funcType, funcCb);
#endif
        default:
            return BSL_SAL_ERR_BAD_PARAM;
    }
}