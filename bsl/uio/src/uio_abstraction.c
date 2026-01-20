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
#ifdef HITLS_BSL_UIO_PLT

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_errno.h"
#include "bsl_uio.h"
#include "uio_base.h"
#include "uio_abstraction.h"

BSL_UIO_Method *BSL_UIO_NewMethod(void)
{
    BSL_UIO_Method *meth = (BSL_UIO_Method *)BSL_SAL_Calloc(1u, sizeof(BSL_UIO_Method));
    if (meth == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05021, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "new method is NULL.", NULL, NULL, NULL, NULL);
        BSL_ERR_PUSH_ERROR(BSL_UIO_MEM_ALLOC_FAIL);
    }

    return meth;
}

void BSL_UIO_FreeMethod(BSL_UIO_Method *meth)
{
    BSL_SAL_FREE(meth);
}

int32_t BSL_UIO_SetMethodType(BSL_UIO_Method *meth, BSL_UIO_TransportType type)
{
    if (meth == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05022, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "set method type is NULL.", NULL, NULL, NULL, NULL);
        return BSL_NULL_INPUT;
    }
    meth->uioType = type;
    return BSL_SUCCESS;
}

int32_t BSL_UIO_SetMethod(BSL_UIO_Method *meth, int32_t type, void *func)
{
    if (meth == NULL || func == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05023, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "set method is NULL.", NULL, NULL, NULL, NULL);
        return BSL_NULL_INPUT;
    }

    switch (type) {
        case BSL_UIO_WRITE_CB:
            meth->uioWrite = func;
            break;
        case BSL_UIO_READ_CB:
            meth->uioRead = func;
            break;
        case BSL_UIO_CTRL_CB:
            meth->uioCtrl = func;
            break;
        case BSL_UIO_CREATE_CB:
            meth->uioCreate = func;
            break;
        case BSL_UIO_DESTROY_CB:
            meth->uioDestroy = func;
            break;
        case BSL_UIO_PUTS_CB:
            meth->uioPuts = func;
            break;
        case BSL_UIO_GETS_CB:
            meth->uioGets = func;
            break;
        default:
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05024, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "method type is wrong.", NULL, NULL, NULL, NULL);
            BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
            return BSL_INVALID_ARG;
    }
    return BSL_SUCCESS;
}

BSL_UIO *BSL_UIO_New(const BSL_UIO_Method *method)
{
    if (method == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05025, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "method is NULL.", NULL, NULL, NULL, NULL);
        return NULL;
    }

    BSL_UIO *uio = (BSL_UIO *)BSL_SAL_Calloc(1, sizeof(struct UIO_ControlBlock));
    if (uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_MEM_ALLOC_FAIL);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05026, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio malloc fail.", NULL, NULL, NULL, NULL);
        return NULL;
    }

    (void)memcpy_s(&uio->method, sizeof(BSL_UIO_Method), method, sizeof(BSL_UIO_Method));

    BSL_SAL_ReferencesInit(&(uio->references));
    BSL_UIO_SetIsUnderlyingClosedByUio(uio, false);

    if (uio->method.uioCreate != NULL) {
        int32_t ret = uio->method.uioCreate(uio);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05027, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                "uio create data fail.", NULL, NULL, NULL, NULL);
            BSL_SAL_FREE(uio);
            return NULL;
        }
    }

    return uio;
}

int32_t BSL_UIO_UpRef(BSL_UIO *uio)
{
    if (uio == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05028, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio is NULL.", NULL, NULL, NULL, NULL);
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }
    if (uio->references.count == INT32_MAX) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_REF_MAX);
        return BSL_UIO_REF_MAX;
    }
    int val = 0;
    BSL_SAL_AtomicUpReferences(&(uio->references), &val);
    return BSL_SUCCESS;
}

void BSL_UIO_Free(BSL_UIO *uio)
{
    if (uio == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05029, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "free uio is NULL.", NULL, NULL, NULL, NULL);
        return;
    }
    int ret = 0;
    BSL_SAL_AtomicDownReferences(&(uio->references), &ret);
    if (ret > 0) {
        return;
    }
    if (uio->userData != NULL && uio->userDataFreeFunc != NULL) {
        (void)uio->userDataFreeFunc(uio->userData);
        uio->userData = NULL;
    }
    if (uio->method.uioDestroy != NULL) {
        (void)uio->method.uioDestroy(uio);
    }
    BSL_SAL_ReferencesFree(&(uio->references));
    BSL_SAL_FREE(uio);
}

int32_t BSL_UIO_Write(BSL_UIO *uio, const void *data, uint32_t len, uint32_t *writeLen)
{
    if (uio == NULL || uio->method.uioWrite == NULL || data == NULL || writeLen == NULL || len == 0) {
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05030, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio write: internal input error.", NULL, NULL, NULL, NULL);
        return BSL_INTERNAL_EXCEPTION;   // if the uio is null, the send size is zero, means no data send;
    }

    if (!uio->init) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_UNINITIALIZED);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05031, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio write: uio is not init.", NULL, NULL, NULL, NULL);
        return BSL_UIO_UNINITIALIZED;
    }

    int32_t ret = uio->method.uioWrite(uio, data, len, writeLen);
    if (ret == BSL_SUCCESS) {
        uio->writeNum += (int64_t)(*writeLen);
    }

    return ret;
}

int32_t BSL_UIO_Read(BSL_UIO *uio, void *data, uint32_t len, uint32_t *readLen)
{
    if (uio == NULL || uio->method.uioRead == NULL || data == NULL || len == 0 || readLen == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05032, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio read: NULL input.", NULL, NULL, NULL, NULL);
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }

    if (!uio->init) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_UNINITIALIZED);
        return BSL_UIO_UNINITIALIZED;
    }

    int32_t ret = uio->method.uioRead(uio, data, len, readLen);
    if (ret == BSL_SUCCESS) {
        uio->readNum += (int64_t)(*readLen);
    }

    return ret;
}


bool BSL_UIO_GetIsUnderlyingClosedByUio(const BSL_UIO *uio)
{
    if (uio == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05034, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio is NULL.", NULL, NULL, NULL, NULL);
        return false; // If the value is empty, the function will not release the value.
    }
    return uio->isUnderlyingClosedByUio;
}

void BSL_UIO_SetIsUnderlyingClosedByUio(BSL_UIO *uio, bool close)
{
    if (uio == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05035, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio is NULL.", NULL, NULL, NULL, NULL);
        return;
    }
    uio->isUnderlyingClosedByUio = close;
}

const BSL_UIO_Method *BSL_UIO_GetMethod(const BSL_UIO *uio)
{
    if (uio == NULL) {
        return NULL;
    }
    return &uio->method;
}

void *BSL_UIO_GetMethodFunc(BSL_UIO_Method *meth, int32_t type)
{
    if (meth == NULL) {
        return NULL;
    }

    switch (type) {
        case BSL_UIO_WRITE_CB:
            return meth->uioWrite;
        case BSL_UIO_READ_CB:
            return meth->uioRead;
        case BSL_UIO_CTRL_CB:
            return meth->uioCtrl;
        case BSL_UIO_CREATE_CB:
            return meth->uioCreate;
        case BSL_UIO_DESTROY_CB:
            return meth->uioDestroy;
        case BSL_UIO_PUTS_CB:
            return meth->uioPuts;
        case BSL_UIO_GETS_CB:
            return meth->uioGets;
        default:
            break;
    }
    return NULL;
}

BSL_UIO_Method *BSL_UIO_GetMethodWithoutConst(BSL_UIO *uio)
{
    if (uio == NULL) {
        return NULL;
    }
    return &uio->method;
}

static int32_t UIO_GetInit(BSL_UIO *uio, int32_t larg, bool *parg)
{
    if (larg != sizeof(bool) || parg == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05036, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio GetInit: internal input error.", NULL, NULL, NULL, NULL);
        return BSL_INVALID_ARG;
    }
    *parg = uio->init;
    return BSL_SUCCESS;
}

static int32_t UIO_GetReadNum(BSL_UIO *uio, int32_t larg, int64_t *parg)
{
    if (larg != sizeof(int64_t) || parg == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05037, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio GetReadNum: internal input error.", NULL, NULL, NULL, NULL);
        return BSL_INVALID_ARG;
    }
    *parg = uio->readNum;
    return BSL_SUCCESS;
}

static int32_t UIO_GetWriteNum(BSL_UIO *uio, int32_t larg, int64_t *parg)
{
    if (larg != sizeof(int64_t) || parg == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05038, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio get write num: internal input error.", NULL, NULL, NULL, NULL);
        return BSL_INVALID_ARG;
    }
    *parg = uio->writeNum;
    return BSL_SUCCESS;
}

int32_t BSL_UIO_Ctrl(BSL_UIO *uio, int32_t cmd, int32_t larg, void *parg)
{
    if (uio == NULL || uio->method.uioCtrl == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05039, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio ctrl: internal input error.", NULL, NULL, NULL, NULL);
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    switch (cmd) {
        case BSL_UIO_GET_INIT:
            return UIO_GetInit(uio, larg, parg);
        case BSL_UIO_GET_READ_NUM:
            return UIO_GetReadNum(uio, larg, parg);
        case BSL_UIO_GET_WRITE_NUM:
            return UIO_GetWriteNum(uio, larg, parg);
        default:
            return uio->method.uioCtrl(uio, cmd, larg, parg);
    }
}

void *BSL_UIO_GetCtx(const BSL_UIO *uio)
{
    if (uio == NULL) {
        return NULL;
    }
    return uio->ctx;
}

void BSL_UIO_SetCtx(BSL_UIO *uio, void *ctx)
{
    if (uio != NULL) {
        uio->ctx = ctx;
    }
}

void BSL_UIO_SetFD(BSL_UIO *uio, int fd)
{
    bool invalid = (uio == NULL) || (fd < 0);
    if (invalid) {
        return;
    }
    BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, (int32_t)sizeof(fd), &fd);
}

int32_t BSL_UIO_GetFd(BSL_UIO *uio)
{
    int32_t fd = -1;
    (void)BSL_UIO_Ctrl(uio, BSL_UIO_GET_FD, (int32_t)sizeof(fd), &fd); // Parameters are checked by each ctrl function.
    return fd;
}

void BSL_UIO_SetInit(BSL_UIO *uio, bool init)
{
    if (uio != NULL) {
        uio->init = init;
    }
}

BSL_UIO_TransportType BSL_UIO_GetTransportType(const BSL_UIO *uio)
{
    if (uio == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05040, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get uio type is NULL.", NULL, NULL, NULL, NULL);
        return BSL_UIO_UNKNOWN;
    }
    return uio->method.uioType;
}

bool BSL_UIO_GetUioChainTransportType(BSL_UIO *uio, const BSL_UIO_TransportType uioType)
{
    if (uio == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05140, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get uio type is NULL.", NULL, NULL, NULL, NULL);
        return false;
    }

    while (uio != NULL) {
        if (BSL_UIO_GetTransportType(uio) == uioType) {
            return true;
        }
        uio = BSL_UIO_Next(uio);
    }
    return false;
}

int32_t BSL_UIO_SetUserData(BSL_UIO *uio, void *data)
{
    if (uio == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05041, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "set uio user data is NULL.", NULL, NULL, NULL, NULL);
        return BSL_NULL_INPUT;
    }

    uio->userData = data;
    return BSL_SUCCESS;
}

int32_t BSL_UIO_SetUserDataFreeFunc(BSL_UIO *uio, BSL_UIO_USERDATA_FREE_FUNC userDataFreeFunc)
{
    if (uio == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    uio->userDataFreeFunc = userDataFreeFunc;
    return BSL_SUCCESS;
}

void *BSL_UIO_GetUserData(const BSL_UIO *uio)
{
    if (uio == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05042, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "get uio user data is NULL.", NULL, NULL, NULL, NULL);
        return NULL;
    }

    return uio->userData;
}

uint32_t UIO_GetCtxLen(const BSL_UIO *uio)
{
    if (uio == NULL) {
        return 0;
    }
    return uio->ctxLen;
}

void BSL_UIO_SetCtxLen(BSL_UIO *uio, uint32_t len)
{
    if (uio != NULL) {
        uio->ctxLen = len;
    }
}

int32_t BSL_UIO_Puts(BSL_UIO *uio, const char *buf, uint32_t *writeLen)
{
    if (uio == NULL || uio->method.uioPuts == NULL || writeLen == NULL || buf == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05043, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio puts: internal input error.", NULL, NULL, NULL, NULL);
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }

    if (!uio->init) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05044, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio puts: uio is not init.", NULL, NULL, NULL, NULL);
        BSL_ERR_PUSH_ERROR(BSL_UIO_UNINITIALIZED);
        return BSL_UIO_UNINITIALIZED;
    }

    int32_t ret = uio->method.uioPuts(uio, buf, writeLen);
    if (ret == BSL_SUCCESS) {
        uio->writeNum += (int64_t)(*writeLen);
    }

    return ret;
}

int32_t BSL_UIO_Gets(BSL_UIO *uio, char *buf, uint32_t *readLen)
{
    if (uio == NULL || uio->method.uioGets == NULL || readLen == NULL || buf == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05045, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio gets: internal input error.", NULL, NULL, NULL, NULL);
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return BSL_INTERNAL_EXCEPTION;
    }

    if (!uio->init) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05046, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio gets: uio is not init.", NULL, NULL, NULL, NULL);
        BSL_ERR_PUSH_ERROR(BSL_UIO_UNINITIALIZED);
        return BSL_UIO_UNINITIALIZED;
    }

    int32_t ret = uio->method.uioGets(uio, buf, readLen);
    if (ret == BSL_SUCCESS) {
        uio->readNum += (int64_t)(*readLen);
    }

    return ret;
}
int32_t BSL_UIO_SetFlags(BSL_UIO *uio, uint32_t flags)
{
    if (uio == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05047, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio is NULL.", NULL, NULL, NULL, NULL);
        return BSL_NULL_INPUT;
    }
    uint32_t validFlags =
        BSL_UIO_FLAGS_RWS | BSL_UIO_FLAGS_SHOULD_RETRY | BSL_UIO_FLAGS_BASE64_NO_NEWLINE | BSL_UIO_FLAGS_BASE64_PEM;
    if ((flags & validFlags) == 0 || flags > validFlags) {
        BSL_ERR_PUSH_ERROR(BSL_INVALID_ARG);
        return BSL_INVALID_ARG;
    }

    uio->flags |= flags;
    return BSL_SUCCESS;
}

int32_t BSL_UIO_ClearFlags(BSL_UIO *uio, uint32_t flags)
{
    if (uio == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05048, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "uio is NULL.", NULL, NULL, NULL, NULL);
        return BSL_NULL_INPUT;
    }
    uio->flags &= ~flags;
    return BSL_SUCCESS;
}

uint32_t BSL_UIO_TestFlags(const BSL_UIO *uio, uint32_t flags, uint32_t *out)
{
    if (uio == NULL || out == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    *out = uio->flags & flags;
    return BSL_SUCCESS;
}

int32_t BSL_UIO_SockShouldRetry(int32_t result)
{
    if (result != BSL_SUCCESS) {
#ifdef HITLS_BSL_SAL_NET
        int32_t err = BSL_SAL_SockGetLastSocketError();
        if (UioIsNonFatalErr(err)) {
            return BSL_SUCCESS;
        }
#endif
    }
    BSL_ERR_PUSH_ERROR(BSL_UIO_FAIL);
    return BSL_UIO_FAIL;
}

/**
 * @brief   Checking for Fatal I/O Errors
 *
 * @param   err [IN] error type
 *
 * @return  true :No Fatal error
 *          false:fatal errors
 */
bool UioIsNonFatalErr(int32_t err)
{
    bool ret = true;
    /** @alias Check whether err is a fatal error and modify ret. */
    switch (err) {
#if defined(ENOTCONN)
        case ENOTCONN:
#endif

#if defined(__WIN32__) || defined(__WIN64__)
#if defined(WSAEWOULDBLOCK)
        case WSAEWOULDBLOCK:
#endif
#endif

#ifdef EINTR
        case EINTR:
#endif

#ifdef EINPROGRESS
        case EINPROGRESS:
#endif

#ifdef EWOULDBLOCK
#if !defined(WSAEWOULDBLOCK) || WSAEWOULDBLOCK != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
#endif

#ifdef EAGAIN
#if EWOULDBLOCK != EAGAIN
        case EAGAIN:
#endif
#endif

#ifdef EALREADY
        case EALREADY:
#endif

#ifdef EPROTO
        case EPROTO:
#endif
#ifdef EMSGSIZE
        case EMSGSIZE:
#endif
            ret = true;
            break;
        default:
            ret = false;
            break;
    }
    return ret;
}

int32_t BSL_UIO_Append(BSL_UIO *uio, BSL_UIO *tail)
{
    bool invalid = (uio == NULL) || (tail == NULL);
    if (invalid) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return BSL_NULL_INPUT;
    }
    BSL_UIO *t = uio;
    while (t->next != NULL) {
        t = t->next;
    }
    t->next = tail;
    tail->prev = t;
    BSL_ERR_SET_MARK();
    (void)BSL_UIO_Ctrl(uio, BSL_UIO_APPEND, 0, tail);
    BSL_ERR_POP_TO_MARK();
    return BSL_SUCCESS;
}

BSL_UIO *BSL_UIO_PopCurrent(BSL_UIO *uio)
{
    if (uio == NULL) {
        return NULL;
    }
    BSL_UIO *ret = uio->next;
    if (uio->prev != NULL) {
        uio->prev->next = uio->next;
    }
    if (uio->next != NULL) {
        uio->next->prev = uio->prev;
    }
    uio->prev = NULL;
    uio->next = NULL;
    return ret;
}

void BSL_UIO_FreeChain(BSL_UIO *uio)
{
    BSL_UIO *b = uio;
    while (b != NULL) {
        int ref = b->references.count;
        BSL_UIO *next = b->next;
        BSL_UIO_Free(b);
        if (ref > 1) {
            break;
        }
        b = next;
    }
}

BSL_UIO *BSL_UIO_Next(BSL_UIO *uio)
{
    if (uio == NULL) {
        return NULL;
    }
    return uio->next;
}

#endif /* HITLS_BSL_UIO_PLT */
