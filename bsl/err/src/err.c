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
#ifdef HITLS_BSL_ERR

#include <stdbool.h>
#include "securec.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_sal.h"
#include "avl.h"
#include "bsl_err.h"
#include "bsl_errno.h"
#include "bsl_binlog_id.h"
#include "bsl_err_internal.h"

#define ERR_FLAG_POP_MARK 0x01

/* Error information stack size */
#define SAL_MAX_ERROR_STACK 20

static BSL_ERR_OutputFunc g_outputFunc = NULL;

/* Error information stack */
typedef struct {
    /* Current point location to the stack. When the value is -1, the stack is empty. */
    uint16_t bottom; /* Stack bottom */
    uint16_t top; /* Stack top */
    /* Prevent error stacks from being cleared. Currently, this parameter is used in asynchronous cases. */
    uint32_t flag;

    /* Store the error code information of a specific thread */
    int32_t errorStack[SAL_MAX_ERROR_STACK];

    /* Error code flag, which is used to partially clear and prevent side channel attack. */
    uint32_t errorFlags[SAL_MAX_ERROR_STACK];

    /* store the error file name. */
    const char *filename[SAL_MAX_ERROR_STACK];

    /* store the line number of the file where the error occurs */
    uint32_t line[SAL_MAX_ERROR_STACK];
} ErrorCodeStack;

/* Avl tree root node of the error stack. */
static BSL_AvlTree *g_avlRoot = NULL;

/* Error description root node */
static BSL_AvlTree *g_descRoot = NULL;

/* Current number of AVL nodes */
static uint32_t g_avlNodeCount = 0;

/* Maximum number of nodes allowed by the AVL tree */
static uint32_t g_maxAvlNodes = 0x0000FFFF;

/* Check the initialization status. 0 means false, if the value is not 0, it means true. Run once. */
BSL_SAL_DECLARE_THREAD_ONCE(g_isErrInit);

/* Handle of the thread lock */
static BSL_SAL_ThreadLockHandle g_errLock = NULL;

static void ErrAutoInit(void)
{
    /* Attempting self-initialization in abnormal conditions */
    (void)BSL_ERR_Init();
}

int32_t BSL_ERR_Init(void)
{
    g_outputFunc = NULL;
    if (g_errLock != NULL) {
        return BSL_SUCCESS;
    }

    return BSL_SAL_ThreadLockNew(&g_errLock);
}

void BSL_ERR_DeInit(void)
{
    (void)memset(&g_isErrInit, 0, sizeof(g_isErrInit));
    if (g_errLock == NULL) {
        return;
    }
    BSL_SAL_ThreadLockFree(g_errLock);
    g_errLock = NULL;
}

static void StackReset(ErrorCodeStack *stack)
{
    if (stack != NULL) {
        (void)memset_s(stack, sizeof(*stack), 0, sizeof(*stack));
    }
}

static void StackResetIndex(ErrorCodeStack *stack, uint32_t i)
{
    bool invalid = stack == NULL || i >= SAL_MAX_ERROR_STACK;
    if (!invalid) {
        stack->errorStack[i] = 0;
        stack->line[i] = 0;
        stack->filename[i] = NULL;
        stack->errorFlags[i] = 0;
    }
}

static void StackDataFree(BSL_ElementData data)
{
    BSL_SAL_FREE(data);
}

static ErrorCodeStack *GetStack(void)
{
    const uint64_t threadId = BSL_SAL_ThreadGetId();
    BSL_AvlTree *curNode = BSL_AVL_SearchNode(g_avlRoot, threadId);
    if (curNode != NULL) {
        /* If an error stack exists, directly returned. */
        return curNode->data;
    }
    /* need to create an error stack */
    if (g_avlNodeCount >= g_maxAvlNodes) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05004, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "New Avl Node failed.", 0, 0, 0, 0);
        return NULL;
    }
    ErrorCodeStack *stack = (ErrorCodeStack *)BSL_SAL_Calloc(1, sizeof(ErrorCodeStack));
    if (stack == NULL) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05005, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "CALLOC error code stack failed", 0, 0, 0, 0);
        return NULL;
    }
    BSL_AvlTree *node = BSL_AVL_MakeLeafNode(stack);
    if (node == NULL) {
        StackDataFree(stack);
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05006, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "avl insert node failed, threadId %lu", threadId, 0, 0, 0);
        return NULL;
    }
    g_avlNodeCount++;
    /* upper layer has ensured that the threadId node does not exist. */
    g_avlRoot = BSL_AVL_InsertNode(g_avlRoot, threadId, node);
    return stack;
}

void BSL_ERR_PushError(int32_t err, const char *file, uint32_t lineNo)
{
    if (err == BSL_SUCCESS) {
        /* push success is not allowed. */
        return;
    }
    (void)BSL_SAL_ThreadRunOnce(&g_isErrInit, ErrAutoInit);
    int32_t ret = BSL_SAL_ThreadWriteLock(g_errLock);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05007, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "acquire lock failed when pushing error, threadId %llu, error code %d", BSL_SAL_ThreadGetId(), ret, 0, 0);
        return;
    }

    ErrorCodeStack *stack = GetStack();
    if (stack != NULL) {
        if (stack->top == stack->bottom && stack->errorStack[stack->top] != 0) {
            stack->bottom = (stack->bottom + 1) % SAL_MAX_ERROR_STACK;
        }
        stack->errorFlags[stack->top] = 0;
        stack->errorStack[stack->top] = err;
        stack->filename[stack->top] = file;
        stack->line[stack->top] = lineNo;
        stack->top = (stack->top + 1) % SAL_MAX_ERROR_STACK;
    }

    BSL_SAL_ThreadUnlock(g_errLock);
}

void BSL_ERR_ClearError(void)
{
    (void)BSL_SAL_ThreadRunOnce(&g_isErrInit, ErrAutoInit);

    uint64_t threadId = BSL_SAL_ThreadGetId();
    int32_t ret = BSL_SAL_ThreadWriteLock(g_errLock);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05008, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "acquire lock failed when clearing error, threadId %llu", threadId, 0, 0, 0);
        return;
    }

    BSL_AvlTree *curNode = BSL_AVL_SearchNode(g_avlRoot, threadId);
    if (curNode != NULL) {
        /* Will not be NULL. */
        ErrorCodeStack *errStack = curNode->data;
        if (errStack->flag == 0) {
            StackReset(errStack);
        }
    }

    BSL_SAL_ThreadUnlock(g_errLock);
}

void BSL_ERR_RemoveErrorStack(bool isRemoveAll)
{
    (void)BSL_SAL_ThreadRunOnce(&g_isErrInit, ErrAutoInit);

    int32_t ret = BSL_SAL_ThreadWriteLock(g_errLock);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05009, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "acquire lock failed when removing error stack, threadId %llu", BSL_SAL_ThreadGetId(), 0, 0, 0);
        return;
    }

    if (g_avlRoot != NULL) {
        if (isRemoveAll) {
            BSL_AVL_DeleteTree(g_avlRoot, StackDataFree);
            g_avlNodeCount = 0;
            g_avlRoot = NULL;
        } else {
            uint64_t threadId = BSL_SAL_ThreadGetId();
            BSL_AvlTree *curNode = BSL_AVL_SearchNode(g_avlRoot, threadId);
            if (curNode != NULL) {
                g_avlNodeCount--;
                g_avlRoot = BSL_AVL_DeleteNode(g_avlRoot, threadId, StackDataFree);
            }
        }
    }

    BSL_SAL_ThreadUnlock(g_errLock);
}

/* Obtain the index. 'last' indicates that the last or first error code is obtained. */
static uint16_t GetIndex(ErrorCodeStack *errStack, bool last)
{
    uint16_t idx;

    if (last) {
        idx = errStack->top - 1;
        if (idx >= SAL_MAX_ERROR_STACK) {
            idx = SAL_MAX_ERROR_STACK - 1;
        }
    } else  {
        idx = errStack->bottom;
    }

    return idx;
}

/* If clr is true, the external operation is get. If clr is false, the external operation is peek.
   The get operation cleans up after the error information is obtained, while the peek operation does not.
   If last is true, the last error code at the top of the stack is obtained.
   If last is false, the first error code at the bottom of the stack is obtained. */
static int32_t GetErrorInfo(const char **file, uint32_t *lineNo, bool clr, bool last)
{
    uint16_t idx;

    int32_t ret = BSL_SAL_ThreadReadLock(g_errLock);
    if (ret != BSL_SUCCESS) {
        return BSL_ERR_ERR_ACQUIRE_READ_LOCK_FAIL;
    }

    if (g_avlRoot == NULL) {
        /* If avlRoot is empty, no thread push error. Therefore, error should be success. */
        BSL_SAL_ThreadUnlock(g_errLock);
        return BSL_SUCCESS;
    }

    const uint64_t threadId = BSL_SAL_ThreadGetId();
    BSL_AvlTree *curNode = BSL_AVL_SearchNode(g_avlRoot, threadId);
    if (curNode == NULL) {
        /* If curNode is empty, the current thread does not have push error. Therefore, error should be success. */
        BSL_SAL_ThreadUnlock(g_errLock);
        return BSL_SUCCESS;
    }

    ErrorCodeStack *errStack = curNode->data; /* will not be null */

    idx = GetIndex(errStack, last);
    if (errStack->errorStack[idx] == 0) { /* error stack is empty */
        BSL_SAL_ThreadUnlock(g_errLock);
        return BSL_SUCCESS;
    }

    int32_t errorCode = errStack->errorStack[idx]; /* Obtain the specified error ID. */
    uint32_t fileLine = errStack->line[idx]; /* Obtain the specified line number. */
    const char *f = errStack->filename[idx]; /* Obtain the specified file name. */
    if (clr) {
        StackResetIndex(errStack, idx);
        if (last) {
            errStack->top = idx;
        } else {
            errStack->bottom = (idx + 1) % SAL_MAX_ERROR_STACK;
        }
    }

    BSL_SAL_ThreadUnlock(g_errLock);

    if (file != NULL && lineNo != NULL) { /* both together, there's no point in getting only one of them. */
        if (f == NULL) {
            *file = "NA";
            *lineNo = 0;
        } else {
            *file = f;
            *lineNo = fileLine;
        }
    }

    return errorCode;
}

static int32_t GetLastErrorInfo(const char **file, uint32_t *lineNo, bool clr)
{
    return GetErrorInfo(file, lineNo, clr, true);
}

static int32_t GetFirstErrorInfo(const char **file, uint32_t *lineNo, bool clr)
{
    return GetErrorInfo(file, lineNo, clr, false);
}

int32_t BSL_ERR_GetLastErrorFileLine(const char **file, uint32_t *lineNo)
{
    return GetLastErrorInfo(file, lineNo, true);
}

int32_t BSL_ERR_PeekLastErrorFileLine(const char **file, uint32_t *lineNo)
{
    return GetLastErrorInfo(file, lineNo, false);
}

int32_t BSL_ERR_GetLastError(void)
{
    return GetLastErrorInfo(NULL, NULL, true);
}

int32_t BSL_ERR_PeekLastError(void)
{
    return GetLastErrorInfo(NULL, NULL, false);
}

int32_t BSL_ERR_GetErrorFileLine(const char **file, uint32_t *lineNo)
{
    return GetFirstErrorInfo(file, lineNo, true);
}

int32_t BSL_ERR_PeekErrorFileLine(const char **file, uint32_t *lineNo)
{
    return GetFirstErrorInfo(file, lineNo, false);
}

int32_t BSL_ERR_GetError(void)
{
    return GetFirstErrorInfo(NULL, NULL, true);
}

int32_t BSL_ERR_PeekError(void)
{
    return GetFirstErrorInfo(NULL, NULL, false);
}

int32_t BSL_ERR_GetErrAll(const char **file, uint32_t *lineNo, const char **desc)
{
    int32_t ret = GetFirstErrorInfo(file, lineNo, true);
    if (ret != BSL_SUCCESS && desc != NULL) {
        *desc = BSL_ERR_GetString(ret);
    }
    return ret;
}

static int32_t AddErrDesc(const BSL_ERR_Desc *desc)
{
    if (desc->error < 0) {
        return BSL_INTERNAL_EXCEPTION;
    }
    BSL_AvlTree *curNode = BSL_AVL_SearchNode(g_descRoot, (uint64_t)desc->error);
    if (curNode != NULL) {
        curNode->data = (BSL_ElementData)(uintptr_t)(desc->string);
        return BSL_SUCCESS;
    }
    BSL_AvlTree *node = BSL_AVL_MakeLeafNode((BSL_ElementData)(uintptr_t)(desc->string));
    if (node == NULL) {
        return BSL_INTERNAL_EXCEPTION;
    }
    g_descRoot = BSL_AVL_InsertNode(g_descRoot, (uint64_t)desc->error, node);
    return BSL_SUCCESS;
}

int32_t BSL_ERR_AddErrStringBatch(const BSL_ERR_Desc *descList, uint32_t num)
{
    if (descList == NULL || num == 0) {
        return BSL_NULL_INPUT;
    }
    int32_t ret = BSL_SAL_ThreadWriteLock(g_errLock);
    if (ret != BSL_SUCCESS) {
        return ret;
    }
    for (uint32_t i = 0; i < num; i++) {
        ret = AddErrDesc(&descList[i]);
        if (ret != BSL_SUCCESS) {
            break;
        }
    }
    BSL_SAL_ThreadUnlock(g_errLock);
    return ret;
}

void BSL_ERR_RemoveErrStringBatch(void)
{
    int32_t ret = BSL_SAL_ThreadWriteLock(g_errLock);
    if (ret != BSL_SUCCESS) {
        BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05085, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
            "acquire lock failed when removing error string, threadId %llu", BSL_SAL_ThreadGetId(), 0, 0, 0);
        return;
    }
    if (g_descRoot != NULL) {
        BSL_AVL_DeleteTree(g_descRoot, NULL);
        g_descRoot = NULL;
    }
    BSL_SAL_ThreadUnlock(g_errLock);
}

const char *BSL_ERR_GetString(int32_t error)
{
    if (error < 0) {
        return NULL;
    }
    int32_t ret = BSL_SAL_ThreadWriteLock(g_errLock);
    if (ret != BSL_SUCCESS) {
        return NULL;
    }
    if (g_descRoot == NULL) {
        BSL_SAL_ThreadUnlock(g_errLock);
        return NULL;
    }
    BSL_AvlTree *curNode = BSL_AVL_SearchNode(g_descRoot, (uint64_t)error);
    if (curNode == NULL) {
        BSL_SAL_ThreadUnlock(g_errLock);
        return NULL;
    }
    const char *str = curNode->data;
    BSL_SAL_ThreadUnlock(g_errLock);
    return str;
}

static int32_t BSL_LIST_WriteLockCreate(ErrorCodeStack **errStack, uint32_t *top)
{
    int32_t ret = BSL_SAL_ThreadWriteLock(g_errLock);
    if (ret != BSL_SUCCESS) {
        return BSL_ERR_ERR_ACQUIRE_WRITE_LOCK_FAIL;
    }

    if (g_avlRoot == NULL) {
        BSL_SAL_ThreadUnlock(g_errLock);
        return BSL_ERR_ERR_NO_STACK;
    }

    const uint64_t threadId = BSL_SAL_ThreadGetId();
    BSL_AvlTree *curNode = BSL_AVL_SearchNode(g_avlRoot, threadId);
    if (curNode == NULL) {
        BSL_SAL_ThreadUnlock(g_errLock);
        return BSL_ERR_ERR_NO_STACK;
    }

    *errStack = curNode->data; /* will not be null */
    if (top == NULL) {
        return ret;
    }
    *top = (*errStack)->top - 1;
    if (*top >= SAL_MAX_ERROR_STACK) {
        *top = SAL_MAX_ERROR_STACK - 1;
    }
    return ret;
}

int32_t BSL_ERR_SetMark(void)
{
    ErrorCodeStack *errStack = NULL;
    uint32_t top = 0;
    int32_t ret = BSL_LIST_WriteLockCreate(&errStack, &top);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    if (errStack->errorStack[top] == 0) { /* error stack is empty */
        BSL_SAL_ThreadUnlock(g_errLock);
        return BSL_ERR_ERR_NO_ERROR;
    }

    errStack->errorFlags[top] |= ERR_FLAG_POP_MARK;

    BSL_SAL_ThreadUnlock(g_errLock);
    return BSL_SUCCESS;
}

int32_t BSL_ERR_PopToMark(void)
{
    ErrorCodeStack *errStack = NULL;
    uint32_t top = 0;
    int32_t ret = BSL_LIST_WriteLockCreate(&errStack, &top);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    while (errStack->errorStack[top] != 0 && ((errStack->errorFlags[top] & ERR_FLAG_POP_MARK) == 0)) {
        StackResetIndex(errStack, top);
        top--;
        if (top >= SAL_MAX_ERROR_STACK) {
            top = SAL_MAX_ERROR_STACK - 1;
        }
    }
    errStack->top = (top + 1) % SAL_MAX_ERROR_STACK;

    if (errStack->errorStack[top] == 0) {
        BSL_SAL_ThreadUnlock(g_errLock);
        return BSL_ERR_ERR_NO_MARK;
    }

    errStack->errorFlags[top] &= ~ERR_FLAG_POP_MARK;

    BSL_SAL_ThreadUnlock(g_errLock);
    return BSL_SUCCESS;
}

int32_t BSL_ERR_ClearLastMark(void)
{
    ErrorCodeStack *errStack = NULL;
    uint32_t top = 0;
    int32_t ret = BSL_LIST_WriteLockCreate(&errStack, &top);
    if (ret != BSL_SUCCESS) {
        return ret;
    }

    while (errStack->errorStack[top] != 0 && ((errStack->errorFlags[top] & ERR_FLAG_POP_MARK) == 0)) {
        top--;
        if (top >= SAL_MAX_ERROR_STACK) {
            top = SAL_MAX_ERROR_STACK - 1;
        }
    }
    errStack->errorFlags[top] &= ~ERR_FLAG_POP_MARK;

    BSL_SAL_ThreadUnlock(g_errLock);
    return BSL_SUCCESS;
}

void BSL_ERR_OutputErrorStack(void)
{
    if (g_outputFunc == NULL) {
        return;
    }
    (void)BSL_SAL_ThreadReadLock(g_errLock);
    if (g_avlRoot == NULL) {
        BSL_SAL_ThreadUnlock(g_errLock);
        return;
    }
    const uint64_t threadId = BSL_SAL_ThreadGetId();
    BSL_AvlTree *curNode = BSL_AVL_SearchNode(g_avlRoot, threadId);
    if (curNode == NULL) {
        BSL_SAL_ThreadUnlock(g_errLock);
        return;
    }
    ErrorCodeStack *errStack = curNode->data; /* will not be null */

    uint16_t idx = errStack->bottom;
    uint16_t count = 0;
    while (errStack->errorStack[idx] != 0 && count < SAL_MAX_ERROR_STACK) {
        const char *file = errStack->filename[idx];
        uint32_t lineNo = errStack->line[idx];
        int32_t errCode = errStack->errorStack[idx];
        bool mark = (errStack->errorFlags[idx] & ERR_FLAG_POP_MARK) != 0;
        if (file == NULL) {
            file = "NA";
            lineNo = 0;
        }
        g_outputFunc(threadId, file, lineNo, errCode, mark);
        idx = (idx + 1) % SAL_MAX_ERROR_STACK;
        count++;
    }
    BSL_SAL_ThreadUnlock(g_errLock);
}

void BSL_ERR_RegErrStackLog(BSL_ERR_OutputFunc func)
{
    g_outputFunc = func;
}
#endif /* HITLS_BSL_ERR */
