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

#ifndef REC_ANTI_REPLAY_H
#define REC_ANTI_REPLAY_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  Anti-replay check function:
 *  Use uint64_t variable to store flag bit，When receive a message, set the flag of corresponding sequence number to 1
 *  The least significant bit of the variable stores the maximum sequence number of the sliding window top,
 *  when the top updates, shift the sliding window to the left
 *  If a duplicate message or a message whose sequence number is smaller than the minimum sliding window value
 *  is received, discard it
 *
 *  window: 64 bits Range: [top-63, top)
 *  1. Initial state：
 *        top - 63         top
 *          | - - - - - - |
 *  2. hen the top + 2 message is received：
 *          top - 61    top + 2
 *          | - - - - - - |
 */
typedef struct {
    uint64_t top;       /* Stores the current maximum sequence number */
    uint64_t window;    /* Sliding window for storing flag bits */
} RecSlidWindow;

/**
 * @brief   Reset of the anti-replay module
 *          The invoker must ensure that the input parameter is not empty
 *
 * @param   w [IN] Sliding window
 */
void RecAntiReplayReset(RecSlidWindow *w);

/**
 * @brief   Anti-Replay Check
 *          The invoker must ensure that the input parameter is not empty
 *
 * @param   w [IN] Sliding window
 * @param   seq [IN] Sequence number to be checked
 *
 * @retval  true    The sequence number is duplicate
 * @retval  false   The sequence number is not duplicate
 */
bool RecAntiReplayCheck(const RecSlidWindow *w, uint64_t seq);

/**
 * @brief   Update the window
 *          This function can be invoked only after the anti-replay check is passed
 *          Ensure that the input parameter is not empty by the invoker
 *
 * @param   w [IN] Sliding window. The input parameter correctness is ensured externally
 * @param   seq [IN] Sequence number of the window to be updated
 */
void RecAntiReplayUpdate(RecSlidWindow *w, uint64_t seq);

#ifdef __cplusplus
}
#endif

#endif /* REC_ANTI_REPLAY_H */
