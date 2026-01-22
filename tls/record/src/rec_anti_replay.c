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
#if defined(HITLS_TLS_PROTO_DTLS12) && defined(HITLS_BSL_UIO_UDP) && defined(HITLS_TLS_FEATURE_ANTI_REPLAY)
#include "rec_anti_replay.h"

#define REC_SLID_WINDOW_SIZE 64

void RecAntiReplayReset(RecSlidWindow *w)
{
    w->top = 0;
    w->window = 0;
}

bool RecAntiReplayCheck(const RecSlidWindow *w, uint64_t seq)
{
    if (seq > w->top) {
        return false;
    }

    uint64_t bit = w->top - seq;
    if (bit >= REC_SLID_WINDOW_SIZE) {
        /* The sequence number must be smaller than or equal to the minimum value of the sliding window */
        return true;
    }
    /* return true: The sequence number is equal to a certain value in the sliding window */
    return (w->window & ((uint64_t)1 << bit)) != 0;
}

void RecAntiReplayUpdate(RecSlidWindow *w, uint64_t seq)
{
    /* If the sequence number is too small, the flag bit is not updated */
    if ((seq + REC_SLID_WINDOW_SIZE) <= w->top) {
        return;
    }

    /* If the sequence number is less than or equal to top, update the flag */
    if (seq <= w->top) {
        uint64_t bit = w->top - seq;
        w->window |= (uint64_t)1 << bit;
        return;
    }

    /* If the sequence number is greater than top, update the maximum sliding window size */
    uint64_t bit = seq - w->top;
    w->top = seq;
    if (bit >= REC_SLID_WINDOW_SIZE) {
        /* If the number exceeds the current number too much, all previous flags are cleared and the maximum value is
         * updated */
        w->window = 1;
    } else {
        w->window <<= bit;
        w->window |= 1;
    }
}
#endif /* HITLS_TLS_PROTO_DTLS12 && HITLS_BSL_UIO_UDP && HITLS_TLS_FEATURE_ANTI_REPLAY */