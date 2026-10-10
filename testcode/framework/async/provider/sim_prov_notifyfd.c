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

/* Simulation provider: portable notify object (D2) - eventfd on Linux, pipe elsewhere */

#include "sim_prov_internal.h"
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef HITLS_CRYPTO_PROVIDER

#ifdef __linux__
#include <sys/eventfd.h>
#endif

int32_t SimNotifyFdCreate(SimNotifyFd *nfd)
{
    if (nfd == NULL) {
        return SIM_PROV_ERR_ARG;
    }
    nfd->fd = -1;
    nfd->write = -1;
#ifdef __linux__
    int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (fd < 0) {
        return SIM_PROV_ERR_MEMORY;
    }
    nfd->fd = fd;
    return SIM_PROV_SUCCESS;
#else
    int fds[2] = {-1, -1};
    if (pipe(fds) != 0) {
        return SIM_PROV_ERR_MEMORY;
    }
    (void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
    (void)fcntl(fds[1], F_SETFL, O_NONBLOCK);
    /* keep the exec behavior identical to the eventfd path (EFD_CLOEXEC) */
    (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    nfd->fd = fds[0];
    nfd->write = fds[1];
    return SIM_PROV_SUCCESS;
#endif
}

void SimNotifyFdDestroy(SimNotifyFd *nfd)
{
    if (nfd == NULL) {
        return;
    }
    if (nfd->fd >= 0) {
        (void)close(nfd->fd);
        nfd->fd = -1;
    }
    if (nfd->write >= 0) {
        (void)close(nfd->write);
        nfd->write = -1;
    }
}

void SimNotifyFdSignal(const SimNotifyFd *nfd)
{
    if (nfd == NULL || nfd->fd < 0) {
        return;
    }
#ifdef __linux__
    uint64_t one = 1;
    (void)write(nfd->fd, &one, sizeof(one));
#else
    uint8_t one = 1;
    if (nfd->write >= 0) {
        (void)write(nfd->write, &one, sizeof(one));
    }
#endif
}

#endif /* HITLS_CRYPTO_PROVIDER */
