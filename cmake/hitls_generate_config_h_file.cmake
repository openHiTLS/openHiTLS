# This file is part of the openHiTLS project.
#
# openHiTLS is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#     http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.


# Generate hitls_build_config.h from template
set(CONFIG_H_OUTPUT_DIR "${CMAKE_BINARY_DIR}/config")
set(CONFIG_H_OUTPUT_PATH "${CONFIG_H_OUTPUT_DIR}/hitls_build_config.h")

# When constant-time validation is requested, probe for <valgrind/memcheck.h>.
# HITLS_CT_SECRET_MARK/HITLS_CT_SECRET_UNMARK would expand to a real Valgrind client
# request, so a missing header must abort with a clear install hint rather than a
# cryptic compile failure. We do not need a separate "header present" macro: the
# cmake check fails the build here, so HITLS_CT_VALIDATION being defined already
# implies the header is available.
if(HITLS_CT_VALIDATION)
    include(CheckIncludeFile)
    check_include_file("valgrind/memcheck.h" _hitls_have_valgrind_hdr)
    if(NOT _hitls_have_valgrind_hdr)
        message(FATAL_ERROR
            "HITLS_CT_VALIDATION=ON requires the Valgrind development headers "
            "(<valgrind/memcheck.h>). On Debian/Ubuntu: apt-get install valgrind; "
            "on RHEL/Fedora: dnf install valgrind-devel.")
    endif()
    unset(_hitls_have_valgrind_hdr)
endif()

file(MAKE_DIRECTORY "${CONFIG_H_OUTPUT_DIR}")
configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/config.h.in"
    "${CONFIG_H_OUTPUT_PATH}"
    @ONLY
)
