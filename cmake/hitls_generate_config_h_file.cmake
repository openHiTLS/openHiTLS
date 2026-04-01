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

file(MAKE_DIRECTORY "${CONFIG_H_OUTPUT_DIR}")
configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/config.h.in"
    "${CONFIG_H_OUTPUT_PATH}"
    @ONLY
)
