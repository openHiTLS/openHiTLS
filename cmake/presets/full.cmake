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


message(STATUS "Loading preset: FULL (all features enabled)")

# Mark preset as loaded (prevents profile system from overriding)
set(HITLS_PRESET_LOADED ON CACHE BOOL "" FORCE)

# ---------------------------------------------------------------
# All Features Enabled
# ---------------------------------------------------------------
set(HITLS_BSL       ON CACHE BOOL "" FORCE)
set(HITLS_CRYPTO    ON CACHE BOOL "" FORCE)
set(HITLS_PKI       ON CACHE BOOL "" FORCE)
set(HITLS_TLS       ON CACHE BOOL "" FORCE)
set(HITLS_AUTH      ON CACHE BOOL "" FORCE)