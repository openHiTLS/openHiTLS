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

/*
 * stub_utils.h - Cross-Platform Stub Framework
 *
 * This framework provides a real-by-default stubbing mechanism:
 *   - Unix/Linux/macOS: Calls real implementations via dlsym(RTLD_NEXT)
 *   - Windows: Placeholder for future GetProcAddress-based implementation
 *   - Allows runtime stubbing for test control
 *
 * Usage:
 *   #include "stub_utils.h"
 *
 *   STUB_DEFINE_RET2(int, Add, int, int);
 *
 *   // By default: Calls real Add from library (Unix) or returns default (Windows placeholder)
 *   int result = Add(10, 20);
 *
 *   // Can stub for testing:
 *   STUB_REPLACE(Add, my_custom_stub);
 *   result = Add(10, 20);  // Uses my_custom_stub
 *
 *   // Restore to real implementation:
 *   STUB_RESTORE(Add);
 */

#ifndef STUB_UTILS_H
#define STUB_UTILS_H

#if defined(__linux__) || defined(__gnu_linux__)
    #ifndef _GNU_SOURCE
        #define _GNU_SOURCE
    #endif
#endif

#include <string.h>
#include <stddef.h>

/* ============================================================================
 * Platform Detection and Includes
 * ============================================================================ */

#if defined(__unix__) || defined(__unix) || defined(__APPLE__) || defined(__MACH__)
    /* Unix-like platforms: Linux, macOS, BSD, etc. */
    #define STUB_PLATFORM_UNIX
    #include <dlfcn.h>

    #ifndef RTLD_NEXT
        #error "RTLD_NEXT not supported on this Unix platform. Please ensure _GNU_SOURCE is defined on Linux."
    #endif

#elif defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    /* Windows platforms */
    #define STUB_PLATFORM_WINDOWS
    #include <windows.h>

    /* Windows implementation is placeholder - real symbol lookup not yet implemented */
    #ifndef STUB_WINDOWS_WARN_ONCE
        #define STUB_WINDOWS_WARN_ONCE
        #pragma message("Warning: Windows real function call support is not yet implemented.")
    #endif

#else
    #error "Unsupported platform. This framework requires Unix-like OS or Windows."
#endif

/* ============================================================================
 * Common Macros
 * ============================================================================ */

#define STUB_COMMON_FIELDS                                                     \
    const char* stub_target_symbol

/* ============================================================================
 * Control Macros (Platform-Independent)
 * ============================================================================ */

#define STUB_REPLACE(FUNCNAME, STUB_FUNC)                                      \
    do { FUNCNAME##_stub.stub_impl = STUB_FUNC; } while(0)

#define STUB_RESTORE(FUNCNAME)                                                 \
    do { FUNCNAME##_stub.stub_impl = NULL; } while(0)

#define WITH_STUB_SCOPED(FUNCNAME, STUB_FUNC)                                  \
    for(int _stub_once = (FUNCNAME##_stub.stub_impl = STUB_FUNC, 1);           \
        _stub_once;                                                            \
        _stub_once = 0, FUNCNAME##_stub.stub_impl = NULL)

/* ============================================================================
 * Platform-Specific: Real Implementation Lookup
 * ============================================================================ */

#ifdef STUB_PLATFORM_UNIX

/* Unix/Linux/macOS: Use dlsym with RTLD_NEXT */
#define STUB_GET_REAL_IMPL(FUNCNAME, FUNC_TYPE)                                 \
    static FUNC_TYPE get_real_##FUNCNAME(void) {                                \
        if (FUNCNAME##_stub.real_impl == NULL) {                                \
            FUNCNAME##_stub.real_impl = (FUNC_TYPE)dlsym(RTLD_NEXT, #FUNCNAME); \
        }                                                                       \
        return FUNCNAME##_stub.real_impl;                                       \
    }

#define STUB_REAL_IMPL_FIELD(FUNC_TYPE) FUNC_TYPE real_impl;

#elif defined(STUB_PLATFORM_WINDOWS)

/* Windows: Placeholder - GetProcAddress-based lookup not yet implemented */
#define STUB_GET_REAL_IMPL(FUNCNAME, FUNC_TYPE)                                 \
    static FUNC_TYPE get_real_##FUNCNAME(void) {                                \
        /* TODO: Implement GetProcAddress-based lookup */                       \
        /* Strategy: Use GetModuleHandle + GetProcAddress to find real impl */  \
        /* For now, always return NULL to fall back to default behavior */      \
        return NULL;                                                            \
    }

/* Windows doesn't cache real_impl since lookup is not implemented */
#define STUB_REAL_IMPL_FIELD(FUNC_TYPE) /* No real_impl field on Windows */

#endif

/* ============================================================================
 * VOID Function Stubs (0-10 arguments)
 * ============================================================================ */

#define STUB_DEFINE_VOID0(FUNCNAME)                                            \
    typedef void (*real_##FUNCNAME##_func_t)(void);                            \
    typedef struct FUNCNAME##_Stub {                                           \
        STUB_COMMON_FIELDS;                                                    \
        void (*stub_impl)(void);                                               \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                         \
    } FUNCNAME##_Stub;                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                        \
        .stub_target_symbol = #FUNCNAME,                                       \
        .stub_impl = NULL,                                                     \
    };                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                     \
    void FUNCNAME##_restore(void) {                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                      \
    }                                                                          \
    void FUNCNAME(void) {                                                      \
        if (FUNCNAME##_stub.stub_impl) {                                       \
            FUNCNAME##_stub.stub_impl();                                       \
            return;                                                            \
        }                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();            \
        if (real_func) {                                                       \
            real_func();                                                       \
        }                                                                      \
    }

#define STUB_DEFINE_VOID1(FUNCNAME, T0)                                        \
    typedef void (*real_##FUNCNAME##_func_t)(T0);                              \
    typedef struct FUNCNAME##_Stub {                                           \
        STUB_COMMON_FIELDS;                                                    \
        void (*stub_impl)(T0);                                                 \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                         \
    } FUNCNAME##_Stub;                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                        \
        .stub_target_symbol = #FUNCNAME,                                       \
        .stub_impl = NULL,                                                     \
    };                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                     \
    void FUNCNAME##_restore(void) {                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                      \
    }                                                                          \
    void FUNCNAME(T0 arg0) {                                                   \
        if (FUNCNAME##_stub.stub_impl) {                                       \
            FUNCNAME##_stub.stub_impl(arg0);                                   \
            return;                                                            \
        }                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();            \
        if (real_func) {                                                       \
            real_func(arg0);                                                   \
        }                                                                      \
    }

#define STUB_DEFINE_VOID2(FUNCNAME, T0, T1)                                    \
    typedef void (*real_##FUNCNAME##_func_t)(T0, T1);                          \
    typedef struct FUNCNAME##_Stub {                                           \
        STUB_COMMON_FIELDS;                                                    \
        void (*stub_impl)(T0, T1);                                             \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                         \
    } FUNCNAME##_Stub;                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                        \
        .stub_target_symbol = #FUNCNAME,                                       \
        .stub_impl = NULL,                                                     \
    };                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                     \
    void FUNCNAME##_restore(void) {                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                      \
    }                                                                          \
    void FUNCNAME(T0 arg0, T1 arg1) {                                          \
        if (FUNCNAME##_stub.stub_impl) {                                       \
            FUNCNAME##_stub.stub_impl(arg0, arg1);                             \
            return;                                                            \
        }                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();            \
        if (real_func) {                                                       \
            real_func(arg0, arg1);                                             \
        }                                                                      \
    }

#define STUB_DEFINE_VOID3(FUNCNAME, T0, T1, T2)                                \
    typedef void (*real_##FUNCNAME##_func_t)(T0, T1, T2);                      \
    typedef struct FUNCNAME##_Stub {                                           \
        STUB_COMMON_FIELDS;                                                    \
        void (*stub_impl)(T0, T1, T2);                                         \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                         \
    } FUNCNAME##_Stub;                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                        \
        .stub_target_symbol = #FUNCNAME,                                       \
        .stub_impl = NULL,                                                     \
    };                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                     \
    void FUNCNAME##_restore(void) {                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                      \
    }                                                                          \
    void FUNCNAME(T0 arg0, T1 arg1, T2 arg2) {                                 \
        if (FUNCNAME##_stub.stub_impl) {                                       \
            FUNCNAME##_stub.stub_impl(arg0, arg1, arg2);                       \
            return;                                                            \
        }                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();            \
        if (real_func) {                                                       \
            real_func(arg0, arg1, arg2);                                       \
        }                                                                      \
    }

#define STUB_DEFINE_VOID4(FUNCNAME, T0, T1, T2, T3)                            \
    typedef void (*real_##FUNCNAME##_func_t)(T0, T1, T2, T3);                  \
    typedef struct FUNCNAME##_Stub {                                           \
        STUB_COMMON_FIELDS;                                                    \
        void (*stub_impl)(T0, T1, T2, T3);                                     \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                         \
    } FUNCNAME##_Stub;                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                        \
        .stub_target_symbol = #FUNCNAME,                                       \
        .stub_impl = NULL,                                                     \
    };                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                     \
    void FUNCNAME##_restore(void) {                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                      \
    }                                                                          \
    void FUNCNAME(T0 arg0, T1 arg1, T2 arg2, T3 arg3) {                        \
        if (FUNCNAME##_stub.stub_impl) {                                       \
            FUNCNAME##_stub.stub_impl(arg0, arg1, arg2, arg3);                 \
            return;                                                            \
        }                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();            \
        if (real_func) {                                                       \
            real_func(arg0, arg1, arg2, arg3);                                 \
        }                                                                      \
    }

#define STUB_DEFINE_VOID5(FUNCNAME, T0, T1, T2, T3, T4)                        \
    typedef void (*real_##FUNCNAME##_func_t)(T0, T1, T2, T3, T4);              \
    typedef struct FUNCNAME##_Stub {                                           \
        STUB_COMMON_FIELDS;                                                    \
        void (*stub_impl)(T0, T1, T2, T3, T4);                                 \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                         \
    } FUNCNAME##_Stub;                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                        \
        .stub_target_symbol = #FUNCNAME,                                       \
        .stub_impl = NULL,                                                     \
    };                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                     \
    void FUNCNAME##_restore(void) {                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                      \
    }                                                                          \
    void FUNCNAME(T0 arg0, T1 arg1, T2 arg2, T3 arg3, T4 arg4) {               \
        if (FUNCNAME##_stub.stub_impl) {                                       \
            FUNCNAME##_stub.stub_impl(arg0, arg1, arg2, arg3, arg4);           \
            return;                                                            \
        }                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();            \
        if (real_func) {                                                       \
            real_func(arg0, arg1, arg2, arg3, arg4);                           \
        }                                                                      \
    }

#define STUB_DEFINE_VOID6(FUNCNAME, T0, T1, T2, T3, T4, T5)                    \
    typedef void (*real_##FUNCNAME##_func_t)(T0, T1, T2, T3, T4, T5);          \
    typedef struct FUNCNAME##_Stub {                                           \
        STUB_COMMON_FIELDS;                                                    \
        void (*stub_impl)(T0, T1, T2, T3, T4, T5);                             \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                         \
    } FUNCNAME##_Stub;                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                        \
        .stub_target_symbol = #FUNCNAME,                                       \
        .stub_impl = NULL,                                                     \
    };                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                     \
    void FUNCNAME##_restore(void) {                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                      \
    }                                                                          \
    void FUNCNAME(T0 arg0, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5) {      \
        if (FUNCNAME##_stub.stub_impl) {                                       \
            FUNCNAME##_stub.stub_impl(arg0, arg1, arg2, arg3, arg4, arg5);     \
            return;                                                            \
        }                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();            \
        if (real_func) {                                                       \
            real_func(arg0, arg1, arg2, arg3, arg4, arg5);                     \
        }                                                                      \
    }

#define STUB_DEFINE_VOID7(FUNCNAME, T0, T1, T2, T3, T4, T5, T6)                \
    typedef void (*real_##FUNCNAME##_func_t)(T0, T1, T2, T3, T4, T5, T6);      \
    typedef struct FUNCNAME##_Stub {                                           \
        STUB_COMMON_FIELDS;                                                    \
        void (*stub_impl)(T0, T1, T2, T3, T4, T5, T6);                         \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                         \
    } FUNCNAME##_Stub;                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                        \
        .stub_target_symbol = #FUNCNAME,                                       \
        .stub_impl = NULL,                                                     \
    };                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                     \
    void FUNCNAME##_restore(void) {                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                      \
    }                                                                          \
    void FUNCNAME(T0 arg0, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6) { \
        if (FUNCNAME##_stub.stub_impl) {                                       \
            FUNCNAME##_stub.stub_impl(arg0, arg1, arg2, arg3, arg4, arg5, arg6); \
            return;                                                            \
        }                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();            \
        if (real_func) {                                                       \
            real_func(arg0, arg1, arg2, arg3, arg4, arg5, arg6);               \
        }                                                                      \
    }

#define STUB_DEFINE_VOID8(FUNCNAME, T0, T1, T2, T3, T4, T5, T6, T7)                         \
    typedef void (*real_##FUNCNAME##_func_t)(T0, T1, T2, T3, T4, T5, T6, T7);               \
    typedef struct FUNCNAME##_Stub {                                                        \
        STUB_COMMON_FIELDS;                                                                 \
        void (*stub_impl)(T0, T1, T2, T3, T4, T5, T6, T7);                                  \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                                      \
    } FUNCNAME##_Stub;                                                                      \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                                     \
        .stub_target_symbol = #FUNCNAME,                                                    \
        .stub_impl = NULL,                                                                  \
    };                                                                                      \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                                  \
    void FUNCNAME##_restore(void) {                                                         \
        FUNCNAME##_stub.stub_impl = NULL;                                                   \
    }                                                                                       \
    void FUNCNAME(T0 arg0, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7) { \
        if (FUNCNAME##_stub.stub_impl) {                                                    \
            FUNCNAME##_stub.stub_impl(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);      \
            return;                                                                         \
        }                                                                                   \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();                         \
        if (real_func) {                                                                    \
            real_func(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);                      \
        }                                                                                   \
    }

#define STUB_DEFINE_VOID9(FUNCNAME, T0, T1, T2, T3, T4, T5, T6, T7, T8)                              \
    typedef void (*real_##FUNCNAME##_func_t)(T0, T1, T2, T3, T4, T5, T6, T7, T8);                    \
    typedef struct FUNCNAME##_Stub {                                                                 \
        STUB_COMMON_FIELDS;                                                                          \
        void (*stub_impl)(T0, T1, T2, T3, T4, T5, T6, T7, T8);                                       \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                                               \
    } FUNCNAME##_Stub;                                                                               \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                                              \
        .stub_target_symbol = #FUNCNAME,                                                             \
        .stub_impl = NULL,                                                                           \
    };                                                                                               \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                                           \
    void FUNCNAME##_restore(void) {                                                                  \
        FUNCNAME##_stub.stub_impl = NULL;                                                            \
    }                                                                                                \
    void FUNCNAME(T0 arg0, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7, T8 arg8) { \
        if (FUNCNAME##_stub.stub_impl) {                                                             \
            FUNCNAME##_stub.stub_impl(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);         \
            return;                                                                                  \
        }                                                                                            \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();                                  \
        if (real_func) {                                                                             \
            real_func(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);                         \
        }                                                                                            \
    }

#define STUB_DEFINE_VOID10(FUNCNAME, T0, T1, T2, T3, T4, T5, T6, T7, T8, T9)                                  \
    typedef void (*real_##FUNCNAME##_func_t)(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9);                         \
    typedef struct FUNCNAME##_Stub {                                                                          \
        STUB_COMMON_FIELDS;                                                                                   \
        void (*stub_impl)(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9);                                            \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                                                        \
    } FUNCNAME##_Stub;                                                                                        \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                                                       \
        .stub_target_symbol = #FUNCNAME,                                                                      \
        .stub_impl = NULL,                                                                                    \
    };                                                                                                        \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                                                    \
    void FUNCNAME##_restore(void) {                                                                           \
        FUNCNAME##_stub.stub_impl = NULL;                                                                     \
    }                                                                                                         \
    void FUNCNAME(T0 arg0, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7, T8 arg8, T9 arg9) { \
        if (FUNCNAME##_stub.stub_impl) {                                                                      \
            FUNCNAME##_stub.stub_impl(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);            \
            return;                                                                                           \
        }                                                                                                     \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();                                           \
        if (real_func) {                                                                                      \
            real_func(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);                            \
        }                                                                                                     \
    }

/* ============================================================================
 * Return Value Function Stubs (0-10 arguments)
 * ============================================================================ */

#define STUB_DEFINE_RET0(RTYPE, FUNCNAME)                                      \
    typedef RTYPE (*real_##FUNCNAME##_func_t)(void);                           \
    typedef struct FUNCNAME##_Stub {                                           \
        STUB_COMMON_FIELDS;                                                    \
        RTYPE (*stub_impl)(void);                                              \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                         \
    } FUNCNAME##_Stub;                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                        \
        .stub_target_symbol = #FUNCNAME,                                       \
        .stub_impl = NULL,                                                     \
    };                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                     \
    void FUNCNAME##_restore(void) {                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                      \
    }                                                                          \
    RTYPE FUNCNAME(void) {                                                     \
        if (FUNCNAME##_stub.stub_impl) {                                       \
            return FUNCNAME##_stub.stub_impl();                                \
        }                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();            \
        if (real_func) {                                                       \
            return real_func();                                                \
        }                                                                      \
        RTYPE default_ret = {0};                                               \
        return default_ret;                                                    \
    }

#define STUB_DEFINE_RET1(RTYPE, FUNCNAME, T0)                                  \
    typedef RTYPE (*real_##FUNCNAME##_func_t)(T0);                             \
    typedef struct FUNCNAME##_Stub {                                           \
        STUB_COMMON_FIELDS;                                                    \
        RTYPE (*stub_impl)(T0);                                                \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                         \
    } FUNCNAME##_Stub;                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                        \
        .stub_target_symbol = #FUNCNAME,                                       \
        .stub_impl = NULL,                                                     \
    };                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                     \
    void FUNCNAME##_restore(void) {                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                      \
    }                                                                          \
    RTYPE FUNCNAME(T0 arg0) {                                                  \
        if (FUNCNAME##_stub.stub_impl) {                                       \
            return FUNCNAME##_stub.stub_impl(arg0);                            \
        }                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();            \
        if (real_func) {                                                       \
            return real_func(arg0);                                            \
        }                                                                      \
        RTYPE default_ret = {0};                                               \
        return default_ret;                                                    \
    }

#define STUB_DEFINE_RET2(RTYPE, FUNCNAME, T0, T1)                              \
    typedef RTYPE (*real_##FUNCNAME##_func_t)(T0, T1);                         \
    typedef struct FUNCNAME##_Stub {                                           \
        STUB_COMMON_FIELDS;                                                    \
        RTYPE (*stub_impl)(T0, T1);                                            \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                         \
    } FUNCNAME##_Stub;                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                        \
        .stub_target_symbol = #FUNCNAME,                                       \
        .stub_impl = NULL,                                                     \
    };                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                     \
    void FUNCNAME##_restore(void) {                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                      \
    }                                                                          \
    RTYPE FUNCNAME(T0 arg0, T1 arg1) {                                         \
        if (FUNCNAME##_stub.stub_impl) {                                       \
            return FUNCNAME##_stub.stub_impl(arg0, arg1);                      \
        }                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();            \
        if (real_func) {                                                       \
            return real_func(arg0, arg1);                                      \
        }                                                                      \
        RTYPE default_ret = {0};                                               \
        return default_ret;                                                    \
    }

#define STUB_DEFINE_RET3(RTYPE, FUNCNAME, T0, T1, T2)                          \
    typedef RTYPE (*real_##FUNCNAME##_func_t)(T0, T1, T2);                     \
    typedef struct FUNCNAME##_Stub {                                           \
        STUB_COMMON_FIELDS;                                                    \
        RTYPE (*stub_impl)(T0, T1, T2);                                        \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                         \
    } FUNCNAME##_Stub;                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                        \
        .stub_target_symbol = #FUNCNAME,                                       \
        .stub_impl = NULL,                                                     \
    };                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                     \
    void FUNCNAME##_restore(void) {                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                      \
    }                                                                          \
    RTYPE FUNCNAME(T0 arg0, T1 arg1, T2 arg2) {                                \
        if (FUNCNAME##_stub.stub_impl) {                                       \
            return FUNCNAME##_stub.stub_impl(arg0, arg1, arg2);                \
        }                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();            \
        if (real_func) {                                                       \
            return real_func(arg0, arg1, arg2);                                \
        }                                                                      \
        RTYPE default_ret = {0};                                               \
        return default_ret;                                                    \
    }

#define STUB_DEFINE_RET4(RTYPE, FUNCNAME, T0, T1, T2, T3)                      \
    typedef RTYPE (*real_##FUNCNAME##_func_t)(T0, T1, T2, T3);                 \
    typedef struct FUNCNAME##_Stub {                                           \
        STUB_COMMON_FIELDS;                                                    \
        RTYPE (*stub_impl)(T0, T1, T2, T3);                                    \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                         \
    } FUNCNAME##_Stub;                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                        \
        .stub_target_symbol = #FUNCNAME,                                       \
        .stub_impl = NULL,                                                     \
    };                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                     \
    void FUNCNAME##_restore(void) {                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                      \
    }                                                                          \
    RTYPE FUNCNAME(T0 arg0, T1 arg1, T2 arg2, T3 arg3) {                       \
        if (FUNCNAME##_stub.stub_impl) {                                       \
            return FUNCNAME##_stub.stub_impl(arg0, arg1, arg2, arg3);          \
        }                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();            \
        if (real_func) {                                                       \
            return real_func(arg0, arg1, arg2, arg3);                          \
        }                                                                      \
        RTYPE default_ret = {0};                                               \
        return default_ret;                                                    \
    }

#define STUB_DEFINE_RET5(RTYPE, FUNCNAME, T0, T1, T2, T3, T4)                  \
    typedef RTYPE (*real_##FUNCNAME##_func_t)(T0, T1, T2, T3, T4);             \
    typedef struct FUNCNAME##_Stub {                                           \
        STUB_COMMON_FIELDS;                                                    \
        RTYPE (*stub_impl)(T0, T1, T2, T3, T4);                                \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                         \
    } FUNCNAME##_Stub;                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                        \
        .stub_target_symbol = #FUNCNAME,                                       \
        .stub_impl = NULL,                                                     \
    };                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                     \
    void FUNCNAME##_restore(void) {                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                      \
    }                                                                          \
    RTYPE FUNCNAME(T0 arg0, T1 arg1, T2 arg2, T3 arg3, T4 arg4) {              \
        if (FUNCNAME##_stub.stub_impl) {                                       \
            return FUNCNAME##_stub.stub_impl(arg0, arg1, arg2, arg3, arg4);    \
        }                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();            \
        if (real_func) {                                                       \
            return real_func(arg0, arg1, arg2, arg3, arg4);                    \
        }                                                                      \
        RTYPE default_ret = {0};                                               \
        return default_ret;                                                    \
    }

#define STUB_DEFINE_RET6(RTYPE, FUNCNAME, T0, T1, T2, T3, T4, T5)                 \
    typedef RTYPE (*real_##FUNCNAME##_func_t)(T0, T1, T2, T3, T4, T5);            \
    typedef struct FUNCNAME##_Stub {                                              \
        STUB_COMMON_FIELDS;                                                       \
        RTYPE (*stub_impl)(T0, T1, T2, T3, T4, T5);                               \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                            \
    } FUNCNAME##_Stub;                                                            \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                           \
        .stub_target_symbol = #FUNCNAME,                                          \
        .stub_impl = NULL,                                                        \
    };                                                                            \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                        \
    void FUNCNAME##_restore(void) {                                               \
        FUNCNAME##_stub.stub_impl = NULL;                                         \
    }                                                                             \
    RTYPE FUNCNAME(T0 arg0, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5) {        \
        if (FUNCNAME##_stub.stub_impl) {                                          \
            return FUNCNAME##_stub.stub_impl(arg0, arg1, arg2, arg3, arg4, arg5); \
        }                                                                         \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();               \
        if (real_func) {                                                          \
            return real_func(arg0, arg1, arg2, arg3, arg4, arg5);                 \
        }                                                                         \
        RTYPE default_ret = {0};                                                  \
        return default_ret;                                                       \
    }

#define STUB_DEFINE_RET7(RTYPE, FUNCNAME, T0, T1, T2, T3, T4, T5, T6)                   \
    typedef RTYPE (*real_##FUNCNAME##_func_t)(T0, T1, T2, T3, T4, T5, T6);              \
    typedef struct FUNCNAME##_Stub {                                                    \
        STUB_COMMON_FIELDS;                                                             \
        RTYPE (*stub_impl)(T0, T1, T2, T3, T4, T5, T6);                                 \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                                  \
    } FUNCNAME##_Stub;                                                                  \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                                 \
        .stub_target_symbol = #FUNCNAME,                                                \
        .stub_impl = NULL,                                                              \
    };                                                                                  \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                              \
    void FUNCNAME##_restore(void) {                                                     \
        FUNCNAME##_stub.stub_impl = NULL;                                               \
    }                                                                                   \
    RTYPE FUNCNAME(T0 arg0, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6) {     \
        if (FUNCNAME##_stub.stub_impl) {                                                \
            return FUNCNAME##_stub.stub_impl(arg0, arg1, arg2, arg3, arg4, arg5, arg6); \
        }                                                                               \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();                     \
        if (real_func) {                                                                \
            return real_func(arg0, arg1, arg2, arg3, arg4, arg5, arg6);                 \
        }                                                                               \
        RTYPE default_ret = {0};                                                        \
        return default_ret;                                                             \
    }

#define STUB_DEFINE_RET8(RTYPE, FUNCNAME, T0, T1, T2, T3, T4, T5, T6, T7)                     \
    typedef RTYPE (*real_##FUNCNAME##_func_t)(T0, T1, T2, T3, T4, T5, T6, T7);                \
    typedef struct FUNCNAME##_Stub {                                                          \
        STUB_COMMON_FIELDS;                                                                   \
        RTYPE (*stub_impl)(T0, T1, T2, T3, T4, T5, T6, T7);                                   \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                                        \
    } FUNCNAME##_Stub;                                                                        \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                                       \
        .stub_target_symbol = #FUNCNAME,                                                      \
        .stub_impl = NULL,                                                                    \
    };                                                                                        \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                                    \
    void FUNCNAME##_restore(void) {                                                           \
        FUNCNAME##_stub.stub_impl = NULL;                                                     \
    }                                                                                         \
    RTYPE FUNCNAME(T0 arg0, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7) {  \
        if (FUNCNAME##_stub.stub_impl) {                                                      \
            return FUNCNAME##_stub.stub_impl(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7); \
        }                                                                                     \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();                           \
        if (real_func) {                                                                      \
            return real_func(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7);                 \
        }                                                                                     \
        RTYPE default_ret = {0};                                                              \
        return default_ret;                                                                   \
    }

#define STUB_DEFINE_RET9(RTYPE, FUNCNAME, T0, T1, T2, T3, T4, T5, T6, T7, T8)                         \
    typedef RTYPE (*real_##FUNCNAME##_func_t)(T0, T1, T2, T3, T4, T5, T6, T7, T8);                    \
    typedef struct FUNCNAME##_Stub {                                                                  \
        STUB_COMMON_FIELDS;                                                                           \
        RTYPE (*stub_impl)(T0, T1, T2, T3, T4, T5, T6, T7, T8);                                       \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                                                \
    } FUNCNAME##_Stub;                                                                                \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                                               \
        .stub_target_symbol = #FUNCNAME,                                                              \
        .stub_impl = NULL,                                                                            \
    };                                                                                                \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                                            \
    void FUNCNAME##_restore(void) {                                                                   \
        FUNCNAME##_stub.stub_impl = NULL;                                                             \
    }                                                                                                 \
    RTYPE FUNCNAME(T0 arg0, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7, T8 arg8) { \
        if (FUNCNAME##_stub.stub_impl) {                                                              \
            return FUNCNAME##_stub.stub_impl(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);   \
        }                                                                                             \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();                                   \
        if (real_func) {                                                                              \
            return real_func(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);                   \
        }                                                                                             \
        RTYPE default_ret = {0};                                                                      \
        return default_ret;                                                                           \
    }

#define STUB_DEFINE_RET10(RTYPE, FUNCNAME, T0, T1, T2, T3, T4, T5, T6, T7, T8, T9)                             \
    typedef RTYPE (*real_##FUNCNAME##_func_t)(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9);                         \
    typedef struct FUNCNAME##_Stub {                                                                           \
        STUB_COMMON_FIELDS;                                                                                    \
        RTYPE (*stub_impl)(T0, T1, T2, T3, T4, T5, T6, T7, T8, T9);                                            \
        STUB_REAL_IMPL_FIELD(real_##FUNCNAME##_func_t)                                                         \
    } FUNCNAME##_Stub;                                                                                         \
    FUNCNAME##_Stub FUNCNAME##_stub = {                                                                        \
        .stub_target_symbol = #FUNCNAME,                                                                       \
        .stub_impl = NULL,                                                                                     \
    };                                                                                                         \
    STUB_GET_REAL_IMPL(FUNCNAME, real_##FUNCNAME##_func_t)                                                     \
    void FUNCNAME##_restore(void) {                                                                            \
        FUNCNAME##_stub.stub_impl = NULL;                                                                      \
    }                                                                                                          \
    RTYPE FUNCNAME(T0 arg0, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7, T8 arg8, T9 arg9) { \
        if (FUNCNAME##_stub.stub_impl) {                                                                       \
            return FUNCNAME##_stub.stub_impl(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);      \
        }                                                                                                      \
        real_##FUNCNAME##_func_t real_func = get_real_##FUNCNAME();                                            \
        if (real_func) {                                                                                       \
            return real_func(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);                      \
        }                                                                                                      \
        RTYPE default_ret = {0};                                                                               \
        return default_ret;                                                                                    \
    }

#endif /* STUB_UTILS_H */
