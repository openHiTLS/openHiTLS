#ifndef HITLS_APP_ERRDECODE_H
#define HITLS_APP_ERRDECODE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error entry structure */
typedef struct {
    uint64_t code;                /* Error code */
    const char *library;          /* Library name */
    const char *function;         /* Function name */
    const char *reason;           /* Error reason */
    const char *fullDescription;  /* Full description */
} ErrorEntry;

/* Error code fields structure for verbose mode */
typedef struct {
    uint64_t fullCode;       /* Full error code */
    int32_t library;         /* Library field */
    int32_t function;        /* Function field */
    int32_t reason;          /* Reason field */
    const char *libName;     /* Library name */
    const char *funcName;    /* Function name */
    const char *reasonStr;   /* Reason description */
} ErrorCodeFields;

/* Command line options */
typedef struct {
    int32_t verboseMode;      /* -v or --verbose */
    int32_t stackMode;        /* --stack */
    int32_t hexMode;          /* -hex */
    int32_t helpMode;         /* -help or -h */
    int32_t stdinMode;        /* Read from stdin */
    char **errorCodes;        /* Error code arguments */
    int32_t numCodes;         /* Number of error codes */
} CommandOptions;

/* Error code format */
typedef enum {
    FORMAT_DECIMAL,             /* Decimal format */
    FORMAT_HEX_WITH_PREFIX,     /* Hexadecimal with 0x prefix */
    FORMAT_HEX_WITHOUT_PREFIX,  /* Hexadecimal without 0x prefix */
    FORMAT_INVALID              /* Invalid format */
} ErrorCodeFormat;

/* Error code field shift and mask constants */
#define ERR_LIB_SHIFT 24
#define ERR_FUNC_SHIFT 12
#define ERR_LIB_MASK 0xFFU
#define ERR_FUNC_MASK 0xFFFU
#define ERR_REASON_MASK 0xFFFU

/* Error code field extraction functions (reference OpenSSL) */
static inline int32_t ErrGetLib(uint64_t code)
{
    return (int32_t)(((code) >> ERR_LIB_SHIFT) & ERR_LIB_MASK);
}

static inline int32_t ErrGetFunc(uint64_t code)
{
    return (int32_t)(((code) >> ERR_FUNC_SHIFT) & ERR_FUNC_MASK);
}

static inline int32_t ErrGetReason(uint64_t code)
{
    return (int32_t)((code) & ERR_REASON_MASK);
}

/* errdecode command entry point */
int32_t HITLS_ErrdecodeMain(int32_t argc, char *argv[]);

#ifdef __cplusplus
}
#endif

#endif /* HITLS_APP_ERRDECODE_H */
