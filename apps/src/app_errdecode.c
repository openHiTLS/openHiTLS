#include "app_errdecode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "securec.h"
#include "app_errno.h"
#include "app_print.h"

/* Constant definitions */
#define HEX_PREFIX_LEN 2
#define HEX_BASE 16
#define DEC_BASE 10
#define ERROR_DATABASE_SIZE (sizeof(g_errorDatabase) / sizeof(ErrorEntry))

/* ========== Error Code Database ========== */

/*
 * Error code database
 * Contains common openHiTLS error codes and their descriptions
 */
static const ErrorEntry g_errorDatabase[] = {
    /* General error codes */
    {0x00000000, "none", "none", "success", "no error"},
    {0x00000001, "system", "generic", "generic error", "system:generic:generic error"},
    {0x00000002, "system", "parameter", "invalid parameter", "system:parameter:invalid parameter"},
    {0x00000003, "system", "memory", "allocation failed", "system:memory:allocation failed"},
    {0x00000004, "system", "buffer", "buffer too small", "system:buffer:buffer too small"},
    {0x00000005, "system", "operation", "not supported", "system:operation:not supported"},
    
    /* SSL/TLS error codes (0x0E prefix) */
    {0x0E000065, "SSL", "ssl3_get_record", "wrong version number",
        "SSL routines:ssl3_get_record:wrong version number"},
    {0x0E000066, "SSL", "ssl_handshake", "protocol version not supported",
        "SSL routines:ssl_handshake:protocol version not supported"},
    {0x0E000067, "SSL", "ssl3_read_bytes", "certificate verify failed",
        "SSL routines:ssl3_read_bytes:certificate verify failed"},
    {0x0E000068, "SSL", "ssl_verify_cert", "certificate expired",
        "SSL routines:ssl_verify_cert:certificate expired"},
    {0x0E000069, "SSL", "ssl_verify_cert", "certificate not yet valid",
        "SSL routines:ssl_verify_cert:certificate not yet valid"},
    {0x0E00006A, "SSL", "ssl_verify_cert", "certificate chain too long",
        "SSL routines:ssl_verify_cert:certificate chain too long"},
    {0x0E00006B, "SSL", "ssl_verify_cert", "certificate revoked",
        "SSL routines:ssl_verify_cert:certificate revoked"},
    {0x0E00006C, "SSL", "ssl_verify_cert", "certificate unknown",
        "SSL routines:ssl_verify_cert:certificate unknown"},
    {0x0E00006D, "SSL", "ssl_verify_cert", "bad certificate",
        "SSL routines:ssl_verify_cert:bad certificate"},
    {0x0E00006E, "SSL", "ssl_verify_cert", "unsupported certificate",
        "SSL routines:ssl_verify_cert:unsupported certificate"},
    {0x1408F10B, "SSL", "ssl3_get_record", "wrong version number",
        "SSL routines:ssl3_get_record:wrong version number"},
    {0x14094410, "SSL", "ssl3_read_bytes", "sslv3 alert handshake failure",
        "SSL routines:ssl3_read_bytes:sslv3 alert handshake failure"},
    
    /* Cryptography error codes (0x06 prefix) */
    {0x06000001, "CIPHER", "cipher_init", "initialization failed", "CIPHER routines:cipher_init:initialization failed"},
    {0x06000002, "CIPHER", "cipher_update", "update failed", "CIPHER routines:cipher_update:update failed"},
    {0x06000003, "CIPHER", "cipher_final", "finalization failed", "CIPHER routines:cipher_final:finalization failed"},
    {0x06000004, "CIPHER", "cipher_init", "invalid algorithm", "CIPHER routines:cipher_init:invalid algorithm"},
    {0x06000005, "CIPHER", "cipher_init", "invalid key length", "CIPHER routines:cipher_init:invalid key length"},
    {0x06000006, "CIPHER", "cipher_init", "invalid IV length", "CIPHER routines:cipher_init:invalid IV length"},
    
    /* Hash error codes (0x05 prefix) */
    {0x05000001, "MD", "md_init", "initialization failed", "MD routines:md_init:initialization failed"},
    {0x05000002, "MD", "md_update", "update failed", "MD routines:md_update:update failed"},
    {0x05000003, "MD", "md_final", "finalization failed", "MD routines:md_final:finalization failed"},
    {0x05000004, "MD", "md_init", "invalid algorithm", "MD routines:md_init:invalid algorithm"},
    
    /* Random number error codes (0x04 prefix) */
    {0x04000001, "RAND", "rand_bytes", "generation failed", "RAND routines:rand_bytes:generation failed"},
    {0x04000002, "RAND", "rand_seed", "insufficient entropy", "RAND routines:rand_seed:insufficient entropy"},
    {0x04000003, "RAND", "rand_seed", "seed failed", "RAND routines:rand_seed:seed failed"},
    
    /* ASN.1 error codes (0x0D prefix) */
    {0x0D000001, "ASN1", "asn1_encode", "encoding error", "ASN1 routines:asn1_encode:encoding error"},
    {0x0D000002, "ASN1", "asn1_decode", "decoding error", "ASN1 routines:asn1_decode:decoding error"},
    {0x0D000003, "ASN1", "asn1_parse", "invalid structure", "ASN1 routines:asn1_parse:invalid structure"},
    {0x0D000004, "ASN1", "asn1_encode", "buffer overflow", "ASN1 routines:asn1_encode:buffer overflow"},
    
    /* X.509 certificate error codes (0x0B prefix) */
    {0x0B000001, "X509", "x509_parse", "parsing failed",
        "X509 routines:x509_parse:parsing failed"},
    {0x0B000002, "X509", "x509_verify", "validation failed",
        "X509 routines:x509_verify:validation failed"},
    {0x0B000003, "X509", "x509_verify_chain", "chain validation failed",
        "X509 routines:x509_verify_chain:chain validation failed"},
    {0x0B000004, "X509", "x509_verify_sig", "signature verification failed",
        "X509 routines:x509_verify_sig:signature verification failed"},
    
    /* Key management error codes (0x07 prefix) */
    {0x07000001, "PKEY", "pkey_gen", "generation failed", "PKEY routines:pkey_gen:generation failed"},
    {0x07000002, "PKEY", "pkey_derive", "derivation failed", "PKEY routines:pkey_derive:derivation failed"},
    {0x07000003, "PKEY", "pkey_exchange", "exchange failed", "PKEY routines:pkey_exchange:exchange failed"},
    {0x07000004, "PKEY", "pkey_parse", "invalid format", "PKEY routines:pkey_parse:invalid format"},
    {0x07000005, "PKEY", "pkey_verify", "verification failed",
        "PKEY routines:pkey_verify:verification failed"}
};

/* ========== Error Code Database Module ========== */

/* Lookup error code in database */
static const ErrorEntry *LookupErrorCode(uint64_t code)
{
    for (size_t i = 0; i < ERROR_DATABASE_SIZE; i++) {
        if (g_errorDatabase[i].code == code) {
            return &g_errorDatabase[i];
        }
    }
    return NULL;
}

/* ========== Input Format Detection and Parsing Module ========== */

/* Detect error code format */
static ErrorCodeFormat DetectFormat(const char *input)
{
    if (input == NULL || *input == '\0') {
        return FORMAT_INVALID;
    }
    
    /* Check if hexadecimal (starts with 0x or 0X) */
    if (strncmp(input, "0x", HEX_PREFIX_LEN) == 0 || strncmp(input, "0X", HEX_PREFIX_LEN) == 0) {
        return FORMAT_HEX_WITH_PREFIX;
    }
    
    /* Check if all characters are hexadecimal (without prefix) */
    int32_t hasHexChar = 0;
    for (const char *p = input; *p != '\0'; p++) {
        if (!isxdigit((unsigned char)*p)) {
            return FORMAT_INVALID;
        }
        if ((*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
            hasHexChar = 1;
        }
    }
    
    /* Contains a-f characters, treat as hexadecimal */
    if (hasHexChar) {
        return FORMAT_HEX_WITHOUT_PREFIX;
    }
    
    /* Otherwise decimal */
    return FORMAT_DECIMAL;
}

/* Parse error code string */
static int32_t ParseErrorCode(const char *input, uint64_t *code)
{
    if (input == NULL || code == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    char *endptr;
    uint64_t result;
    
    /* Check if hexadecimal (starts with 0x or 0X) */
    if (strncmp(input, "0x", HEX_PREFIX_LEN) == 0 || strncmp(input, "0X", HEX_PREFIX_LEN) == 0) {
        result = strtoull(input, &endptr, HEX_BASE);
    } else {
        /* Auto-detect format */
        ErrorCodeFormat format = DetectFormat(input);
        if (format == FORMAT_HEX_WITHOUT_PREFIX) {
            result = strtoull(input, &endptr, HEX_BASE);
        } else if (format == FORMAT_DECIMAL) {
            result = strtoull(input, &endptr, DEC_BASE);
        } else {
            return HITLS_APP_INVALID_ARG;
        }
    }
    
    /* Check for invalid characters */
    if (*endptr != '\0') {
        return HITLS_APP_INVALID_ARG;
    }
    
    /* Check if empty or only prefix */
    if (endptr == input ||
        (strncmp(input, "0x", HEX_PREFIX_LEN) == 0 && endptr == input + HEX_PREFIX_LEN)) {
        return HITLS_APP_INVALID_ARG;
    }
    
    *code = result;
    return HITLS_APP_SUCCESS;
}

/* ========== Error Code Field Extraction Module ========== */

/* Get library name from library code */
static const char *GetLibraryName(int32_t libCode)
{
    switch (libCode) {
        case 0x00: return "none";
        case 0x04: return "RAND";
        case 0x05: return "MD";
        case 0x06: return "CIPHER";
        case 0x07: return "PKEY";
        case 0x0B: return "X509";
        case 0x0D: return "ASN1";
        case 0x0E: return "SSL";
        case 0x14: return "SSL";
        default: return "unknown";
    }
}

/* Get function name from function code */
static const char *GetFunctionName(int32_t funcCode)
{
    (void)funcCode;
    return "function";
}

/* Get reason string from reason code */
static const char *GetReasonString(int32_t reasonCode)
{
    (void)reasonCode;
    return "reason";
}

/* Extract error code fields */
static void ExtractErrorFields(uint64_t code, ErrorCodeFields *fields)
{
    if (fields == NULL) {
        return;
    }
    
    fields->fullCode = code;
    fields->library = ErrGetLib(code);
    fields->function = ErrGetFunc(code);
    fields->reason = ErrGetReason(code);
    
    /* Try to get detailed information from database */
    const ErrorEntry *entry = LookupErrorCode(code);
    if (entry != NULL) {
        fields->libName = entry->library;
        fields->funcName = entry->function;
        fields->reasonStr = entry->reason;
    } else {
        fields->libName = GetLibraryName(fields->library);
        fields->funcName = GetFunctionName(fields->function);
        fields->reasonStr = GetReasonString(fields->reason);
    }
}

/* ========== Output Formatting Module ========== */

/* Print basic error information */
static void PrintBasicError(uint64_t code, const ErrorEntry *entry)
{
    if (entry != NULL) {
        /* Format: error:error_code:library:function:reason */
        AppPrintError("error:%016llX:%s:%s:%s\n", (unsigned long long)code, entry->library, entry->function, entry->reason);
    } else {
        /* Unknown error code */
        AppPrintError("error:%016llX:unknown\n", (unsigned long long)code);
    }
}

/* Print verbose error information (verbose mode) */
static void PrintVerboseError(const ErrorCodeFields *fields)
{
    if (fields == NULL) {
        return;
    }
    
    AppPrintError("error code: 0x%016llX\n", (unsigned long long)fields->fullCode);
    AppPrintError("library   : %s (0x%02X)\n", fields->libName, fields->library);
    AppPrintError("function  : %s (0x%03X)\n", fields->funcName, fields->function);
    AppPrintError("reason    : %s (0x%03X)\n", fields->reasonStr, fields->reason);
}

/* ========== Command Line Argument Parsing Module ========== */

/* Print usage information */
static void PrintUsage(const char *programName)
{
    AppPrintError("Usage: %s errdecode [options] [error_code ...]\n", programName);
    AppPrintError("\n");
    AppPrintError("Convert error codes to human-readable strings.\n");
    AppPrintError("\n");
    AppPrintError("Options:\n");
    AppPrintError("  -h, -help       Show this help message\n");
    AppPrintError("  -v, --verbose   Show detailed error code fields\n");
    AppPrintError("  --stack         Show error stack (if supported)\n");
    AppPrintError("  -hex            Force hexadecimal parsing\n");
    AppPrintError("\n");
    AppPrintError("Arguments:\n");
    AppPrintError("  error_code      Error code in decimal or hexadecimal format\n");
    AppPrintError("                  Hexadecimal can be with (0x) or without prefix\n");
    AppPrintError("\n");
    AppPrintError("Examples:\n");
    AppPrintError("  %s errdecode 101\n", programName);
    AppPrintError("  %s errdecode 0x0E000065\n", programName);
    AppPrintError("  %s errdecode -v 0x1408F10B\n", programName);
    AppPrintError("  %s errdecode 101 0x0E000065 234567890\n", programName);
    AppPrintError("  echo \"0x1408F10B\" | %s errdecode\n", programName);
}

/* Parse command line arguments */
static int32_t ParseCommandLine(int32_t argc, char *argv[], CommandOptions *options)
{
    if (options == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    /* Initialize options */
    (void)memset_s(options, sizeof(CommandOptions), 0, sizeof(CommandOptions));
    
    int32_t argIndex = 1;
    
    /* Parse options */
    while (argIndex < argc && argv[argIndex][0] == '-') {
        if (strcmp(argv[argIndex], "-h") == 0 || strcmp(argv[argIndex], "-help") == 0) {
            options->helpMode = 1;
            return HITLS_APP_SUCCESS;
        } else if (strcmp(argv[argIndex], "-v") == 0 || strcmp(argv[argIndex], "--verbose") == 0) {
            options->verboseMode = 1;
        } else if (strcmp(argv[argIndex], "--stack") == 0) {
            options->stackMode = 1;
        } else if (strcmp(argv[argIndex], "-hex") == 0) {
            options->hexMode = 1;
        } else {
            AppPrintError("Error: unknown option: %s\n", argv[argIndex]);
            return HITLS_APP_INVALID_ARG;
        }
        argIndex++;
    }
    
    /* Collect error code arguments */
    if (argIndex < argc) {
        options->errorCodes = &argv[argIndex];
        options->numCodes = argc - argIndex;
    } else {
        /* No arguments, read from stdin */
        options->stdinMode = 1;
    }
    
    return HITLS_APP_SUCCESS;
}

/* ========== Batch Processing Module ========== */

/* Process single error code */
static int32_t ProcessSingleError(const char *errorCodeStr, const CommandOptions *options)
{
    uint64_t code;
    
    /* Parse error code */
    int32_t parseResult = ParseErrorCode(errorCodeStr, &code);
    if (parseResult != HITLS_APP_SUCCESS) {
        AppPrintError("Error: invalid error code format: %s\n", errorCodeStr);
        return HITLS_APP_INVALID_ARG;
    }
    
    /* Lookup error code */
    const ErrorEntry *entry = LookupErrorCode(code);
    
    /* Output based on mode */
    if (options->verboseMode) {
        ErrorCodeFields fields;
        ExtractErrorFields(code, &fields);
        PrintVerboseError(&fields);
    } else {
        PrintBasicError(code, entry);
    }
    
    return HITLS_APP_SUCCESS;
}

/* Batch process error codes from command line arguments */
static int32_t ProcessBatchFromArgs(char **codes, int32_t numCodes, const CommandOptions *options)
{
    int32_t hasError = 0;
    
    for (int32_t i = 0; i < numCodes; i++) {
        int32_t result = ProcessSingleError(codes[i], options);
        if (result != HITLS_APP_SUCCESS) {
            hasError = 1;
            /* Continue processing subsequent error codes */
        }
    }
    
    return hasError ? HITLS_APP_INVALID_ARG : HITLS_APP_SUCCESS;
}

/* Batch process error codes from stdin */
static int32_t ProcessBatchFromStdin(const CommandOptions *options)
{
    char line[1024];  /* Increased buffer size to handle longer inputs */
    int32_t hasError = 0;
    
    while (fgets(line, sizeof(line), stdin) != NULL) {
        /* Check if line was truncated (no newline and buffer is full) */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] != '\n' && len == sizeof(line) - 1) {
            AppPrintError("Error: input line too long (max %zu characters)\n", sizeof(line) - 1);
            /* Discard remaining characters in the line */
            int c;
            while ((c = getchar()) != '\n' && c != EOF) {
                /* Consume remaining characters */
            }
            hasError = 1;
            continue;
        }
        
        /* Remove newline character */
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        
        /* Skip empty lines */
        if (line[0] == '\0') {
            continue;
        }
        
        int32_t result = ProcessSingleError(line, options);
        if (result != HITLS_APP_SUCCESS) {
            hasError = 1;
            /* Continue processing subsequent lines */
        }
    }
    
    return hasError ? HITLS_APP_INVALID_ARG : HITLS_APP_SUCCESS;
}

/* ========== Error Stack Processing Module ========== */

/* Process error stack (simplified implementation, needs integration with openHiTLS error stack interface) */
static int32_t ProcessErrorStack(const CommandOptions *options)
{
    (void)options;
    
    AppPrintError("no errors in queue\n");
    return HITLS_APP_SUCCESS;
}

/* ========== Main Program Entry Point ========== */

/* errdecode command entry point */
int32_t HITLS_ErrdecodeMain(int32_t argc, char *argv[])
{
    CommandOptions options;
    
    /* Parse command line arguments */
    int32_t parseResult = ParseCommandLine(argc, argv, &options);
    if (parseResult != HITLS_APP_SUCCESS) {
        PrintUsage(argv[0]);
        return HITLS_APP_INVALID_ARG;
    }
    
    /* Show help information */
    if (options.helpMode) {
        PrintUsage(argv[0]);
        return HITLS_APP_SUCCESS;
    }
    
    /* Error stack mode */
    if (options.stackMode) {
        return ProcessErrorStack(&options);
    }
    
    /* Batch processing mode */
    if (options.stdinMode) {
        return ProcessBatchFromStdin(&options);
    } else if (options.numCodes > 0) {
        return ProcessBatchFromArgs(options.errorCodes, options.numCodes, &options);
    }
    
    /* No arguments, show help */
    PrintUsage(argv[0]);
    return HITLS_APP_SUCCESS;
}
