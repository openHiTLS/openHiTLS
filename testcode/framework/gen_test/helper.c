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

#include "helper.h"
#include <dirent.h>
#include "securec.h"
#include "crypt_utils.h"

#define INCLUDE_BASE "/* INCLUDE_BASE"
#define BEGIN_HEADER "/* BEGIN_HEADER */"
#define END_HEADER "/* END_HEADER */"
#define BEGIN_CASE "/* BEGIN_CASE */"
#define END_CASE "/* END_CASE */"

#define PRINT_TESTSUITES_TAG "</testsuites>\n"
#define PRINT_TESTSUITE_TAG "  </testsuite>\n"
#define PRINT_TESTCASE_TAG "    </testcase>\n"
#define PRINT_TESTCASE_LIST_TAG "    <testcase name=\"%s\" status=\"run\" time=\"0\" classname=\"%s\" />\n"
#define PRINT_FAILURE_TAG "      <failure message=\"failed\" type=\"\" />\n"

#define LINE_BREAK_SYMBOL '\n'
#define LINE_HEAD_SYMBOL '\r'

FunctionTable g_testFunc[MAX_TEST_FUCNTION_COUNT];
int g_testFuncCount = 0;
char g_expTable[MAX_EXPRESSION_COUNT][MAX_EXPRESSION_LEN];
int g_expCount = 0;
FILE *g_fpOutput = NULL;
int g_lineCount = 0;
char g_suiteFileName[MAX_FILE_PATH_LEN];

void SetOutputFile(FILE *fp)
{
    g_fpOutput = fp;
}

FILE *GetOutputFile(void)
{
    return g_fpOutput;
}

void FreeHex(Hex *data)
{
    if (data == NULL) {
        return;
    }
    data->len = 0;
    if (data->x != NULL) {
        free(data->x);
        data->x = NULL;
    }
}

Hex *NewHex(void)
{
    Hex *data = (Hex *)malloc(sizeof(Hex));
    if (data == NULL) {
        return NULL;
    }
    data->len = 0;
    data->x = NULL;
    return data;
}

int IsInt(const char *str)
{
    uint32_t i = 0;
    if (str[0] == '-') {
        i = 1;
    }
    for (; i < strlen(str); i++) {
        if (str[i] > '9' || str[i] < '0') {
            return 0;
        }
    }
    return 1;
}

void Print(const char *fmt, ...)
{
#ifdef PRINT_TO_TERMINAL
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
#else
    va_list args;
    va_start(args, fmt);
    (void)vfprintf(g_fpOutput, fmt, args);
    va_end(args);
#endif
}

int ReadLine(FILE *file, char *buf, uint32_t bufLen, bool skipHash, bool skipEmptyLine)
{
    int foundLine = 0;
    int i;
    char *ret = NULL;
    while (!foundLine) {
        ret = fgets(buf, bufLen, file);
        if (ret == NULL) {
            return -1;
        }
        g_lineCount++;

        int len = strlen(buf);
        if ((buf[0] == '#') && skipHash) {
            continue;
        }
        if (!skipEmptyLine) {
            foundLine = 1;
        }
        for (i = 0; i < len; i++) {
            char cur = buf[i];
            if (cur != ' ' && cur != LINE_BREAK_SYMBOL && cur != LINE_HEAD_SYMBOL) {
                foundLine = 1;
            }
            if (cur == LINE_BREAK_SYMBOL || cur == LINE_HEAD_SYMBOL) {
                buf[i] = '\0';
                break;
            }
        }
    }
    return 0;
}

int SplitArguments(char *inStr, uint32_t inLen, char **outParam, uint32_t *paramLen)
{
    uint32_t cur = 0;
    uint32_t count = 0;
    bool inString = false;
    char *in = inStr;
    char **param = outParam;

    param[count] = &in[cur];
    count++;
    cur++;
    if (count > *paramLen) {
        return 1;
    }
    while (cur < inLen && in[cur] != '\0') {
        if (in[cur] == '\"') {
            inString = !inString;
        }
        if (in[cur] == ':' && !inString) {
            if (cur == inLen - 1) {
                param[count] = &in[cur];
            } else {
                param[count] = &in[cur + 1];
                count++;
            }
            if (count > *paramLen) {
                printf("Exceed maximum param limit, expect num %u, actual num %u\n",
                    *paramLen, count);
                return 1;
            }
            in[cur] = '\0';
        }
        cur++;
    }
    if (in[cur - 1] == '\n') {
        in[cur - 1] = '\0';
    }

    *paramLen = count;
    if (inString) {
        return 1;
    }
    return 0;
}
static int g_fuzzEnd = 0;
int CheckTag(char *in, uint32_t len)
{
    char *cur = in;
    while (*cur == ' ') {
        cur++;
    }

    uint32_t beginHeaderLen = strlen(BEGIN_HEADER);
    uint32_t endHeaderLen = strlen(END_HEADER);
    uint32_t beginCaseLen = strlen(BEGIN_CASE);
    uint32_t endCaseLen = strlen(END_CASE);
    uint32_t includeBaseLen = strlen(INCLUDE_BASE);

    if ((len >= beginHeaderLen) && (strlen(cur) >= beginHeaderLen) &&
        (strncmp(cur, BEGIN_HEADER, beginHeaderLen) == 0)) {
        return TAG_BEGIN_HEADER;
    } else if ((len >= endHeaderLen) && (strlen(cur) >= endHeaderLen) &&
        (strncmp(cur, END_HEADER, endHeaderLen) == 0)) {
        return TAG_END_HEADER;
    } else if ((len >= beginCaseLen) && (strlen(cur) >= beginCaseLen) &&
        (strncmp(cur, BEGIN_CASE, beginCaseLen) == 0)) {
        return TAG_BEGIN_CASE;
    } else if ((len >= endCaseLen) && (strlen(cur) >= endCaseLen) &&
        (strncmp(cur, END_CASE, endCaseLen) == 0)) {
        return TAG_END_CASE;
    } else if ((len >= includeBaseLen) && (strlen(cur) >= includeBaseLen) &&
        (strncmp(cur, INCLUDE_BASE, includeBaseLen) == 0)) {
        return TAG_INCLUDE_BASE;
    }
    return TAG_NOT_TAG;
}

static int ClearVoid(const char *in, const uint32_t inLen, uint32_t *cur, uint32_t *prev)
{
    uint32_t localCur = *cur;
    uint32_t localPrev;
    while (localCur < inLen && in[localCur] == ' ') {
        localCur++;
    }
    localPrev = localCur;

    if (strncmp(&in[localCur], "void", strlen("void")) != 0) {
        return 1;
    }

    localCur += strlen("void");
    while (localCur < inLen && in[localCur] == ' ') {
        localCur++;
    }
    localPrev = localCur;

    *cur = localCur;
    *prev = localPrev;
    return 0;
}

static int NextArgument(const char *in, const uint32_t inLen, uint32_t *cur)
{
    uint32_t localCur = *cur;

    while (localCur < inLen && in[localCur] != ',' && in[localCur] != ')') {
        localCur++;
    }

    if (localCur >= inLen) {
        return 1;
    }

    *cur = localCur;
    return 0;
}

static int CheckType(const char *in, const uint32_t cur, const uint32_t prev, int *outType)
{
    int *type = outType;
    if ((cur - prev == strlen("int")) && (strncmp(&in[prev], "int", strlen("int")) == 0)) {
        *type = ARG_TYPE_INT;
    } else if ((cur - prev == strlen("Hex")) && (strncmp(&in[prev], "Hex", strlen("Hex")) == 0)) {
        *type = ARG_TYPE_HEX;
    } else if ((cur - prev == strlen("char")) && (strncmp(&in[prev], "char", strlen("char")) == 0)) {
        *type = ARG_TYPE_STR;
    } else {
        return 1;
    }

    return 0;
}

int ReadFunction(const char *in, const uint32_t inLen, char *outFuncName, uint32_t outLen, int argv[MAX_ARGUMENT_COUNT],
    uint32_t *argCount)
{
    uint32_t cur = 0;
    uint32_t prev = 0;
    char *funcName = outFuncName;

    if (ClearVoid(in, inLen, &cur, &prev) != 0) {
        return 1;
    }

    // get function name
    while (cur < inLen && in[cur] != '(') {
        cur++;
    }
    if (cur >= inLen) {
        return 1;
    }
    if (strncpy_s(funcName, outLen, &in[prev], cur - prev) != 0) {
        return 1;
    }
    funcName[cur - prev] = '\0';
    cur++;

    // get argument types
    uint32_t count = 0;
    while (cur < inLen) {
        while (cur < inLen && in[cur] == ' ') {
            cur++;
        }
        prev = cur;

        while (cur < inLen && in[cur] != ' ' && in[cur] != ',' && in[cur] != '*' && in[cur] != ')') {
            cur++;
        }

        if (in[cur] == ')') {
            break;
        }

        if (cur == inLen || in[cur] == ',') {
            return 1;
        }

        int type = -1;
        if (CheckType(in, cur, prev, &type) != 0) {
            Print("******\nERROR: check type failed at: \n");
            return 1;
        }
        argv[count] = type;

        count++;
        if (NextArgument(in, inLen, &cur) != 0) {
            return 1;
        }
        if (in[cur] == ')') {
            break;
        }
        cur++;
    }

    *argCount = count;

    return 0;
}

int AddFunction(const char *funcName, int argv[MAX_ARGUMENT_COUNT], const uint32_t argCount)
{
    if (g_testFuncCount >= MAX_TEST_FUCNTION_COUNT || argCount > MAX_ARGUMENT_COUNT) {
        return 1;
    }

    if (strcpy_s(g_testFunc[g_testFuncCount].name, MAX_TEST_FUNCTION_NAME, funcName) != 0) {
        return 1;
    }
    g_testFunc[g_testFuncCount].argCount = argCount;
    for (uint32_t i = 0; i < argCount; i++) {
        g_testFunc[g_testFuncCount].argType[i] = argv[i];
    }

    g_testFunc[g_testFuncCount].id = g_testFuncCount;
    g_testFuncCount++;

    return 0;
}

int GenFunctionWrapper(FILE *file, FunctionTable *function)
{
    int ret;
    ret = fprintf(file, "void %s_wrapper(void **param)\n", function->name);
    if (ret < 0) {
        return 1;
    }
    ret = fprintf(file, "{\n");
    if (ret < 0) {
        return 1;
    }
    ret = fprintf(file, "    (void)signal(SIGALRM, handleAlarmSignal);\n");
    if (ret < 0) {
        return 1;
    }
    ret = fprintf(file, "    alarm(600u);\n");
    if (ret < 0) {
        return 1;
    }
    if (function->argCount == 0) {
        ret = fprintf(file, "    (void) param;\n");
        if (ret < 0) {
            return 1;
        }
    }
    ret = fprintf(file, "    %s(", function->name);
    if (ret < 0) {
        return 1;
    }
    for (uint32_t i = 0; i < function->argCount; i++) {
        if (function->argType[i] == ARG_TYPE_INT) {
            ret = fprintf(file, "*((int*)param[%d])", (int)i);
            if (ret < 0) {
                return 1;
            }
        } else if (function->argType[i] == ARG_TYPE_STR) {
            ret = fprintf(file, "(char*)param[%d]", (int)i);
            if (ret < 0) {
                return 1;
            }
        } else if (function->argType[i] == ARG_TYPE_HEX) {
            ret = fprintf(file, "(Hex*)param[%d]", (int)i);
            if (ret < 0) {
                return 1;
            }
        }
        if (i != function->argCount - 1) {
            ret = fprintf(file, ", ");
            if (ret < 0) {
                return 1;
            }
        }
    }
    ret = fprintf(file, ");\n}\n\n");
    if (ret < 0) {
        return 1;
    }
    return 0;
}

int GenFunctionPointer(FILE *file)
{
    if (file == NULL) {
        return 1;
    }
    int ret;
    ret = fprintf(file, "%s\n\n", "typedef void (*TestWrapper)(void **param);");
    if (ret < 0) {
        return 1;
    }
    ret = fprintf(file, "%s\n%s\n", "TestWrapper test_funcs[] = ", "{");
    if (ret < 0) {
        return 1;
    }
    for (int i = 0; i < g_testFuncCount; i++) {
        ret = fprintf(file, "    %s_wrapper, \n", g_testFunc[i].name);
        if (ret < 0) {
            return 1;
        }
    }
    ret = fprintf(file, "%s\n", "};");
    if (ret < 0) {
        return 1;
    }
    return 0;
}

static int ConnectFunction(char *lineBuf, uint32_t bufLen, FILE *fp)
{
    char buf[MAX_FUNCTION_LINE_LEN];
    bool reachEnd = false;
    int ret = 0;
    while (!reachEnd) {
        for (int i = 0; lineBuf[i] != '\0'; i++) {
            if (lineBuf[i] == ')') {
                ret = 0;
                reachEnd = true;
            }
            if (lineBuf[i] == '{') {
                ret = 1;
                reachEnd = true;
            }
        }
        if (reachEnd) {
            break;
        }
        if (ReadLine(fp, buf, MAX_FUNCTION_LINE_LEN, 0, 0) == 0) {
            if (strcat_s(lineBuf, bufLen, buf) != 0) {
                return 1;
            }
        } else {
            return 1;
        }
    }
    return ret;
}

int ScanAllFunction(FILE *inFile, FILE *outFile)
{
    char buf[MAX_FUNCTION_LINE_LEN];
    int ret = 0;
    uint32_t len = MAX_ARGUMENT_COUNT;
    bool inFunction = false;
    bool isDeclaration = true;
    int arguments[MAX_ARGUMENT_COUNT];
    char funcName[MAX_TEST_FUNCTION_NAME];
    while (ReadLine(inFile, buf, MAX_FUNCTION_LINE_LEN, 0, 0) == 0) {
        int curTag = CheckTag(buf, strlen(buf));
        if (curTag == TAG_NOT_TAG) {
            if (!inFunction) {
                fprintf(outFile, "%s\n", buf);
                continue;
            }
        } else if (curTag == TAG_BEGIN_CASE) {
            if (!inFunction) {
                inFunction = true;
                isDeclaration = true;
                continue;
            }
            Print("ERROR: missing end case tag\n");
            return 1;
        } else if (curTag == TAG_END_CASE) {
            if (inFunction) {
                inFunction = false;
                fprintf(outFile, "\n");
                continue;
            }
            return 1;
        } else {
            return 1;
        }

        if (isDeclaration) {
            if (ConnectFunction(buf, sizeof(buf), inFile) != 0) {
                Print("******\nERROR: connect function failed at: \n");
                Print("%s\n", buf);
                return 1;
            }
            ret = ReadFunction(buf, strlen(buf), funcName, sizeof(funcName), arguments, &len);
            if (ret != 0) {
                Print("*******\nERROR: Read function failed at: \n");
                Print("%s\n", buf);
                return ret;
            }
            ret = AddFunction(funcName, arguments, len);
            if (ret != 0) {
                return ret;
            }
            isDeclaration = false;
            len = MAX_ARGUMENT_COUNT;
        }

        (void)fprintf(outFile, "%s\n", buf);
    }

    return 0;
}

static int IncludeBase(char *line, uint32_t len, FILE *outFile, const char *dir)
{
    if (len < strlen(INCLUDE_BASE)) {
        return 1;
    }

    char *name = &line[strlen(INCLUDE_BASE)];
    while (*name == ' ') {
        name++;
    }

    if (*name == '\0') {
        return 1;
    }

    char *end = name;

    while (*end != ' ') {
        end++;
    }
    *end = '\0';

    char fileBuf[MAX_FILE_PATH_LEN];
    if (snprintf_s(fileBuf, MAX_FILE_PATH_LEN, MAX_FILE_PATH_LEN, BASE_FILE_FORMAT, dir, name) == -1) {
        return 1;
    }
    g_lineCount = 0;
    FILE *fpBase = fopen(fileBuf, "r");
    if (fpBase == NULL) {
        Print("ERROR:Open the base file. %s An error occurred when\n", fileBuf);
        return 1;
    }

    int ret;
    char buf[MAX_FUNCTION_LINE_LEN];
    while (ReadLine(fpBase, buf, MAX_FUNCTION_LINE_LEN, 0, 0) == 0) {
        ret = fprintf(outFile, "%s\n", buf);
        if (ret < 0) {
            goto EXIT;
        }
    }

EXIT:
    if (fclose(fpBase) != 0) {
        Print("base file close failed\n");
    }
    return 0;
}

int WriteHeader(FILE *outFile)
{
    if (fprintf(outFile, "#include \"helper.h\"\n#include \"test.h\"\n#include <time.h>\n#include <unistd.h>\n") < 0) {
        return 1;
    }
    return 0;
}

int ScanHeader(FILE *inFile, FILE *outFile, const char *dir)
{
    char buf[MAX_FUNCTION_LINE_LEN];
    bool inHeader = false;

    while (ReadLine(inFile, buf, MAX_FUNCTION_LINE_LEN, 0, !inHeader) == 0) {
        int curTag = CheckTag(buf, strlen(buf));
        if (curTag == TAG_BEGIN_HEADER) {
            if (!inHeader) {
                inHeader = true;
            } else {
                Print("******\nERROR: duplicate begin header tag\n");
                return 1;
            }
        } else if (curTag == TAG_END_HEADER) {
            if (inHeader) {
                (void)fprintf(outFile, "%s\n", buf);
                return 0;
            } else {
                Print("******\nERROR: found end header without begin\n");
                return 1;
            }
        } else if (curTag == TAG_INCLUDE_BASE) {
            int tmpLineCount = g_lineCount;
            if (IncludeBase(buf, strlen(buf), outFile, dir) != 0) {
                Print("******\nERROR: include base file failed\n");
                return 1;
            }
            g_lineCount = tmpLineCount;
            continue;
        } else if (curTag != TAG_NOT_TAG) {
            Print("******\nERROR: missing end header tag\n");
            return 1;
        }
        (void)fprintf(outFile, "%s\n", buf);
    }
    return 0;
}

static int AddExp(const char *exp)
{
    if (g_expCount >= MAX_EXPRESSION_COUNT) {
        Print("Too much macros. Max macro count is %d\n", MAX_EXPRESSION_COUNT);
        return -1;
    }
    for (int i = 0; i < g_expCount; i++) {
        if (strcmp(exp, g_expTable[i]) == 0) {
            return i;
        }
    }
    if (strcpy_s(g_expTable[g_expCount], MAX_EXPRESSION_LEN, exp) != 0) {
        Print("Macro too long, max length is %d\n", MAX_EXPRESSION_LEN);
        return -1;
    }
    g_expCount++;
    return g_expCount - 1;
}

static int GetFuncIdByName(const char *name, uint32_t len)
{
    int funcId = -1;
    for (int i = 0; i < g_testFuncCount; i++) {
        if ((len < MAX_TEST_FUNCTION_NAME) && (strcmp(name, g_testFunc[i].name) == 0)) {
            funcId = i;
            break;
        }
    }

    return funcId;
}

int GenDatax(FILE *inFile, FILE *outFile)
{
    char buf[MAX_DATA_LINE_LEN];
    char title[MAX_DATA_LINE_LEN];
    int ret;
    int funcId = -1;
    char *param[MAX_ARGUMENT_COUNT];
    uint32_t paramLen = MAX_ARGUMENT_COUNT;
    while (ReadLine(inFile, title, MAX_DATA_LINE_LEN, 1, 1) == 0) {
        ret = fprintf(outFile, "%s\n", title);
        if (ret < 0) {
            return 1;
        }

        if ((ReadLine(inFile, buf, MAX_DATA_LINE_LEN, 1, 1) != 0)) {
            return 1;
        }
        paramLen = MAX_ARGUMENT_COUNT;
        ret = SplitArguments(buf, strlen(buf), param, &paramLen);
        if (ret != 0) {
            Print("******\nERROR: Generate datax failed: split argument failed at testcase:\n");
            Print("%s\n", title);
            return ret;
        }

        funcId = GetFuncIdByName(param[0], strlen(param[0]));
        if (funcId == -1) {
            Print("******\nERROR: Generate datax failed: no function id for %s at testcase:\n", param[0]);
            Print("%s\n", title);
            return 1;
        }

        if (paramLen != g_testFunc[funcId].argCount + 1) {
            Print("******\nERROR: Generate datax failed: invalid argument count for function %s at testcase:\n",
                param[0]);
            Print("%s\n", title);
            return 1;
        }

        ret = fprintf(outFile, "%d:", funcId);
        if (ret < 0) {
            return 1;
        }
        int expId = 0;
        for (uint32_t i = 0; i < g_testFunc[funcId].argCount; i++) {
            if (g_testFunc[funcId].argType[i] == ARG_TYPE_INT && (IsInt(param[i + 1]) == 1)) {
                ret = fprintf(outFile, "int:%s", param[i + 1]);
            } else if (g_testFunc[funcId].argType[i] == ARG_TYPE_INT && (!IsInt(param[i + 1]))) {
                expId = AddExp(param[i + 1]);
                ret = fprintf(outFile, "exp:%d", expId);
            } else if (g_testFunc[funcId].argType[i] == ARG_TYPE_STR) {
                ret = fprintf(outFile, "char:%s", param[i + 1]);
            } else if (g_testFunc[funcId].argType[i] == ARG_TYPE_HEX) {
                ret = fprintf(outFile, "Hex:%s", param[i + 1]);
            } else {
                Print("invalid argument type\n");
                return 1;
            }
            if (ret < 0) {
                return 1;
            }
            if (i != g_testFunc[funcId].argCount - 1) {
                ret = fprintf(outFile, ":");
            }
            if (expId == -1) {
                return 1;
            }
            expId = 0;
        }
        ret = fprintf(outFile, "\n\n");
        if (ret < 0) {
            return 1;
        }
    }

    return 0;
}

int GenExpTable(FILE *outFile)
{
    int ret;
    ret = fprintf(outFile, "int getExpression(int expId, int *out)\n{\n");
    if (ret < 0) {
        return 1;
    }
    if (g_expCount == 0) {
        ret = fprintf(outFile, "    (void) out;\n    (void) expId;\n");
        if (ret < 0) {
            return 1;
        }
    }
    ret = fprintf(outFile, "    int ret = 0;\n");
    if (ret < 0) {
        return 1;
    }
    ret = fprintf(outFile, "    switch (expId)\n    {\n");
    if (ret < 0) {
        return 1;
    }

    for (int i = 0; i < g_expCount; i++) {
        ret = fprintf(outFile, "        case %d:\n", i);
        if (ret < 0) {
            return 1;
        }
        ret = fprintf(outFile, "            *out = %s;\n", g_expTable[i]);
        if (ret < 0) {
            return 1;
        }
        ret = fprintf(outFile, "            break;\n");
        if (ret < 0) {
            return 1;
        }
    }

    ret = fprintf(outFile, "        default:\n");
    if (ret < 0) {
        return 1;
    }
    ret = fprintf(outFile, "            ret = 1;\n");
    if (ret < 0) {
        return 1;
    }
    ret = fprintf(outFile, "            break;\n");
    if (ret < 0) {
        return 1;
    }
    ret = fprintf(outFile, "    }\n    return ret;\n}\n");
    if (ret < 0) {
        return 1;
    }

    return 0;
}

int LoadFunctionName(FILE *outFile)
{
    int ret;
    ret = fprintf(outFile, "const char * funcName[] = {\n");
    if (ret < 0) {
        return 1;
    }
    for (int i = 0; i < g_testFuncCount; i++) {
        ret = fprintf(outFile, "    \"%s\",\n", g_testFunc[i].name);
        if (ret < 0) {
            return 1;
        }
    }
    ret = fprintf(outFile, "};\n\n");
    if (ret < 0) {
        return 1;
    }
    return 0;
}

int LoadHelper(FILE *inFile, FILE *outFile)
{
    int ret;
    char buf[MAX_FUNCTION_LINE_LEN];
    if (inFile == NULL || outFile == NULL) {
        return 1;
    }
    while (fgets(buf, MAX_FUNCTION_LINE_LEN, inFile) != NULL) {
        ret = fprintf(outFile, "%s", buf);
        if (ret < 0) {
            return 1;
        }
    }
    (void)fprintf(outFile, "\n\n");
    return 0;
}

int SplitHex(Hex *src, Hex *dest, int max)
{
    uint32_t blocks = src->len / SPILT_HEX_BLOCK_SIZE;
    uint32_t remain = src->len % SPILT_HEX_BLOCK_SIZE;
    uint32_t i;
    if (blocks + 1 > (uint32_t)max) {
        return 0;
    }
    for (i = 0; i < blocks; i++) {
        dest[i].x = src->x + i * SPILT_HEX_BLOCK_SIZE;
        dest[i].len = SPILT_HEX_BLOCK_SIZE;
    }

    if (remain == 0) {
        return blocks;
    } else {
        dest[i].x = src->x + i * SPILT_HEX_BLOCK_SIZE;
        dest[i].len = remain;
        return blocks + 1;
    }
}


int SplitHexRand(Hex *src, Hex *dest, int max)
{
    uint32_t left = src->len;
    int id = 0;

    if (left <= 3) {
        dest[id].x = src->x;
        dest[id].len = left;
        id++;
        return id;
    }

    while (left > 3) {
        dest[id].x = src->x + (src->len - left);
        uint16_t clen = GET_UINT16_LE(dest[id].x, 0);
        dest[id].len = clen > left ? left : clen;
        left -= dest[id].len;
        id++;
        if (id > max - 1) {
            break;
        }
    }

    if (left > 0) {
        dest[id - 1].len += left;
    }

    return id;
}

FILE *OpenFile(const char *name, const char *option, const char *format)
{
    FILE *fp = NULL;
    char fileBuf[MAX_FILE_PATH_LEN];
    if (snprintf_s(fileBuf, MAX_FILE_PATH_LEN, MAX_FILE_PATH_LEN, format, name) == -1) {
        Print("argument too long\n");
        return NULL;
    }
    fp = fopen(fileBuf, option);
    return fp;
}

int StripDir(const char *in, char *suiteName, const uint32_t suiteNameLen, char *dir, const uint32_t dirNameLen)
{
    int len = strlen(in);
    int begin = len - 1;

    char *localDir = dir;
    char *localSuiteName = suiteName;
    while (begin >= 0 && in[begin] != '/') {
        begin--;
    }

    if (begin < 0) {
        return 1;
    }

    if (strncpy_s(localDir, dirNameLen, in, begin) != 0) {
        return 1;
    }

    if (strcpy_s(localSuiteName, suiteNameLen, &in[begin + 1]) != 0) {
        return 1;
    }

    if (strcpy_s(g_suiteFileName, MAX_FILE_PATH_LEN, &in[begin + 1]) != 0) {
        return 1;
    }

    return 0;
}

int ScanFunctionFile(FILE *fpIn, FILE *fpOut, const char *dir)
{
    int ret;
    ret = ScanHeader(fpIn, fpOut, dir);
    if (ret != 0) {
        Print("scan header failed\n");
        return 1;
    }

    ret = ScanAllFunction(fpIn, fpOut);
    if (ret != 0) {
        Print("scan function failed\n");
        return 1;
    }
    if (fprintf(fpOut, "\n void handleAlarmSignal(int signum)\n{\n\
    (void)signum; \n\
    fprintf(stderr, \"timeout 600\\n\");\n\
    exit(-1);\n}\n") < 0) {
        return 1;
    }

    for (int i = 0; i < g_testFuncCount; i++) {
        ret = GenFunctionWrapper(fpOut, &g_testFunc[i]);
        if (ret < 0) {
            Print("generate function wrapper failed\n");
            return 1;
        }
    }
    if (g_fuzzEnd == 1) {
        ret = fprintf(fpOut, "#define FREE_FUZZ_TC 1\n\n");
    } else {
        ret = fprintf(fpOut, "#define FREE_FUZZ_TC 0\n\n");
    }
    if (ret < 0) {
        return 1;
    }
    return 0;
}

static bool IsSuite(char *buf, uint32_t bufLen)
{
    uint32_t beginTagLen = strlen("Begin time:");
    uint32_t endTagLen = strlen("End time:");
    uint32_t resultTagLen = strlen("Result:");
    uint32_t atTagLen = strlen("at:");

    if (bufLen >= beginTagLen && strncmp(buf, "Begin time:", beginTagLen) == 0) {
        return false;
    } else if (bufLen >= endTagLen && strncmp(buf, "End time:", endTagLen) == 0) {
        return false;
    } else if (bufLen >= resultTagLen && strncmp(buf, "Result:", resultTagLen) == 0) {
        return false;
    } else if (bufLen >= atTagLen && strncmp(buf, "at:", atTagLen) == 0) {
        return false;
    }

    return true;
}

static int ReadAllLogFile(DIR *logDir, int *totalSuiteCount, FILE *outFile, TestSuiteResult *result, int resultLen)
{
    struct dirent *dir = NULL;
    int suiteCount = 0;
    int cur;
    DIR *localLogDir = logDir;

    // Stores the execution results of all test cases.
    FILE *fpAllLog = OpenFile("result.log", "w+", "%s");
    if (fpAllLog == NULL) {
        return 1;
    }
    FILE *fpLog = NULL;

    while ((dir = readdir(localLogDir)) != NULL) {
        char buf[MAX_LOG_LEN];
        uint32_t bufLen = sizeof(buf);
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) {
            continue;
        }
        // len of ".log" is 4
        if (strlen(dir->d_name) <= 4 || strlen(dir->d_name) > MAX_FILE_PATH_LEN - 1) {
            (void)fclose(fpAllLog);
            return 1;
        }
        fpLog = OpenFile(dir->d_name, "r", LOG_FILE_FORMAT);
        if (fpLog == NULL) {
            (void)fclose(fpAllLog);
            return 1;
        }
        if (suiteCount >= resultLen) {
            Print("Reached maximum suite count\n");
            (void)fclose(fpLog);
            (void)fclose(fpAllLog);
            return 1;
        }

        if (strcpy_s(result[suiteCount].name, MAX_TEST_FUNCTION_NAME - 1, dir->d_name) != EOK) {
            Print("Dir's Name is too long\n");
            (void)fclose(fpLog);
            (void)fclose(fpAllLog);
            return 1;
        }
        // len of ".log" is 4
        result[suiteCount].name[strlen(dir->d_name) - 4] = '\0';
        result[suiteCount].total = 0;
        result[suiteCount].pass = 0;
        result[suiteCount].skip = 0;
        result[suiteCount].line = 0;

        while (ReadLine(fpLog, buf, bufLen, 0, 0) == 0) {
            char testCaseName[MAX_TEST_FUNCTION_NAME];
            memset_s(testCaseName, MAX_TEST_FUNCTION_NAME, 0, MAX_TEST_FUNCTION_NAME);
            if (!IsSuite(buf, strlen(buf))) {
                continue;
            }
            result[suiteCount].total++;
            // Find the end of the string to start backward search
            size_t lineLen = strlen(buf);
            int end = (int)lineLen - 1;
            // Trim trailing whitespace/newlines to ensure we start at the status text
            while (end >= 0 && (buf[end] == '\r' || buf[end] == '\n' || buf[end] == ' ')) {
                end--;
            }
            // Search backwards for the "." separator
            int dotPos = -1;
            for (int i = end; i >= 1; i--) {
                // Look for the last occurrence of "."
                if (buf[i] == '.' && buf[i - 1] != '.') {
                    dotPos = i; // Pointing to the second dot
                    break;
                }
            }
            if (dotPos == -1) {
                Print("Read log file %s failed\n", dir->d_name);
                (void)fclose(fpLog);
                (void)fclose(fpAllLog);
                return 1;
            }
            int nameLen = dotPos - 1;
            if (nameLen >= MAX_TEST_FUNCTION_NAME || nameLen < 0) {
                Print("TestCaseName is too long\n");
                (void)fclose(fpLog);
                (void)fclose(fpAllLog);
                return 1;
            }

            if (strncpy_s(testCaseName, sizeof(testCaseName), buf, nameLen) != EOK) {
                (void)fclose(fpLog);
                (void)fclose(fpAllLog);
                return 1;
            }
            testCaseName[nameLen] = '\0';
            // Move pointer past the dots to find the status string
            cur = dotPos;
            while (buf[cur] == '.') {
                cur++;
            }

            if (strncmp(&buf[cur], "pass", strlen("pass")) == 0) {
                result[suiteCount].pass++;
                result[suiteCount].line++;
                (void)fprintf(outFile, PRINT_TESTCASE_LIST_TAG, testCaseName, result[suiteCount].name);
                (void)fprintf(fpAllLog, "%s    %s\n", testCaseName, "PASS");
            } else if (strncmp(&buf[cur], "skip", strlen("skip")) == 0) {
                result[suiteCount].skip++;
                result[suiteCount].line++;
                (void)fprintf(outFile, PRINT_TESTCASE_LIST_TAG, testCaseName, result[suiteCount].name);
                (void)fprintf(fpAllLog, "%s    %s\n", testCaseName, "SKIP");
            } else {
                result[suiteCount].line += 3; // Incorrect test case requires 3 lines
                (void)fprintf(outFile, PRINT_TESTCASE_LIST_TAG, testCaseName, result[suiteCount].name);
                (void)fprintf(fpAllLog, "%s    %s\n", testCaseName, "FAIL");
                (void)fprintf(outFile, PRINT_FAILURE_TAG);
                (void)fprintf(outFile, PRINT_TESTCASE_TAG);
            }
        }
        suiteCount++;
        cur = 0;
        (void)fclose(fpLog);
    }
    *totalSuiteCount = suiteCount;
    (void)fclose(fpAllLog);
    return 0;
}

static int GenResultFile(FILE *in, FILE *out, TestSuiteResult result[MAX_SUITE_COUNT], int testSuiteCount)
{
    int totalTests = 0;
    int totalPass = 0;
    int totalSkip = 0;

    if (testSuiteCount >= MAX_SUITE_COUNT) {
        Print("suites count too great\n");
        return 1;
    }

    for (int i = 0; i < testSuiteCount; i++) {
        totalTests += result[i].total;
        totalPass += result[i].pass;
        totalSkip += result[i].skip;
    }
    (void)fprintf(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    (void)fprintf(out, "<testsuites tests=\"%d\" failures=\"%d\" disabled=\"%d\" errors=\"0\" ", totalTests,
        totalTests - totalPass - totalSkip, totalSkip);
    (void)fprintf(out, "timestamp=\"0000-00-00T00:00:00\" time=\"0\" name=\"AllTests\">\n");

    for (int i = 0; i < testSuiteCount; i++) {
        (void)fprintf(out,
            "  <testsuite name=\"%s\" tests=\"%d\" skips = \"%d\" failures=\"%d\" ",
            result[i].name, result[i].total, result[i].skip,
            result[i].total - result[i].pass - result[i].skip);
        (void)fprintf(out, "disabled=\"0\" errors=\"0\" time=\"0\">\n");

        for (int j = 0; j < result[i].line; j++) {
            char buf[MAX_LOG_LEN];
            if (fgets(buf, sizeof(buf), in) != NULL) {
                (void)fputs(buf, out);
            } else {
                return 1;
            }
        }
        (void)fprintf(out, PRINT_TESTSUITE_TAG);
    }
    (void)fprintf(out, PRINT_TESTSUITES_TAG);
    return 0;
}

int GenResult(void)
{
    int ret;
    TestSuiteResult result[MAX_SUITE_COUNT];
    int testSuiteCount = 0;
    DIR *logDir = NULL;
    logDir = opendir(LOG_FILE_DIR);
    if (logDir == NULL) {
        Print("fail to open log directory\n");
        return 1;
    }

    FILE *fpTmp = NULL;
    fpTmp = fopen("tmp.txt", "w+");
    if (fpTmp == NULL) {
        Print("open tmp.txt failed\n");
        (void)closedir(logDir);
        return 1;
    }

    FILE *fpResult = NULL;
    fpResult = fopen("result.xml", "w");
    if (fpResult == NULL) {
        Print("open result.xml failed\n");
        (void)closedir(logDir);
        (void)fclose(fpTmp);
        (void)remove("tmp.txt");
        return 1;
    }

    ret = ReadAllLogFile(logDir, &testSuiteCount, fpTmp, result, sizeof(result));
    if (ret != 0) {
        Print("read log failed\n");
        goto EXIT;
    }

    rewind(fpTmp);
    ret = GenResultFile(fpTmp, fpResult, result, testSuiteCount);
    if (ret != 0) {
        Print("gen result failed\n");
        goto EXIT;
    }

EXIT:
    (void)closedir(logDir);
    (void)fclose(fpTmp);
    (void)fclose(fpResult);
    (void)remove("tmp.txt");
    return ret;
}
