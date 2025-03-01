
static int32_t TestProvGetCaps(void *provCtx, int32_t cmd, CRYPT_EAL_ProcCapsCb cb, void *args)
{
    if (cb == NULL) {
        return CRYPT_SUCCESS;
    }

    // 返回测试用的group信息
    return cb(TEST_GROUP, TEST_GROUP_VALUE, args);
}

// 修改初始化函数，添加GetCaps回调
static int32_t TestProvInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param,
    CRYPT_EAL_Func *capFuncs, CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    // ... existing initialization code ...

    // 设置GetCaps回调
    mgrCtx->provGetCap = TestProvGetCaps;

    // ... rest of initialization code ...
    return CRYPT_SUCCESS;
}
