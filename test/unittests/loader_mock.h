/* IVMC: Ethereum Client-VM Connector API.
 * Copyright 2019 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 */

/**
 * @file
 * The loader OS mock for opening DLLs. To be inserted in loader.c for unit tests.
 */

static const int magic_handle = 0xE7AC;

const char* ivmc_test_library_path = NULL;
const char* ivmc_test_library_symbol = NULL;
ivmc_create_fn ivmc_test_create_fn = NULL;

static const char* ivmc_test_last_error_msg = NULL;

/* Limited variant of strcpy_s(). Exposed to unittests when building with IVMC_LOADER_MOCK. */
int strcpy_sx(char* dest, size_t destsz, const char* src);

static int ivmc_test_load_library(const char* filename)
{
    ivmc_test_last_error_msg = NULL;
    if (filename && ivmc_test_library_path && strcmp(filename, ivmc_test_library_path) == 0)
        return magic_handle;
    ivmc_test_last_error_msg = "cannot load library";
    return 0;
}

static void ivmc_test_free_library(int handle)
{
    (void)handle;
}

static ivmc_create_fn ivmc_test_get_symbol_address(int handle, const char* symbol)
{
    if (handle != magic_handle)
        return NULL;

    if (ivmc_test_library_symbol && strcmp(symbol, ivmc_test_library_symbol) == 0)
        return ivmc_test_create_fn;
    return NULL;
}

static const char* ivmc_test_get_last_error_msg()
{
    // Return the last error message only once.
    const char* m = ivmc_test_last_error_msg;
    ivmc_test_last_error_msg = NULL;
    return m;
}

#define DLL_HANDLE int
#define DLL_OPEN(filename) ivmc_test_load_library(filename)
#define DLL_CLOSE(handle) ivmc_test_free_library(handle)
#define DLL_GET_CREATE_FN(handle, name) ivmc_test_get_symbol_address(handle, name)
#define DLL_GET_ERROR_MSG() ivmc_test_get_last_error_msg()
