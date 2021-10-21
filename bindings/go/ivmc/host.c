/* IVMC: Ethereum Client-VM Connector API.
 * Copyright 2018-2019 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 */

#include "_cgo_export.h"

#include <stdlib.h>

/* Go does not support exporting functions with parameters with const modifiers,
 * so we have to cast function pointers to the function types defined in IVMC.
 * This disables any type checking of exported Go functions. To mitigate this
 * problem the go_exported_functions_type_checks() function simulates usage
 * of Go exported functions with expected types to check them during compilation.
 */
const struct ivmc_host_interface ivmc_go_host = {
    (ivmc_account_exists_fn)accountExists,
    (ivmc_get_storage_fn)getStorage,
    (ivmc_set_storage_fn)setStorage,
    (ivmc_get_balance_fn)getBalance,
    (ivmc_get_code_size_fn)getCodeSize,
    (ivmc_get_code_hash_fn)getCodeHash,
    (ivmc_copy_code_fn)copyCode,
    (ivmc_selfdestruct_fn)selfdestruct,
    (ivmc_call_fn)call,
    (ivmc_get_tx_context_fn)getTxContext,
    (ivmc_get_block_hash_fn)getBlockHash,
    (ivmc_emit_log_fn)emitLog,
    (ivmc_access_account_fn)accessAccount,
    (ivmc_access_storage_fn)accessStorage,
};


#pragma GCC diagnostic error "-Wconversion"
static inline void go_exported_functions_type_checks()
{
    struct ivmc_host_context* context = NULL;
    ivmc_address* address = NULL;
    ivmc_bytes32 bytes32;
    uint8_t* data = NULL;
    size_t size = 0;
    int64_t number = 0;
    struct ivmc_message* message = NULL;

    ivmc_uint256be uint256be;
    (void)uint256be;
    struct ivmc_tx_context tx_context;
    (void)tx_context;
    struct ivmc_result result;
    (void)result;
    enum ivmc_access_status access_status;
    (void)access_status;
    enum ivmc_storage_status storage_status;
    (void)storage_status;
    bool bool_flag;
    (void)bool_flag;

    ivmc_account_exists_fn account_exists_fn = NULL;
    bool_flag = account_exists_fn(context, address);
    bool_flag = accountExists(context, address);

    ivmc_get_storage_fn get_storage_fn = NULL;
    bytes32 = get_storage_fn(context, address, &bytes32);
    bytes32 = getStorage(context, address, &bytes32);

    ivmc_set_storage_fn set_storage_fn = NULL;
    storage_status = set_storage_fn(context, address, &bytes32, &bytes32);
    storage_status = setStorage(context, address, &bytes32, &bytes32);

    ivmc_get_balance_fn get_balance_fn = NULL;
    uint256be = get_balance_fn(context, address);
    uint256be = getBalance(context, address);

    ivmc_get_code_size_fn get_code_size_fn = NULL;
    size = get_code_size_fn(context, address);
    size = getCodeSize(context, address);

    ivmc_get_code_hash_fn get_code_hash_fn = NULL;
    bytes32 = get_code_hash_fn(context, address);
    bytes32 = getCodeHash(context, address);

    ivmc_copy_code_fn copy_code_fn = NULL;
    size = copy_code_fn(context, address, size, data, size);
    size = copyCode(context, address, size, data, size);

    ivmc_selfdestruct_fn selfdestruct_fn = NULL;
    selfdestruct_fn(context, address, address);
    selfdestruct(context, address, address);

    ivmc_call_fn call_fn = NULL;
    result = call_fn(context, message);
    result = call(context, message);

    ivmc_get_tx_context_fn get_tx_context_fn = NULL;
    tx_context = get_tx_context_fn(context);
    tx_context = getTxContext(context);

    ivmc_get_block_hash_fn get_block_hash_fn = NULL;
    bytes32 = get_block_hash_fn(context, number);
    bytes32 = getBlockHash(context, number);

    ivmc_emit_log_fn emit_log_fn = NULL;
    emit_log_fn(context, address, data, size, &bytes32, size);
    emitLog(context, address, data, size, &bytes32, size);

    ivmc_access_account_fn access_account_fn = NULL;
    access_status = access_account_fn(context, address);
    access_status = accessAccount(context, address);

    ivmc_access_storage_fn access_storage_fn = NULL;
    access_status = access_storage_fn(context, address, &bytes32);
    access_status = accessStorage(context, address, &bytes32);
}
