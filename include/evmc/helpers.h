/* IVMC: Ethereum Client-VM Connector API.
 * Copyright 2018-2019 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 */

/**
 * IVMC Helpers
 *
 * A collection of C helper functions for invoking a VM instance methods.
 * These are convenient for languages where invoking function pointers
 * is "ugly" or impossible (such as Go).
 *
 * It also contains helpers (overloaded operators) for using IVMC types effectively in C++.
 *
 * @defgroup helpers IVMC Helpers
 * @{
 */
#pragma once

#include <ivmc/ivmc.h>
#include <stdlib.h>
#include <string.h>

/**
 * Returns true if the VM has a compatible ABI version.
 */
static inline bool ivmc_is_abi_compatible(struct ivmc_vm* vm)
{
    return vm->abi_version == IVMC_ABI_VERSION;
}

/**
 * Returns the name of the VM.
 */
static inline const char* ivmc_vm_name(struct ivmc_vm* vm)
{
    return vm->name;
}

/**
 * Returns the version of the VM.
 */
static inline const char* ivmc_vm_version(struct ivmc_vm* vm)
{
    return vm->version;
}

/**
 * Checks if the VM has the given capability.
 *
 * @see ivmc_get_capabilities_fn
 */
static inline bool ivmc_vm_has_capability(struct ivmc_vm* vm, enum ivmc_capabilities capability)
{
    return (vm->get_capabilities(vm) & (ivmc_capabilities_flagset)capability) != 0;
}

/**
 * Destroys the VM instance.
 *
 * @see ivmc_destroy_fn
 */
static inline void ivmc_destroy(struct ivmc_vm* vm)
{
    vm->destroy(vm);
}

/**
 * Sets the option for the VM, if the feature is supported by the VM.
 *
 * @see ivmc_set_option_fn
 */
static inline enum ivmc_set_option_result ivmc_set_option(struct ivmc_vm* vm,
                                                          char const* name,
                                                          char const* value)
{
    if (vm->set_option)
        return vm->set_option(vm, name, value);
    return IVMC_SET_OPTION_INVALID_NAME;
}

/**
 * Executes code in the VM instance.
 *
 * @see ivmc_execute_fn.
 */
static inline struct ivmc_result ivmc_execute(struct ivmc_vm* vm,
                                              const struct ivmc_host_interface* host,
                                              struct ivmc_host_context* context,
                                              enum ivmc_revision rev,
                                              const struct ivmc_message* msg,
                                              uint8_t const* code,
                                              size_t code_size)
{
    return vm->execute(vm, host, context, rev, msg, code, code_size);
}

/// The ivmc_result release function using free() for releasing the memory.
///
/// This function is used in the ivmc_make_result(),
/// but may be also used in other case if convenient.
///
/// @param result The result object.
static void ivmc_free_result_memory(const struct ivmc_result* result)
{
    free((uint8_t*)result->output_data);
}

/// Creates the result from the provided arguments.
///
/// The provided output is copied to memory allocated with malloc()
/// and the ivmc_result::release function is set to one invoking free().
///
/// In case of memory allocation failure, the result has all fields zeroed
/// and only ivmc_result::status_code is set to ::IVMC_OUT_OF_MEMORY internal error.
///
/// @param status_code  The status code.
/// @param gas_left     The amount of gas left.
/// @param output_data  The pointer to the output.
/// @param output_size  The output size.
static inline struct ivmc_result ivmc_make_result(enum ivmc_status_code status_code,
                                                  int64_t gas_left,
                                                  const uint8_t* output_data,
                                                  size_t output_size)
{
    struct ivmc_result result;
    memset(&result, 0, sizeof(result));

    if (output_size != 0)
    {
        uint8_t* buffer = (uint8_t*)malloc(output_size);

        if (!buffer)
        {
            result.status_code = IVMC_OUT_OF_MEMORY;
            return result;
        }

        memcpy(buffer, output_data, output_size);
        result.output_data = buffer;
        result.output_size = output_size;
        result.release = ivmc_free_result_memory;
    }

    result.status_code = status_code;
    result.gas_left = gas_left;
    return result;
}

/**
 * Releases the resources allocated to the execution result.
 *
 * @param result  The result object to be released. MUST NOT be NULL.
 *
 * @see ivmc_result::release() ivmc_release_result_fn
 */
static inline void ivmc_release_result(struct ivmc_result* result)
{
    if (result->release)
        result->release(result);
}


/**
 * Helpers for optional storage of ivmc_result.
 *
 * In some contexts (i.e. ivmc_result::create_address is unused) objects of
 * type ivmc_result contains a memory storage that MAY be used by the object
 * owner. This group defines helper types and functions for accessing
 * the optional storage.
 *
 * @defgroup result_optional_storage Result Optional Storage
 * @{
 */

/**
 * The union representing ivmc_result "optional storage".
 *
 * The ivmc_result struct contains 24 bytes of optional storage that can be
 * reused by the object creator if the object does not contain
 * ivmc_result::create_address.
 *
 * A VM implementation MAY use this memory to keep additional data
 * when returning result from ivmc_execute_fn().
 * The host application MAY use this memory to keep additional data
 * when returning result of performed calls from ivmc_call_fn().
 *
 * @see ivmc_get_optional_storage(), ivmc_get_const_optional_storage().
 */
union ivmc_result_optional_storage
{
    uint8_t bytes[24]; /**< 24 bytes of optional storage. */
    void* pointer;     /**< Optional pointer. */
};

/** Provides read-write access to ivmc_result "optional storage". */
static inline union ivmc_result_optional_storage* ivmc_get_optional_storage(
    struct ivmc_result* result)
{
    return (union ivmc_result_optional_storage*)&result->create_address;
}

/** Provides read-only access to ivmc_result "optional storage". */
static inline const union ivmc_result_optional_storage* ivmc_get_const_optional_storage(
    const struct ivmc_result* result)
{
    return (const union ivmc_result_optional_storage*)&result->create_address;
}

/** @} */

/** Returns text representation of the ::ivmc_status_code. */
static inline const char* ivmc_status_code_to_string(enum ivmc_status_code status_code)
{
    switch (status_code)
    {
    case IVMC_SUCCESS:
        return "success";
    case IVMC_FAILURE:
        return "failure";
    case IVMC_REVERT:
        return "revert";
    case IVMC_OUT_OF_GAS:
        return "out of gas";
    case IVMC_INVALID_INSTRUCTION:
        return "invalid instruction";
    case IVMC_UNDEFINED_INSTRUCTION:
        return "undefined instruction";
    case IVMC_STACK_OVERFLOW:
        return "stack overflow";
    case IVMC_STACK_UNDERFLOW:
        return "stack underflow";
    case IVMC_BAD_JUMP_DESTINATION:
        return "bad jump destination";
    case IVMC_INVALID_MEMORY_ACCESS:
        return "invalid memory access";
    case IVMC_CALL_DEPTH_EXCEEDED:
        return "call depth exceeded";
    case IVMC_STATIC_MODE_VIOLATION:
        return "static mode violation";
    case IVMC_PRECOMPILE_FAILURE:
        return "precompile failure";
    case IVMC_CONTRACT_VALIDATION_FAILURE:
        return "contract validation failure";
    case IVMC_ARGUMENT_OUT_OF_RANGE:
        return "argument out of range";
    case IVMC_WASM_UNREACHABLE_INSTRUCTION:
        return "wasm unreachable instruction";
    case IVMC_WASM_TRAP:
        return "wasm trap";
    case IVMC_INSUFFICIENT_BALANCE:
        return "insufficient balance";
    case IVMC_INTERNAL_ERROR:
        return "internal error";
    case IVMC_REJECTED:
        return "rejected";
    case IVMC_OUT_OF_MEMORY:
        return "out of memory";
    }
    return "<unknown>";
}

/** Returns the name of the ::ivmc_revision. */
static inline const char* ivmc_revision_to_string(enum ivmc_revision rev)
{
    switch (rev)
    {
    case IVMC_FRONTIER:
        return "Frontier";
    case IVMC_HOMESTEAD:
        return "Homestead";
    case IVMC_TANGERINE_WHISTLE:
        return "Tangerine Whistle";
    case IVMC_SPURIOUS_DRAGON:
        return "Spurious Dragon";
    case IVMC_BYZANTIUM:
        return "Byzantium";
    case IVMC_CONSTANTINOPLE:
        return "Constantinople";
    case IVMC_PETERSBURG:
        return "Petersburg";
    case IVMC_ISTANBUL:
        return "Istanbul";
    case IVMC_BERLIN:
        return "Berlin";
    case IVMC_LONDON:
        return "London";
    case IVMC_SHANGHAI:
        return "Shanghai";
    }
    return "<unknown>";
}

/** @} */
