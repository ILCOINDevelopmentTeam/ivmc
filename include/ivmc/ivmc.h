/**
 * IVMC: Ethereum Client-VM Connector API
 *
 * @copyright
 * Copyright 2016-2019 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 *
 * @defgroup IVMC IVMC
 * @{
 */
#ifndef IVMC_H
#define IVMC_H

#if defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 6)
/**
 * Portable declaration of "deprecated" attribute.
 *
 * Available for clang and GCC 6+ compilers. The older GCC compilers know
 * this attribute, but it cannot be applied to enum elements.
 */
#define IVMC_DEPRECATED __attribute__((deprecated))
#else
#define IVMC_DEPRECATED
#endif


#include <stdbool.h> /* Definition of bool, true and false. */
#include <stddef.h>  /* Definition of size_t. */
#include <stdint.h>  /* Definition of int64_t, uint64_t. */

#ifdef __cplusplus
extern "C" {
#endif

/* BEGIN Python CFFI declarations */

enum
{
    /**
     * The IVMC ABI version number of the interface declared in this file.
     *
     * The IVMC ABI version always equals the major version number of the IVMC project.
     * The Host SHOULD check if the ABI versions match when dynamically loading VMs.
     *
     * @see @ref versioning
     */
    IVMC_ABI_VERSION = 10
};


/**
 * The fixed size array of 32 bytes.
 *
 * 32 bytes of data capable of storing e.g. 256-bit hashes.
 */
typedef struct ivmc_bytes32
{
    /** The 32 bytes. */
    uint8_t bytes[32];
} ivmc_bytes32;

/**
 * The alias for ivmc_bytes32 to represent a big-endian 256-bit integer.
 */
typedef struct ivmc_bytes32 ivmc_uint256be;

/** Big-endian 160-bit hash suitable for keeping an Ethereum address. */
typedef struct ivmc_address
{
    /** The 20 bytes of the hash. */
    uint8_t bytes[20];
} ivmc_address;

/** The kind of call-like instruction. */
enum ivmc_call_kind
{
    IVMC_CALL = 0,         /**< Request CALL. */
    IVMC_DELEGATECALL = 1, /**< Request DELEGATECALL. Valid since Homestead.
                                The value param ignored. */
    IVMC_CALLCODE = 2,     /**< Request CALLCODE. */
    IVMC_CREATE = 3,       /**< Request CREATE. */
    IVMC_CREATE2 = 4       /**< Request CREATE2. Valid since Constantinople.*/
};

/** The flags for ::ivmc_message. */
enum ivmc_flags
{
    IVMC_STATIC = 1 /**< Static call mode. */
};

/**
 * The message describing an EVM call, including a zero-depth calls from a transaction origin.
 *
 * Most of the fields are modelled by the section 8. Message Call of the Ethereum Yellow Paper.
 */
struct ivmc_message
{
    /** The kind of the call. For zero-depth calls ::IVMC_CALL SHOULD be used. */
    enum ivmc_call_kind kind;

    /**
     * Additional flags modifying the call execution behavior.
     * In the current version the only valid values are ::IVMC_STATIC or 0.
     */
    uint32_t flags;

    /**
     * The present depth of the message call stack.
     *
     * Defined as `e` in the Yellow Paper.
     */
    int32_t depth;

    /**
     * The amount of gas available to the message execution.
     *
     * Defined as `g` in the Yellow Paper.
     */
    int64_t gas;

    /**
     * The recipient of the message.
     *
     * This is the address of the account which storage/balance/nonce is going to be modified
     * by the message execution. In case of ::IVMC_CALL, this is also the account where the
     * message value ivmc_message::value is going to be transferred.
     * For ::IVMC_CALLCODE or ::IVMC_DELEGATECALL, this may be different from
     * the ivmc_message::code_address.
     *
     * Defined as `r` in the Yellow Paper.
     */
    ivmc_address recipient;

    /**
     * The sender of the message.
     *
     * The address of the sender of a message call defined as `s` in the Yellow Paper.
     * This must be the message recipient of the message at the previous (lower) depth,
     * except for the ::IVMC_DELEGATECALL where recipient is the 2 levels above the present depth.
     * At the depth 0 this must be the transaction origin.
     */
    ivmc_address sender;

    /**
     * The message input data.
     *
     * The arbitrary length byte array of the input data of the call,
     * defined as `d` in the Yellow Paper.
     * This MAY be NULL.
     */
    const uint8_t* input_data;

    /**
     * The size of the message input data.
     *
     * If input_data is NULL this MUST be 0.
     */
    size_t input_size;

    /**
     * The amount of Ether transferred with the message.
     *
     * This is transferred value for ::IVMC_CALL or apparent value for ::IVMC_DELEGATECALL.
     * Defined as `v` or `v~` in the Yellow Paper.
     */
    ivmc_uint256be value;

    /**
     * The optional value used in new contract address construction.
     *
     * Needed only for a Host to calculate created address when kind is ::IVMC_CREATE2.
     * Ignored in ivmc_execute_fn().
     */
    ivmc_bytes32 create2_salt;

    /**
     * The address of the code to be executed.
     *
     * For ::IVMC_CALLCODE or ::IVMC_DELEGATECALL this may be different from
     * the ivmc_message::recipient.
     * Not required when invoking ivmc_execute_fn(), only when invoking ivmc_call_fn().
     * Ignored if kind is ::IVMC_CREATE or ::IVMC_CREATE2.
     *
     * In case of ::IVMC_CAPABILITY_PRECOMPILES implementation, this fields should be inspected
     * to identify the requested precompile.
     *
     * Defined as `c` in the Yellow Paper.
     */
    ivmc_address code_address;
};


/** The transaction and block data for execution. */
struct ivmc_tx_context
{
    ivmc_uint256be tx_gas_price;     /**< The transaction gas price. */
    ivmc_address tx_origin;          /**< The transaction origin account. */
    ivmc_address block_coinbase;     /**< The miner of the block. */
    int64_t block_number;            /**< The block number. */
    int64_t block_timestamp;         /**< The block timestamp. */
    int64_t block_gas_limit;         /**< The block gas limit. */
    ivmc_uint256be block_difficulty; /**< The block difficulty. */
    ivmc_uint256be chain_id;         /**< The blockchain's ChainID. */
    ivmc_uint256be block_base_fee;   /**< The block base fee per gas (EIP-1559, EIP-3198). */
};

/**
 * @struct ivmc_host_context
 * The opaque data type representing the Host execution context.
 * @see ivmc_execute_fn().
 */
struct ivmc_host_context;

/**
 * Get transaction context callback function.
 *
 *  This callback function is used by an EVM to retrieve the transaction and
 *  block context.
 *
 *  @param      context  The pointer to the Host execution context.
 *  @return              The transaction context.
 */
typedef struct ivmc_tx_context (*ivmc_get_tx_context_fn)(struct ivmc_host_context* context);

/**
 * Get block hash callback function.
 *
 * This callback function is used by a VM to query the hash of the header of the given block.
 * If the information about the requested block is not available, then this is signalled by
 * returning null bytes.
 *
 * @param context  The pointer to the Host execution context.
 * @param number   The block number.
 * @return         The block hash or null bytes
 *                 if the information about the block is not available.
 */
typedef ivmc_bytes32 (*ivmc_get_block_hash_fn)(struct ivmc_host_context* context, int64_t number);

/**
 * The execution status code.
 *
 * Successful execution is represented by ::IVMC_SUCCESS having value 0.
 *
 * Positive values represent failures defined by VM specifications with generic
 * ::IVMC_FAILURE code of value 1.
 *
 * Status codes with negative values represent VM internal errors
 * not provided by EVM specifications. These errors MUST not be passed back
 * to the caller. They MAY be handled by the Client in predefined manner
 * (see e.g. ::IVMC_REJECTED), otherwise internal errors are not recoverable.
 * The generic representant of errors is ::IVMC_INTERNAL_ERROR but
 * an EVM implementation MAY return negative status codes that are not defined
 * in the IVMC documentation.
 *
 * @note
 * In case new status codes are needed, please create an issue or pull request
 * in the IVMC repository (https://github.com/ILCOINDevelopmentTeam/ivmc).
 */
enum ivmc_status_code
{
    /** Execution finished with success. */
    IVMC_SUCCESS = 0,

    /** Generic execution failure. */
    IVMC_FAILURE = 1,

    /**
     * Execution terminated with REVERT opcode.
     *
     * In this case the amount of gas left MAY be non-zero and additional output
     * data MAY be provided in ::ivmc_result.
     */
    IVMC_REVERT = 2,

    /** The execution has run out of gas. */
    IVMC_OUT_OF_GAS = 3,

    /**
     * The designated INVALID instruction has been hit during execution.
     *
     * The EIP-141 (https://github.com/ILCOINDevelopmentTeam/EIPs/blob/master/EIPS/eip-141.md)
     * defines the instruction 0xfe as INVALID instruction to indicate execution
     * abortion coming from high-level languages. This status code is reported
     * in case this INVALID instruction has been encountered.
     */
    IVMC_INVALID_INSTRUCTION = 4,

    /** An undefined instruction has been encountered. */
    IVMC_UNDEFINED_INSTRUCTION = 5,

    /**
     * The execution has attempted to put more items on the EVM stack
     * than the specified limit.
     */
    IVMC_STACK_OVERFLOW = 6,

    /** Execution of an opcode has required more items on the EVM stack. */
    IVMC_STACK_UNDERFLOW = 7,

    /** Execution has violated the jump destination restrictions. */
    IVMC_BAD_JUMP_DESTINATION = 8,

    /**
     * Tried to read outside memory bounds.
     *
     * An example is RETURNDATACOPY reading past the available buffer.
     */
    IVMC_INVALID_MEMORY_ACCESS = 9,

    /** Call depth has exceeded the limit (if any) */
    IVMC_CALL_DEPTH_EXCEEDED = 10,

    /** Tried to execute an operation which is restricted in static mode. */
    IVMC_STATIC_MODE_VIOLATION = 11,

    /**
     * A call to a precompiled or system contract has ended with a failure.
     *
     * An example: elliptic curve functions handed invalid EC points.
     */
    IVMC_PRECOMPILE_FAILURE = 12,

    /**
     * Contract validation has failed (e.g. due to EVM 1.5 jump validity,
     * Casper's purity checker or ewasm contract rules).
     */
    IVMC_CONTRACT_VALIDATION_FAILURE = 13,

    /**
     * An argument to a state accessing method has a value outside of the
     * accepted range of values.
     */
    IVMC_ARGUMENT_OUT_OF_RANGE = 14,

    /**
     * A WebAssembly `unreachable` instruction has been hit during execution.
     */
    IVMC_WASM_UNREACHABLE_INSTRUCTION = 15,

    /**
     * A WebAssembly trap has been hit during execution. This can be for many
     * reasons, including division by zero, validation errors, etc.
     */
    IVMC_WASM_TRAP = 16,

    /** The caller does not have enough funds for value transfer. */
    IVMC_INSUFFICIENT_BALANCE = 17,

    /** EVM implementation generic internal error. */
    IVMC_INTERNAL_ERROR = -1,

    /**
     * The execution of the given code and/or message has been rejected
     * by the EVM implementation.
     *
     * This error SHOULD be used to signal that the EVM is not able to or
     * willing to execute the given code type or message.
     * If an EVM returns the ::IVMC_REJECTED status code,
     * the Client MAY try to execute it in other EVM implementation.
     * For example, the Client tries running a code in the EVM 1.5. If the
     * code is not supported there, the execution falls back to the EVM 1.0.
     */
    IVMC_REJECTED = -2,

    /** The VM failed to allocate the amount of memory needed for execution. */
    IVMC_OUT_OF_MEMORY = -3
};

/* Forward declaration. */
struct ivmc_result;

/**
 * Releases resources assigned to an execution result.
 *
 * This function releases memory (and other resources, if any) assigned to the
 * specified execution result making the result object invalid.
 *
 * @param result  The execution result which resources are to be released. The
 *                result itself it not modified by this function, but becomes
 *                invalid and user MUST discard it as well.
 *                This MUST NOT be NULL.
 *
 * @note
 * The result is passed by pointer to avoid (shallow) copy of the ::ivmc_result
 * struct. Think of this as the best possible C language approximation to
 * passing objects by reference.
 */
typedef void (*ivmc_release_result_fn)(const struct ivmc_result* result);

/** The EVM code execution result. */
struct ivmc_result
{
    /** The execution status code. */
    enum ivmc_status_code status_code;

    /**
     * The amount of gas left after the execution.
     *
     * If ivmc_result::status_code is neither ::IVMC_SUCCESS nor ::IVMC_REVERT
     * the value MUST be 0.
     */
    int64_t gas_left;

    /**
     * The reference to output data.
     *
     *  The output contains data coming from RETURN opcode (iff ivmc_result::code
     *  field is ::IVMC_SUCCESS) or from REVERT opcode.
     *
     *  The memory containing the output data is owned by EVM and has to be
     *  freed with ivmc_result::release().
     *
     *  This MAY be NULL.
     */
    const uint8_t* output_data;

    /**
     * The size of the output data.
     *
     *  If output_data is NULL this MUST be 0.
     */
    size_t output_size;

    /**
     * The method releasing all resources associated with the result object.
     *
     * This method (function pointer) is optional (MAY be NULL) and MAY be set
     * by the VM implementation. If set it MUST be called by the user once to
     * release memory and other resources associated with the result object.
     * Once the resources are released the result object MUST NOT be used again.
     *
     * The suggested code pattern for releasing execution results:
     * @code
     * struct ivmc_result result = ...;
     * if (result.release)
     *     result.release(&result);
     * @endcode
     *
     * @note
     * It works similarly to C++ virtual destructor. Attaching the release
     * function to the result itself allows VM composition.
     */
    ivmc_release_result_fn release;

    /**
     * The address of the contract created by create instructions.
     *
     * This field has valid value only if:
     * - it is a result of the Host method ivmc_host_interface::call
     * - and the result describes successful contract creation
     *   (ivmc_result::status_code is ::IVMC_SUCCESS).
     * In all other cases the address MUST be null bytes.
     */
    ivmc_address create_address;

    /**
     * Reserved data that MAY be used by a ivmc_result object creator.
     *
     *  This reserved 4 bytes together with 20 bytes from create_address form
     *  24 bytes of memory called "optional data" within ivmc_result struct
     *  to be optionally used by the ivmc_result object creator.
     *
     *  @see ivmc_result_optional_data, ivmc_get_optional_data().
     *
     *  Also extends the size of the ivmc_result to 64 bytes (full cache line).
     */
    uint8_t padding[4];
};


/**
 * Check account existence callback function.
 *
 * This callback function is used by the VM to check if
 * there exists an account at given address.
 * @param context  The pointer to the Host execution context.
 * @param address  The address of the account the query is about.
 * @return         true if exists, false otherwise.
 */
typedef bool (*ivmc_account_exists_fn)(struct ivmc_host_context* context,
                                       const ivmc_address* address);

/**
 * Get storage callback function.
 *
 * This callback function is used by a VM to query the given account storage entry.
 *
 * @param context  The Host execution context.
 * @param address  The address of the account.
 * @param key      The index of the account's storage entry.
 * @return         The storage value at the given storage key or null bytes
 *                 if the account does not exist.
 */
typedef ivmc_bytes32 (*ivmc_get_storage_fn)(struct ivmc_host_context* context,
                                            const ivmc_address* address,
                                            const ivmc_bytes32* key);


/**
 * The effect of an attempt to modify a contract storage item.
 *
 * For the purpose of explaining the meaning of each element, the following
 * notation is used:
 * - 0 is zero value,
 * - X != 0 (X is any value other than 0),
 * - Y != X, Y != 0 (Y is any value other than X and 0),
 * - Z != Y (Z is any value other than Y),
 * - the "->" means the change from one value to another.
 */
enum ivmc_storage_status
{
    /**
     * The value of a storage item has been left unchanged: 0 -> 0 and X -> X.
     */
    IVMC_STORAGE_UNCHANGED = 0,

    /**
     * The value of a storage item has been modified: X -> Y.
     */
    IVMC_STORAGE_MODIFIED = 1,

    /**
     * A storage item has been modified after being modified before: X -> Y -> Z.
     */
    IVMC_STORAGE_MODIFIED_AGAIN = 2,

    /**
     * A new storage item has been added: 0 -> X.
     */
    IVMC_STORAGE_ADDED = 3,

    /**
     * A storage item has been deleted: X -> 0.
     */
    IVMC_STORAGE_DELETED = 4
};


/**
 * Set storage callback function.
 *
 * This callback function is used by a VM to update the given account storage entry.
 * The VM MUST make sure that the account exists. This requirement is only a formality because
 * VM implementations only modify storage of the account of the current execution context
 * (i.e. referenced by ivmc_message::recipient).
 *
 * @param context  The pointer to the Host execution context.
 * @param address  The address of the account.
 * @param key      The index of the storage entry.
 * @param value    The value to be stored.
 * @return         The effect on the storage item.
 */
typedef enum ivmc_storage_status (*ivmc_set_storage_fn)(struct ivmc_host_context* context,
                                                        const ivmc_address* address,
                                                        const ivmc_bytes32* key,
                                                        const ivmc_bytes32* value);

/**
 * Get balance callback function.
 *
 * This callback function is used by a VM to query the balance of the given account.
 *
 * @param context  The pointer to the Host execution context.
 * @param address  The address of the account.
 * @return         The balance of the given account or 0 if the account does not exist.
 */
typedef ivmc_uint256be (*ivmc_get_balance_fn)(struct ivmc_host_context* context,
                                              const ivmc_address* address);

/**
 * Get code size callback function.
 *
 * This callback function is used by a VM to get the size of the code stored
 * in the account at the given address.
 *
 * @param context  The pointer to the Host execution context.
 * @param address  The address of the account.
 * @return         The size of the code in the account or 0 if the account does not exist.
 */
typedef size_t (*ivmc_get_code_size_fn)(struct ivmc_host_context* context,
                                        const ivmc_address* address);

/**
 * Get code hash callback function.
 *
 * This callback function is used by a VM to get the keccak256 hash of the code stored
 * in the account at the given address. For existing accounts not having a code, this
 * function returns keccak256 hash of empty data.
 *
 * @param context  The pointer to the Host execution context.
 * @param address  The address of the account.
 * @return         The hash of the code in the account or null bytes if the account does not exist.
 */
typedef ivmc_bytes32 (*ivmc_get_code_hash_fn)(struct ivmc_host_context* context,
                                              const ivmc_address* address);

/**
 * Copy code callback function.
 *
 * This callback function is used by an EVM to request a copy of the code
 * of the given account to the memory buffer provided by the EVM.
 * The Client MUST copy the requested code, starting with the given offset,
 * to the provided memory buffer up to the size of the buffer or the size of
 * the code, whichever is smaller.
 *
 * @param context      The pointer to the Host execution context. See ::ivmc_host_context.
 * @param address      The address of the account.
 * @param code_offset  The offset of the code to copy.
 * @param buffer_data  The pointer to the memory buffer allocated by the EVM
 *                     to store a copy of the requested code.
 * @param buffer_size  The size of the memory buffer.
 * @return             The number of bytes copied to the buffer by the Client.
 */
typedef size_t (*ivmc_copy_code_fn)(struct ivmc_host_context* context,
                                    const ivmc_address* address,
                                    size_t code_offset,
                                    uint8_t* buffer_data,
                                    size_t buffer_size);

/**
 * Selfdestruct callback function.
 *
 * This callback function is used by an EVM to SELFDESTRUCT given contract.
 * The execution of the contract will not be stopped, that is up to the EVM.
 *
 * @param context      The pointer to the Host execution context. See ::ivmc_host_context.
 * @param address      The address of the contract to be selfdestructed.
 * @param beneficiary  The address where the remaining ETH is going to be transferred.
 */
typedef void (*ivmc_selfdestruct_fn)(struct ivmc_host_context* context,
                                     const ivmc_address* address,
                                     const ivmc_address* beneficiary);

/**
 * Log callback function.
 *
 * This callback function is used by an EVM to inform about a LOG that happened
 * during an EVM bytecode execution.
 *
 * @param context       The pointer to the Host execution context. See ::ivmc_host_context.
 * @param address       The address of the contract that generated the log.
 * @param data          The pointer to unindexed data attached to the log.
 * @param data_size     The length of the data.
 * @param topics        The pointer to the array of topics attached to the log.
 * @param topics_count  The number of the topics. Valid values are between 0 and 4 inclusively.
 */
typedef void (*ivmc_emit_log_fn)(struct ivmc_host_context* context,
                                 const ivmc_address* address,
                                 const uint8_t* data,
                                 size_t data_size,
                                 const ivmc_bytes32 topics[],
                                 size_t topics_count);

/**
 * Access status per EIP-2929: Gas cost increases for state access opcodes.
 */
enum ivmc_access_status
{
    /**
     * The entry hasn't been accessed before – it's the first access.
     */
    IVMC_ACCESS_COLD = 0,

    /**
     * The entry is already in accessed_addresses or accessed_storage_keys.
     */
    IVMC_ACCESS_WARM = 1
};

/**
 * Access account callback function.
 *
 * This callback function is used by a VM to add the given address
 * to accessed_addresses substate (EIP-2929).
 *
 * @param context  The Host execution context.
 * @param address  The address of the account.
 * @return         IVMC_ACCESS_WARM if accessed_addresses already contained the address
 *                 or IVMC_ACCESS_COLD otherwise.
 */
typedef enum ivmc_access_status (*ivmc_access_account_fn)(struct ivmc_host_context* context,
                                                          const ivmc_address* address);

/**
 * Access storage callback function.
 *
 * This callback function is used by a VM to add the given account storage entry
 * to accessed_storage_keys substate (EIP-2929).
 *
 * @param context  The Host execution context.
 * @param address  The address of the account.
 * @param key      The index of the account's storage entry.
 * @return         IVMC_ACCESS_WARM if accessed_storage_keys already contained the key
 *                 or IVMC_ACCESS_COLD otherwise.
 */
typedef enum ivmc_access_status (*ivmc_access_storage_fn)(struct ivmc_host_context* context,
                                                          const ivmc_address* address,
                                                          const ivmc_bytes32* key);

/**
 * Pointer to the callback function supporting EVM calls.
 *
 * @param context  The pointer to the Host execution context.
 * @param msg      The call parameters.
 * @return         The result of the call.
 */
typedef struct ivmc_result (*ivmc_call_fn)(struct ivmc_host_context* context,
                                           const struct ivmc_message* msg);

/**
 * The Host interface.
 *
 * The set of all callback functions expected by VM instances. This is C
 * realisation of vtable for OOP interface (only virtual methods, no data).
 * Host implementations SHOULD create constant singletons of this (similarly
 * to vtables) to lower the maintenance and memory management cost.
 */
struct ivmc_host_interface
{
    /** Check account existence callback function. */
    ivmc_account_exists_fn account_exists;

    /** Get storage callback function. */
    ivmc_get_storage_fn get_storage;

    /** Set storage callback function. */
    ivmc_set_storage_fn set_storage;

    /** Get balance callback function. */
    ivmc_get_balance_fn get_balance;

    /** Get code size callback function. */
    ivmc_get_code_size_fn get_code_size;

    /** Get code hash callback function. */
    ivmc_get_code_hash_fn get_code_hash;

    /** Copy code callback function. */
    ivmc_copy_code_fn copy_code;

    /** Selfdestruct callback function. */
    ivmc_selfdestruct_fn selfdestruct;

    /** Call callback function. */
    ivmc_call_fn call;

    /** Get transaction context callback function. */
    ivmc_get_tx_context_fn get_tx_context;

    /** Get block hash callback function. */
    ivmc_get_block_hash_fn get_block_hash;

    /** Emit log callback function. */
    ivmc_emit_log_fn emit_log;

    /** Access account callback function. */
    ivmc_access_account_fn access_account;

    /** Access storage callback function. */
    ivmc_access_storage_fn access_storage;
};


/* Forward declaration. */
struct ivmc_vm;

/**
 * Destroys the VM instance.
 *
 * @param vm  The VM instance to be destroyed.
 */
typedef void (*ivmc_destroy_fn)(struct ivmc_vm* vm);

/**
 * Possible outcomes of ivmc_set_option.
 */
enum ivmc_set_option_result
{
    IVMC_SET_OPTION_SUCCESS = 0,
    IVMC_SET_OPTION_INVALID_NAME = 1,
    IVMC_SET_OPTION_INVALID_VALUE = 2
};

/**
 * Configures the VM instance.
 *
 * Allows modifying options of the VM instance.
 * Options:
 * - code cache behavior: on, off, read-only, ...
 * - optimizations,
 *
 * @param vm     The VM instance to be configured.
 * @param name   The option name. NULL-terminated string. Cannot be NULL.
 * @param value  The new option value. NULL-terminated string. Cannot be NULL.
 * @return       The outcome of the operation.
 */
typedef enum ivmc_set_option_result (*ivmc_set_option_fn)(struct ivmc_vm* vm,
                                                          char const* name,
                                                          char const* value);


/**
 * EVM revision.
 *
 * The revision of the EVM specification based on the Ethereum
 * upgrade / hard fork codenames.
 */
enum ivmc_revision
{
    /**
     * The Frontier revision.
     *
     * The one Ethereum launched with.
     */
    IVMC_FRONTIER = 0,

    /**
     * The Homestead revision.
     *
     * https://eips.ethereum.org/EIPS/eip-606
     */
    IVMC_HOMESTEAD = 1,

    /**
     * The Tangerine Whistle revision.
     *
     * https://eips.ethereum.org/EIPS/eip-608
     */
    IVMC_TANGERINE_WHISTLE = 2,

    /**
     * The Spurious Dragon revision.
     *
     * https://eips.ethereum.org/EIPS/eip-607
     */
    IVMC_SPURIOUS_DRAGON = 3,

    /**
     * The Byzantium revision.
     *
     * https://eips.ethereum.org/EIPS/eip-609
     */
    IVMC_BYZANTIUM = 4,

    /**
     * The Constantinople revision.
     *
     * https://eips.ethereum.org/EIPS/eip-1013
     */
    IVMC_CONSTANTINOPLE = 5,

    /**
     * The Petersburg revision.
     *
     * Other names: Constantinople2, ConstantinopleFix.
     *
     * https://eips.ethereum.org/EIPS/eip-1716
     */
    IVMC_PETERSBURG = 6,

    /**
     * The Istanbul revision.
     *
     * https://eips.ethereum.org/EIPS/eip-1679
     */
    IVMC_ISTANBUL = 7,

    /**
     * The Berlin revision.
     *
     * https://github.com/ILCOINDevelopmentTeam/eth1.0-specs/blob/master/network-upgrades/mainnet-upgrades/berlin.md
     */
    IVMC_BERLIN = 8,

    /**
     * The London revision.
     *
     * https://github.com/ILCOINDevelopmentTeam/eth1.0-specs/blob/master/network-upgrades/mainnet-upgrades/london.md
     */
    IVMC_LONDON = 9,

    /**
     * The Shanghai revision.
     *
     * https://github.com/ILCOINDevelopmentTeam/eth1.0-specs/blob/master/network-upgrades/mainnet-upgrades/shanghai.md
     */
    IVMC_SHANGHAI = 10,

    /** The maximum EVM revision supported. */
    IVMC_MAX_REVISION = IVMC_SHANGHAI,

    /**
     * The latest known EVM revision with finalized specification.
     *
     * This is handy for EVM tools to always use the latest revision available.
     */
    IVMC_LATEST_STABLE_REVISION = IVMC_LONDON
};


/**
 * Executes the given code using the input from the message.
 *
 * This function MAY be invoked multiple times for a single VM instance.
 *
 * @param vm         The VM instance. This argument MUST NOT be NULL.
 * @param host       The Host interface. This argument MUST NOT be NULL unless
 *                   the @p vm has the ::IVMC_CAPABILITY_PRECOMPILES capability.
 * @param context    The opaque pointer to the Host execution context.
 *                   This argument MAY be NULL. The VM MUST pass the same
 *                   pointer to the methods of the @p host interface.
 *                   The VM MUST NOT dereference the pointer.
 * @param rev        The requested EVM specification revision.
 * @param msg        The call parameters. See ::ivmc_message. This argument MUST NOT be NULL.
 * @param code       The reference to the code to be executed. This argument MAY be NULL.
 * @param code_size  The length of the code. If @p code is NULL this argument MUST be 0.
 * @return           The execution result.
 */
typedef struct ivmc_result (*ivmc_execute_fn)(struct ivmc_vm* vm,
                                              const struct ivmc_host_interface* host,
                                              struct ivmc_host_context* context,
                                              enum ivmc_revision rev,
                                              const struct ivmc_message* msg,
                                              uint8_t const* code,
                                              size_t code_size);

/**
 * Possible capabilities of a VM.
 */
enum ivmc_capabilities
{
    /**
     * The VM is capable of executing EVM1 bytecode.
     */
    IVMC_CAPABILITY_EVM1 = (1u << 0),

    /**
     * The VM is capable of executing ewasm bytecode.
     */
    IVMC_CAPABILITY_EWASM = (1u << 1),

    /**
     * The VM is capable of executing the precompiled contracts
     * defined for the range of code addresses.
     *
     * The EIP-1352 (https://eips.ethereum.org/EIPS/eip-1352) specifies
     * the range 0x000...0000 - 0x000...ffff of addresses
     * reserved for precompiled and system contracts.
     *
     * This capability is **experimental** and MAY be removed without notice.
     */
    IVMC_CAPABILITY_PRECOMPILES = (1u << 2)
};

/**
 * Alias for unsigned integer representing a set of bit flags of IVMC capabilities.
 *
 * @see ivmc_capabilities
 */
typedef uint32_t ivmc_capabilities_flagset;

/**
 * Return the supported capabilities of the VM instance.
 *
 * This function MAY be invoked multiple times for a single VM instance,
 * and its value MAY be influenced by calls to ivmc_vm::set_option.
 *
 * @param vm  The VM instance.
 * @return    The supported capabilities of the VM. @see ivmc_capabilities.
 */
typedef ivmc_capabilities_flagset (*ivmc_get_capabilities_fn)(struct ivmc_vm* vm);


/**
 * The VM instance.
 *
 * Defines the base struct of the VM implementation.
 */
struct ivmc_vm
{
    /**
     * IVMC ABI version implemented by the VM instance.
     *
     * Can be used to detect ABI incompatibilities.
     * The IVMC ABI version represented by this file is in ::IVMC_ABI_VERSION.
     */
    const int abi_version;

    /**
     * The name of the IVMC VM implementation.
     *
     * It MUST be a NULL-terminated not empty string.
     * The content MUST be UTF-8 encoded (this implies ASCII encoding is also allowed).
     */
    const char* name;

    /**
     * The version of the IVMC VM implementation, e.g. "1.2.3b4".
     *
     * It MUST be a NULL-terminated not empty string.
     * The content MUST be UTF-8 encoded (this implies ASCII encoding is also allowed).
     */
    const char* version;

    /**
     * Pointer to function destroying the VM instance.
     *
     * This is a mandatory method and MUST NOT be set to NULL.
     */
    ivmc_destroy_fn destroy;

    /**
     * Pointer to function executing a code by the VM instance.
     *
     * This is a mandatory method and MUST NOT be set to NULL.
     */
    ivmc_execute_fn execute;

    /**
     * A method returning capabilities supported by the VM instance.
     *
     * The value returned MAY change when different options are set via the set_option() method.
     *
     * A Client SHOULD only rely on the value returned if it has queried it after
     * it has called the set_option().
     *
     * This is a mandatory method and MUST NOT be set to NULL.
     */
    ivmc_get_capabilities_fn get_capabilities;

    /**
     * Optional pointer to function modifying VM's options.
     *
     *  If the VM does not support this feature the pointer can be NULL.
     */
    ivmc_set_option_fn set_option;
};

/* END Python CFFI declarations */

#ifdef IVMC_DOCUMENTATION
/**
 * Example of a function creating an instance of an example EVM implementation.
 *
 * Each EVM implementation MUST provide a function returning an EVM instance.
 * The function SHOULD be named `ivmc_create_<vm-name>(void)`. If the VM name contains hyphens
 * replaces them with underscores in the function names.
 *
 * @par Binaries naming convention
 * For VMs distributed as shared libraries, the name of the library SHOULD match the VM name.
 * The convetional library filename prefixes and extensions SHOULD be ignored by the Client.
 * For example, the shared library with the "beta-interpreter" implementation may be named
 * `libbeta-interpreter.so`.
 *
 * @return  The VM instance or NULL indicating instance creation failure.
 */
struct ivmc_vm* ivmc_create_example_vm(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
/** @} */
