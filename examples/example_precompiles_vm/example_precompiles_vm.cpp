/* IVMC: Ethereum Client-VM Connector API.
 * Copyright 2019 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 */

#include "example_precompiles_vm.h"
#include <algorithm>

static ivmc_result execute_identity(const ivmc_message* msg)
{
    auto result = ivmc_result{};

    // Check the gas cost.
    auto gas_cost = 15 + 3 * ((int64_t(msg->input_size) + 31) / 32);
    auto gas_left = msg->gas - gas_cost;
    if (gas_left < 0)
    {
        result.status_code = IVMC_OUT_OF_GAS;
        return result;
    }

    // Execute.
    auto data = new uint8_t[msg->input_size];
    std::copy_n(msg->input_data, msg->input_size, data);

    // Return the result.
    result.status_code = IVMC_SUCCESS;
    result.output_data = data;
    result.output_size = msg->input_size;
    result.release = [](const ivmc_result* r) { delete[] r->output_data; };
    result.gas_left = gas_left;
    return result;
}

static ivmc_result execute_empty(const ivmc_message* msg)
{
    auto result = ivmc_result{};
    result.status_code = IVMC_SUCCESS;
    result.gas_left = msg->gas;
    return result;
}

static ivmc_result not_implemented()
{
    auto result = ivmc_result{};
    result.status_code = IVMC_REJECTED;
    return result;
}

static ivmc_result execute(ivmc_vm*,
                           const ivmc_host_interface*,
                           ivmc_host_context*,
                           enum ivmc_revision rev,
                           const ivmc_message* msg,
                           const uint8_t* /*code*/,
                           size_t /*code_size*/)
{
    // The EIP-1352 (https://eips.ethereum.org/EIPS/eip-1352) defines
    // the range 0 - 0xffff (2 bytes) of addresses reserved for precompiled contracts.
    // Check if the code address is within the reserved range.

    constexpr auto prefix_size = sizeof(ivmc_address) - 2;
    const auto& addr = msg->code_address;
    // Check if the address prefix is all zeros.
    if (std::any_of(&addr.bytes[0], &addr.bytes[prefix_size], [](uint8_t x) { return x != 0; }))
    {
        // If not, reject the execution request.
        auto result = ivmc_result{};
        result.status_code = IVMC_REJECTED;
        return result;
    }

    // Extract the precompiled contract id from last 2 bytes of the code address.
    const auto id = (addr.bytes[prefix_size] << 8) | addr.bytes[prefix_size + 1];
    switch (id)
    {
    case 0x0001:  // ECDSARECOVER
    case 0x0002:  // SHA256
    case 0x0003:  // RIPEMD160
        return not_implemented();

    case 0x0004:  // Identity
        return execute_identity(msg);

    case 0x0005:  // EXPMOD
    case 0x0006:  // SNARKV
    case 0x0007:  // BNADD
    case 0x0008:  // BNMUL
        if (rev < IVMC_BYZANTIUM)
            return execute_empty(msg);
        return not_implemented();

    default:  // As if empty code was executed.
        return execute_empty(msg);
    }
}

ivmc_vm* ivmc_create_example_precompiles_vm()
{
    static struct ivmc_vm vm = {
        IVMC_ABI_VERSION,
        "example_precompiles_vm",
        PROJECT_VERSION,
        [](ivmc_vm*) {},
        execute,
        [](ivmc_vm*) { return ivmc_capabilities_flagset{IVMC_CAPABILITY_PRECOMPILES}; },
        nullptr,
    };
    return &vm;
}
