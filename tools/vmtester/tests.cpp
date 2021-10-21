// IVMC: Ethereum Client-VM Connector API
// Copyright 2018-2019 The IVMC Authors.
// Licensed under the Apache License, Version 2.0.

#include "vmtester.hpp"
#include <ivmc/ivmc.hpp>
#include <ivmc/mocked_host.hpp>
#include <array>
#include <cstring>

namespace
{
// NOTE: this is to avoid compiler optimisations when reading the buffer
uint8_t read_uint8(const volatile uint8_t* p) noexcept
{
    return *p;
}

void read_buffer(const uint8_t* ptr, size_t size) noexcept
{
    for (size_t i = 0; i < size; i++)
        read_uint8(&ptr[i]);
}
}  // namespace

TEST_F(ivmc_vm_test, abi_version_match)
{
    ASSERT_EQ(vm->abi_version, IVMC_ABI_VERSION);
}

TEST_F(ivmc_vm_test, name)
{
    ASSERT_TRUE(vm->name != nullptr);
    EXPECT_NE(std::strlen(vm->name), size_t{0}) << "VM name cannot be empty";

    EXPECT_STREQ(owned_vm.name(), vm->name);
}

TEST_F(ivmc_vm_test, version)
{
    ASSERT_TRUE(vm->version != nullptr);
    EXPECT_NE(std::strlen(vm->version), size_t{0}) << "VM version cannot be empty";

    EXPECT_STREQ(owned_vm.version(), vm->version);
}

TEST_F(ivmc_vm_test, capabilities)
{
    // The VM should have at least one of EVM1 or EWASM capabilities.
    EXPECT_TRUE(ivmc_vm_has_capability(vm, IVMC_CAPABILITY_EVM1) ||
                ivmc_vm_has_capability(vm, IVMC_CAPABILITY_EWASM) ||
                ivmc_vm_has_capability(vm, IVMC_CAPABILITY_PRECOMPILES));
}

TEST_F(ivmc_vm_test, execute_call)
{
    ivmc::MockedHost mockedHost;
    ivmc_message msg{};
    std::array<uint8_t, 2> code = {{0xfe, 0x00}};

    ivmc_result result =
        vm->execute(vm, &ivmc::MockedHost::get_interface(), mockedHost.to_context(),
                    IVMC_MAX_REVISION, &msg, code.data(), code.size());

    // Validate some constraints
    if (result.status_code != IVMC_SUCCESS && result.status_code != IVMC_REVERT)
    {
        EXPECT_EQ(result.gas_left, 0);
    }

    if (result.output_data == nullptr)
    {
        EXPECT_EQ(result.output_size, size_t{0});
    }
    else
    {
        EXPECT_NE(result.output_size, size_t{0});
        read_buffer(result.output_data, result.output_size);
    }

    EXPECT_TRUE(ivmc::is_zero(result.create_address));

    if (result.release != nullptr)
        result.release(&result);
}

TEST_F(ivmc_vm_test, execute_create)
{
    ivmc::MockedHost mockedHost;
    ivmc_message msg{IVMC_CREATE,
                     0,
                     0,
                     65536,
                     ivmc_address{},
                     ivmc_address{},
                     nullptr,
                     0,
                     ivmc_uint256be{},
                     ivmc_bytes32{},
                     ivmc_address{}};
    std::array<uint8_t, 2> code = {{0xfe, 0x00}};

    ivmc_result result =
        vm->execute(vm, &ivmc::MockedHost::get_interface(), mockedHost.to_context(),
                    IVMC_MAX_REVISION, &msg, code.data(), code.size());

    // Validate some constraints
    if (result.status_code != IVMC_SUCCESS && result.status_code != IVMC_REVERT)
    {
        EXPECT_EQ(result.gas_left, 0);
    }

    if (result.output_data == nullptr)
    {
        EXPECT_EQ(result.output_size, size_t{0});
    }
    else
    {
        EXPECT_NE(result.output_size, size_t{0});
        read_buffer(result.output_data, result.output_size);
    }

    // The VM will never provide the create address.
    EXPECT_TRUE(ivmc::is_zero(result.create_address));

    if (result.release != nullptr)
        result.release(&result);
}

TEST_F(ivmc_vm_test, set_option_unknown_name)
{
    if (vm->set_option != nullptr)
    {
        ivmc_set_option_result r = vm->set_option(vm, "unknown_option_csk9twq", "v");
        EXPECT_EQ(r, IVMC_SET_OPTION_INVALID_NAME);
        r = vm->set_option(vm, "unknown_option_csk9twq", "x");
        EXPECT_EQ(r, IVMC_SET_OPTION_INVALID_NAME);
    }
}

TEST_F(ivmc_vm_test, set_option_empty_value)
{
    if (vm->set_option != nullptr)
    {
        ivmc_set_option_result r = vm->set_option(vm, "unknown_option_csk9twq", nullptr);
        EXPECT_EQ(r, IVMC_SET_OPTION_INVALID_NAME);
    }
}

TEST_F(ivmc_vm_test, set_option_unknown_value)
{
    auto r = ivmc_set_option(vm, "verbose", "1");

    // Execute more tests if the VM supports "verbose" option.
    if (r != IVMC_SET_OPTION_INVALID_NAME)
    {
        // The VM supports "verbose" option. Try dummy value for it.
        auto r2 = ivmc_set_option(vm, "verbose", "GjNOONsbUl");
        EXPECT_EQ(r2, IVMC_SET_OPTION_INVALID_VALUE);

        // For null the behavior should be the same.
        auto r3 = ivmc_set_option(vm, "verbose", nullptr);
        EXPECT_EQ(r3, IVMC_SET_OPTION_INVALID_VALUE);
    }
}

TEST_F(ivmc_vm_test, precompile_test)
{
    // This logic is based on and should match the description in EIP-2003.

    if (!ivmc_vm_has_capability(vm, IVMC_CAPABILITY_PRECOMPILES))
        return;

    // Iterate every address (as per EIP-1352)
    for (size_t i = 0; i < 0xffff; i++)
    {
        auto addr = ivmc_address{};
        addr.bytes[18] = static_cast<uint8_t>(i >> 8);
        addr.bytes[19] = static_cast<uint8_t>(i & 0xff);

        ivmc_message msg{IVMC_CALL,
                         0,
                         0,
                         65536,
                         ivmc_address{},
                         ivmc_address{},
                         nullptr,
                         0,
                         ivmc_uint256be{},
                         ivmc_bytes32{},
                         addr};

        ivmc_result result = vm->execute(vm, nullptr, nullptr, IVMC_MAX_REVISION, &msg, nullptr, 0);

        // Validate some constraints

        // Precompiles can only return a limited subset of codes.
        EXPECT_TRUE(result.status_code == IVMC_SUCCESS || result.status_code == IVMC_OUT_OF_GAS ||
                    result.status_code == IVMC_FAILURE || result.status_code == IVMC_REVERT ||
                    result.status_code == IVMC_REJECTED);

        if (result.status_code != IVMC_SUCCESS && result.status_code != IVMC_REVERT)
        {
            EXPECT_EQ(result.gas_left, 0);
        }

        if (result.output_data == nullptr)
        {
            EXPECT_EQ(result.output_size, size_t{0});
        }
        else if (result.output_size != 0)
        {
            read_buffer(result.output_data, result.output_size);
        }

        if (result.release != nullptr)
            result.release(&result);
    }
}
