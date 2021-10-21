/* IVMC: Ethereum Client-VM Connector API.
 * Copyright 2016-2019 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 */

/// @file
/// Example implementation of an IVMC Host.

#include "example_host.h"

#include <ivmc/ivmc.hpp>

#include <algorithm>
#include <map>
#include <vector>

using namespace ivmc::literals;

namespace ivmc
{
struct account
{
    virtual ~account() = default;

    ivmc::uint256be balance = {};
    std::vector<uint8_t> code;
    std::map<ivmc::bytes32, ivmc::bytes32> storage;

    virtual ivmc::bytes32 code_hash() const
    {
        // Extremely dumb "hash" function.
        ivmc::bytes32 ret{};
        for (std::vector<uint8_t>::size_type i = 0; i != code.size(); i++)
        {
            auto v = code[i];
            ret.bytes[v % sizeof(ret.bytes)] ^= v;
        }
        return ret;
    }
};

using accounts = std::map<ivmc::address, account>;

}  // namespace ivmc

class ExampleHost : public ivmc::Host
{
    ivmc::accounts accounts;
    ivmc_tx_context tx_context{};

public:
    ExampleHost() = default;
    explicit ExampleHost(ivmc_tx_context& _tx_context) noexcept : tx_context{_tx_context} {}
    ExampleHost(ivmc_tx_context& _tx_context, ivmc::accounts& _accounts) noexcept
      : accounts{_accounts}, tx_context{_tx_context}
    {}

    bool account_exists(const ivmc::address& addr) const noexcept final
    {
        return accounts.find(addr) != accounts.end();
    }

    ivmc::bytes32 get_storage(const ivmc::address& addr,
                              const ivmc::bytes32& key) const noexcept final
    {
        const auto account_iter = accounts.find(addr);
        if (account_iter == accounts.end())
            return {};

        const auto storage_iter = account_iter->second.storage.find(key);
        if (storage_iter != account_iter->second.storage.end())
            return storage_iter->second;
        return {};
    }

    ivmc_storage_status set_storage(const ivmc::address& addr,
                                    const ivmc::bytes32& key,
                                    const ivmc::bytes32& value) noexcept final
    {
        auto& account = accounts[addr];
        auto prev_value = account.storage[key];
        account.storage[key] = value;

        return (prev_value == value) ? IVMC_STORAGE_UNCHANGED : IVMC_STORAGE_MODIFIED;
    }

    ivmc::uint256be get_balance(const ivmc::address& addr) const noexcept final
    {
        auto it = accounts.find(addr);
        if (it != accounts.end())
            return it->second.balance;
        return {};
    }

    size_t get_code_size(const ivmc::address& addr) const noexcept final
    {
        auto it = accounts.find(addr);
        if (it != accounts.end())
            return it->second.code.size();
        return 0;
    }

    ivmc::bytes32 get_code_hash(const ivmc::address& addr) const noexcept final
    {
        auto it = accounts.find(addr);
        if (it != accounts.end())
            return it->second.code_hash();
        return {};
    }

    size_t copy_code(const ivmc::address& addr,
                     size_t code_offset,
                     uint8_t* buffer_data,
                     size_t buffer_size) const noexcept final
    {
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return 0;

        const auto& code = it->second.code;

        if (code_offset >= code.size())
            return 0;

        const auto n = std::min(buffer_size, code.size() - code_offset);

        if (n > 0)
            std::copy_n(&code[code_offset], n, buffer_data);
        return n;
    }

    void selfdestruct(const ivmc::address& addr, const ivmc::address& beneficiary) noexcept final
    {
        (void)addr;
        (void)beneficiary;
    }

    ivmc::result call(const ivmc_message& msg) noexcept final
    {
        return {IVMC_REVERT, msg.gas, msg.input_data, msg.input_size};
    }

    ivmc_tx_context get_tx_context() const noexcept final { return tx_context; }

    ivmc::bytes32 get_block_hash(int64_t number) const noexcept final
    {
        const int64_t current_block_number = get_tx_context().block_number;

        return (number < current_block_number && number >= current_block_number - 256) ?
                   0xb10c8a5fb10c8a5fb10c8a5fb10c8a5fb10c8a5fb10c8a5fb10c8a5fb10c8a5f_bytes32 :
                   0_bytes32;
    }

    void emit_log(const ivmc::address& addr,
                  const uint8_t* data,
                  size_t data_size,
                  const ivmc::bytes32 topics[],
                  size_t topics_count) noexcept final
    {
        (void)addr;
        (void)data;
        (void)data_size;
        (void)topics;
        (void)topics_count;
    }

    ivmc_access_status access_account(const ivmc::address& addr) noexcept final
    {
        (void)addr;
        return IVMC_ACCESS_COLD;
    }

    ivmc_access_status access_storage(const ivmc::address& addr,
                                      const ivmc::bytes32& key) noexcept final
    {
        (void)addr;
        (void)key;
        return IVMC_ACCESS_COLD;
    }
};


extern "C" {

const ivmc_host_interface* example_host_get_interface()
{
    return &ivmc::Host::get_interface();
}

ivmc_host_context* example_host_create_context(ivmc_tx_context tx_context)
{
    auto host = new ExampleHost{tx_context};
    return host->to_context();
}

void example_host_destroy_context(ivmc_host_context* context)
{
    delete ivmc::Host::from_context<ExampleHost>(context);
}
}
