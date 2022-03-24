// IVMC: Ethereum Client-VM Connector API.
// Copyright 2019-2020 The IVMC Authors.
// Licensed under the Apache License, Version 2.0.

#include <ivmc/ivmc.hpp>
#include <ivmc/hex.hpp>
#include <ivmc/mocked_host.hpp>
#include <ivmc/tooling.hpp>
#include <chrono>
#include <ostream>
#include <sstream>
#include <iomanip>

namespace ivmc::tooling
{
namespace
{
/// The address where a new contract is created with --create option.
constexpr auto create_address = 0xc9ea7ed000000000000000000000000000000001_address;

/// The gas limit for contract creation.
constexpr auto create_gas = 10'000'000;

constexpr int from_hex(char c) noexcept
{
    return (c >= 'a' && c <= 'f') ? c - ('a' - 10) :
           (c >= 'A' && c <= 'F') ? c - ('A' - 10) :
                                    c - '0';
}

constexpr uint8_t byte(const char* s, size_t i) noexcept
{
    return static_cast<uint8_t>((from_hex(s[2 * i]) << 4) | from_hex(s[2 * i + 1]));
}

bytes32 from_hex32(const char* s)
{
    return {
        {{byte(s, 0),  byte(s, 1),  byte(s, 2),  byte(s, 3),  byte(s, 4),  byte(s, 5),  byte(s, 6),
          byte(s, 7),  byte(s, 8),  byte(s, 9),  byte(s, 10), byte(s, 11), byte(s, 12), byte(s, 13),
          byte(s, 14), byte(s, 15), byte(s, 16), byte(s, 17), byte(s, 18), byte(s, 19), byte(s, 20),
          byte(s, 21), byte(s, 22), byte(s, 23), byte(s, 24), byte(s, 25), byte(s, 26), byte(s, 27),
          byte(s, 28), byte(s, 29), byte(s, 30), byte(s, 31)}}};
}

auto bench(MockedHost& host,
           ivmc::VM& vm,
           ivmc_revision rev,
           const ivmc_message& msg,
           bytes_view code,
           const ivmc::result& expected_result,
           std::ostream& out)
{
    {
        using clock = std::chrono::steady_clock;
        using unit = std::chrono::nanoseconds;
        constexpr auto unit_name = " ns";
        constexpr auto target_bench_time = std::chrono::seconds{1};
        constexpr auto warning =
            "WARNING! Inconsistent execution result likely due to the use of storage ";

        // Probe run: execute once again the already warm code to estimate a single run time.
        const auto probe_start = clock::now();
        const auto result = vm.execute(host, rev, msg, code.data(), code.size());
        const auto bench_start = clock::now();
        const auto probe_time = bench_start - probe_start;

        if (result.gas_left != expected_result.gas_left)
            out << warning << "(gas used: " << (msg.gas - result.gas_left) << ")\n";
        if (bytes_view{result.output_data, result.output_size} !=
            bytes_view{expected_result.output_data, expected_result.output_size})
            out << warning << "(output: " << hex({result.output_data, result.output_size}) << ")\n";

        // Benchmark loop.
        const auto num_iterations = std::max(static_cast<int>(target_bench_time / probe_time), 1);
        for (int i = 0; i < num_iterations; ++i)
            vm.execute(host, rev, msg, code.data(), code.size());
        const auto bench_time = (clock::now() - bench_start) / num_iterations;

        out << "Time:     " << std::chrono::duration_cast<unit>(bench_time).count() << unit_name
            << " (avg of " << num_iterations << " iterations)\n";
    }
}
}  // namespace

int run(ivmc::VM& vm,
        ivmc_revision rev,
        int64_t gas,
        const std::string& code_hex,
        const std::string& input_hex,
        const std::string& storage_hex,
        const std::string& recipient,
        const std::string& sender,
        bool create,
        bool bench,
        std::ostream& out)
{
    out << (create ? "Creating and executing on " : "Executing on ") << rev << " with " << gas << " gas limit\n";

    const bytes code = ivmc::from_hex(code_hex);
    const bytes input = ivmc::from_hex(input_hex);

    const char *storage_c = storage_hex.c_str();
    const bytes32 storage = from_hex32(storage_c);
    // std::string storage_s = "00000000000001234560000000000000000000000000000000000000000000ea";
    // bytes32 storage = from_hex32(storage_c);

    MockedHost host;

    auto recipient_add = address{};
    std::copy(recipient.begin(), recipient.end(), std::begin(recipient_add.bytes));

    auto sender_add = address{};
    std::copy(sender.begin(), sender.end(), std::begin(sender_add.bytes));

    ivmc_message msg{};
    msg.gas = gas;
    msg.input_data = input.data();
    msg.input_size = input.size();
    msg.recipient = create_address;
    msg.sender = create_address;

    // const ivmc_bytes32 storage_key3 = 0x82eca1b50a096e7f1e065cf3528c2ebeb8041672321732640dfe1bdb94c5225c_bytes32;
    const ivmc_bytes32 storage_key3 = {};

    bytes_view exec_code = code;
    if (create)
    {
        ivmc_message create_msg{};
        create_msg.kind = IVMC_CREATE;
        create_msg.recipient = create_address;
        create_msg.gas = create_gas;

        const auto create_result = vm.execute(host, rev, create_msg, code.data(), code.size());
        if (create_result.status_code != IVMC_SUCCESS)
        {
            out << "Contract creation failed: " << create_result.status_code << "\n";
            return create_result.status_code;
        }

        auto& created_account = host.accounts[create_address];
        created_account.code = bytes(create_result.output_data, create_result.output_size);

        msg.recipient = create_address;
        exec_code = created_account.code;

        int key_size_ = sizeof(msg.recipient.bytes) / sizeof(msg.recipient.bytes[0]);
        std::ostringstream convert;
        for (int a = 0; a < key_size_; a++) {
            convert << std::hex << (int)msg.recipient.bytes[a];
        }

        std::string key_string = convert.str();
        out << "Address:   " << key_string << "\n";
    }
    out << "\n";

    if(storage_hex != "") host.set_storage(msg.recipient, storage_key3, storage);

    auto result = vm.execute(host, rev, msg, exec_code.data(), exec_code.size());

    if (bench)
        tooling::bench(host, vm, rev, msg, exec_code, result, out);

    const auto gas_used = msg.gas - result.gas_left;
    out << "Result:   " << result.status_code << "\nGas used: " << gas_used << "\n";

    if (result.status_code == IVMC_SUCCESS || result.status_code == IVMC_REVERT)
        out << "Output:   " << hex({result.output_data, result.output_size}) << "\n";

    if(host.account_exists(msg.recipient)){

      ivmc_bytes32 storage_value3 = host.get_storage(msg.recipient, storage_key3);

      std::ostringstream convert3;
      for (int i = 0; i < sizeof(storage_value3.bytes) / sizeof(storage_value3.bytes[0]); i++){
          convert3 << std::setw(2) << std::setfill('0') << std::hex << (int)storage_value3.bytes[i];
          // out << std::to_string(i+1)+":   " << std::hex << (int)storage_value3.bytes[i] << "\n";
      }

      std::string key_string3 = convert3.str();
      out << "Storage:   " << key_string3 << "\n";

      auto& recipient_account = host.accounts[msg.recipient];

      //*******************************************
      bytes _code_account = recipient_account.code;

      std::ostringstream convert4;
      for (int i = 0; i < sizeof(_code_account) / sizeof(_code_account[0]); i++){
          convert4 << std::setw(2) << std::setfill('0') << std::hex << (int)_code_account[i];
          // out << std::to_string(i+1)+":   " << std::hex << (int)_code_account[i] << "\n";
      }

      std::string key_string4 = convert4.str();
      out << "Code:   " << key_string4 << "\n";
      out << "\n";

      MockedHost host2;

      ivmc_message msg2{};
      msg2.gas = gas;
      msg2.input_data = input.data();
      msg2.input_size = input.size();
      msg2.recipient = create_address;
      msg2.sender = create_address;

      out << "Count accounts:   " << host.accounts.size() << "\n";

      const char *__storage_c = key_string3.c_str();
      const bytes32 __storage = from_hex32(__storage_c);
      const bytes __code_account = ivmc::from_hex(key_string4);

      auto& __recipient_account = host.accounts[msg.recipient];
      out << "Count Storage:   " << __recipient_account.storage.size() << "\n";

      // Address
      std::ostringstream convert7;
      for (int i = 0; i < sizeof(msg.recipient.bytes) / sizeof(msg.recipient.bytes[0]); i++){
          convert7 << std::setw(2) << std::setfill('0') << std::hex << (int)msg.recipient.bytes[i];
      }
      std::string key_string7 = convert7.str();

      std::string full_address_storage = key_string7;

      // Storage
      int c = 0;
      auto it = __recipient_account.storage.begin();
      while(it != __recipient_account.storage.end())
      {
          std::ostringstream convert5;
          for (int i = 0; i < sizeof(it->first.bytes) / sizeof(it->first.bytes[0]); i++){
              convert5 << std::setw(2) << std::setfill('0') << std::hex << (int)it->first.bytes[i];
          }
          std::string key_string5 = convert5.str();

          std::ostringstream convert6;
          for (int i = 0; i < sizeof(((storage_value)it->second).value.bytes) / sizeof(((storage_value)it->second).value.bytes[0]); i++){
              convert6 << std::setw(2) << std::setfill('0') << std::hex << (int)((storage_value)it->second).value.bytes[i];
          }
          std::string key_string6 = convert6.str();

          out << std::to_string(++c) + ":   " << key_string5 + " - " << key_string6 << "\n";
          out << "\n";

          full_address_storage += key_string5 + key_string6;

          // Set up
          const char *_key_string5 = key_string5.c_str();
          const ivmc_bytes32 __storage_key3 =  from_hex32(_key_string5);
          const char *_key_string6 = key_string6.c_str();
          const ivmc_bytes32 __storage_value =  from_hex32(_key_string6);

          host2.set_storage(msg2.recipient, __storage_key3, __storage_value);

          it++;
      }

      auto result2 = vm.execute(host2, rev, msg2, result.output_data, result.output_size);

      const auto gas_used2 = msg2.gas - result2.gas_left;
      out << "Result2:   " << result2.status_code << "\nGas used2: " << gas_used2 << "\n";

      if (result2.status_code == IVMC_SUCCESS || result2.status_code == IVMC_REVERT)
          out << "Output2:   " << hex({result2.output_data, result2.output_size}) << "\n";

      out << "Storage2:   " << full_address_storage << "\n";
    }

    return 0;
}

}  // namespace ivmc::tooling
