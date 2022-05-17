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
#include <syslog.h>

namespace ivmc::tooling
{
namespace
{
/// The address where a new contract is created with --create option.
constexpr auto create_address = 0xc9ea7ed000000000000000000000000000000001_address;

const int ADDRESS_SIZE = 40;
const int STORAGE_SIZE = 64;

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

    std::string full_address_storage_tmp = storage_hex;

    int pos_str = 0;
    int len_str = ADDRESS_SIZE;
    std::string storage_address_string = full_address_storage_tmp.substr(pos_str, len_str);

    if(!storage_address_string.empty()){

      bytes storage_address_bytes = ivmc::from_hex(storage_address_string);
      auto storage_address = address{};
      std::copy(storage_address_bytes.begin(), storage_address_bytes.end(), std::begin(storage_address.bytes));

      std::string storage_key_string;
      std::string storage_value_string;

      int _i = 0;

      do {
        pos_str += len_str;
        len_str = STORAGE_SIZE;
        storage_key_string = pos_str < full_address_storage_tmp.length() ? full_address_storage_tmp.substr(pos_str, len_str) : "";

        pos_str += len_str;
        len_str = STORAGE_SIZE;
        storage_value_string = pos_str < full_address_storage_tmp.length() ? full_address_storage_tmp.substr(pos_str, len_str) : "";

        if(!storage_key_string.empty() && !storage_value_string.empty()){

          // Set up
          const char *_storage_key_c = storage_key_string.c_str();
          const ivmc_bytes32 __storage_key_c =  from_hex32(_storage_key_c);
          const char *_storage_value_c = storage_value_string.c_str();
          const ivmc_bytes32 __storage_value_c =  from_hex32(_storage_value_c);

          host.set_storage(storage_address, __storage_key_c, __storage_value_c);
          // out << "iiii:   " << ++_i << " : " << storage_key_string << " : " << storage_value_string << "\n";
        }

      } while (!storage_key_string.empty() && !storage_value_string.empty());
    }

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

    auto result = vm.execute(host, rev, msg, exec_code.data(), exec_code.size());

    if (bench)
        tooling::bench(host, vm, rev, msg, exec_code, result, out);

    const auto gas_used = msg.gas - result.gas_left;
    out << "Result:   " << result.status_code << "\nGas used: " << gas_used << "\n";

    if (result.status_code == IVMC_SUCCESS || result.status_code == IVMC_REVERT)
        out << "Output:   " << hex({result.output_data, result.output_size}) << "\n";

    if(host.account_exists(msg.recipient)){

      auto& recipient_account = host.accounts[msg.recipient];

      // out << "Count accounts:   " << host.accounts.size() << "\n";
      // out << "Count Storage:   " << recipient_account.storage.size() << "\n";

      // Address
      std::ostringstream convert7;
      for (int i = 0; i < sizeof(msg.recipient.bytes) / sizeof(msg.recipient.bytes[0]); i++){
          convert7 << std::setw(2) << std::setfill('0') << std::hex << (int)msg.recipient.bytes[i];
      }
      std::string key_string7 = convert7.str();
      std::string full_address_storage = key_string7;

      // Storage
      int c = 0;
      auto it = recipient_account.storage.begin();
      while(it != recipient_account.storage.end())
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

          // out << std::to_string(++c) + ":   " << key_string5 + " - " << key_string6 << "\n";
          // out << "\n";

          full_address_storage += key_string5 + key_string6;

          it++;
      }

      out << "Storage:   " << full_address_storage << "\n";
    }

    return 0;
}

MockedHost host2;

int run2(ivmc::VM& vm,
        ivmc_revision rev,
        int64_t gas,
        const std::string& code_hex,
        const std::string& input_hex,
        const std::string& storage_hex,
        const std::string& recipient,
        const std::string& sender,
        std::ostream& out)
{
    out << "Executing on " << rev << " with " << gas << " gas limit\n";

    const bytes code = ivmc::from_hex(code_hex);
    const bytes input = ivmc::from_hex(input_hex);

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

    syslog(LOG_NOTICE, ("Code: " + code_hex).c_str());
    syslog(LOG_NOTICE, ("Input: " + input_hex).c_str());
    syslog(LOG_NOTICE, ("Storage: " + storage_hex).c_str());

    // Read Index ordered from vector.

    // End

    // Read the data where index points and load it into host.

    // End
    std::string full_address_storage_tmp = storage_hex;

    int pos_str = 0;
    int len_str = ADDRESS_SIZE;
    std::string storage_address_string = full_address_storage_tmp.substr(pos_str, len_str);

    if(!storage_address_string.empty()){

      bytes storage_address_bytes = ivmc::from_hex(storage_address_string);
      auto storage_address = address{};
      std::copy(storage_address_bytes.begin(), storage_address_bytes.end(), std::begin(storage_address.bytes));

      std::string storage_key_string;
      std::string storage_value_string;

      int _i = 0;

      do {
        pos_str += len_str;
        len_str = STORAGE_SIZE;
        storage_key_string = pos_str < full_address_storage_tmp.length() ? full_address_storage_tmp.substr(pos_str, len_str) : "";

        pos_str += len_str;
        len_str = STORAGE_SIZE;
        storage_value_string = pos_str < full_address_storage_tmp.length() ? full_address_storage_tmp.substr(pos_str, len_str) : "";

        if(!storage_key_string.empty() && !storage_value_string.empty()){

          // Set up
          const char *_storage_key_c = storage_key_string.c_str();
          const ivmc_bytes32 __storage_key_c =  from_hex32(_storage_key_c);
          const char *_storage_value_c = storage_value_string.c_str();
          const ivmc_bytes32 __storage_value_c =  from_hex32(_storage_value_c);

          host2.set_storage(storage_address, __storage_key_c, __storage_value_c);
          // out << "iiii:   " << ++_i << " : " << storage_key_string << " : " << storage_value_string << "\n";
        }

      } while (!storage_key_string.empty() && !storage_value_string.empty());
    }

    const ivmc_bytes32 storage_key3 = {};

    bytes_view exec_code = code;
    out << "\n";

    auto result = vm.execute(host2, rev, msg, exec_code.data(), exec_code.size());

    const auto gas_used = msg.gas - result.gas_left;
    out << "Result:   " << result.status_code << "\nGas used: " << gas_used << "\n";

    syslog(LOG_NOTICE, ("Result: " + std::to_string(result.status_code)).c_str());
    syslog(LOG_NOTICE, ("Gas used: " + std::to_string(gas_used)).c_str());

    if (result.status_code == IVMC_SUCCESS || result.status_code == IVMC_REVERT){
      out << "Output:   " << hex({result.output_data, result.output_size}) << "\n";
      syslog(LOG_NOTICE, ("Output: " + hex({result.output_data, result.output_size})).c_str());
    }

    if(host2.account_exists(msg.recipient)){

      auto& recipient_account = host2.accounts[msg.recipient];

      // out << "Count accounts:   " << host2.accounts.size() << "\n";
      // out << "Count Storage:   " << recipient_account.storage.size() << "\n";

      // Address
      std::ostringstream convert7;
      for (int i = 0; i < sizeof(msg.recipient.bytes) / sizeof(msg.recipient.bytes[0]); i++){
          convert7 << std::setw(2) << std::setfill('0') << std::hex << (int)msg.recipient.bytes[i];
      }
      std::string key_string7 = convert7.str();
      std::string full_address_storage = key_string7;

      // Storage
      int c = 0;
      auto it = recipient_account.storage.begin();
      while(it != recipient_account.storage.end())
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

          // out << std::to_string(++c) + ":   " << key_string5 + " - " << key_string6 << "\n";
          // out << "\n";

          full_address_storage += key_string5 + key_string6;

          it++;
      }

      out << "Storage:   " << full_address_storage << "\n";
      syslog(LOG_NOTICE, ("Storage: " + full_address_storage).c_str());

      // Write Index ordered from vector in index.dat file

      // End

      // Write the data where index points in storage.dat file

      // End
    }

    return 0;
}

}  // namespace ivmc::tooling
