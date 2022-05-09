// IVMC: Ethereum Client-VM Connector API.
// Copyright 2020 The IVMC Authors.
// Licensed under the Apache License, Version 2.0.

#include <ivmc/ivmc.hpp>
#include <iosfwd>
#include <string>

namespace ivmc::tooling
{
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
        std::ostream& out);


int run2(ivmc::VM& vm,
        ivmc_revision rev,
        int64_t gas,
        const std::string& code_hex,
        const std::string& input_hex,
        const std::string& storage_hex,
        const std::string& recipient,
        const std::string& sender,
        std::ostream& out);
}  // namespace ivmc::tooling
