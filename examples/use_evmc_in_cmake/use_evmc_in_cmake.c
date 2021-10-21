/* IVMC: Ethereum Client-VM Connector API.
 * Copyright 2018-2019 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 */

/** This example shows how to use ivmc INTERFACE library from ivmc CMake package. */

#include <ivmc/ivmc.h>

int main()
{
    struct ivmc_vm vm = {.abi_version = IVMC_ABI_VERSION};
    return vm.abi_version - IVMC_ABI_VERSION;
}
