/* IVMC: Ethereum Client-VM Connector API.
 * Copyright 2018-2019 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 */

/** This example shows how to use ivmc::instructions library from ivmc CMake package. */

#include <ivmc/instructions.h>

int main()
{
    return ivmc_get_instruction_metrics_table(IVMC_BYZANTIUM)[OP_STOP].gas_cost;
}
