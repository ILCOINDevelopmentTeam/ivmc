/* IVMC: Ethereum Client-VM Connector API.
 * Copyright 2016-2019 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 */

#include <ivmc/ivmc.h>

#if __cplusplus
extern "C" {
#endif

const struct ivmc_host_interface* example_host_get_interface();

struct ivmc_host_context* example_host_create_context(struct ivmc_tx_context tx_context);

void example_host_destroy_context(struct ivmc_host_context* context);

#if __cplusplus
}
#endif
