/* IVMC: Ethereum Client-VM Connector API.
 * Copyright 2018-2019 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 */

#pragma once

#include <ivmc/ivmc.h>
#include <ivmc/utils.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates IVMC Example VM.
 */
IVMC_EXPORT struct ivmc_vm* ivmc_create_example_vm(void);

#ifdef __cplusplus
}
#endif
