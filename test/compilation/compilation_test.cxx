/* IVMC: Ethereum Client-VM Connector API.
 * Copyright 2018-2019 The IVMC Authors.
 * Licensed under the Apache License, Version 2.0.
 */

// Test compilation of C and C++ public headers.

#include <ivmc/ivmc.h>
#include <ivmc/ivmc.hpp>
#include <ivmc/helpers.h>
#include <ivmc/instructions.h>
#include <ivmc/loader.h>
#include <ivmc/mocked_host.hpp>
#include <ivmc/utils.h>

// Include again to check if headers have proper include guards.
#include <ivmc/ivmc.h>
#include <ivmc/ivmc.hpp>
#include <ivmc/helpers.h>
#include <ivmc/instructions.h>
#include <ivmc/loader.h>
#include <ivmc/mocked_host.hpp>
#include <ivmc/utils.h>
