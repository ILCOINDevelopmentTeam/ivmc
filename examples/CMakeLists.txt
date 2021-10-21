# IVMC: Ethereum Client-VM Connector API.
# Copyright 2016-2019 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

include(GNUInstallDirs)

add_subdirectory(example_vm)
add_subdirectory(example_precompiles_vm)

add_library(ivmc-example-host STATIC example_host.cpp)
target_link_libraries(ivmc-example-host PRIVATE ivmc::ivmc_cpp)

add_executable(ivmc-example-static example.c)
target_link_libraries(ivmc-example-static PRIVATE ivmc-example-host ivmc::example-vm-static ivmc::ivmc)
target_compile_definitions(ivmc-example-static PRIVATE STATICALLY_LINKED_EXAMPLE)

add_executable(ivmc-example example.c)
target_link_libraries(ivmc-example PRIVATE ivmc-example-host ivmc::loader)
