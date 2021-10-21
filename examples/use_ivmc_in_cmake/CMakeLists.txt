# IVMC: Ethereum Client-VM Connector API.
# Copyright 2018-2019 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

# This example shows how to use ivmc INTERFACE library from ivmc CMake package.

cmake_minimum_required(VERSION 3.5)

project(use_ivmc_in_cmake)

find_package(ivmc CONFIG REQUIRED)

add_executable(use_ivmc_in_cmake use_ivmc_in_cmake.c)
target_link_libraries(use_ivmc_in_cmake PRIVATE ivmc::ivmc)



# Only for integration tests.
if(NOT COMMAND ivmc_add_vm_test)
    message(FATAL_ERROR "Function ivmc_add_vm_test() not in IVMC.cmake module")
endif()
