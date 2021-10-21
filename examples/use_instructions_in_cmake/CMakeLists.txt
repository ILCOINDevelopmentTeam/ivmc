# IVMC: Ethereum Client-VM Connector API.
# Copyright 2018-2019 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

# This example shows how to use ivmc::instructions library from ivmc CMake package.

cmake_minimum_required(VERSION 3.5)

project(use_instructions_in_cmake)

find_package(ivmc CONFIG REQUIRED)

add_executable(use_instructions_in_cmake use_instructions_in_cmake.c)
target_link_libraries(use_instructions_in_cmake PRIVATE ivmc::instructions)
