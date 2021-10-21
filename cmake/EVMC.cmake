# IVMC: Ethereum Client-VM Connector API.
# Copyright 2019 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.


# Adds a CMake test to check the given IVMC VM implementation with the ivmc-vmtester tool.
#
# ivmc_add_vm_test(NAME <test_name> TARGET <vm>)
# - NAME argument specifies the name of the added test,
# - TARGET argument specifies the CMake target being a shared library with IVMC VM implementation.
function(ivmc_add_vm_test)
    if(NOT TARGET ivmc::ivmc-vmtester)
        message(FATAL_ERROR "The ivmc-vmtester has not been installed with this IVMC package")
    endif()

    cmake_parse_arguments("" "" NAME;TARGET "" ${ARGN})
    add_test(NAME ${_NAME} COMMAND $<TARGET_FILE:ivmc::ivmc-vmtester> $<TARGET_FILE:${_TARGET}>)
endfunction()
