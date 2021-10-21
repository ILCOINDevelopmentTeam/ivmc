# IVMC: Ethereum Client-VM Connector API.
# Copyright 2018-2019 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

include(IVMC)

set(prefix ${PROJECT_NAME}/vmtester)

ivmc_add_vm_test(NAME ${prefix}/examplevm TARGET example-vm)
ivmc_add_vm_test(NAME ${prefix}/example_precompiles_vm TARGET example-precompiles-vm)

add_test(NAME ${prefix}/help COMMAND ivmc::ivmc-vmtester --version --help)
set_tests_properties(${prefix}/help PROPERTIES PASS_REGULAR_EXPRESSION "Usage:")

add_test(NAME ${prefix}/nonexistingvm COMMAND ivmc::ivmc-vmtester nonexistingvm)
set_tests_properties(${prefix}/nonexistingvm PROPERTIES PASS_REGULAR_EXPRESSION "[Cc]annot open")

add_test(NAME ${prefix}/noarg COMMAND ivmc::ivmc-vmtester)
set_tests_properties(${prefix}/noarg PROPERTIES PASS_REGULAR_EXPRESSION "is required")

add_test(NAME ${prefix}/too-many-args COMMAND ivmc::ivmc-vmtester a b)
set_tests_properties(${prefix}/too-many-args PROPERTIES PASS_REGULAR_EXPRESSION "Unexpected")

add_test(NAME ${prefix}/version COMMAND ivmc::ivmc-vmtester --version)
set_tests_properties(${prefix}/version PROPERTIES PASS_REGULAR_EXPRESSION ${PROJECT_VERSION})

add_test(NAME ${prefix}/unknown-option COMMAND ivmc::ivmc-vmtester --verbose)
set_tests_properties(${prefix}/unknown-option PROPERTIES PASS_REGULAR_EXPRESSION "Unknown")

add_test(NAME ${prefix}/option-long-prefix COMMAND ivmc::ivmc-vmtester ---)
set_tests_properties(${prefix}/option-long-prefix PROPERTIES PASS_REGULAR_EXPRESSION "Unknown")

get_property(vmtester_tests DIRECTORY PROPERTY TESTS)
set_tests_properties(${vmtester_tests} PROPERTIES ENVIRONMENT LLVM_PROFILE_FILE=${CMAKE_BINARY_DIR}/vmtester-%p.profraw)
