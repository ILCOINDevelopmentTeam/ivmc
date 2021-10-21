# IVMC: Ethereum Client-VM Connector API.
# Copyright 2018-2019 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

include(GoogleTest)

hunter_add_package(GTest)
find_package(GTest CONFIG REQUIRED)

# Disable support for std::tr1::tuple in GTest. This causes problems in Visual Studio 2015.
set_target_properties(GTest::gtest PROPERTIES INTERFACE_COMPILE_DEFINITIONS GTEST_HAS_TR1_TUPLE=0)

add_library(loader-mocked STATIC ${PROJECT_SOURCE_DIR}/lib/loader/loader.c)
target_link_libraries(loader-mocked PRIVATE ivmc::ivmc)
target_compile_definitions(loader-mocked PRIVATE IVMC_LOADER_MOCK=1)

add_executable(
    ivmc-unittests
    cpp_test.cpp
    example_vm_test.cpp
    helpers_test.cpp
    instructions_test.cpp
    loader_mock.h
    loader_test.cpp
    mocked_host_test.cpp
    tooling_test.cpp
    hex_test.cpp
)

target_link_libraries(
    ivmc-unittests
    PRIVATE
    loader-mocked
    ivmc::example-vm-static
    ivmc::example-precompiles-vm-static
    ivmc::instructions
    ivmc::ivmc_cpp
    ivmc::tooling
    ivmc::hex
    GTest::gtest_main
)
target_include_directories(ivmc-unittests PRIVATE ${PROJECT_SOURCE_DIR})

gtest_add_tests(TARGET ivmc-unittests TEST_PREFIX ${PROJECT_NAME}/unittests/ TEST_LIST unittests)

set_tests_properties(${unittests} PROPERTIES ENVIRONMENT LLVM_PROFILE_FILE=${CMAKE_BINARY_DIR}/unittests-%p.profraw)
