# IVMC: Ethereum Client-VM Connector API.
# Copyright 2018-2020 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

add_library(ivmc INTERFACE)
add_library(ivmc::ivmc ALIAS ivmc)
target_compile_features(ivmc INTERFACE c_std_99)
target_include_directories(ivmc INTERFACE $<BUILD_INTERFACE:${IVMC_INCLUDE_DIR}>$<INSTALL_INTERFACE:include>)

add_library(ivmc_cpp INTERFACE)
add_library(ivmc::ivmc_cpp ALIAS ivmc_cpp)
target_compile_features(ivmc_cpp INTERFACE cxx_std_17)
target_include_directories(ivmc_cpp INTERFACE $<BUILD_INTERFACE:${IVMC_INCLUDE_DIR}>$<INSTALL_INTERFACE:include>)
target_link_libraries(ivmc_cpp INTERFACE ivmc::ivmc)

add_subdirectory(hex)
add_subdirectory(instructions)
add_subdirectory(loader)
add_subdirectory(mocked_host)
add_subdirectory(tooling)

if(IVMC_INSTALL)
    install(TARGETS ivmc ivmc_cpp EXPORT ivmcTargets)
endif()
