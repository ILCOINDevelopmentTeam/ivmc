# IVMC: Ethereum Client-VM Connector API.
# Copyright 2021 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

add_library(tooling STATIC)
add_library(ivmc::tooling ALIAS tooling)
target_compile_features(tooling PUBLIC cxx_std_17)
target_link_libraries(tooling PUBLIC ivmc::ivmc_cpp ivmc::mocked_host ivmc::hex)

target_sources(
    tooling PRIVATE
    ${IVMC_INCLUDE_DIR}/ivmc/tooling.hpp
    run.cpp
)

if(IVMC_INSTALL)
    install(TARGETS tooling EXPORT ivmcTargets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
