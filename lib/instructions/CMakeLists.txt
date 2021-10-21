# IVMC: Ethereum Client-VM Connector API.
# Copyright 2018-2019 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

add_library(
    instructions STATIC
    ${IVMC_INCLUDE_DIR}/ivmc/instructions.h
    instruction_metrics.c
    instruction_names.c
)

add_library(ivmc::instructions ALIAS instructions)
set_target_properties(instructions PROPERTIES
    OUTPUT_NAME ivmc-instructions
    POSITION_INDEPENDENT_CODE TRUE
)
target_include_directories(instructions PUBLIC
    $<BUILD_INTERFACE:${IVMC_INCLUDE_DIR}>$<INSTALL_INTERFACE:include>
)

if(IVMC_INSTALL)
    install(TARGETS instructions EXPORT ivmcTargets DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
