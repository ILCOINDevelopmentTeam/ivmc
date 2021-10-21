# IVMC: Ethereum Client-VM Connector API.
# Copyright 2018-2019 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

add_library(
    loader STATIC
    ${IVMC_INCLUDE_DIR}/ivmc/loader.h
    loader.c
)

add_library(ivmc::loader ALIAS loader)
set_target_properties(loader PROPERTIES
    OUTPUT_NAME ivmc-loader
    POSITION_INDEPENDENT_CODE TRUE
)
target_link_libraries(loader INTERFACE ${CMAKE_DL_LIBS} PUBLIC ivmc::ivmc)

if(IVMC_INSTALL)
    install(TARGETS loader EXPORT ivmcTargets DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
