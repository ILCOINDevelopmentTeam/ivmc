# IVMC: Ethereum Client-VM Connector API.
# Copyright 2019 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

add_library(mocked_host INTERFACE)
target_sources(mocked_host INTERFACE $<BUILD_INTERFACE:${IVMC_INCLUDE_DIR}/ivmc/mocked_host.hpp>)

add_library(ivmc::mocked_host ALIAS mocked_host)
target_link_libraries(mocked_host INTERFACE ivmc::ivmc_cpp)

if(IVMC_INSTALL)
    install(TARGETS mocked_host EXPORT ivmcTargets)
endif()
