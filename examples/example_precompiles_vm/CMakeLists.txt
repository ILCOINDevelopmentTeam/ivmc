# IVMC: Ethereum Client-VM Connector API.
# Copyright 2019 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

add_library(example-precompiles-vm SHARED example_precompiles_vm.cpp example_precompiles_vm.h)
add_library(ivmc::example-precompiles-vm ALIAS example-precompiles-vm)
target_compile_features(example-precompiles-vm PRIVATE cxx_std_11)
target_link_libraries(example-precompiles-vm PRIVATE ivmc::ivmc)

add_library(example-precompiles-vm-static STATIC example_precompiles_vm.cpp example_precompiles_vm.h)
add_library(ivmc::example-precompiles-vm-static ALIAS example-precompiles-vm-static)
target_compile_features(example-precompiles-vm-static PRIVATE cxx_std_11)
target_link_libraries(example-precompiles-vm-static PRIVATE ivmc::ivmc)

set_source_files_properties(example_precompiles_vm.cpp PROPERTIES
    COMPILE_DEFINITIONS PROJECT_VERSION="${PROJECT_VERSION}")

if(IVMC_INSTALL)
    install(TARGETS example-precompiles-vm
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()
