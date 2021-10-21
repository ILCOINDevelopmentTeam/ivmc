# IVMC: Ethereum Client-VM Connector API.
# Copyright 2019-2020 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

add_library(example-vm SHARED example_vm.cpp example_vm.h)
add_library(ivmc::example-vm ALIAS example-vm)
target_compile_features(example-vm PRIVATE cxx_std_11)
target_link_libraries(example-vm PRIVATE ivmc::ivmc)

add_library(example-vm-static STATIC example_vm.cpp example_vm.h)
add_library(ivmc::example-vm-static ALIAS example-vm-static)
target_compile_features(example-vm-static PRIVATE cxx_std_11)
target_link_libraries(example-vm-static PRIVATE ivmc::ivmc)

set_source_files_properties(example_vm.cpp PROPERTIES
    COMPILE_DEFINITIONS PROJECT_VERSION="${PROJECT_VERSION}")

if(IVMC_INSTALL)
    install(TARGETS example-vm
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()
