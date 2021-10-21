# IVMC: Ethereum Client-VM Connector API.
# Copyright 2019-2020 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

hunter_add_package(CLI11)
find_package(CLI11 REQUIRED)

add_executable(ivmc-tool main.cpp)
add_executable(ivmc::tool ALIAS ivmc-tool)
set_target_properties(ivmc-tool PROPERTIES OUTPUT_NAME ivmc)
set_source_files_properties(main.cpp PROPERTIES
    COMPILE_DEFINITIONS PROJECT_VERSION="${PROJECT_VERSION}")
target_link_libraries(ivmc-tool PRIVATE ivmc::tooling ivmc::loader CLI11::CLI11)
