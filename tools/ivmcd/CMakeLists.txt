# IVMC: Ethereum Client-VM Connector API.
# Copyright 2019-2022 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

hunter_add_package(CLI11)
find_package(CLI11 REQUIRED)

link_libraries( -levent -pthread -levent_pthreads -lboost_system -lboost_thread -lboost_filesystem -lssl -lcrypto)

add_executable(ivmc-deamon deamon.cpp)
add_executable(ivmc::deamon ALIAS ivmc-deamon)
set_target_properties(ivmc-deamon PROPERTIES OUTPUT_NAME ivmcd)
set_source_files_properties(deamon.cpp PROPERTIES
    COMPILE_DEFINITIONS PROJECT_VERSION="${PROJECT_VERSION}")
target_link_libraries(ivmc-deamon PRIVATE ivmc::tooling ivmc::loader CLI11::CLI11)
