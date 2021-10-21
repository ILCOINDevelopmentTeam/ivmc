# IVMC: Ethereum Client-VM Connector API.
# Copyright 2020 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

include(UseJava)

find_package(Java REQUIRED COMPONENTS Development)
find_package(JNI REQUIRED)

add_jar(ivmc-jar
    OUTPUT_NAME ivmc-java
    VERSION ${PROJECT_VERSION}
    SOURCES
    java/src/main/java/org/ethereum/ivmc/IvmcLoaderException.java
    java/src/main/java/org/ethereum/ivmc/IvmcVm.java
    java/src/main/java/org/ethereum/ivmc/Host.java
    java/src/main/java/org/ethereum/ivmc/HostContext.java
    GENERATE_NATIVE_HEADERS ivmc-java-native-headers)

add_library(ivmc-java SHARED)
target_sources(ivmc-java PRIVATE
    c/ivmc-vm.c
    c/host.c
    c/host.h)
target_include_directories(ivmc-java PRIVATE ${JNI_INCLUDE_DIRS})
target_link_libraries(ivmc-java PRIVATE ivmc-java-native-headers ivmc::ivmc ivmc::loader ${JNI_LIBRARIES})

if(IVMC_INSTALL)
    install(TARGETS ivmc-java EXPORT ivmcTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    install_jar(ivmc-jar DESTINATION ${CMAKE_INSTALL_DATADIR}/java)
endif()