# IVMC: Ethereum Client-VM Connector API.
# Copyright 2016-2020 The IVMC Authors.
# Licensed under the Apache License, Version 2.0.

cmake_minimum_required(VERSION 3.10)

if(POLICY CMP0074)
    cmake_policy(SET CMP0074 NEW)
endif()

if(TARGET ivmc)
    # The ivmc library has been already created (probably by other submodule).
    return()
endif()

include(cmake/cable/bootstrap.cmake)
include(CableBuildType)
include(CableCompilerSettings)
include(CablePackage)
include(CMakeDependentOption)
include(CMakePackageConfigHelpers)

option(IVMC_JAVA "Enable building Java Native Interface (JNI) bindings" OFF)

option(IVMC_INSTALL "Enable IVMC installation (e.g. make install)" ON)

option(IVMC_TESTING "Build everything (libraries, tools, examples, internal tests)" OFF)

cmake_dependent_option(IVMC_TOOLS "Build IVMC tools" OFF
    "NOT IVMC_TESTING" ON)

cmake_dependent_option(IVMC_EXAMPLES "Build IVMC examples" OFF
    "NOT IVMC_TESTING" ON)

option(HUNTER_ENABLED "Enable Hunter package manager support" ${IVMC_TOOLS})

if(HUNTER_ENABLED)
    set(HUNTER_CONFIGURATION_TYPES Release CACHE STRING "Build type of Hunter packages")
    option(HUNTER_USE_CACHE_SERVERS "Use default Hunter cache servers" NO)
    include(HunterGate)
    include(Hunter/init)
endif()

cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Debug Release)

project(ivmc)
set(PROJECT_VERSION 10.0.0-alpha.1)

include(GNUInstallDirs)  # Must be included after any language is enabled.
if(NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    # By default put every executable in top-level /bin dir.
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR})
endif()


cable_configure_compiler(NO_STACK_PROTECTION)
if(CABLE_COMPILER_GNULIKE)
    # TODO: Resolve issues or remove "result optional storage" and enable -Wcast-align.
    add_compile_options(-Wmissing-declarations)
    cable_add_cxx_compiler_flag_if_supported(-Wfinal-dtor-non-final-class)
    cable_add_cxx_compiler_flag_if_supported(-Wnewline-eof)
    cable_add_cxx_compiler_flag_if_supported(-Wsuggest-destructor-override)
    cable_add_cxx_compiler_flag_if_supported(-Wunreachable-code-break)
    cable_add_cxx_compiler_flag_if_supported(-Wduplicated-cond)
    cable_add_cxx_compiler_flag_if_supported(-Wduplicate-enum)
    cable_add_cxx_compiler_flag_if_supported(-Wlogical-op)
endif()
if(CABLE_COMPILER_CLANG)
    set(CMAKE_C_FLAGS_COVERAGE "-fprofile-instr-generate -fcoverage-mapping")
    set(CMAKE_CXX_FLAGS_COVERAGE "-fprofile-instr-generate -fcoverage-mapping")
elseif(CABLE_COMPILER_GNU)
    set(CMAKE_C_FLAGS_COVERAGE "--coverage")
    set(CMAKE_CXX_FLAGS_COVERAGE "--coverage")
endif()

set(IVMC_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)

add_subdirectory(lib)

if(IVMC_JAVA)
    add_subdirectory(bindings/java)
endif()

if(IVMC_TOOLS)
    add_subdirectory(tools)
endif()

if(IVMC_EXAMPLES)
    add_subdirectory(examples)
endif()

if(IVMC_TESTING)
    enable_testing()
    add_subdirectory(test)
endif()

write_basic_package_version_file(ivmcConfigVersion.cmake COMPATIBILITY ExactVersion)

configure_package_config_file(
    cmake/Config.cmake.in
    ivmcConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ivmc
)

if(IVMC_INSTALL)
    install(DIRECTORY include/ivmc DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

    install(
        EXPORT ivmcTargets
        NAMESPACE ivmc::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ivmc
    )
    install(
        FILES
        ${CMAKE_CURRENT_BINARY_DIR}/ivmcConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/ivmcConfigVersion.cmake
        cmake/IVMC.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ivmc
    )
endif()

set(
    CPACK_SOURCE_IGNORE_FILES
    /\\\\.git/
    /\\\\.idea/
    /build/
    /cmake-build-.*/
    /bindings/
    /Cargo.lock
    /Cargo.toml
    /target/
)
cable_add_archive_package()
