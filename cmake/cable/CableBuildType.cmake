# Cable: CMake Bootstrap Library <https://github.com/ILCOINDevelopmentTeam/cable>
# Copyright 2018-2019 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

# Cable Build Type, version 1.0.0
#
# This CMake module helps with setting default build type
# and build configurations for multi-configuration generators.
# Use cable_set_build_type().


if(cable_build_type_included)
    return()
endif()
set(cable_build_type_included TRUE)

macro(cable_set_build_type)
    if(NOT PROJECT_SOURCE_DIR)  # Before the main project().
        cmake_parse_arguments(build_type "" DEFAULT CONFIGURATION_TYPES ${ARGN})

        if(CMAKE_CONFIGURATION_TYPES)
            if(build_type_CONFIGURATION_TYPES)
                set(
                    CMAKE_CONFIGURATION_TYPES
                    ${build_type_CONFIGURATION_TYPES}
                    CACHE
                    STRING
                    "Available configurations for multi-configuration generators"
                    FORCE
                )
            endif()
            message(STATUS "Configurations: ${CMAKE_CONFIGURATION_TYPES}")
        else()
            if(build_type_DEFAULT AND NOT CMAKE_BUILD_TYPE)
                set(
                    CMAKE_BUILD_TYPE
                    ${build_type_DEFAULT}
                    CACHE STRING
                    "Build type for single-configuration generators"
                    FORCE
                )
            endif()
            message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
        endif()
    elseif(PROJECT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)  # After the main project().
        message(FATAL_ERROR "cable_set_build_type() must be used before project()")
    endif()  # Sub-project - silently ignore.
endmacro()
