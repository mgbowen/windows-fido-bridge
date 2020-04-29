cmake_minimum_required(VERSION 3.13)
project(windows-fido-bridge)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH})

find_package(fmt REQUIRED)

enable_testing()
find_package(GTest)
include(GoogleTest)

add_subdirectory(src/common)
add_subdirectory(src/cbor)

if(BUILD_TARGET STREQUAL linux)
    add_subdirectory(src/linux)
elseif(BUILD_TARGET STREQUAL windows)
    add_subdirectory(src/windows)
else()
    message(FATAL_ERROR "BUILD_TARGET CMake variable is not defined")
endif()
