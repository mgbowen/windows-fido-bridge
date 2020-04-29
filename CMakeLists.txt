cmake_minimum_required(VERSION 3.13)
project(windows_fido_bridge)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH})

find_package(fmt REQUIRED)

enable_testing()
find_package(GTest)
include(GoogleTest)

add_subdirectory(common)
add_subdirectory(cbor)

if (NOT DEFINED TARGET)
    message(FATAL_ERROR "TARGET CMake variable is not defined")
else()
    add_subdirectory(${TARGET})
endif()
