cmake_minimum_required(VERSION 3.16)
project(windows_fido_bridge)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH})

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost REQUIRED)

find_package(nlohmann_json REQUIRED)
find_package(fmt REQUIRED)

enable_testing()
find_package(GTest REQUIRED)
include(GoogleTest)

add_subdirectory(common)

if (NOT DEFINED TARGET)
    message(FATAL_ERROR "TARGET CMake variable is not defined")
else()
    add_subdirectory(${TARGET})
endif()
