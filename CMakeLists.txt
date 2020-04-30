cmake_minimum_required(VERSION 3.13)
project(windows-fido-bridge)

option(BUILD_LINUX_TARGET "Build the Linux OpenSSH middleware library" ON)
option(BUILD_WINDOWS_TARGET "Build the Windows WebAuthN API bridge executable" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH})

find_package(fmt REQUIRED)

enable_testing()
find_package(GTest)
include(GoogleTest)

add_subdirectory(src/common)
add_subdirectory(src/cbor)

if (BUILD_LINUX_TARGET AND BUILD_WINDOWS_TARGET)
    add_subdirectory(src/linux)

    # The Windows target needs to be cross-compiled with MinGW, which is tricky
    # to do when we're also building a native library, so use ExternalProject to
    # create an entirely separate CMake build directory.
    include(ExternalProject)
    set(windows_prefix windows-build)
    set(windows_install_dir ${CMAKE_BINARY_DIR}/${windows_prefix}/install)
    ExternalProject_Add(
        windows
        PREFIX ${windows_prefix}
        SOURCE_DIR ${CMAKE_SOURCE_DIR}
        CMAKE_ARGS
            -DBUILD_LINUX_TARGET=OFF
            -DBUILD_WINDOWS_TARGET=ON
            -DCMAKE_BUILD_TYPE=$<CONFIG>
            -DCMAKE_INSTALL_PREFIX=${windows_install_dir}
            -DCMAKE_TOOLCHAIN_FILE=${CMAKE_SOURCE_DIR}/cmake/toolchain-mingw64.cmake
        BUILD_ALWAYS ON
    )

    install(DIRECTORY ${windows_install_dir}/
        DESTINATION .
        USE_SOURCE_PERMISSIONS
    )
elseif (BUILD_LINUX_TARGET)
    add_subdirectory(src/linux)
elseif (BUILD_WINDOWS_TARGET)
    add_subdirectory(src/windows)
endif()
