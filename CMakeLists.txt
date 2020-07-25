cmake_minimum_required(VERSION 3.13)
project(windows-fido-bridge)

option(BUILD_LINUX_TARGET "Build the Linux OpenSSH middleware library" ON)
option(BUILD_WINDOWS_TARGET "Build the Windows WebAuthN API bridge executable" ON)

# Used to prevent two copies of the Windows bridge executable from being
# included in a CPack package.
#
# The default component name (if not specified in an install() command) is
# literally "Unspecified" sans quotes, see docs here:
# https://cmake.org/cmake/help/v3.16/variable/CMAKE_INSTALL_DEFAULT_COMPONENT_NAME.html
option(WINDOWS_TARGET_COMPONENT_NAME "The component to install the Windows executable to" Unspecified)

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
    set(windows_prefix nested-windows-build)
    set(windows_install_dir ${CMAKE_BINARY_DIR}/${windows_prefix}/install)
    ExternalProject_Add(
        nested_windows
        PREFIX ${windows_prefix}
        SOURCE_DIR ${CMAKE_SOURCE_DIR}
        CMAKE_ARGS
            -DBUILD_LINUX_TARGET=OFF
            -DBUILD_WINDOWS_TARGET=ON
            -DCMAKE_BUILD_TYPE=$<CONFIG>
            -DCMAKE_INSTALL_PREFIX=${windows_install_dir}
            -DCMAKE_TOOLCHAIN_FILE=${CMAKE_SOURCE_DIR}/cmake/toolchain-mingw64.cmake
            -DWINDOWS_TARGET_COMPONENT_NAME=nested-windows
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

# Only install in a deb
install(FILES "${CMAKE_SOURCE_DIR}/package/deb/copyright"
    DESTINATION share/doc/windows-fido-bridge
    COMPONENT deb
    EXCLUDE_FROM_ALL
)

set(CPACK_GENERATOR DEB)

set(CPACK_PACKAGE_VERSION_MAJOR 1)
set(CPACK_PACKAGE_VERSION_MINOR 0)
set(CPACK_PACKAGE_VERSION_PATCH 0)

set(CPACK_PACKAGE_CONTACT "Matthew Bowen <matthew@mgbowen.com>")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/mgbowen/windows-fido-bridge")

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "\
an OpenSSH security key middleware for WSL \
\n windows-fido-bridge is an OpenSSH security key middleware that allows you \
\n to use a FIDO2/U2F security key (e.g. a YubiKey) to SSH into a remote server \
\n from WSL.")

set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "openssh-client (>=1:8.3)")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

set(CPACK_COMPONENTS_ALL Unspecified deb)
set(CPACK_COMPONENTS_ALL_IN_ONE_PACKAGE ON)
set(CPACK_DEB_COMPONENT_INSTALL ON)

include(CPack)
