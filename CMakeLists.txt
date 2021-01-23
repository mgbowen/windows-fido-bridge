cmake_minimum_required(VERSION 3.13)
project(windows-fido-bridge)

option(BUILD_LINUX_TARGET "Build the Linux OpenSSH middleware library" ON)
option(BUILD_WINDOWS_TARGET "Build the Windows WebAuthN API bridge executable" ON)
option(BUILD_TESTS "Build tests" ON)

# Configurable OpenSSH security key API version
set(SK_API_VERSION 5 CACHE STRING "OpenSSH security key API version to target")
list(APPEND VALID_SK_API_VERSIONS 5 7)
if (NOT SK_API_VERSION IN_LIST VALID_SK_API_VERSIONS)
    message(FATAL_ERROR "Unrecognized OpenSSH security key API version \"${SK_API_VERSION}\"")
endif()

# Used to prevent two copies of the Windows bridge executable from being
# included in a CPack package.
#
# The default component name (if not specified in an install() command) is
# literally "Unspecified" sans quotes, see docs here:
# https://cmake.org/cmake/help/v3.16/variable/CMAKE_INSTALL_DEFAULT_COMPONENT_NAME.html
option(WINDOWS_TARGET_COMPONENT_NAME "The component to install the Windows executable into" Unspecified)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH})

set(CMAKE_CXX_STANDARD 20)

# Needed to link static libfmt.a into the Linux shared library target.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(DetectWSL)
include(Util)

# 3P dependencies.
include(BuildMingwStdThreads)
include(BuildFmt)
include(BuildSpdlog)
include(BuildGoogleTest)

if (BUILD_TESTS)
    enable_testing()
endif()

include(GoogleTest)

add_subdirectory(src/common)

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
            "-DCMAKE_BUILD_TYPE=$<CONFIG>"
            "-DCMAKE_INSTALL_PREFIX=${windows_install_dir}"
            "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_SOURCE_DIR}/cmake/toolchain-mingw64.cmake"
            -DWINDOWS_TARGET_COMPONENT_NAME=nested-windows
            "-DBUILD_TESTS=${BUILD_TESTS}"

            # Reuse the 3P source trees we've already downloaded in the nested
            # build.
            "-Dfmt_POPULATED=${fmt_POPULATED}"
            "-Dfmt_SOURCE_DIR=${fmt_SOURCE_DIR}"
            "-Dfmt_BINARY_DIR=<BINARY_DIR>/_deps/fmt-build"
            "-Dspdlog_POPULATED=${spdlog_POPULATED}"
            "-Dspdlog_SOURCE_DIR=${spdlog_SOURCE_DIR}"
            "-Dspdlog_BINARY_DIR=<BINARY_DIR>/_deps/spdlog-build"
            "-Dgoogletest_POPULATED=${googletest_POPULATED}"
            "-Dgoogletest_SOURCE_DIR=${googletest_SOURCE_DIR}"
            "-Dgoogletest_BINARY_DIR=<BINARY_DIR>/_deps/googletest-build"
        BUILD_ALWAYS ON
    )

    ExternalProject_Get_Property(nested_windows BINARY_DIR)

    # Run the nested build's tests as a part of the main build's tests.
    add_test(
        NAME nested_windows_tests
        COMMAND "${CMAKE_COMMAND}" --build "${BINARY_DIR}" --target test
    )

    # Install the nested build's artifacts into the main build.
    install(DIRECTORY ${windows_install_dir}/
        DESTINATION .
        USE_SOURCE_PERMISSIONS
    )
elseif (BUILD_LINUX_TARGET)
    add_subdirectory(src/linux)
elseif (BUILD_WINDOWS_TARGET)
    add_subdirectory(src/windows)
endif()

set(CPACK_GENERATOR DEB)
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_ALL_IN_ONE_PACKAGE OFF)
set(CPACK_COMPONENTS_GROUPING ONE_PER_GROUP)

set(CPACK_PACKAGE_VERSION_MAJOR 1)
set(CPACK_PACKAGE_VERSION_MINOR 1)
set(CPACK_PACKAGE_VERSION_PATCH 0)

set(CPACK_PACKAGE_CONTACT "Matthew Bowen <matthew@mgbowen.com>")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/mgbowen/windows-fido-bridge")
set(CPACK_DEBIAN_PACKAGE_SECTION main)

#
# real_deb_group
#

set(CPACK_DEBIAN_REAL_DEB_GROUP_PACKAGE_NAME "windows-fido-bridge-skapiv${SK_API_VERSION}")

set(skapi_deb_description_configured_file_path "${CMAKE_CURRENT_BINARY_DIR}/skapi_deb_description")
configure_file(
    "${CMAKE_SOURCE_DIR}/package/deb/skapi/description.template"
    "${skapi_deb_description_configured_file_path}"
    @ONLY
)
read_deb_description_from_file(
    "${skapi_deb_description_configured_file_path}"
    CPACK_COMPONENT_REAL_DEB_GROUP_DESCRIPTION
)

# Only install in a deb
install(FILES "${CMAKE_SOURCE_DIR}/package/deb/skapi/copyright"
    DESTINATION "share/doc/${CPACK_DEBIAN_REAL_DEB_GROUP_PACKAGE_NAME}"
    COMPONENT real_deb
    EXCLUDE_FROM_ALL
)

set(CPACK_DEBIAN_REAL_DEB_GROUP_PACKAGE_DEPENDS
    "windows-fido-bridge (= ${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH})"
)

if ("${SK_API_VERSION}" EQUAL 5)
    set(CPACK_DEBIAN_REAL_DEB_GROUP_PACKAGE_DEPENDS
        "${CPACK_DEBIAN_REAL_DEB_GROUP_PACKAGE_DEPENDS}, openssh-client (>= 1:8.3), openssh-client (<< 1:8.4)"
    )
elseif ("${SK_API_VERSION}" EQUAL 7)
    set(CPACK_DEBIAN_REAL_DEB_GROUP_PACKAGE_DEPENDS
        "${CPACK_DEBIAN_REAL_DEB_GROUP_PACKAGE_DEPENDS}, openssh-client (>= 1:8.4)"
    )
else()
    message(FATAL_ERROR "Unknown SK_API_VERSION ${SK_API_VERSION} when configuring deb package")
endif()

set(CPACK_DEBIAN_REAL_DEB_GROUP_PACKAGE_SHLIBDEPS ON)

# We now provide separate packages for each OpenSSH skapi, so we need to
# conflict with the first public release to avoid installation problems.
#
# The pattern of providing, replacing, and conflicting with the virtual package
# is described in the Debian package maintainer's guide, see:
# https://www.debian.org/doc/debian-policy/ch-relationships.html#s-virtual.
set(CPACK_DEBIAN_REAL_DEB_GROUP_PACKAGE_PROVIDES "windows-fido-bridge-skapi")
set(CPACK_DEBIAN_REAL_DEB_GROUP_PACKAGE_REPLACES "windows-fido-bridge-skapi")
set(CPACK_DEBIAN_REAL_DEB_GROUP_PACKAGE_CONFLICTS "windows-fido-bridge (<< 1.1.0), windows-fido-bridge-skapi")

set(CPACK_COMPONENT_REAL_DEB_GROUP real_deb_group)
set(CPACK_COMPONENT_UNSPECIFIED_GROUP real_deb_group)
set(CPACK_DEBIAN_REAL_DEB_GROUP_FILE_NAME DEB-DEFAULT)

#
# version_selection_shim_group
#

set(CPACK_DEBIAN_VERSION_SELECTION_SHIM_GROUP_PACKAGE_NAME "windows-fido-bridge")

read_deb_description_from_file(
    "${CMAKE_SOURCE_DIR}/package/deb/version-selection-shim/description"
    CPACK_COMPONENT_VERSION_SELECTION_SHIM_GROUP_DESCRIPTION
)

# Only install in a deb
install(FILES "${CMAKE_SOURCE_DIR}/package/deb/version-selection-shim/copyright"
    DESTINATION share/doc/windows-fido-bridge
    RENAME copyright
    COMPONENT version_selection_shim
    EXCLUDE_FROM_ALL
)

# Depend on one of the skapi packages we support.
set(CPACK_DEBIAN_VERSION_SELECTION_SHIM_GROUP_PACKAGE_DEPENDS "")
foreach (ver IN LISTS VALID_SK_API_VERSIONS)
    if (NOT "${CPACK_DEBIAN_VERSION_SELECTION_SHIM_GROUP_PACKAGE_DEPENDS}" STREQUAL "")
        set(CPACK_DEBIAN_VERSION_SELECTION_SHIM_GROUP_PACKAGE_DEPENDS "${CPACK_DEBIAN_VERSION_SELECTION_SHIM_GROUP_PACKAGE_DEPENDS} | ")
    endif()

    set(CPACK_DEBIAN_VERSION_SELECTION_SHIM_GROUP_PACKAGE_DEPENDS "${CPACK_DEBIAN_VERSION_SELECTION_SHIM_GROUP_PACKAGE_DEPENDS}windows-fido-bridge-skapiv${ver}")
endforeach()

# For reasons that are unclear to me, when upgrading between OpenSSH versions
# that change the skapi version (which subsequently requires swapping out which
# package provides the windows-fido-bridge-skapi virtual package), apt will
# sometimes decide the best course of action is to remove windows-fido-bridge
# completely. However, its dependency resolver seems to do the right thing, i.e.
# swapping the skapi package, if we explicitly depend on every package that
# provides the windows-fido-bridge-skapi virtual package _and_ the virtual
# package itself, in that order. Seems to run counter to the point of using
# virtual packages at all, but oh well.
set(CPACK_DEBIAN_VERSION_SELECTION_SHIM_GROUP_PACKAGE_DEPENDS
    "${CPACK_DEBIAN_VERSION_SELECTION_SHIM_GROUP_PACKAGE_DEPENDS} | windows-fido-bridge-skapi"
)

set(CPACK_COMPONENT_VERSION_SELECTION_SHIM_GROUP version_selection_shim_group)
set(CPACK_DEBIAN_VERSION_SELECTION_SHIM_GROUP_FILE_NAME DEB-DEFAULT)

include(CPack)
