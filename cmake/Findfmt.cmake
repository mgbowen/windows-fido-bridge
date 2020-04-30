# fmt distributes a CMake config file, but on some platforms (e.g. Debian), it
# installs to /usr/include, which causes issues when cross compiling. This
# script uses some custom logic to avoid that problem.
find_path(
    FMT_INCLUDE_DIR
    fmt/format.h
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    fmt
    REQUIRED_VARS FMT_INCLUDE_DIR
)

if (fmt_FOUND AND NOT TARGET fmt::fmt)
    # Create a symlink in our build directory to avoid problems when
    # cross-compiling with MinGW
    set(_symlink_parent_dir "${CMAKE_BINARY_DIR}/fmt_shim")
    file(MAKE_DIRECTORY "${_symlink_parent_dir}")
    execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink "${FMT_INCLUDE_DIR}/fmt" "${_symlink_parent_dir}/fmt")
    set(FMT_INCLUDE_DIR "${_symlink_parent_dir}")

    add_library(fmt::fmt INTERFACE IMPORTED)
    set_target_properties(fmt::fmt PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${FMT_INCLUDE_DIR}"
    )
endif()
