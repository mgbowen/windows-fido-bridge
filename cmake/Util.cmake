function(read_deb_description_from_file FILE_PATH OUTVAR)
    file(READ "${FILE_PATH}" _desc)

    # Strip trailing whitespace.
    string(REGEX REPLACE "\r?\n[ \r\n]*$" "" _desc "${_desc}")

    if (CMAKE_VERSION VERSION_LESS "3.16.0")
        # Debian package descriptions with multiple lines need a single leading
        # space for every line after the first one. Prior to CMake 3.16, CPack's
        # deb generator did not do any special processing to multi-line
        # descriptions, which means you have to do this yourself.
        #
        # See CMake 3.16.0's release notes:
        # https://cmake.org/cmake/help/latest/release/3.16.html#cpack
        # and this windows-fido-bridge GitHub issue:
        # https://github.com/mgbowen/windows-fido-bridge/issues/8.
        string(REGEX REPLACE "(\r?\n)" "\\1 " _desc "${_desc}")
    endif()

    set(${OUTVAR} "${_desc}" PARENT_SCOPE)
endfunction()
