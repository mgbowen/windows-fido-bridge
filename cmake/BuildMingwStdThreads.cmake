include(FetchContent)

if (TARGET mingw_stdthreads)
    return()
endif()

if (MINGW)
    FetchContent_Declare(mingw_stdthreads
        # HEAD as of 2020/10/28
        URL https://codeload.github.com/meganz/mingw-std-threads/zip/c01463398bd2b09c2afa0cd06c12d7b1cc8a470d
    )

    if (NOT mingw_stdthreads_POPULATED)
        FetchContent_GetProperties(mingw_stdthreads)
        FetchContent_Populate(mingw_stdthreads)
    endif()

    option(MINGW_STDTHREADS_GENERATE_STDHEADERS "" ON)
    add_subdirectory(${mingw_stdthreads_SOURCE_DIR} ${mingw_stdthreads_BINARY_DIR})
else()
    # Empty library to make downstream consumption easier.
    add_library(mingw_stdthreads INTERFACE IMPORTED)
endif()
