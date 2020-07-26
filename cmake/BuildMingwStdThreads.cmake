include(FetchContent)

if (TARGET mingw_stdthreads)
    return()
endif()

if (MINGW)
    FetchContent_Declare(mingw_stdthreads
        GIT_REPOSITORY https://github.com/meganz/mingw-std-threads.git
        GIT_TAG bee085c0a6cb32c59f0b55c7bba976fe6dcfca7f  # HEAD as of 2020/07/25
        GIT_SHALLOW ON
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
