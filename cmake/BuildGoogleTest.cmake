include(FetchContent)

if (TARGET gtest)
    return()
endif()

FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG 703bd9caab50b139428cea1aaff9974ebee5742e  # 1.10.0
    GIT_SHALLOW ON
)

if (NOT googletest_POPULATED)
    FetchContent_GetProperties(googletest)
    FetchContent_Populate(googletest)
endif()

option(BUILD_GMOCK "" OFF)
option(INSTALL_GTEST "" OFF)
add_subdirectory(${googletest_SOURCE_DIR} ${googletest_BINARY_DIR})

if (MINGW)
    # When cross-compiling with MinGW, make the Google Test-generated
    # executables statically-linked to allow them to run with no extra DLLs.
    include(BuildMingwStdThreads)

    target_link_libraries(gtest PUBLIC -static mingw_stdthreads)
    target_link_libraries(gtest_main PUBLIC -static mingw_stdthreads)
endif()
