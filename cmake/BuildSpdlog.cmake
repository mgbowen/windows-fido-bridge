include(BuildFmt)
include(BuildMingwStdThreads)

include(FetchContent)

if (TARGET spdlog)
    return()
endif()

FetchContent_Declare(spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG 616caa5d30172b65cc3a06800894c575d70cb8e6  # 1.7.0
    GIT_SHALLOW ON
)

if (NOT spdlog_POPULATED)
    FetchContent_GetProperties(spdlog)
    FetchContent_Populate(spdlog)
endif()

option(SPDLOG_FMT_EXTERNAL "" ON)
add_subdirectory(${spdlog_SOURCE_DIR} ${spdlog_BINARY_DIR})

if (MINGW)
    target_link_libraries(spdlog PUBLIC mingw_stdthreads fmt)
endif()
