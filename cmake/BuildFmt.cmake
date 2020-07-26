include(FetchContent)

if (TARGET fmt)
    return()
endif()

FetchContent_Declare(fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG f19b1a521ee8b606dedcadfda69fd10ddf882753  # 7.0.1
    GIT_SHALLOW ON
)

if (NOT fmt_POPULATED)
    FetchContent_GetProperties(fmt)
    FetchContent_Populate(fmt)
endif()

add_subdirectory(${fmt_SOURCE_DIR} ${fmt_BINARY_DIR})
