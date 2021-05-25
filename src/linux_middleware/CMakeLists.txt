project(windowsfidobridge)

add_library(${PROJECT_NAME} SHARED
    src/bridge.cpp
    src/dll_entry_points.cpp
    src/posix_pipe.cpp
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE "WFB_SK_API_VERSION=${SK_API_VERSION}"
)

target_link_libraries(${PROJECT_NAME}
    common fmt spdlog

    # GCC 8 std::filesystem support
    stdc++fs
)

install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION lib
)
