project(win32_middleware_common)

add_library(${PROJECT_NAME} STATIC
    src/openssh_sk_middleware.cpp
    src/webauthn.cpp
    src/window.cpp
    src/windows_error.cpp
    src/windows_util.cpp
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/3p-include
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        common spdlog

        # For PathFindFileNameW.
        -lshlwapi
)

target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        UNICODE
        _UNICODE

        # Windows 10
        WINVER=0x0A00
        _WIN32_WINNT=0x0A00
)
