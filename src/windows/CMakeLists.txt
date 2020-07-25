project(windowsfidobridge)

add_executable(${PROJECT_NAME}
    src/main.cpp
    src/webauthn_linking.cpp
    src/window.cpp
    src/windows_error.cpp
    src/windows_util.cpp
)

target_include_directories(${PROJECT_NAME}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/3p-include
)

target_link_libraries(${PROJECT_NAME}
    cbor
    common

    -static-libgcc
    -static-libstdc++
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        UNICODE
        _UNICODE

        # Windows 10
        WINVER=0x0A00
        _WIN32_WINNT=0x0A00
)

install(TARGETS ${PROJECT_NAME}
    # Override this, it's not intended to be executed directly
    RUNTIME DESTINATION lib
    COMPONENT "${WINDOWS_TARGET_COMPONENT_NAME}"
)
