project(windowsfidobridge)

add_executable(${PROJECT_NAME}
    src/main.cpp
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

    # TODO: don't hardcode this
    "/mnt/c/Program Files (x86)/Windows Kits/10/Lib/10.0.18362.0/um/x64/webauthn.lib"
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        _UNICODE

        # Windows 10
        WINVER=0x0A00
        _WIN32_WINNT=0x0A00
)

install(TARGETS ${PROJECT_NAME}
    # Override this, it's not intended to be executed directly
    RUNTIME DESTINATION lib
)
