project(win32_middleware_exe)

add_executable(${PROJECT_NAME}
    src/main.cpp
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        win32_middleware_common

        # Use static libraries wherever possible to make distribution easier.
        -static
)

install(TARGETS ${PROJECT_NAME}
    # Override this, it's not intended to be executed directly
    RUNTIME DESTINATION lib
    COMPONENT "${WINDOWS_MIDDLEWARE_EXE_COMPONENT}"
)
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "windowsfidobridge"
)
