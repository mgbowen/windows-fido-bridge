project(win32_middleware_lib)

add_library(${PROJECT_NAME} SHARED
    src/dll_entry_points.cpp
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        win32_middleware_common

        # Use static libraries wherever possible to make distribution easier.
        -static
)

install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION lib
    COMPONENT "${WINDOWS_MIDDLEWARE_LIB_COMPONENT}"
)
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "windowsfidobridge"
) 
