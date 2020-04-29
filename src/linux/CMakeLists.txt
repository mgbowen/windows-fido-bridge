project(windowsfidobridge)

add_library(${PROJECT_NAME} SHARED
    src/bridge.cpp
    src/openssh_sk_middleware.cpp
    src/posix_pipe.cpp
    src/webauthn.cpp
)

target_include_directories(${PROJECT_NAME}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/3p-include
)

target_link_libraries(${PROJECT_NAME}
    cbor
    common

    fmt::fmt

    # GCC 8 std::filesystem support
    stdc++fs
)

install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION lib
)
