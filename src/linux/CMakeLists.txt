project(windowsfidobridge)

add_library(${PROJECT_NAME} SHARED
    src/bridge.cpp
    src/openssh_sk_middleware.cpp
    src/posix_pipe.cpp
    src/webauthn.cpp
)

# Create a shim that points sk-api.h to the version we're targeting
set(sk_api_shim_dir_path ${CMAKE_CURRENT_BINARY_DIR}/sk-api-shim)
file(MAKE_DIRECTORY ${sk_api_shim_dir_path})
execute_process(
    COMMAND ${CMAKE_COMMAND} -E create_symlink
        "${CMAKE_CURRENT_SOURCE_DIR}/3p-include/sk-api-v${SK_API_VERSION}.h"
        "${sk_api_shim_dir_path}/sk-api.h"
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/3p-include
        ${sk_api_shim_dir_path}
)

target_compile_definitions(${PROJECT_NAME}
    PRIVATE "WFB_SK_API_VERSION=${SK_API_VERSION}"
)

target_link_libraries(${PROJECT_NAME}
    cbor
    common

    fmt

    # GCC 8 std::filesystem support
    stdc++fs
)

install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION lib
)
