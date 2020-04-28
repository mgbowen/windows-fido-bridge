project(linux_client)

#
# Library
#

add_library(${PROJECT_NAME} SHARED
    src/bridge.cpp
    src/linux_client.cpp
    src/posix_pipe.cpp
    src/webauthn.cpp
)

target_link_libraries(${PROJECT_NAME}
    cbor
    common

    nlohmann_json::nlohmann_json
    fmt::fmt
)
