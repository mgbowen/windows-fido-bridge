project(windows_server)

add_executable(
    ${PROJECT_NAME}
    windows_server.cpp
)

target_link_libraries(
    ${PROJECT_NAME}
    common

    -static-libgcc
    -static-libstdc++
    "/mnt/c/Program Files (x86)/Windows Kits/10/Lib/10.0.18362.0/um/x64/webauthn.lib"
)
