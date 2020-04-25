project(linux_client)

#add_library(${PROJECT_NAME} SHARED
add_executable(${PROJECT_NAME}
    src/binary_io.cpp
    src/linux_client.cpp
)

target_link_libraries(
    ${PROJECT_NAME}
    PRIVATE
        common

        Boost::boost
        nlohmann_json::nlohmann_json
        fmt::fmt
)
