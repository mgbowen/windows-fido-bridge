project(common)

add_library(
    ${PROJECT_NAME} STATIC
    src/base64.cpp
    src/communication.cpp
)

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        src
)

target_link_libraries(
    ${PROJECT_NAME}
    PUBLIC
        Boost::boost
        fmt::fmt
        nlohmann_json::nlohmann_json
)

set_property(
    TARGET ${PROJECT_NAME}
    PROPERTY POSITION_INDEPENDENT_CODE ON
)
