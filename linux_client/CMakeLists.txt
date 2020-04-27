project(linux_client)

#
# Library
#

add_library(${PROJECT_NAME} SHARED
    src/cbor.cpp
    src/linux_client.cpp
    src/util.cpp
)

target_link_libraries(${PROJECT_NAME}
    common

    nlohmann_json::nlohmann_json
    fmt::fmt
)

#
# Tests
#

set(test_target ${PROJECT_NAME}_tests)
add_executable(${test_target}
    test/test_cbor.cpp
)

target_link_libraries(${test_target}
    ${PROJECT_NAME}

    GTest::GTest
    GTest::Main
)

gtest_discover_tests(${test_target})

target_include_directories(${test_target}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

#
# Scratch
#

add_executable(${PROJECT_NAME}_scratch
    src/scratch.cpp
)

target_link_libraries(${PROJECT_NAME}_scratch ${PROJECT_NAME})
