project(cbor)

#
# Library
#

add_library(
    ${PROJECT_NAME} STATIC

    src/types/array.cpp
    src/types/integer.cpp
    src/types/value.cpp
    src/detail.cpp
    src/parse.cpp
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
        common

        fmt::fmt
)

set_property(
    TARGET ${PROJECT_NAME}
    PROPERTY POSITION_INDEPENDENT_CODE ON
)

#
# Tests
#

set(test_target ${PROJECT_NAME}_tests)
add_executable(${test_target}
    test/test_cbor.cpp
    test/test_integer.cpp
    test/test_value.cpp
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
