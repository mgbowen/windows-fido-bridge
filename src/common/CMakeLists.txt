project(common)

add_library(${PROJECT_NAME} STATIC
    src/communication.cpp
    src/exceptions.cpp
    src/util.cpp

    src/cbor/types/array.cpp
    src/cbor/types/integer.cpp
    src/cbor/types/null.cpp
    src/cbor/types/value.cpp
    src/cbor/detail.cpp
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        src
)

target_link_libraries(${PROJECT_NAME}
    PUBLIC
        fmt
)

set_property(TARGET ${PROJECT_NAME}
    PROPERTY POSITION_INDEPENDENT_CODE ON
)

#
# Tests
#

# Only build tests if we're not cross-compiling or if we're running under WSL;
# in the case of the latter, the cross-compiled artifacts can be run directly
# on the build machine.
if (BUILD_TESTS AND (NOT MINGW OR WSL))
    set(test_target ${PROJECT_NAME}_tests)
    add_executable(${test_target}
        test/test_array.cpp
        test/test_integer.cpp
        test/test_map.cpp
        test/test_string.cpp
        test/test_value.cpp
    )

    target_link_libraries(${test_target}
        ${PROJECT_NAME}

        gtest gtest_main
    )

    gtest_discover_tests(${test_target})

    target_include_directories(${test_target}
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
endif()
