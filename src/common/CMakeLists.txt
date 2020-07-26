project(common)

add_library(${PROJECT_NAME} STATIC
    src/communication.cpp
    src/exceptions.cpp
    src/util.cpp
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
