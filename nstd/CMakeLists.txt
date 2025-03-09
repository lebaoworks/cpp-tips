cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

####################################
# Main Project
####################################
project(nstd)

add_library(nstd INTERFACE)

target_include_directories(nstd
    INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

####################################
# Test
####################################

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(testing
    "${CMAKE_CURRENT_SOURCE_DIR}/test/encoding.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/hash.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/threading.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/test/utility.cpp"
)

target_link_libraries(testing
    GTest::gtest_main
    nstd
)

enable_testing()
include(GoogleTest)
gtest_discover_tests(testing)