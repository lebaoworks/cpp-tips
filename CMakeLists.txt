cmake_minimum_required(VERSION 3.10)

####################################
# Main Project
####################################
project(main)

add_executable(main main.cpp)

add_subdirectory(nstd)
target_link_libraries(main PRIVATE nstd)

####################################
# Test
####################################

enable_testing()