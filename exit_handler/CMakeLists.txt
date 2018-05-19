cmake_minimum_required(VERSION 3.6)
project(libvmi_test C CXX)

include(${SOURCE_CMAKE_DIR}/project.cmake)

init_project(
    INCLUDES ${CMAKE_CURRENT_LIST_DIR}/../../hypervisor/include
)

add_subdirectory(main)
