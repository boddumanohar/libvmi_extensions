cmake_minimum_required(VERSION 3.6)
project(libvmi_extensions C CXX)

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project()

list(APPEND ARGN
)

add_vmm_executable(
		libvmi_extensions	
    SOURCES vmcall_handler.cpp
)
