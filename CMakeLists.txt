cmake_minimum_required(VERSION 3.5)
project(lldpr)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")

set(SOURCE_FILES
        lldpr.c tlv.h tlv.c test_tlv.c)

add_executable(lldpr ${SOURCE_FILES})
include_directories(/usr/include)