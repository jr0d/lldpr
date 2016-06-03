cmake_minimum_required(VERSION 3.5)
project(lldpr)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")

include_directories(/usr/include src)

add_executable(test_tlv tests/test_tlv.c src/lldpr.c src/tlv.c src/tlv_formatters.c src/tlv_formatters.h)
