cmake_minimum_required(VERSION 2.4)

set(CMAKE_VERBOSE_MAKEFILE 0)

add_executable(iftop src/main.cpp src/iftop.cpp)

set(CXX_FLAGS_OPT "-O3 -march=native -Wall -std=c++11")

include_directories(src)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_FLAGS_OPT}")

target_link_libraries(iftop -lrt -lpcap -lpthread)

install (TARGETS iftop DESTINATION bin)


