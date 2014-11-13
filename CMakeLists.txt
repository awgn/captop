cmake_minimum_required(VERSION 2.4)

set(CMAKE_VERBOSE_MAKEFILE 0)

add_executable(pcap-top main.cpp pcap-top.cpp)

set(CXX_FLAGS_OPT "-O3 -march=native -Wall -std=c++11")

include_directories(. lib)

if (USE_PFQ)

    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -L /opt/PFQ-pcap/libpcap-1.3.0/ ${CXX_FLAGS_OPT}")

    include_directories(/opt/PFQ-pcap/libpcap-1.3.0/)

    target_link_libraries(pcap-top -lpcap -lpfq -lpthread)

else()

    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_FLAGS_OPT}")

    target_link_libraries(pcap-top -lpcap -lpthread)

endif()



