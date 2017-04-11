# 
# Copyright (c) 2014 Nicola Bonelli <nicola@pfq.io>
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# 

cmake_minimum_required(VERSION 2.4)

set(CMAKE_VERBOSE_MAKEFILE 0)

add_executable(captop src/main.cpp 
                      src/captop.cpp
                      src/handler.cpp
                      src/global.cpp)

set(CXX_FLAGS_OPT "-O3 -march=native -Wall -std=c++11")

include_directories(hdr)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_FLAGS_OPT}")

target_link_libraries(captop -lrt -lpthread -ldl /usr/local/lib/libpcap.so)

install (TARGETS captop DESTINATION bin)
install_files (/include/ FILES hdr/captop.h)

