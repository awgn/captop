/*
 *  Copyright (c) 2014 Nicola Bonelli <nicola@pfq.io>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#pragma once

#include <capthread.hpp>

#include <thread>
#include <atomic>
#include <chrono>
#include <vector>
#include <memory>
#include <mutex>

#include <pcap/pcap.h>


namespace global
{
    extern unsigned char default_packet[];

    extern std::vector<std::unique_ptr<capthread>> thread_ctx;
    extern std::vector<std::thread> thread;

    extern std::atomic_bool stop;

    extern std::mutex syncout;
}
