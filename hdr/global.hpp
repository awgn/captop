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

#include <pcap/pcap.h>

#include <atomic>
#include <chrono>


namespace global
{
    extern char errbuf[];
    extern char errbuf2[];

    extern std::atomic_long fail;

    extern std::atomic_long in_count;
    extern std::atomic_long out_count;

    extern std::atomic_long in_band;
    extern std::atomic_long out_band;

    extern pcap_t *in, *out;

    extern pcap_t *dead;
    extern pcap_dumper_t *dumper;

    extern std::chrono::time_point<std::chrono::system_clock> now_;

    extern unsigned char default_packet[]; 
}
