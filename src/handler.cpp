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

#include <capthread.hpp>
#include <global.hpp>
#include <options.hpp>

#include <iostream>
#include <cstdlib>
#include <stdexcept>

#include <pcap/pcap.h>
#include <dlfcn.h>


extern "C" {

    void
    captop_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *payload)
    {
        auto that = reinterpret_cast<capthread *>(user);

        if (that->in)
        {
            that->atomic_stat.in_count.fetch_add(1, std::memory_order_relaxed);
            that->atomic_stat.in_band.fetch_add(h->len, std::memory_order_relaxed);
        }

        if (that->out)
        {
            int ret = pcap_inject(that->out, payload, h->caplen);
            if (ret != -1)
            {
                that->atomic_stat.out_count.fetch_add(1, std::memory_order_relaxed);
                that->atomic_stat.out_band.fetch_add(h->len, std::memory_order_relaxed);
            }
            else
                that->fail.fetch_add(1, std::memory_order_relaxed);
        }

        if (unlikely(global::stop.load(std::memory_order_relaxed)))
            pcap_breakloop(that->in);

        if (unlikely(that->dumper != nullptr))
            pcap_dump(reinterpret_cast<u_char *>(that->dumper), h, payload);
    }
}


pcap_handler
get_packet_handler(options const &opt)
{
    if (opt.handler.empty())
        return captop_handler;

    if (system(("g++ -O2 -std=c++11 " + opt.handler + " -o /tmp/handler.so -fPIC -shared").c_str()) != 0) {
        throw std::runtime_error("g++: compiler error");
    }

 	auto handle = dlopen("/tmp/handler.so", RTLD_NOW);
	if (!handle)
	    throw std::runtime_error(std::string{"dlopen: "} + dlerror());

    auto r = reinterpret_cast<pcap_handler>(dlsym(handle, "handler"));
    if (!r)
        throw std::runtime_error(opt.handler + ": function 'handler' not found!");

    return r;
}


