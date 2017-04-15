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
#include <algorithm>

#include <sys/types.h>
#include <pcap/pcap.h>
#include <dlfcn.h>
#include <unistd.h>


extern "C" {

    void
    captop_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *payload)
    {
        auto that = reinterpret_cast<capthread *>(user);

        if (unlikely(global::stop.load(std::memory_order_relaxed)))
            return;

        if (likely(that != nullptr))
        {
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
                else {
                    that->atomic_stat.fail.fetch_add(1, std::memory_order_relaxed);
                }
            }

            if (unlikely(that->dumper != nullptr))
                pcap_dump(reinterpret_cast<u_char *>(that->dumper), h, payload);
        }
    }
}


pcap_handler
get_packet_handler(options const &opt)
{
    auto is_suffix = [] (std::string const & value, std::string const & ending)
    {
        if (ending.size() > value.size()) return false;
            return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
    };

    if (opt.handler.empty())
        return captop_handler;

    auto pid = getpid();

    auto handler_so = "/tmp/captop_" + std::to_string(pid) + ".so";

    auto compiler = !opt.compiler.empty()          ? opt.compiler :
                    is_suffix(opt.handler, ".cpp") ? "g++ -std=c++11" :
                    is_suffix(opt.handler, ".cc" ) ? "g++ -std=c++11" :
                    is_suffix(opt.handler, ".c")   ? "gcc"
                    : "";

    if (compiler.empty())
        throw std::runtime_error("captop: compiler not found for " + opt.handler + "!");

    std::string args;

    for(auto &x : opt.arguments)
    {
        args += ' ' + x;
    }

    auto cmd = compiler + " -O2 " + opt.handler + " -o " + handler_so + " -fPIC -shared" + args;

    std::cout << "captop: running " << cmd << std::endl;

    if (system(cmd.c_str()) != 0)
    {
        throw std::runtime_error("g++: compiler error");
    }

 	auto handle = dlopen(handler_so.c_str(), RTLD_NOW);
	if (!handle)
	    throw std::runtime_error(std::string{"dlopen: "} + dlerror());

    auto r = reinterpret_cast<pcap_handler>(dlsym(handle, "handler"));
    if (!r)
        throw std::runtime_error(opt.handler + ": function 'captop_handler' not found!");

    return r;
}


