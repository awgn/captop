#include <global.hpp>
#include <options.hpp>

#include <iostream>
#include <cstdlib>
#include <stdexcept>

#include <pcap/pcap.h>
#include <dlfcn.h>


extern "C" {

    void
    default_handler(u_char *, const struct pcap_pkthdr *h, const u_char *payload)
    {
        if (global::in)
        {
            global::in_count.fetch_add(1, std::memory_order_relaxed);
            global::in_band.fetch_add(h->len, std::memory_order_relaxed);
        }

        if (global::out)
        {
            int ret = pcap_inject(global::out, payload, h->caplen);
            if (ret != -1)
            {
                global::out_count.fetch_add(1, std::memory_order_relaxed);
                global::out_band.fetch_add(h->len, std::memory_order_relaxed);
            }
            else
                global::fail.fetch_add(1, std::memory_order_relaxed);
        }

        if (global::dumper)
            pcap_dump(reinterpret_cast<u_char *>(global::dumper), h, payload);
    }
}


pcap_handler
get_packet_handler(options const &opt)
{
    if (opt.handler.empty())
        return default_handler;

    if (system(("g++ " + opt.handler + " -o /tmp/handler.so -fPIC -shared").c_str()) != 0) {
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


