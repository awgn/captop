#include <pcap/pcap.h>
#include <dlfcn.h>
#include <iostream>

#include <global.hpp>
#include <options.hpp>

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

    return nullptr;
}


