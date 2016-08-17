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
