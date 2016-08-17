#pragma once 

#include <pcap/pcap.h>
#include <options.hpp>

extern pcap_handler get_packet_handler(options const &);
