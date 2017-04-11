#pragma once

#include <pcap/pcap.h>

extern "C"
{
	void captop_handler(u_char *, const struct pcap_pkthdr *h, const u_char *payload);
}
