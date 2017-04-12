#pragma once

#include <pcap/pcap.h>

#ifdef __cplusplus
extern "C"
{
#endif

	void captop_handler(u_char *, const struct pcap_pkthdr *h, const u_char *payload);

#ifdef __cplusplus
}
#endif
