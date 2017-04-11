#include <pcap/pcap.h>

#include <iostream>

extern "C"
{
	void captop_handler(u_char *, const struct pcap_pkthdr *h, const u_char *payload);

	void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
	{
		std::cout << "packet!" << std::endl;

		captop_handler(user, h, bytes);
	}
}

