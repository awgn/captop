#include <captop.h>

#include <iostream>

extern "C"
{
	void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
	{
		std::cout << "packet!" << std::endl;

		captop_handler(user, h, bytes);
	}
}

