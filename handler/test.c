#include <captop.h>
#include <stdio.h>

void handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	printf("packet!\n");
	captop_handler(user, h, bytes);
}

