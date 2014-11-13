#include <string>
#include <iostream>

#include <options.hpp>


int
pcap_top(options const &opts, std::string const &bpf)
{
    if (!bpf.empty())
        std::cout << "BPF: " << bpf << std::endl;

    return 0;
}
