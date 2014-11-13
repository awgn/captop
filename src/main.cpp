#include <iostream>
#include <string>
#include <cstring>
#include <stdexcept>

#include <options.hpp>

namespace
{
    std::string name    = "iftop";
    std::string version = name + " v1.0";
}


void usage()
{
    std::cerr << version << std::endl << std::endl;
    std::cerr << "usage: " + name + " [OPTIONS] [BPF expression]\n\n"
                 "  -B --buffer SIZE             Set the operating system capture buffer size.\n"
                 "  -c count                     Exit after receiving count packets.\n"
                 "  -s snaplen                   Specify the capture length of packets in bytes.\n"
                 "  -i --interface NAME          Listen on interface.\n"
                 "     --version                 Print the version strings and exit.\n"
                 "  -? --help                    Print this help.\n";

    _Exit(0);
}


extern int pcap_top(struct options const &, std::string const &bpf);

int
main(int argc, char *argv[])
try
{
    auto opt = default_options;
    int i = 1;

    if (argc < 2)
        usage();

    for(; i < argc; ++i)
    {
        if ( strcmp(argv[i], "-B") == 0 ||
             strcmp(argv[i], "--buffer") == 0) {
            i++;
            if (i == argc)
            {
                throw std::runtime_error("buffer size missing");
            }

            opt.buffer_size = static_cast<size_t>(std::atoi(argv[i]));
            continue;
        }

        if ( strcmp(argv[i], "-c") == 0 ||
             strcmp(argv[i], "--count") == 0) {
            i++;
            if (i == argc)
            {
                throw std::runtime_error("count missing");
            }

            opt.count = static_cast<size_t>(std::atoi(argv[i]));
            continue;
        }

        if ( strcmp(argv[i], "-s") == 0 ||
             strcmp(argv[i], "--snaplen") == 0) {
            i++;
            if (i == argc)
            {
                throw std::runtime_error("snaplen missing");
            }

            opt.snaplen = static_cast<size_t>(std::atoi(argv[i]));
            continue;
        }

        if ( strcmp(argv[i], "-i") == 0 ||
             strcmp(argv[i], "--interface") == 0) {
            i++;
            if (i == argc)
            {
                throw std::runtime_error("interface missing");
            }

            opt.ifname = argv[i];
            continue;
        }

        if (strcmp(argv[i], "--version") == 0) {
            std::cout << version << std::endl;
            _Exit(0);
        }


        if ( strcmp(argv[i], "-h") == 0 ||
             strcmp(argv[i], "-?") == 0 ||
             strcmp(argv[i], "--help") == 0
             )
            usage();

        if (argv[i][0] != '-')
            break;

        throw std::runtime_error(std::string(argv[i]) + " unknown option!");
    }

    if (opt.ifname.empty())
        throw std::runtime_error("interface missing");

    return pcap_top(opt, i == argc ? "" : argv[i]);
}
catch(std::exception &e)
{
    std::cerr << name << ": " << e.what() << std::endl;
}
