#include <iostream>
#include <string>
#include <cstring>
#include <stdexcept>

namespace { std::string version = "v1.0"; }

void usage(std::string name)
{
    std::cerr << "usage: " + std::move(name) + " [OPTIONS] [BPF expression]\n\n"
                 "  -B --buffer SIZE             Set the operating system capture buffer size.\n"
                 "  -c count                     Exit after receiving count packets.\n"
                 "  -s snaplen                   Specify the capture length of packets in bytes.\n"
                 "  -i --interface NAME          Listen on interface.\n"
                 "     --version                 Print the version strings and exit.\n"
                 "  -? --help                    Print this help.\n";

    _Exit(0);
}


struct option
{
    size_t buffer_size;
    size_t count;
    size_t snaplen;

    std::string ifname;

};


int
main(int argc, char *argv[])
try
{
    struct option opt =
    {
        0,
        0,
        65535,
        ""
    };

    if (argc < 2)
        usage(argv[0]);

    for(int i = 1; i < argc; ++i)
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
            usage(argv[0]);

        throw std::runtime_error(std::string(argv[0]) + ": " + std::string(argv[i]) + " unknown option!");
    }

    return 0;
}
catch(std::exception &e)
{
    std::cerr << e.what() << std::endl;
}
