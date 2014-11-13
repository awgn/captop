#pragma once

#include <cstddef>
#include <string>

struct options
{
    size_t buffer_size;
    size_t count;
    size_t snaplen;
    std::string ifname;
};


namespace
{
    struct options default_options = options
    {
        0,
        0,
        65535,
        ""
    };
}

