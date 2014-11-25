/*
 *  Copyright (c) 2014 Nicola Bonelli <nicola@pfq.io>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#pragma once

#include <cstddef>
#include <string>

struct options
{
    size_t buffer_size;
    size_t count;
    size_t snaplen;
    size_t timeout;

    uint32_t genlen;

    bool   oflag;

    struct
    {
        std::string ifname;
        std::string filename;
    } in;

    struct
    {
        std::string ifname;
        std::string filename;
    } out;
};

namespace
{
    struct options default_options = options
    {
        0,
        0,
        65535,
        10,
        98,
        true,
        { "", "" },
        { "", "" }
    };
}


