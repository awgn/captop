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

#include <string>
#include <cstring>
#include <sstream>
#include <chrono>

#include <vt100.hpp>


inline bool any_strcmp(const char *arg, const char *opt)
{
    return strcmp(arg,opt) == 0;
}
template <typename ...Ts>
inline bool any_strcmp(const char *arg, const char *opt, Ts&&...args)
{
    return (strcmp(arg,opt) == 0 ? true : any_strcmp(arg, std::forward<Ts>(args)...));
}


template <typename T>
std::string to_string_(std::ostringstream &out, T &&arg)
{
    out << std::move(arg);
    return out.str();
}
template <typename T, typename ...Ts>
std::string to_string_(std::ostringstream &out, T &&arg, Ts&&... args)
{
    out << std::move(arg);
    return to_string_(out, std::forward<Ts>(args)...);
}

template <typename ...Ts>
inline std::string
to_string(Ts&& ... args)
{
    std::ostringstream out;
    return to_string_(out, std::forward<Ts>(args)...);
}

template <typename T>
std::string highlight (T const &value)
{
    return to_string(vt100::BOLD, value, vt100::RESET);
}


template <typename T, typename Duration>
double persecond(T value, Duration dur)
{
    return static_cast<double>(value) * 1000000 /
        std::chrono::duration_cast<std::chrono::microseconds>(dur).count();
}


template <typename T>
std::string pretty(T value)
{
    if (value < 1000000000) {
    if (value < 1000000) {
    if (value < 1000) {
         return to_string(value);
    }
    else return to_string(value/1000, "_K");
    }
    else return to_string(value/1000000, "_M");
    }
    else return to_string(value/1000000000, "_G");
}


