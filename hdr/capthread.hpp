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

#include <pcap/pcap.h>

#include <atomic>
#include <vector>

struct capthread
{
    struct stat
    {
        unsigned long in_count;
        unsigned long out_count;
        unsigned long in_band;
        unsigned long out_band;
        unsigned long fail;
    };

    int id;

    char errbuf[PCAP_ERRBUF_SIZE];
    char errbuf2[PCAP_ERRBUF_SIZE];

    struct atomic_stat
    {
        std::atomic_ulong in_count;
        std::atomic_ulong out_count;
        std::atomic_ulong in_band;
        std::atomic_ulong out_band;
        std::atomic_ulong fail;

        operator stat() const
        {
            return {   in_count .load(std::memory_order_relaxed)
                   ,   out_count.load(std::memory_order_relaxed)
                   ,   in_band  .load(std::memory_order_relaxed)
                   ,   out_band .load(std::memory_order_relaxed)
                   ,   fail     .load(std::memory_order_relaxed)
                   };
        }

    } atomic_stat;

    pcap_t *in, *out;

    pcap_t *pstat;
    pcap_dumper_t *dumper;
};


inline
capthread::stat
operator+(capthread::stat const &lhs, capthread::stat const &rhs)
{
    return { lhs.in_count  + rhs.in_count
           , lhs.out_count + rhs.out_count
           , lhs.in_band   + rhs.in_band
           , lhs.out_band  + rhs.out_band 
           , lhs.fail      + rhs.fail};
}

inline
capthread::stat
operator-(capthread::stat const &lhs, capthread::stat const &rhs)
{
    return { lhs.in_count  - rhs.in_count
           , lhs.out_count - rhs.out_count
           , lhs.in_band   - rhs.in_band
           , lhs.out_band  - rhs.out_band 
           , lhs.fail      - rhs.fail };
}

inline
capthread::stat
sum(std::vector<capthread::stat> const &v)
{
    capthread::stat total {0,0,0,0,0};

    for(auto &s : v) {
        total = total + s;
    }

    return total;
}


#define likely(x)		__builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
