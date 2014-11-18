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

#include <string>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <chrono>

#include <thread>
#include <atomic>

#include <options.hpp>
#include <vt100.hpp>

#include <signal.h>
#include <time.h>
#include <pcap/pcap.h>


namespace global
{
    char errbuf[PCAP_ERRBUF_SIZE];

    std::atomic_long count;
    std::atomic_long bandw;

    pcap_t *p;

    std::chrono::time_point<std::chrono::system_clock> now_;
}


void print_pcap_stats(pcap_t *p, uint64_t count)
{
    struct pcap_stat stat;

    if (pcap_stats(p, &stat) < 0)
        throw std::runtime_error(std::string(global::errbuf));

    std::cout << count          << " packets captured" << std::endl;
    std::cout << stat.ps_recv   << " packets received by filter" << std::endl;
    std::cout << stat.ps_drop   << " packets dropped by kernel" << std::endl;
    std::cout << stat.ps_ifdrop << " packets dropped by interface" << std::endl;
}


void set_stop(int)
{
    pcap_breakloop(global::p);
    print_pcap_stats(global::p, global::count);
    _Exit(0);
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


std::string
pretty(double value)
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


template <typename T, typename Duration>
double persecond(T value, Duration dur)
{
    return static_cast<double>(value) * 1000000 /
        std::chrono::duration_cast<std::chrono::microseconds>(dur).count();
}


void thread_stats(pcap_t *p)
{
    struct pcap_stat stat_, stat;

    auto now_   = std::chrono::system_clock::now();
    auto count_ = global::count.load(std::memory_order_relaxed);
    auto bandw_ = global::bandw.load(std::memory_order_relaxed);

    if (pcap_stats(p, &stat_) < 0)
        throw std::runtime_error(std::string(global::errbuf));

    for(;;)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        if (pcap_stats(p, &stat) < 0)
            throw std::runtime_error(std::string(global::errbuf));

        auto now = std::chrono::system_clock::now();

        auto count = global::count.load(std::memory_order_relaxed);
        auto bandw = global::bandw.load(std::memory_order_relaxed);

        auto delta  = now - now_;

        auto pps    = persecond(count - count_, delta);
        auto band   = persecond((bandw - bandw_) * 8, delta);
        auto drop   = persecond(stat.ps_drop - stat_.ps_drop, delta);
        auto ifdrop = persecond(stat.ps_ifdrop - stat_.ps_ifdrop, delta);

        std::cout << "packets: "   << highlight(count) << " (" << highlight(pps) << " pps) ";
        std::cout << "drop: "      << highlight(drop) << " pps, ifdrop: " << highlight(ifdrop) << " pps, ";
        std::cout << "bandwidth: " << highlight(pretty(band)) << "bit/sec " << std::endl;

        count_ = count;
        bandw_ = bandw;
        now_   = now;
        stat_  = stat;
    }
}


void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *)
{
    global::count.fetch_add(1, std::memory_order_relaxed);
    global::bandw.fetch_add(h->len, std::memory_order_relaxed);
}


int
pcap_top(options const &opt, std::string const &filter)
{
    bpf_program fcode;

    // set signal handlers...
    //

    if (signal(SIGINT, set_stop) == SIG_ERR)
        throw std::runtime_error("signal");


    // print header...
    //

    std::cout << "listening on " << opt.ifname << ", snaplen " << opt.snaplen;


    // create a pcap handler
    //

    int status;

    global::p = pcap_create(opt.ifname.c_str(), global::errbuf);
    if (global::p == nullptr)
        throw std::runtime_error(std::string(global::errbuf));

    if (opt.buffer_size)
    {
        std::cout << ", buffer size " << opt.buffer_size;
        if ((status = pcap_set_buffer_size(global::p, opt.buffer_size)) != 0)
            throw std::runtime_error(std::string("pcap_set_buffer: ") + pcap_statustostr(status));
    }

    // snaplen...
    //
    if ((status = pcap_set_snaplen(global::p, opt.snaplen)) != 0)
        throw std::runtime_error(std::string("pcap_set_snaplen: ") + pcap_statustostr(status));

    // snaplen...
    //
    if ((status = pcap_set_promisc(global::p, 1)) != 0)
        throw std::runtime_error(std::string("pcap_set_promisc: ") + pcap_statustostr(status));

    // set timeout...
    //

    std::cout << ", timeout " << opt.timeout << "_ms";
    if ((status = pcap_set_timeout(global::p, opt.timeout)) != 0)
    {
        throw std::runtime_error(std::string("pcap_set_timeout: ") + pcap_statustostr(status));
    }

    std::cout<< std::endl;

    // activate...
    //
    if ((status = pcap_activate(global::p)) != 0)
        throw std::runtime_error(pcap_statustostr(status));

    // set BPF...
    //
    if (!filter.empty())
    {
        if (pcap_compile(global::p, &fcode, filter.c_str(), opt.oflag, PCAP_NETMASK_UNKNOWN) < 0)
            throw std::runtime_error(std::string("pcap_compile: ") + pcap_geterr(global::p));
    }

    // run thread of stats
    //

    std::thread (thread_stats, global::p).detach();

    // start capture...
    //
    if (pcap_loop(global::p, opt.count, packet_handler, nullptr) == -1)
        throw std::runtime_error("pcap_loop: " + std::string(global::errbuf));

    print_pcap_stats(global::p, global::count);

    pcap_close(global::p);

    return 0;
}
