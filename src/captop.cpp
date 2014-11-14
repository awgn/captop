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

#include <options.hpp>
#include <vt100.hpp>

#include <signal.h>
#include <time.h>
#include <pcap/pcap.h>


namespace global
{
    char errbuf[PCAP_ERRBUF_SIZE];

    sig_atomic_t  tick = 0;

    uint64_t  count_    = 0, count    = 0;
    uint64_t  bandwidth_ = 0, bandwidth = 0;
    uint64_t  drop_ = 0, ifdrop_ = 0;

    struct pcap_stat stat_, stat;

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


void tick_handler(int)
{
    global::tick = 1;
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


void print_stats(std::ostream &out, pcap_t *p)
{
    if (pcap_stats(p, &global::stat) < 0)
        throw std::runtime_error(std::string(global::errbuf));

    auto now    = std::chrono::system_clock::now();
    auto delta  = now - global::now_;

    auto pps    = persecond(global::count - global::count_, delta);
    auto band   = persecond((global::bandwidth - global::bandwidth_) * 8, delta);
    auto drop   = persecond(global::stat.ps_drop - global::stat_.ps_drop, delta);
    auto ifdrop = persecond(global::stat.ps_ifdrop - global::stat_.ps_ifdrop, delta);

    out << "packets: "   << highlight(global::count) << " (" << highlight(pps) << " pps) ";
    out << "drop: "      << highlight(drop) << " pps, ifdrop: " << highlight(ifdrop) << " pps, ";
    out << "bandwidth: " << highlight(pretty(band)) << "bit/sec " << std::endl;

    global::count_     = global::count;
    global::bandwidth_ = global::bandwidth;
    global::now_       = now;
    global::stat_      = global::stat;
    global::tick       = 0;
}


void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *)
{
    global::count++;
    global::bandwidth += h->len;

    if (global::tick)
        print_stats(std::cout, global::p);
}


int
pcap_top(options const &opt, std::string const &filter)
{
    bpf_program fcode;
    timer_t t;

    itimerspec timer_spec
    {
        { 1, 0 },   // interval
        { 1, 0 }    // first expiration
    };


    // set signal handlers...
    //
    if (signal(SIGALRM, tick_handler) == SIG_ERR)
        throw std::runtime_error("signal");

    if (signal(SIGINT, set_stop) == SIG_ERR)
        throw std::runtime_error("signal");

    // create a timer...
    //
    if (timer_create(CLOCK_REALTIME, nullptr, &t) < 0)
        throw std::runtime_error("timer_create");

    global::now_ = std::chrono::system_clock::now();

    // start the timer...
    //
    if (timer_settime(t, 0, &timer_spec, nullptr) < 0)
        throw std::runtime_error("timer_settime");

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

    // start capture...
    //
    if (pcap_loop(global::p, opt.count, packet_handler, nullptr) == -1)
        throw std::runtime_error("pcap_loop: " + std::string(global::errbuf));

    print_pcap_stats(global::p, global::count);

    pcap_close(global::p);

    return 0;
}
