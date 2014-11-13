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
    sig_atomic_t  stop = 0;

    uint64_t  count_    = 0, count    = 0;
    uint64_t  bandwidth_ = 0, bandwidth = 0;
    uint64_t  drop_ = 0, ifdrop_ = 0;

    struct pcap_stat stat_, stat;

    std::chrono::time_point<std::chrono::system_clock> now_;
}


void tick_handler(int)
{
    global::tick = 1;
}

void set_stop(int)
{
    global::stop = 1;
}


template <typename T>
inline std::ostringstream &
osstream(T &out)
{
    return static_cast<std::ostringstream &>(out);
}


template <typename T>
std::string highlight (T const &value)
{
    std::ostringstream out;
    return osstream(out << vt100::BOLD  << value << vt100::RESET).str();
}


std::string
pretty(double value)
{
    std::ostringstream out;

    if (value < 1000000000) {
    if (value < 1000000) {
    if (value < 1000) {
        return osstream(out << value).str();
    }
    else ;
        return osstream(out << (value/1000) << "_K").str();
    }
    else ;
        return osstream(out << (value/1000000) << "_M").str();
    }
    else ;
        return osstream(out << (value/1000000000) << "_G").str();
}


template <typename T, typename Duration>
double persecond(T value, Duration dur)
{
    return static_cast<double>(value) * 1000000 / std::chrono::duration_cast<std::chrono::microseconds>(dur).count();
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
    auto p = reinterpret_cast<pcap_t *>(user);

    global::count++;
    global::bandwidth += h->len;

    if (global::tick)
        print_stats(std::cout, p);

    if (global::stop) {
        pcap_breakloop(p);
    }
}


int
pcap_top(options const &opt, std::string const &bpf)
{
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

    auto p = pcap_create(opt.ifname.c_str(), global::errbuf);
    if (p == nullptr)
        throw std::runtime_error(std::string(global::errbuf));

    if (opt.buffer_size)
    {
        std::cout << ", buffer size " << opt.buffer_size;
        if ((status = pcap_set_buffer_size(p, opt.buffer_size)) != 0)
            throw std::runtime_error(std::string("pcap_set_buffer: ") + pcap_statustostr(status));
    }

    std::cout<< std::endl;

    // snaplen...
    //
    if ((status = pcap_set_snaplen(p, opt.snaplen)) != 0)
        throw std::runtime_error(std::string("pcap_set_snaplen: ") + pcap_statustostr(status));

    // snaplen...
    //
    if ((status = pcap_set_promisc(p, 1)) != 0)
        throw std::runtime_error(std::string("pcap_set_promisc: ") + pcap_statustostr(status));

    // set timeout...
    //
    if ((status = pcap_set_timeout(p, 1000)) != 0)
        throw std::runtime_error(std::string("pcap_set_timeout: ") + pcap_statustostr(status));

    // activate...
    //
    if ((status = pcap_activate(p)) != 0)
        throw std::runtime_error(std::string("pcap_activate: ") + pcap_statustostr(status));

    // start capture...
    //
    if (pcap_loop(p, opt.count, packet_handler, reinterpret_cast<u_char *>(p)) == -1)
        throw std::runtime_error("pcap_loop: " + std::string(global::errbuf));

    pcap_close(p);

    // print stats...
    //

    std::cout << global::count << " packets captured" << std::endl;
    std::cout << global::stat.ps_recv << " packets received by filter" << std::endl;
    std::cout << global::stat.ps_drop << " packets dropped by kernel" << std::endl;
    std::cout << global::stat.ps_ifdrop << " packets dropped by interface" << std::endl;

    return 0;
}
