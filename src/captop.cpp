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

#include <signal.h>
#include <time.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>

#include <string>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <limits>
#include <random>
#include <thread>
#include <atomic>

#include <handler.hpp>
#include <global.hpp>
#include <options.hpp>
#include <util.hpp>


void print_pcap_stats(pcap_t *p)
{
    struct pcap_stat stat;

    std::cout << global::in_count.load(std::memory_order_relaxed) << " packets captured" << std::endl;

    if (global::out) {
        std::cout << global::out_count.load(std::memory_order_relaxed) << " packets injected, "
                  << global::fail.load(std::memory_order_relaxed) << " send failed" << std::endl;
    }

    if (p && pcap_stats(p, &stat) != -1) {
        std::cout << stat.ps_recv   << " packets received by filter" << std::endl;
        std::cout << stat.ps_drop   << " packets dropped by kernel" << std::endl;
        std::cout << stat.ps_ifdrop << " packets dropped by interface" << std::endl;
    }
}


void set_stop(int)
{
    if (global::in)
        pcap_breakloop(global::in);

    if (global::dumper)
        pcap_dump_close(global::dumper);

    print_pcap_stats(global::in);

    _Exit(0);
}


void thread_stats(pcap_t *p)
{
    struct pcap_stat stat_ = {0, 0, 0}, stat = {0, 0, 0};

    auto now_       = std::chrono::system_clock::now();
    auto in_count_  = global::in_count.load(std::memory_order_relaxed);
    auto out_count_ = global::out_count.load(std::memory_order_relaxed);
    auto in_band_   = global::in_band.load(std::memory_order_relaxed);
    auto out_band_  = global::out_band.load(std::memory_order_relaxed);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    if (!p) 
        return;

    if (pcap_stats(p, &stat_) < 0)
    {
        std::cout << "cannot read stats: " << pcap_geterr(p) << std::endl;
        return;
    }

    for(;; std::this_thread::sleep_for(std::chrono::seconds(1)))
    {
        pcap_stats(p, &stat);

        auto now = std::chrono::system_clock::now();

        auto in_count  = global::in_count.load(std::memory_order_relaxed);
        auto out_count = global::out_count.load(std::memory_order_relaxed);
        auto in_band   = global::in_band.load(std::memory_order_relaxed);
        auto out_band  = global::out_band.load(std::memory_order_relaxed);

        auto delta   = now - now_;

        auto in_pps  = persecond(in_count - in_count_, delta);
        auto out_pps = persecond(out_count - out_count_, delta);
        auto in_bps  = persecond((in_band - in_band_) * 8, delta);
        auto out_bps = persecond((out_band - out_band_) * 8, delta);
        auto drop    = persecond(stat.ps_drop - stat_.ps_drop, delta);
        auto ifdrop  = persecond(stat.ps_ifdrop - stat_.ps_ifdrop, delta);

        if (global::in) {
            std::cout << "packets: "   << highlight(in_count) << " (" << highlight(in_pps) << " pps) ";
            std::cout << "drop: "      << highlight(drop) << " pps, ifdrop: " << highlight(ifdrop) << " pps, ";
            std::cout << "in bandwidth: " << highlight(pretty(in_bps)) << "bit/sec ";
        }

        if (global::out) {
            std::cout << "injected: "   << highlight(out_count) << " (" << highlight(out_pps) << " pps) ";
            std::cout << "out bandwidth: " << highlight(pretty(out_bps)) << "bit/sec";
        }

        std::cout << std::endl;

        in_count_  = in_count;
        out_count_ = out_count;
        in_band_   = in_band;
        out_band_  = out_band;
        now_       = now;
        stat_      = stat;
    }
}



int
pcap_top_inject_live(options const &opt)
{
    // print header...
    //

    auto snap = opt.snaplen > opt.genlen ? opt.genlen : opt.snaplen;

    std::cout << "injecting to " << opt.out.ifname << ", " << snap << " snaplen, " << opt.genlen << " genlen"  << std::endl;

    // create a pcap handler
    //

    global::out = pcap_open_live(opt.out.ifname.c_str(), snap, 1, opt.timeout, global::errbuf2);
    if (global::out == nullptr)
        throw std::runtime_error("pcap_open_live:" + std::string(global::errbuf2));

    return 0;
}


int
pcap_top_inject_file(options const &opt)
{
    // print header...
    //

    std::cout << "writing to " << opt.out.filename << std::endl;

    // create a pcap handler
    //

    if (!global::in)
        throw std::runtime_error("dump to file requires input source!");

    global::dumper = pcap_dump_open(global::in, opt.out.filename.c_str());
    if (global::dumper == nullptr)
        throw std::runtime_error(std::string("pcap_dump_open: ") + pcap_geterr(global::in));

    return 0;
}


int
pcap_top_live(options const &opt, std::string const &filter)
{
    bpf_program fcode;

    // set signal handlers...
    //

    if (signal(SIGINT, set_stop) == SIG_ERR)
        throw std::runtime_error("signal");

    // print header...
    //

    std::cout << "listening on " << opt.in.ifname << ", snaplen " << opt.snaplen;

    // create a pcap handler
    //

    int status;

    global::in = pcap_create(opt.in.ifname.c_str(), global::errbuf);
    if (global::in == nullptr)
        throw std::runtime_error(std::string(global::errbuf));

    if (opt.buffer_size)
    {
        std::cout << ", buffer size " << opt.buffer_size;
        if ((status = pcap_set_buffer_size(global::in, opt.buffer_size)) != 0)
            throw std::runtime_error(std::string("pcap_set_buffer_size: ") + pcap_geterr(global::in));
    }

    // snaplen...
    //
    if ((status = pcap_set_snaplen(global::in, opt.snaplen)) != 0)
        throw std::runtime_error(std::string("pcap_set_snaplen: ") + pcap_geterr(global::in));

    // promisc...
    //
    if ((status = pcap_set_promisc(global::in, 1)) != 0)
        throw std::runtime_error(std::string("pcap_set_promisc: ") + pcap_geterr(global::in));

    // set timeout...
    //

    std::cout << ", timeout " << opt.timeout << "_ms";
    if ((status = pcap_set_timeout(global::in, opt.timeout)) != 0)
    {
        throw std::runtime_error(std::string("pcap_set_timeout: ") + pcap_geterr(global::in));
    }

    std::cout<< std::endl;

    // activate...
    //
    if ((status = pcap_activate(global::in)) != 0)
        throw std::runtime_error(pcap_geterr(global::in));

    // set BPF...
    //
    if (!filter.empty())
    {
        if (pcap_compile(global::in, &fcode, filter.c_str(), opt.oflag, PCAP_NETMASK_UNKNOWN) < 0)
            throw std::runtime_error(std::string("pcap_compile: ") + pcap_geterr(global::in));

        if (pcap_setfilter(global::in, &fcode) < 0)
            throw std::runtime_error(std::string("pcap_setfilter: ") + pcap_geterr(global::in));
    }

    // open output device...
    //

    if (!opt.out.filename.empty())
        pcap_top_inject_file(opt);

    else if (!opt.out.ifname.empty())
        pcap_top_inject_live(opt);

    // run thread of stats
    //

    std::thread (thread_stats, global::in).detach();

    auto packet_handler = get_packet_handler(opt);

    // start capture...
    //
    if (!opt.next)
    {
        if (pcap_loop(global::in, opt.count, packet_handler, nullptr) == -1)
            throw std::runtime_error("pcap_loop: " + std::string(pcap_geterr(global::in)));
    }
    else
    {
        std::cout << "using pcap_next..." << std::endl;
        auto stop = opt.count ? opt.count : std::numeric_limits<size_t>::max();
        for(size_t n = 0; n < stop; )
        {
            struct pcap_pkthdr hdr;
            const u_char *pkt = pcap_next(global::in, &hdr);
            if (pkt)
            {
                if (opt.rfilt.empty() || opt.rfilt(n))
                    packet_handler(nullptr, &hdr, pkt);
                n++;
            }
            else
                break;
        }
    }

    print_pcap_stats(global::in);
    pcap_close(global::in);
    return 0;
}


int
pcap_top_file(options const &opt, std::string const &filter)
{
    bpf_program fcode;

    // set signal handlers...
    //

    if (signal(SIGINT, set_stop) == SIG_ERR)
        throw std::runtime_error("signal");

    // create a pcap handler
    //

    global::in = pcap_open_offline(opt.in.filename.c_str(), global::errbuf);
    if (global::in == nullptr)
        throw std::runtime_error("pcap_open_offline:" + std::string(global::errbuf));

    // set BPF...
    //
    if (!filter.empty())
    {
        if (pcap_compile(global::in, &fcode, filter.c_str(), opt.oflag, PCAP_NETMASK_UNKNOWN) < 0)
            throw std::runtime_error(std::string("pcap_compile: ") + pcap_geterr(global::in));

        if (pcap_setfilter(global::in, &fcode) < 0)
            throw std::runtime_error(std::string("pcap_setfilter: ") + pcap_geterr(global::in));
    }

    // open output device...
    //

    if (!opt.out.filename.empty())
        pcap_top_inject_file(opt);

    else if (!opt.out.ifname.empty())
        pcap_top_inject_live(opt);


    // run thread of stats
    //

    std::thread (thread_stats, global::out).detach();

    // print header...
    //

    std::cout << "reading " << opt.in.filename << "..." << std::endl;

    auto packet_handler = get_packet_handler(opt);

    // start capture...
    //
    if (!opt.next)
    {
        if (pcap_loop(global::in, opt.count, packet_handler, nullptr) == -1)
            throw std::runtime_error("pcap_loop: " + std::string(pcap_geterr(global::in)));
    }
    else {
        std::cout << "using pcap_next..." << std::endl;
        auto stop = opt.count ? opt.count : std::numeric_limits<size_t>::max();
        for(size_t n = 0; n < stop; )
        {
            struct pcap_pkthdr hdr;
            const u_char *pkt = pcap_next(global::in, &hdr);
            if (pkt)
            {
                if (opt.rfilt.empty() || opt.rfilt(n))
                    packet_handler(nullptr, &hdr, pkt);
                n++;
            }
            else
                break;
        }
    }

    print_pcap_stats(global::in);
    pcap_close(global::in);
    return 0;
}


int
pcap_top_gen(options const &opt, std::string const &)
{
    auto len = opt.genlen > 1514 ? 1514 : opt.genlen;

    // set signal handlers...
    //

    if (signal(SIGINT, set_stop) == SIG_ERR)
        throw std::runtime_error("signal");

    if (!opt.out.filename.empty())
        pcap_top_inject_file(opt);

    else if (!opt.out.ifname.empty())
        pcap_top_inject_live(opt);

    // run thread of stats
    //

    std::thread (thread_stats, global::out).detach();

    auto stop = opt.count ? opt.count : std::numeric_limits<size_t>::max();

    std::mt19937 gen;

    auto ip = reinterpret_cast<iphdr *>(global::default_packet + 14);

    for(size_t n = 0; n < stop; n++)
    {
            if (opt.rand_ip)
            {
                ip->saddr = static_cast<uint32_t>(gen());
                ip->daddr = static_cast<uint32_t>(gen());
            }

            int ret = pcap_inject(global::out, global::default_packet, len);
            if (ret >= 0)
            {
                global::out_count.fetch_add(1, std::memory_order_relaxed);
                global::out_band.fetch_add(len, std::memory_order_relaxed);
            }
            else
                global::fail.fetch_add(1, std::memory_order_relaxed);
    }

    return 0;
}


int
pcap_top(options const &opt, std::string const &filter)
{
    if (!opt.in.filename.empty())
        return pcap_top_file(opt, filter);

    if (!opt.in.ifname.empty())
        return pcap_top_live(opt, filter);

    if (!opt.out.ifname.empty() || !opt.out.filename.empty())
        return pcap_top_gen(opt, filter);

    throw std::runtime_error("interface/filename missing");
}

