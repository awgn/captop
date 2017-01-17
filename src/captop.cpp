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
#include <mutex>
#include <chrono>
#include <limits>
#include <random>
#include <thread>
#include <atomic>
#include <memory>

#include <capthread.hpp>
#include <handler.hpp>
#include <global.hpp>
#include <options.hpp>
#include <util.hpp>


int pcap_top_inject_file(options const &opt, int id);


void set_stop(int)
{
    global::stop.store(true, std::memory_order_relaxed);
}


void thread_stats()
{
    struct pcap_stat stat_ = {0, 0, 0}, stat = {0, 0, 0};

    std::vector<capthread::stat> tstats_;

    auto read_tstat = [] {
        std::vector<capthread::stat> s;
        for(auto &t : global::thread)
        {
            s.push_back(static_cast<capthread::stat>(t->atomic_stat));
        }
        return s;
    };

    std::this_thread::sleep_for(std::chrono::seconds(1));

    auto now_  = std::chrono::system_clock::now();

    // if (pcap_stats(p, &stat_) < 0)
    // {
    //     std::cout << "cannot read stats: " << pcap_geterr(p) << std::endl;
    //     return;
    // }

    auto tstat_ = sum(read_tstat());

    for(;; std::this_thread::sleep_for(std::chrono::seconds(1)))
    {
        // pcap_stats(p, &stat);

        auto now = std::chrono::system_clock::now();
        auto tstat = sum(read_tstat());
        auto delta = now - now_;

        auto drop    = persecond(stat.ps_drop - stat_.ps_drop, delta);
        auto ifdrop  = persecond(stat.ps_ifdrop - stat_.ps_ifdrop, delta);

        auto in_pps  = persecond(tstat.in_count  - tstat_.in_count, delta);
        auto out_pps = persecond(tstat.out_count - tstat_.out_count, delta);
        auto in_bps  = persecond((tstat.in_band  - tstat_.in_band) * 8, delta);
        auto out_bps = persecond((tstat.out_band - tstat_.out_band) * 8, delta);

        std::cout << "packets: "       << highlight(tstat.in_count) << " (" << highlight(in_pps) << " pps) ";
        std::cout << "drop: "          << highlight(drop)     << " pps, ifdrop: " << highlight(ifdrop) << " pps, ";
        std::cout << "in bandwidth: "  << highlight(pretty(in_bps)) << "bit/sec ";
        std::cout << "injected: "      << highlight(tstat.out_count) << " (" << highlight(out_pps) << " pps) ";
        std::cout << "out bandwidth: " << highlight(pretty(out_bps)) << "bit/sec";

        std::cout << std::endl;

        tstat_ = tstat;
        now_   = now;
        stat_  = stat;

        if (unlikely(global::stop.load(std::memory_order_relaxed)))
            break;
    }

}


void print_pcap_stats(pcap_t *p, int id)
{
    static std::mutex m;
    std::lock_guard<std::mutex> lock(m);

    struct pcap_stat stat;

    std::cout << "#" << id << " thread:" << std::endl;

    std::cout << global::thread.at(id)->atomic_stat.in_count.load(std::memory_order_relaxed) << " packets captured" << std::endl;

    if (global::thread.at(id)->out) {
        std::cout << global::thread.at(id)->atomic_stat.out_count.load(std::memory_order_relaxed) << " packets injected, "
                  << global::thread.at(id)->fail.load(std::memory_order_relaxed) << " send failed" << std::endl;
    }

    if (p && pcap_stats(p, &stat) != -1) {
        std::cout << stat.ps_recv   << " packets received by filter" << std::endl;
        std::cout << stat.ps_drop   << " packets dropped by kernel" << std::endl;
        std::cout << stat.ps_ifdrop << " packets dropped by interface" << std::endl;
    }
}


int
pcap_top_inject_file(options const &opt, int id)
{
    // print header...
    //

    std::cout << "writing to " << opt.out.filename << std::endl;

    // create a pcap handler
    //

    if (!global::thread.at(id)->in)
        throw std::runtime_error("dump to file requires input source!");

    global::thread.at(id)->dumper = pcap_dump_open(global::thread.at(id)->in, opt.out.filename.c_str());
    if (global::thread.at(id)->dumper == nullptr)
        throw std::runtime_error(std::string("pcap_dump_open: ") + pcap_geterr(global::thread.at(id)->in));

    return 0;
}



int
pcap_top_inject_live(options const &opt, int id)
{
    // print header...
    //
    auto this_thread = global::thread.at(id).get();

    auto snap = opt.snaplen > opt.genlen ? opt.genlen : opt.snaplen;
    std::cout << "injecting to " << opt.out.ifname << ", " << snap << " snaplen, " << opt.genlen << " genlen"  << std::endl;

    // create a pcap handler
    //

    this_thread->out = pcap_open_live(opt.out.ifname.c_str(), snap, 1, opt.timeout, this_thread->errbuf2);
    if (this_thread->out == nullptr)
        throw std::runtime_error("pcap_open_live:" + std::string(this_thread->errbuf2));

    return 0;
}

//
// pcap_top_file...
//

struct pcap_top_file : public capthread
{
    pcap_top_file(int i)
    {
        id = i;
    }

    int
    operator()(options const &opt, std::string const &filter)
    {
        bpf_program fcode;

        // create a pcap handler
        //

        in = pcap_open_offline(opt.in.filename.c_str(), errbuf);
        if (in == nullptr)
            throw std::runtime_error("pcap_open_offline:" + std::string(errbuf));

        // set BPF...
        //
        if (!filter.empty())
        {
            if (pcap_compile(in, &fcode, filter.c_str(), opt.oflag, PCAP_NETMASK_UNKNOWN) < 0)
                throw std::runtime_error(std::string("pcap_compile: ") + pcap_geterr(in));

            if (pcap_setfilter(in, &fcode) < 0)
                throw std::runtime_error(std::string("pcap_setfilter: ") + pcap_geterr(in));
        }

        // open output device...
        //

        if (!opt.out.filename.empty())
            pcap_top_inject_file(opt, id);

        else if (!opt.out.ifname.empty())
            pcap_top_inject_live(opt, id);


        // print header...
        //

        std::cout << "reading " << opt.in.filename << "..." << std::endl;

        auto packet_handler = get_packet_handler(opt);

        // start capture...
        //
        if (!opt.next)
        {
            if (pcap_loop(this->in, opt.count, packet_handler, reinterpret_cast<u_char *>(this)) == -1)
                throw std::runtime_error("pcap_loop: " + std::string(pcap_geterr(this->in)));
        }
        else {
            std::cout << "using pcap_next..." << std::endl;
            auto stop = opt.count ? opt.count : std::numeric_limits<size_t>::max();
            for(size_t n = 0; n < stop; )
            {
                struct pcap_pkthdr hdr;
                const u_char *pkt = pcap_next(this->in, &hdr);
                if (pkt)
                {
                    if (opt.rfilt.empty() || opt.rfilt(n))
                        packet_handler(reinterpret_cast<u_char*>(this), &hdr, pkt);
                    n++;
                }
                else
                    break;
            }
        }

        if (this->dumper)
            pcap_dump_close(this->dumper);

        print_pcap_stats(this->in, id);
        pcap_close(this->in);
        return 0;
    }
};


#ifndef PCAP_VERSION_FANOUT
int pcap_fanout(pcap_t *p, int group, const char *fanout)
{
    throw std::runtime_error("pcap_fanout: not supported by this pcap library!");
}
#endif

struct pcap_top_live : public capthread
{
    pcap_top_live(int i)
    {
        id = i;
    }

    int
    operator()(options const &opt, std::string const &filter)
    {
        std::unique_lock<std::mutex> lock(global::syncout);

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

        this->in = pcap_create(opt.in.ifname.c_str(), this->errbuf);
        if (this->in == nullptr)
            throw std::runtime_error(std::string(this->errbuf));

        this->pstat = this->in;

        // buffer size
        //
        if (opt.buffer_size)
        {
            std::cout << ", buffer size " << opt.buffer_size;
            if ((status = pcap_set_buffer_size(this->in, opt.buffer_size)) != 0)
                throw std::runtime_error(std::string("pcap_set_buffer_size: ") + pcap_geterr(this->in));
        }

        // snaplen...
        //
        if ((status = pcap_set_snaplen(this->in, opt.snaplen)) != 0)
            throw std::runtime_error(std::string("pcap_set_snaplen: ") + pcap_geterr(this->in));

        // promisc...
        //
        if ((status = pcap_set_promisc(this->in, 1)) != 0)
            throw std::runtime_error(std::string("pcap_set_promisc: ") + pcap_geterr(this->in));

        // set timeout...
        //

        std::cout << ", timeout " << opt.timeout << "_ms";
        if ((status = pcap_set_timeout(this->in, opt.timeout)) != 0)
        {
            throw std::runtime_error(std::string("pcap_set_timeout: ") + pcap_geterr(this->in));
        }

        std::cout<< std::endl;

        lock.unlock();

        // activate...
        //
        if ((status = pcap_activate(this->in)) != 0)
            throw std::runtime_error(pcap_geterr(this->in));

#ifdef PCAP_VERSION_FANOUT
        if (!opt.fanout.empty()) {
            if ((status = pcap_fanout(this->in, opt.group, opt.fanout.c_str())) != 0) {
                    throw std::runtime_error(std::string("pcap_fabout: ") + pcap_geterr(this->in));
            }
        }
#endif
        // set BPF...
        //
        if (!filter.empty())
        {
            if (pcap_compile(this->in, &fcode, filter.c_str(), opt.oflag, PCAP_NETMASK_UNKNOWN) < 0)
                throw std::runtime_error(std::string("pcap_compile: ") + pcap_geterr(this->in));

            if (pcap_setfilter(this->in, &fcode) < 0)
                throw std::runtime_error(std::string("pcap_setfilter: ") + pcap_geterr(this->in));
        }

        // open output device...
        //

        if (!opt.out.filename.empty())
            pcap_top_inject_file(opt, id);

        else if (!opt.out.ifname.empty())
            pcap_top_inject_live(opt, id);

        // run thread of stats
        //

        auto packet_handler = get_packet_handler(opt);

        // start capture...
        //
        if (!opt.next)
        {
            if (pcap_loop(this->in, opt.count, packet_handler, reinterpret_cast<u_char*>(this)) == -1)
                throw std::runtime_error("pcap_loop: " + std::string(pcap_geterr(this->in)));
        }
        else
        {
            std::cout << "using pcap_next..." << std::endl;
            auto stop = opt.count ? opt.count : std::numeric_limits<size_t>::max();
            for(size_t n = 0; n < stop; )
            {
                struct pcap_pkthdr hdr;
                const u_char *pkt = pcap_next(this->in, &hdr);
                if (pkt)
                {
                    if (opt.rfilt.empty() || opt.rfilt(n))
                        packet_handler(reinterpret_cast<u_char*>(this), &hdr, pkt);
                    n++;
                }
                else
                    break;
            }
        }

        print_pcap_stats(this->in, this->id);
        pcap_close(this->in);
        return 0;
    }

};


struct pcap_top_gen : public capthread
{
    pcap_top_gen(int i)
    {
        id = i;
    }

    int
    operator()(options const &opt, std::string const &)
    {
        auto len = opt.genlen > 1514 ? 1514 : opt.genlen;

        // set signal handlers...
        //

        if (signal(SIGINT, set_stop) == SIG_ERR)
            throw std::runtime_error("signal");

        if (!opt.out.filename.empty())
            pcap_top_inject_file(opt, id);

        else if (!opt.out.ifname.empty())
            pcap_top_inject_live(opt, 0xdeadbeef);

        // run thread of stats
        //

        this->pstat = this->out;

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

                int ret = pcap_inject(this->out, global::default_packet, len);
                if (ret >= 0)
                {
                    this->atomic_stat.out_count.fetch_add(1, std::memory_order_relaxed);
                    this->atomic_stat.out_band.fetch_add(len, std::memory_order_relaxed);
                }
                else {
                    // FIXME
                    // this->atomic_stat.fail.fetch_add(1, std::memory_order_relaxed);
                }
        }

        return 0;
    }

};


int
pcap_top(options const &opt, std::string const &filter)
{
    if (signal(SIGINT, set_stop) == SIG_ERR)
            throw std::runtime_error("signal SIGINT");

    for(size_t n = 0; n < opt.numthread; n++)
    {
        std::unique_ptr<capthread> t(
            [&] () -> capthread * {

            if (!opt.in.filename.empty()) {
                auto ctx = new pcap_top_file(n);
                std::thread(std::ref(*ctx), opt, filter).detach();
                return ctx;
            }
            if (!opt.in.ifname.empty()) {
                auto ctx = new pcap_top_live(n);
                std::thread(std::ref(*ctx), opt, filter).detach();
                return ctx;
            }
            if (!opt.out.ifname.empty() || !opt.out.filename.empty()) {
                auto ctx = new pcap_top_gen(n);
                std::thread(std::ref(*ctx), opt, filter).detach();
                return ctx;
            }

            throw std::runtime_error("interface/filename missing");

            }()
        );

        global::thread.push_back(std::move(t));

    }

    std::thread s(thread_stats);
    s.join();

    return 0;
}

