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
#include <iomanip>
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

#include <pthread.h>

int pcap_top_inject_file(options const &opt, int id);

static inline
void thread_affinity(std::thread &t, size_t n)
{
    if(t.get_id() == std::thread::id())
        throw std::runtime_error("thread not running");

    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(n, &cpuset);

    auto pth = t.native_handle();
    if ( ::pthread_setaffinity_np(pth, sizeof(cpuset), &cpuset) != 0)
        throw std::runtime_error("pthread_setaffinity_np");
}


void set_stop(int)
{
    global::stop.store(true, std::memory_order_relaxed);
}


template <typename Dur>
void print_stats(std::string tid, capthread::stat const &t, capthread::stat const &t_, Dur delta)
{
        auto in_pps  = persecond(t.in_count  - t_.in_count, delta);
        auto out_pps = persecond(t.out_count - t_.out_count, delta);
        auto in_bps  = persecond((t.in_band  - t_.in_band) * 8, delta);
        auto out_bps = persecond((t.out_band - t_.out_band) * 8, delta);
        auto fail_ps = persecond(t.fail - t_.fail, delta);

        std::cout << std::setw(4) << tid <<  "| ";
        std::cout << " packets: "  << (highlight(t.in_count)      + "(" + highlight(in_pps) + " pps)");
        std::cout << " in-band: "  << (highlight(pretty(in_bps))  + "bit/sec");
        std::cout << " injected: " << (highlight(t.out_count)     + "(" + highlight(out_pps) + " pps)");
        std::cout << " fail: "     << (highlight(t.fail)          + "(" + highlight(fail_ps) + "/sec)");
        std::cout << " out-band: " << (highlight(pretty(out_bps)) + "bit/sec");
}


void thread_stats(options const &opt, pcap_t *pstat)
{
    struct pcap_stat stat_ = {0, 0, 0}, stat = {0, 0, 0};
    std::vector<capthread::stat> tstats_;

    auto read_tstat = [] {
        std::vector<capthread::stat> s;
        for(auto &t : global::thread_ctx)
        {
            s.push_back(static_cast<capthread::stat>(t->atomic_stat));
        }
        return s;
    };

    std::this_thread::sleep_for(std::chrono::seconds(1));

    auto now_  = std::chrono::system_clock::now();

    if (!pstat) {
        std::cout << "stats not available..." << std::endl;
        return;
    }

    if (pcap_stats(pstat, &stat_) < 0) {
        std::cout << "cannot read stats: " << pcap_geterr(pstat) << std::endl;
        return;
    }

    auto tstat_ = read_tstat();
    auto tsum_  = sum(tstat_);

    for(;; std::this_thread::sleep_for(std::chrono::seconds(1)))
    {
        if (unlikely(global::stop.load(std::memory_order_relaxed)))
            break;

        pcap_stats(pstat, &stat);

        auto now = std::chrono::system_clock::now();
        auto tstat = read_tstat();
        auto tsum  = sum(tstat);

        auto delta = now - now_;

        auto drop    = persecond(stat.ps_drop - stat_.ps_drop, delta);
        auto ifdrop  = persecond(stat.ps_ifdrop - stat_.ps_ifdrop, delta);

        if (opt.numthread > 1)
        {
            for(size_t i = 0; i < tstat.size(); i++) {
                print_stats('#' + std::to_string(i), tstat[i], tstat_[i], delta);
                std::cout << std::endl;
            }
            print_stats("TOT", tsum, tsum_, delta);
            std::cout << " drop: " << highlight(drop) << " pps, ifdrop: " << highlight(ifdrop) << " pps" << std::endl;
        }
        else
        {
            print_stats("*", tsum, tsum_, delta);
            std::cout << " drop: " << highlight(drop) << " pps, ifdrop: " << highlight(ifdrop) << " pps" << std::endl;
        }

        tstat_ = tstat;
        now_   = now;
        stat_  = stat;
        tsum_  = std::move(tsum);
    }
}


void print_pcap_stats(pcap_t *p, int id)
{
    static std::mutex m;
    std::lock_guard<std::mutex> lock(m);

    struct pcap_stat stat;

    std::cout << "#" << id << " thread:" << std::endl;

    auto &ctx = global::thread_ctx.at(id);

    std::cout << ctx->atomic_stat.in_count.load(std::memory_order_relaxed) << " packets captured" << std::endl;

    if (ctx->out) {
        std::cout << ctx->atomic_stat.out_count.load(std::memory_order_relaxed) << " packets injected, "
                  << ctx->atomic_stat.fail.load(std::memory_order_relaxed) << " send failed" << std::endl;
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

    auto &ctx = global::thread_ctx.at(id);

    if (!ctx->in)
        throw std::runtime_error("dump to file requires input source!");

    ctx->dumper = pcap_dump_open(ctx->in, opt.out.filename.c_str());
    if (ctx->dumper == nullptr)
        throw std::runtime_error(std::string("pcap_dump_open: ") + pcap_geterr(ctx->in));

    return 0;
}



int
pcap_top_inject_live(options const &opt, int id)
{
    // print header...
    //
    auto this_thread = global::thread_ctx.at(id).get();

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

        std::cout << "reading from " << opt.in.filename << "..." << std::endl;

        auto packet_handler = get_packet_handler(opt);

        // start capture...
        //
        if (!opt.next)
        {
            if (pcap_loop(this->in, opt.count, packet_handler, reinterpret_cast<u_char *>(this)) == -1)
                std::cerr << "pcap_loop: " << pcap_geterr(this->in) << std::endl;
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

        if (this->dumper) {
            std::cout << "closing file..." << std::endl;
            pcap_dump_close(this->dumper);
        }

        global::stop.store(true, std::memory_order_relaxed);
        print_pcap_stats(this->in, id);
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
                    throw std::runtime_error(std::string("pcap_fanout: ") + pcap_geterr(this->in));
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

        global::stop.store(true, std::memory_order_relaxed);
        print_pcap_stats(this->in, this->id);
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
                    this->atomic_stat.fail.fetch_add(1, std::memory_order_relaxed);
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
                std::thread t(std::ref(*ctx), opt, filter);
                thread_affinity(t, opt.firstcore + n);
                global::thread.push_back(std::move(t));
                return ctx;
            }
            if (!opt.in.ifname.empty()) {
                auto ctx = new pcap_top_live(n);
                std::thread t(std::ref(*ctx), opt, filter);
                thread_affinity(t, opt.firstcore + n);
                global::thread.push_back(std::move(t));
                return ctx;
            }

            if (!opt.out.ifname.empty() || !opt.out.filename.empty()) {
                auto ctx = new pcap_top_gen(n);
                std::thread t(std::ref(*ctx), opt, filter);
                thread_affinity(t, opt.firstcore + n);
                global::thread.push_back(std::move(t));
                return ctx;
            }

            throw std::runtime_error("interface/filename missing");

            }()
        );

        global::thread_ctx.push_back(std::move(t));
    }
    
    for(auto &t : global::thread)
       t.detach();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    auto stat = [&] () -> pcap_t *{
        for(auto &c : global::thread_ctx) {
            if (c->pstat) {
                return c->pstat;
            }
        }
        return nullptr;
    }();
    
    std::thread s(thread_stats, opt, stat);
    s.join();

    return 0;
}

