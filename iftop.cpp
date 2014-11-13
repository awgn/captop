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
std::string highlight (T const &value)
{
    std::ostringstream out;
    out << vt100::BOLD  << value << vt100::RESET;
    return out.str();
}


template <typename T>
inline std::ostringstream &
osstream(T &out)
{
    return static_cast<std::ostringstream &>(out);
}


std::string
pretty(double value)
{
    std::ostringstream out;

    if (value < 1000000000) {
    if (value < 1000000) {
    if (value < 1000) {
        return osstream(out << highlight(value)).str();
    }
    else ;
        return osstream(out << highlight(value/1000) << "_K").str();
    }
    else ;
        return osstream(out << highlight(value/1000000) << "_M").str();
    }
    else ;
        return osstream(out << highlight(value/1000000000) << "_G").str();
}


void print_stats(std::ostream &out, pcap_t *p)
{
    struct pcap_stat stat;

    if (pcap_stats(p, &stat) < 0)
        throw std::runtime_error(std::string(global::errbuf));

    auto now    = std::chrono::system_clock::now();
    auto delta  = std::chrono::duration_cast<std::chrono::microseconds>(now - global::now_).count();

    auto pps    = static_cast<double>(global::count - global::count_) * 1000000 / delta;
    auto band   = static_cast<double>(global::bandwidth - global::bandwidth_) * 8 * 1000000 / delta;

    auto drop   = static_cast<double>(stat.ps_drop - global::drop_) * 1000000 / delta;
    auto ifdrop = static_cast<double>(stat.ps_ifdrop - global::ifdrop_) * 1000000 / delta;

    out << "packets: " << highlight(global::count) << " (" << highlight(pps) << " pps) drop: "    << highlight(drop)  << " pps, ifdrop: " << highlight(ifdrop) << " pps, ";
    out << "bandwidth: " << pretty(band)   << "bit/sec " << std::endl;

    global::count_     = global::count;
    global::bandwidth_ = global::bandwidth;
    global::now_       = now;
    global::drop_      = stat.ps_drop;
    global::ifdrop_    = stat.ps_drop;
    global::tick       = 0;
}


void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *)
{
    auto p = reinterpret_cast<pcap_t *>(user);

    global::count++;
    global::bandwidth += h->len;

    if (global::tick)
        print_stats(std::cout, p);

    if (global::stop)
        pcap_breakloop(p);
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
    auto p = pcap_create(opt.ifname.c_str(), global::errbuf);
    if (p == nullptr)
        throw std::runtime_error(std::string(global::errbuf));

    if (opt.buffer_size)
    {
        std::cout << ", buffer size " << opt.buffer_size;
        if (pcap_set_buffer_size(p, opt.buffer_size) != 0)
            throw std::runtime_error("pcap_set_buffer: " + std::string(global::errbuf));
    }

    std::cout<< std::endl;

    // snaplen...
    //
    if (pcap_set_snaplen(p, opt.snaplen) != 0)
            throw std::runtime_error("pcap_set_snaplen: " + std::string(global::errbuf));

    // snaplen...
    //
    if (pcap_set_promisc(p, 1) != 0)
            throw std::runtime_error("pcap_set_promisc: " + std::string(global::errbuf));

    // activate...
    //
    if (pcap_activate(p) != 0)
        throw std::runtime_error("pcap_activate: " + std::string(global::errbuf));

    // start capture...
    //
    if (pcap_loop(p, opt.count, packet_handler, reinterpret_cast<u_char *>(p)) == -1)
        throw std::runtime_error("pcap_loop: " + std::string(global::errbuf));

    // print stats...
    //

    struct pcap_stat stat;

    if (pcap_stats(p, &stat) < 0)
        throw std::runtime_error(std::string(global::errbuf));

    std::cout << global::count << " packets captured" << std::endl;
    std::cout << stat.ps_recv << " packets received by filter" << std::endl;
    std::cout << stat.ps_drop << " packets dropped by kernel" << std::endl;
    std::cout << stat.ps_ifdrop << " packets dropped by interface" << std::endl;

    return 0;
}
