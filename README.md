captop 
======

Utility to measure the performance of pcap network interfaces.

Usage
-----

```
captop v1.10
libpcap version 1.6.2

usage: captop [OPTIONS] [BPF expression]

Pcap options:
  -B --buffer SIZE             Set the operating system capture buffer size.
  -c count                     Exit after receiving count packets.
  -s --snaplen VALUE           Specify the capture length of packets in bytes.
  -t --timeout NUM             Specify the timeout in msec.
  -O --no-optimize             Do not run the packet-matching code optimizer.

Generator:
  -R --rand-ip                 Randomize IPs addresses.
  -g --genlen  VALUE           Specify the length of injected packets.

Interface:
  -i --interface IFNAME        Listen on interface.
  -o --output IFNAME           Inject packets into interface.

File:
  -r --read  FILE              Read packets from file.
  -w --write FILE              Write packets to file.

Miscellaneous:
     --version                 Print the version strings and exit.
  -? --help                    Print this help.
```
