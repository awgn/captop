captop 
======

Simple top, for pcap network interfaces.


Usage
-----

```
captop v1.3

usage: captop [OPTIONS] [BPF expression]

  -B --buffer SIZE             Set the operating system capture buffer size.
  -c count                     Exit after receiving count packets.
  -s snaplen                   Specify the capture length of packets in bytes.
  -t --timeout NUM             Specify the timeout in msec.
  -i --interface IFNAME        Listen on interface.
  -r --read FILE               Read packets from file.
  -o --output IFNAME           Inject packets to interface.
  -w --write FILE              Write packets to file.
  -O --no-optimize             Do not run the packet-matching code optimizer.
     --version                 Print the version strings and exit.
  -? --help                    Print this help.
```
