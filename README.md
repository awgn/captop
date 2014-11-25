captop 
======

Simple top, for pcap network interfaces.


Usage
-----

```
captop v1.5

usage: captop [OPTIONS] [BPF expression]

Pcap options:
  -B --buffer SIZE             Set the operating system capture buffer size.
  -c count                     Exit after receiving count packets.
  -s --snaplen VALUE           Specify the capture length of packets in bytes.
  -g --genlen  VALUE           Specify the length of injected packets (when no input is specified).
  -t --timeout NUM             Specify the timeout in msec.
  -O --no-optimize             Do not run the packet-matching code optimizer.

Interface:
  -i --interface IFNAME        Listen on interface.
  -o --output IFNAME           Inject packets to interface.

File:
  -r --read  FILE              Read packets from file.
  -w --write FILE              Write packets to file.

Miscellaneous:
     --version                 Print the version strings and exit.
  -? --help                    Print this help.
```
