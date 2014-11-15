captop 
======

Simple top, for pcap network interfaces.


Usage
-----

```
captop v1.2

usage: captop [OPTIONS] [BPF expression]

  -B --buffer SIZE             Set the operating system capture buffer size.
  -c count                     Exit after receiving count packets.
  -s snaplen                   Specify the capture length of packets in bytes.
  -t --timeout NUM             Specify the timeout in msec.
  -i --interface NAME          Listen on interface.
  -O --no-optimize             Do not run the packet-matching code optimizer.
     --version                 Print the version strings and exit.
  -? --help                    Print this help.
```
