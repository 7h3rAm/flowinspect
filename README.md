flowinspect
===========
A network traffic inspection tool


Description:
------------
It uses [__libnids__](http://libnids.sourceforge.net/) (via its python bindings from Jon Oberheide: [__pynids__](http://jon.oberheide.org/pynids/)) to defragment IP and reassemble TCP packets (UDP is inspected on a per-packet basis) to generate network flows. These flows are then inspected using the one of the four inspection modes:
* regex ([__re2__](http://code.google.com/p/re2/) - python bindings: [__pyre2__](https://github.com/axiak/pyre2))
* fuzzy strings matching ([__fuzzywuzzy__](https://github.com/seatgeek/fuzzywuzzy))
* [__libemu__](http://libemu.carnivore.it/) (python bindings: [__pylibemu__](https://github.com/buffer/pylibemu))
* [__yara__](http://code.google.com/p/yara-project/) (python bindings: [__yara-python__](http://code.google.com/p/yara-project/source/browse/trunk/yara-python/README))

Regex matches are performed using the re2 library and its Python bindings, pyre2, that supports PCRE, case-insensitive, invert and multiline matches, etc. It has enormous performance gains compared to the built-in re module in Python (which is used as a fallback in case re2 is not installed).

Fuzzy string matching features are carried out via the fuzzywuzzy module. It helps to perform both an exact and relative string mathing. A default match threshold of 75 is used as a default and can be overridden through cli.

Libemu and its Python bindings, pylibemu, are used for shellcode detection. The GetPC heuristics used by libemu provide a decent detection ratio. There are a few cases where libemu simply fails but for most usecases it is good enough.

Yara is a signature-based malware identification and classification tool. Its yara-python bindings provide an API to use existing/custom signature files on an input buffer which in this case is a network stream.

Inspection could be requested for any of the CTS/STC/ANY directions or their combinations. Inspection buffers are populated as network traffic arrives and as such CTS matches (CTS or ANY) happen first. If more than one mode of inspection is requested, flows are inspected in the following order: regex, fuzzy, libemu, and finally yara. For TCP, if any of the inspection modes succeed, the matched flow won't be inspected any further. This is an optimistic approach and is enabled by default. However if for a certain usecase a TCP stream has to inspected multiple times, it can be requested explicitly using a cli.

Inspection could be completely disabled if required via the linemode cli option. This mode is really helpful and when combined with a suitable outmode helps to have a look at network communication as-is while its happening over wire. Linemode is auto enabled as a fallback if no inspection mode is provided via cli.

For UDP, matches happen on a per-packet basis and as such subsequent packets will be tested even after a match has already been found on a UDP flow. Since only subsequent packets and their content is inspected, it ensures that the data already matched during earlier inspection cycles is not inspected again.

Match scope could be limited through BPF expressions, Snort-like offset-depth content modifiers or via packets/streams inspection limit cli options. For TCP, matched flows could also be killed if need be. Flows could also be logged to files in addition to being dumped on stdout. A few useful output modes (quite, meta, hex, print, raw) help with further analysis. The meta outmode is expecially useful as it shows some really important match specific details like the total size of matched content, offset of the start of a match in the network stream, the packet ids a match spans, the direction of the packet on which a match happened, etc.

Pcap generation for matching flows is also supported. If enabled, it would dump all the packets from the start upto the end of the flow. Matched TCP flows are dumped as soon as a close/reset is seen and for those flows where we don't see a close/reset, they are dumped before the tool exits. For UDP, since there is no close/reset like state information available, they are dumped only when the tool exits. This ensure that all the packets, even those that arrive post match, are captured in the flow pcap. Except for the custom pcap global header, per-packet pcap header and the Ethernet II L2 header (which is not seen by flowinspect), everything above remains as-is in the dumped packet captures.


HELP:
-----
```c
        ______              _                            __
       / __/ /___ _      __(_)___  _________  ___  _____/ /_
      / /_/ / __ \ | /| / / / __ \/ ___/ __ \/ _ \/ ___/ __/
     / __/ / /_/ / |/ |/ / / / / (__  ) /_/ /  __/ /__/ /_
    /_/ /_/\____/|__/|__/_/_/ /_/____/ .___/\___/\___/\__/
                                    /_/
    
flowinspect v0.2 - A network inspection tool
Ankur Tyagi (7h3rAm [at] gmail [dot] com)

usage: flowinspect.py [-h] (-p --pcap | -d --device) [-c --cregex]
                      [-s --sregex] [-a --aregex] [-i] [-m] [-G --cfuzz]
                      [-H --sfuzz] [-I --afuzz] [-r fuzzminthreshold]
                      [-C --cdfa] [-S --sdfa] [-A --adfa] [-l] [-X --dfaexpr]
                      [-g [graphdir]] [-P --cyararules] [-Q --syararules]
                      [-R --ayararules] [-M] [-y] [-Y --emuprofileoutsize]
                      [-O --offset] [-D --depth] [-T --maxinspstreams]
                      [-U --maxinsppackets] [-t --maxdispstreams]
                      [-u --maxdisppackets] [-b --maxdispbytes] [-w [logdir]]
                      [-o {quite,meta,hex,print,raw}] [-f --bpf] [-v] [-V]
                      [-e] [-k] [-j] [-Z] [-n] [-L]

optional arguments:
  -h, --help            show this help message and exit
  -p --pcap             input pcap file
  -d --device           listening device

RegEx per Direction:
  -c --cregex           regex to match against CTS data
  -s --sregex           regex to match against STC data
  -a --aregex           regex to match against ANY data

RegEx Options:
  -i                    ignore case
  -m                    disable multiline match

Fuzzy Patterns per Direction:
  -G --cfuzz            string to fuzzy match against CTS data
  -H --sfuzz            string to fuzzy match against STC data
  -I --afuzz            string to fuzzy match against ANY data

Fuzzy Options:
  -r fuzzminthreshold   threshold for fuzzy match (1-100) - default 75

DFAs per Direction ('m[0-9][1-9]=<dfa>'):
  -C --cdfa             DFA expression to match against CTS data
  -S --sdfa             DFA expression to match against STC data
  -A --adfa             DFA expression to match against ANY data

DFA Options:
  -l                    switch default boolean operator to 'or'
  -X --dfaexpr          expression to test chain members
  -g [graphdir]         generate DFA transitions graph

Yara Rules per Direction:
  -P --cyararules       Yara rules to match on CTS data
  -Q --syararules       Yara rules to match on STC data
  -R --ayararules       Yara rules to match on ANY data

Shellcode Detection:
  -M                    enable shellcode detection
  -y                    generate emulator profile for detected shellcode
  -Y --emuprofileoutsize
                        emulator profile memory size (default 1024K | max:
                        10240K)

Content Modifiers:
  -O --offset           bytes to skip before matching
  -D --depth            bytes to look at while matching (starting from offset)

Inspection Limits:
  -T --maxinspstreams   max streams to inspect
  -U --maxinsppackets   max packets to inspect

Display Limits:
  -t --maxdispstreams   max streams to display
  -u --maxdisppackets   max packets to display
  -b --maxdispbytes     max bytes to display

Output Options:
  -w [logdir]           write matching packets/streams
  -o {quite,meta,hex,print,raw}
                        match output modes

Misc. Options:
  -f --bpf              BPF expression
  -v                    invert match
  -V                    verbose output
  -e                    highlight CTS/STC matches
  -k                    kill matching TCP stream
  -j                    enable TCP multi match mode
  -Z                    write matching flows to pcap
  -n                    confirm before initializing NIDS
  -L                    enable linemode (disables inspection)
```


EXAMPLES:
---------
__Look at live HTTP sessions__:
```c
./flowinspect.py -d eth0 -c "^(GET|POST|HEAD|PUT).*" -f "tcp and port 80" -o print

GET / HTTP/1.1
User-Agent: curl/7.22.0 (i686-pc-linux-gnu) libcurl/7.22.0 OpenSSL/1.0.1 zlib/1.2.3.4 libidn/1.23 librtmp/2.3
Host: www.google.com
Accept: */*

[U] Processed: 0 | Matches: 0 | Shortest: 0B (#0) | Longest: 0B (#0)
[T] Processed: 1 | Matches: 1 | Shortest: 164B (#1) | Longest: 164B (#1)
```


__Inspect HTTP streams for Metasploit ie_cgenericelement_uaf exploit (CVE-2013-1347)__:
```c
./flowinspect.py -p cgenericelement.pcap -s 'CollectGarbage\(\).*mstime_malloc\({shellcode:' -b32

[MATCH] (00000006/00000001) [TCP#00000002] 10.204.136.200:39771 - 10.204.138.121:8080 matches regex: 'CollectGarbage\\(\\).*mstime_malloc\\({shellcode:'
[MATCH] (00000006/00000001) [TCP#00000002] match @ STC[39105:39335] - 230B | packet[5] - packet[5]
00000000:  43 6f 6c 6c 65 63 74 47 61 72 62 61 67 65 28 29   |CollectGarbage()|
00000010:  3b 0a 09 66 31 2e 61 70 70 65 6e 64 43 68 69 6c   |;..f1.appendChil|
00000020:  64 28 64 6f 63 75 6d 65 6e 74 2e 63 72 65 61 74   |d(document.creat|
00000030:  65 45 6c 65 6d 65 6e 74 28 27 74 61 62 6c 65 27   |eElement('table'|
00000040:  29 29 3b 0a 09 74 72 79 20 20 20 20 20 20 7b 20   |));..try      { |
00000050:  66 30 2e 6f 66 66 73 65 74 50 61 72 65 6e 74 3d   |f0.offsetParent=|
00000060:  6e 75 6c 6c 3b 7d 0a 09 63 61 74 63 68 28 65 29   |null;}..catch(e)|
00000070:  20 7b 20 7d 0a 09 66 32 2e 69 6e 6e 65 72 48 54   | { }..f2.innerHT|
00000080:  4d 4c 20 3d 20 22 22 3b 0a 09 66 31 2e 69 6e 6e   |ML = "";..f1.inn|
00000090:  65 72 48 54 4d 4c 20 3d 20 22 22 3b 0a 09 66 30   |erHTML = "";..f0|
000000a0:  2e 61 70 70 65 6e 64 43 68 69 6c 64 28 64 6f 63   |.appendChild(doc|
000000b0:  75 6d 65 6e 74 2e 63 72 65 61 74 65 45 6c 65 6d   |ument.createElem|
000000c0:  65 6e 74 28 27 68 72 27 29 29 3b 0a 09 6d 73 74   |ent('hr'));..mst|
000000d0:  69 6d 65 5f 6d 61 6c 6c 6f 63 28 7b 73 68 65 6c   |ime_malloc({shel|
000000e0:  6c 63 6f 64 65 3a                                 |lcode:|

[U] Processed: 0 | Matches: 0 | Shortest: 0B (#0) | Longest: 0B (#0)
[T] Processed: 2 | Matches: 1 | Shortest: 230B (#2) | Longest: 230B (#2)
```


__Scan for SIP INVITE messages using fuzzy string matching (_inite_ as the query string and min. match threshold of 50%)__:
```c
./flowinspect.py -p metasploit-sip-invite-spoof.pcap -H 'inite' -r 50

[MATCH] (00000002/00000001) [UDP#00000002] 10.0.1.45:10270 < 10.0.1.199:5060 
[MATCH] (00000002/00000001) [UDP#00000002] match @ STC[0:269] - 269B
00000000:  53 49 50 2f 32 2e 30 20 31 38 30 20 52 69 6e 67   |SIP/2.0 180 Ring|
00000010:  69 6e 67 0d 0a 56 69 61 3a 20 53 49 50 2f 32 2e   |ing..Via: SIP/2.|
00000020:  30 2f 55 44 50 20 31 30 2e 30 2e 31 2e 34 35 3b   |0/UDP 10.0.1.45;|
00000030:  72 65 63 65 69 76 65 64 3d 31 30 2e 30 2e 31 2e   |received=10.0.1.|
00000040:  31 39 39 0d 0a 43 6f 6e 74 61 63 74 3a 20 3c 73   |199..Contact: <s|
00000050:  69 70 3a 31 32 37 2e 30 2e 30 2e 31 3e 0d 0a 54   |ip:127.0.0.1>..T|
00000060:  6f 3a 20 3c 73 69 70 3a 31 30 2e 30 2e 31 2e 34   |o: <sip:10.0.1.4|
00000070:  35 3e 3b 74 61 67 3d 32 30 64 37 30 36 37 33 0d   |5>;tag=20d70673.|
00000080:  0a 46 72 6f 6d 3a 20 22 74 65 73 74 74 65 73 74   |.From: "testtest|
00000090:  22 3c 73 69 70 3a 31 30 2e 30 2e 31 2e 31 39 39   |"<sip:10.0.1.199|
000000a0:  3e 0d 0a 43 61 6c 6c 2d 49 44 3a 20 31 34 38 31   |>..Call-ID: 1481|
000000b0:  30 2e 30 2e 31 2e 34 35 0d 0a 43 53 65 71 3a 20   |0.0.1.45..CSeq: |
000000c0:  31 20 49 4e 56 49 54 45 0d 0a 55 73 65 72 2d 41   |1 INVITE..User-A|
000000d0:  67 65 6e 74 3a 20 58 2d 4c 69 74 65 20 72 65 6c   |gent: X-Lite rel|
000000e0:  65 61 73 65 20 31 30 30 39 72 20 73 74 61 6d 70   |ease 1009r stamp|
000000f0:  20 33 38 39 36 34 0d 0a 43 6f 6e 74 65 6e 74 2d   | 38964..Content-|
00000100:  4c 65 6e 67 74 68 3a 20 30 0d 0a 0d 0a            |Length: 0....|

[U] Processed: 2 | Matches: 1 | Shortest: 269B (#2) | Longest: 269B (#2)
[T] Processed: 0 | Matches: 0 | Shortest: 0B (#0) | Longest: 0B (#0)
```


__Scan for the presence of shellcode in a network stream (currently on ANY direction only)__:
```c
./flowinspect.py -p shellcodepcaps/millenium.pcap -M

[MATCH] (00000004/00000001) [TCP#00000001] 10.204.136.200:32822 - 10.204.138.121:8080 contains shellcode (Offset: 4034)
[MATCH] (00000004/00000001) [TCP#00000001] match @ STC[4034:4350] - 316B | packet[4] - packet[4]
00000000:  d9 eb d9 74 24 f4 bd 43 21 8a 8a 5f 2b c9 b1 46   |...t$..C!.._+..F|
00000010:  83 c7 04 31 6f 13 03 2c 32 68 7f 33 f0 38 72 cc   |...1o..,2h.3.8r.|
00000020:  06 19 99 a9 20 ee 7a 39 e3 dd 31 b6 35 2b 51 b3   |.... .z9..1.5+Q.|
00000030:  47 9b 11 b5 ab 50 53 25 3f 20 94 de 41 8d 2f d6   |G....PS%? ..A./.|
00000040:  85 82 37 63 05 45 49 5a 16 97 29 d7 85 7c 8e 6c   |..7c.EIZ..)..|.l|
00000050:  10 41 45 26 b3 c1 58 2c 48 7b 43 3b 15 5c 72 d0   |.AE&..X,H{C;..r.|
00000060:  49 a8 3d ad ba 5a bc 5f f3 a3 8e 5f 08 f7 75 9f   |I.=..Z._..._..u.|
00000070:  85 0f b7 d0 6b 11 f0 05 87 2a 82 fd 40 38 9b 76   |....k....*..@8.v|
00000080:  ca e6 5a 63 8d 6d 50 38 d9 28 75 bf 36 47 81 34   |..Zc.mP8.(u.6G.4|
00000090:  c9 b0 03 0e ee 5c 75 4d 5c 54 5c 85 28 80 17 e7   |......uM.T..(...|
000000a0:  43 c5 66 e9 7f 8b 9e 6a 80 d3 a0 1d 3a 28 e4 63   |C.f....j....:(.c|
000000b0:  1d d2 69 1c 81 37 dc ca 34 c8 1f f5 c0 72 e8 61   |..i..7..4....r.a|
000000c0:  bf 10 c8 30 57 da 3a 9c c3 74 4e 93 6e f7 38 0f   |...0W.:..tN.n.8.|
000000d0:  55 fd b1 49 c3 fe 97 91 65 c2 48 22 dd 61 25 e8   |U..I....e.H".a%.|
000000e0:  99 7a 92 42 4e e3 25 9d 71 8c b6 19 d6 6d 21 b8   |.z.BN.%.q....m!.|
000000f0:  81 08 f3 52 03 b6 80 d1 aa e3 ef 49 e9 19 79 92   |...R.......I..y.|
00000100:  99 45 59 74 7a 1e d4 27 3c ff 8e b5 af 92 6e 51   |.EYtz..'<.....nQ|
00000110:  5f 41 4f c7 f7 d1 ea 6b 64 d3 3d fb 38 37 ae 72   |_AO....kd.=.87.r|
00000120:  21 06 1c d6 f1 38 f2 29 25 8b 32 85 39 b9 ba eb   |!....8.)%.2.9...|
00000130:  06 13 ed 93 55 01 10 e9 ec ef ff ff               |....U.......|

[U] Processed: 0 | Matches: 0 | Shortest: 0B (#0) | Longest: 0B (#0)
[T] Processed: 1 | Matches: 1 | Shortest: 316B (#1) | Longest: 316B (#1)
```


__Use a Yara signature to look for UPX packed binaries on STC direction__:
```c
./flowinspect.py -p e03a7f89a6cbc45144aafac2779c7b6d.pcap -R upx.yara

[MATCH] (00000156/00000001) [TCP#00000001] 111.110.77.53:54159 - 79.115.117.66:80 matches rule: 'UPX' from upx.yara
[MATCH] (00000156/00000001) [TCP#00000001] match @ STC[185362:185401] - 39B | packet[156] - packet[156]
00000000:  ff d5 8d 87 1f 02 00 00 80 20 7f 80 60 28 7f 58   |......... ..`(.X|
00000010:  50 54 50 53 57 ff d5 58 61 8d 44 24 80 6a 00 39   |PTPSW..Xa.D$.j.9|
00000020:  c4 75 fa 83 ec 80 e9                              |.u.....|

[U] Processed: 0 | Matches: 0 | Shortest: 0B (#0) | Longest: 0B (#0)
[T] Processed: 1 | Matches: 1 | Shortest: 39B (#1) | Longest: 39B (#1)
```


__multimatch Demo__:
First lets test a pcap in the default firstmatch mode:

```c
./flowinspect.py -p ../testfiles/pcaps/http.cap -s '.*' -b32 

[MATCH] (00000001/00000001) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000001/00000001) [TCP#00000001] match @ STC[0:1380] - 1380B | packet[1] - packet[1]
00000000:  48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d   |HTTP/1.1 200 OK.|
00000010:  0a 44 61 74 65 3a 20 54 68 75 2c 20 31 33 20 4d   |.Date: Thu, 13 M|

[MATCH] (00000001/00000001) [UDP#00000001] 145.253.2.203:53 < 145.254.160.237:3009 matches regex: '.*'
[MATCH] (00000001/00000001) [UDP#00000001] match @ STC[0:146] - 146B
00000000:  00 23 81 80 00 01 00 04 00 00 00 00 07 70 61 67   |.#...........pag|
00000010:  65 61 64 32 11 67 6f 6f 67 6c 65 73 79 6e 64 69   |ead2.googlesyndi|

[U] Processed: 1 | Matches: 1 | Shortest: 146B (#1) | Longest: 146B (#1)
[T] Processed: 1 | Matches: 1 | Shortest: 1380B (#1) | Longest: 1380B (#1)
[+] Flowsrch session complete. Exiting.
```

There's exactly 1 match for both UDP and TCP flows in the input pcap. The number of flows processed is 1 as well. Since the regex was a .* that would obviously match any data in a flow, this means either the pcap has just 2 flows or only two flows have data in them. Let's now test the same pcap using the .* regex in multimatch mode:

```c
./flowinspect.py -p ../testfiles/pcaps/http.cap -s '.*' -b32 -j

[MATCH] (00000001/00000001) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000001/00000001) [TCP#00000001] match @ STC[0:1380] - 1380B | packet[1] - packet[1]
00000000:  48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d   |HTTP/1.1 200 OK.|
00000010:  0a 44 61 74 65 3a 20 54 68 75 2c 20 31 33 20 4d   |.Date: Thu, 13 M|

[MATCH] (00000002/00000002) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000002/00000002) [TCP#00000001] match @ STC[1380:2760] - 1380B | packet[2] - packet[2]
00000000:  20 20 20 20 20 20 20 20 20 20 3c 61 20 68 72 65   |          <a hre|
00000010:  66 3d 22 73 65 61 72 63 68 2e 68 74 6d 6c 22 3e   |f="search.html">|

[MATCH] (00000003/00000003) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000003/00000003) [TCP#00000001] match @ STC[2760:4140] - 1380B | packet[3] - packet[3]
00000000:  33 36 32 39 22 3b 0a 67 6f 6f 67 6c 65 5f 61 64   |3629";.google_ad|
00000010:  5f 77 69 64 74 68 20 3d 20 34 36 38 3b 0a 67 6f   |_width = 468;.go|

[MATCH] (00000004/00000004) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000004/00000004) [TCP#00000001] match @ STC[4140:5520] - 1380B | packet[4] - packet[4]
00000000:  22 66 74 70 3a 2f 2f 66 74 70 2e 70 6c 61 6e 65   |"ftp://ftp.plane|
00000010:  74 6d 69 72 72 6f 72 2e 63 6f 6d 2f 70 75 62 2f   |tmirror.com/pub/|

[MATCH] (00000005/00000005) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000005/00000005) [TCP#00000001] match @ STC[5520:6900] - 1380B | packet[5] - packet[5]
00000000:  65 74 68 65 72 65 61 6c 2f 77 69 6e 33 32 2f 22   |ethereal/win32/"|
00000010:  3e 4d 61 69 6e 20 73 69 74 65 3c 2f 61 3e 0a 3c   |>Main site</a>.<|

[MATCH] (00000006/00000006) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000006/00000006) [TCP#00000001] match @ STC[6900:8280] - 1380B | packet[6] - packet[6]
00000000:  72 65 74 61 70 70 65 64 2e 6e 65 74 2f 70 75 62   |retapped.net/pub|
00000010:  2f 73 65 63 75 72 69 74 79 2f 70 61 63 6b 65 74   |/security/packet|

[MATCH] (00000001/00000001) [UDP#00000001] 145.253.2.203:53 < 145.254.160.237:3009 matches regex: '.*'
[MATCH] (00000001/00000001) [UDP#00000001] match @ STC[0:146] - 146B
00000000:  00 23 81 80 00 01 00 04 00 00 00 00 07 70 61 67   |.#...........pag|
00000010:  65 61 64 32 11 67 6f 6f 67 6c 65 73 79 6e 64 69   |ead2.googlesyndi|

[MATCH] (00000007/00000007) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000007/00000007) [TCP#00000001] match @ STC[8280:9660] - 1380B | packet[7] - packet[7]
00000000:  72 65 2f 65 74 68 65 72 65 61 6c 2f 73 6f 6c 61   |re/ethereal/sola|
00000010:  72 69 73 2f 22 3e 41 75 73 74 72 61 6c 69 61 3c   |ris/">Australia<|

[MATCH] (00000008/00000008) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000008/00000008) [TCP#00000001] match @ STC[9660:11040] - 1380B | packet[8] - packet[8]
00000000:  20 20 20 3c 61 20 68 72 65 66 3d 22 68 74 74 70   |   <a href="http|
00000010:  3a 2f 2f 70 61 63 6b 61 67 65 73 2e 64 65 62 69   |://packages.debi|

[MATCH] (00000009/00000009) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000009/00000009) [TCP#00000001] match @ STC[11040:12420] - 1380B | packet[9] - packet[9]
00000000:  69 63 61 3c 2f 61 3e 0a 20 20 20 20 3c 62 72 3e   |ica</a>.    <br>|
00000010:  28 6d 6f 72 65 20 6d 69 72 72 6f 72 73 20 61 72   |(more mirrors ar|

[MATCH] (00000010/00000010) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000010/00000010) [TCP#00000001] match @ STC[12420:13800] - 1380B | packet[10] - packet[10]
00000000:  6b 67 73 72 63 2f 6e 65 74 2f 65 74 68 65 72 65   |kgsrc/net/ethere|
00000010:  61 6c 2f 52 45 41 44 4d 45 2e 68 74 6d 6c 22 3e   |al/README.html">|

[MATCH] (00000011/00000011) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000011/00000011) [TCP#00000001] match @ STC[13800:15180] - 1380B | packet[11] - packet[11]
00000000:  76 65 6e 22 3e 0a 20 20 3c 74 64 20 76 61 6c 69   |ven">.  <td vali|
00000010:  67 6e 3d 22 74 6f 70 22 3e 53 47 49 3a 3c 62 72   |gn="top">SGI:<br|

[MATCH] (00000012/00000012) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000012/00000012) [TCP#00000001] match @ STC[15180:16560] - 1380B | packet[12] - packet[12]
00000000:  77 77 2e 73 75 73 65 2e 63 6f 6d 2f 75 73 2f 70   |ww.suse.com/us/p|
00000010:  72 69 76 61 74 65 2f 64 6f 77 6e 6c 6f 61 64 2f   |rivate/download/|

[MATCH] (00000013/00000013) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000013/00000013) [TCP#00000001] match @ STC[16560:17940] - 1380B | packet[13] - packet[13]
00000000:  65 2e 0a 3c 2f 70 3e 0a 3c 68 34 3e 44 6f 63 75   |e..</p>.<h4>Docu|
00000010:  6d 65 6e 74 61 74 69 6f 6e 3c 2f 68 34 3e 0a 3c   |mentation</h4>.<|

[MATCH] (00000014/00000014) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000014/00000014) [TCP#00000001] match @ STC[17940:18364] - 424B | packet[14] - packet[14]
00000000:  65 6e 64 20 73 75 70 70 6f 72 74 20 71 75 65 73   |end support ques|
00000010:  74 69 6f 6e 73 20 61 62 6f 75 74 20 45 74 68 65   |tions about Ethe|

[U] Processed: 1 | Matches: 1 | Shortest: 146B (#1) | Longest: 146B (#1)
[T] Processed: 1 | Matches: 14 | Shortest: 424B (#1) | Longest: 1380B (#1)
[+] Flowsrch session complete. Exiting.
```

This time we see a total of 14 matches for TCP flow and 1 match for UDP flow. Since the processed count is still 1, the lone TCP flow was inspected multiple times and the .* regex passed on each occasion. Note that offsets of all the 14 matches are different. This implies that for each inspection cycle, content that was matched earlier is not inspected again, assuring absolutely unique matches for the input regex even when a stream in inspected multiple times.


__Write matching flows to a pcap__:
```c
./flowinspect.py -p ../testfiles/pcaps/http.cap -s '.*' -b32 -Z

[MATCH] (00000001/00000001) [TCP#00000001] 145.254.160.237:3372 < 65.208.228.223:80 matches regex: '.*'
[MATCH] (00000001/00000001) [TCP#00000001] match @ STC[0:1380] - 1380B | packet[1] - packet[1]
00000000:  48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d   |HTTP/1.1 200 OK.|
00000010:  0a 44 61 74 65 3a 20 54 68 75 2c 20 31 33 20 4d   |.Date: Thu, 13 M|

[MATCH] (00000001/00000001) [UDP#00000001] 145.253.2.203:53 < 145.254.160.237:3009 matches regex: '.*'
[MATCH] (00000001/00000001) [UDP#00000001] match @ STC[0:146] - 146B
00000000:  00 23 81 80 00 01 00 04 00 00 00 00 07 70 61 67   |.#...........pag|
00000010:  65 61 64 32 11 67 6f 6f 67 6c 65 73 79 6e 64 69   |ead2.googlesyndi|

[U] Processed: 1 | Matches: 1 | Shortest: 146B (#1) | Longest: 146B (#1)
[T] Processed: 1 | Matches: 1 | Shortest: 1380B (#1) | Longest: 1380B (#1)
[+] Flowsrch session complete. Exiting.


ls -l *.pcap

-rw-r--r-- 1 root root 21263 Oct  1 10:25 TCP-00000001-145.254.160.237.3372-65.208.228.223.80.pcap
-rw-r--r-- 1 root root   333 Oct  1 10:25 UDP-00000001-145.254.160.237.3009-145.253.2.203.53.pcap


capinfos TCP-00000001-145.254.160.237.3372-65.208.228.223.80.pcap 

File name:           TCP-00000001-145.254.160.237.3372-65.208.228.223.80.pcap
File type:           Wireshark/tcpdump/... - libpcap
File encapsulation:  Ethernet
Packet size limit:   file hdr: 65535 bytes
Number of packets:   34
File size:           21263 bytes
Data size:           20695 bytes
Capture duration:    0 seconds
Start time:          Tue Jan 15 18:25:57 2013
End time:            Tue Jan 15 18:25:57 2013
Data byte rate:      334156.35 bytes/sec
Data bit rate:       2673250.78 bits/sec
Average packet size: 608.68 bytes
Average packet rate: 548.99 packets/sec
SHA1:                23e0883082f69aa70dde186262f72b938130d597
RIPEMD160:           26105199653b9d93d253e0c0ad539adaed1cb6f6
MD5:                 9c8c0d0ca5bc27d726d8935da079af6e
Strict time order:   True


tshark -q -z conv,ip -r TCP-00000001-145.254.160.237.3372-65.208.228.223.80.pcap 

OOPS: dissector table "sctp.ppi" doesn't exist
Protocol being registered is "Datagram Transport Layer Security"
Running as user "root" and group "root". This could be dangerous.
================================================================================
IPv4 Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |   Rel. Start   |   Duration   |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |                |              |
145.254.160.237      <-> 65.208.228.223            18     19344      16      1351      34     20695     0.000000000         0.0619
================================================================================


capinfos UDP-00000001-145.254.160.237.3009-145.253.2.203.53.pcap 

File name:           UDP-00000001-145.254.160.237.3009-145.253.2.203.53.pcap
File type:           Wireshark/tcpdump/... - libpcap
File encapsulation:  Ethernet
Packet size limit:   file hdr: 65535 bytes
Number of packets:   2
File size:           333 bytes
Data size:           277 bytes
Capture duration:    0 seconds
Start time:          Tue Jan 15 18:25:57 2013
End time:            Tue Jan 15 18:25:57 2013
Data byte rate:      98193.22 bytes/sec
Data bit rate:       785545.78 bits/sec
Average packet size: 138.50 bytes
Average packet rate: 708.98 packets/sec
SHA1:                ea17a52d3f7b95543c36a726c67ad1b31f03c978
RIPEMD160:           47604bc8244c07e5946102afa8b84747263b834c
MD5:                 2ae39fee3f39098f8fdf0f7560ece8e4
Strict time order:   True


tshark -q -z conv,ip -r UDP-00000001-145.254.160.237.3009-145.253.2.203.53.pcap 

OOPS: dissector table "sctp.ppi" doesn't exist
Protocol being registered is "Datagram Transport Layer Security"
Running as user "root" and group "root". This could be dangerous.
================================================================================
IPv4 Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |   Rel. Start   |   Duration   |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |                |              |
145.254.160.237      <-> 145.253.2.203              1       188       1        89       2       277     0.000000000         0.0028
================================================================================

```


INSTALLATION:
-------------

1. Make sure you have a working Python 2.7 installation.
2. Obtain and install pynids. For those on Ubuntu, please make sure you have libpcap-dev, libnet1, libnet1-dev, and libglib2.0-dev packages pre-installed before installing pynids. Also, you might have to manually install libnids that comes bundled with pynids using the usual configure && make && make install process.

For the four inspection modes, you need respective python packages () to be installed and configured correctly. Reach out if you need help setting these up or for any other queries.


STATUS:
-------
A few [issues](https://github.com/7h3rAm/flowinspect/blob/master/issues) have been found through some basic testing I did during initial development. They are being worked upon. Please feel free to use flowinspect and let me know if you find any others. There's a [todo](https://github.com/7h3rAm/flowinspect/blob/develop/todo) list as well that could be useful if you are willing to contribute.


