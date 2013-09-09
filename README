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

Regex matches are performed using the __re2__ module that supports PCRE, case-insensitive, invert and multiline matches, etc. It has enormous performance gains compared to the built-in __re__ module in Python(which is used as a fallback in case __re2__ is not installed).

__Libemu__ is used for shellcode detection purposes. The GetPC heuristics within __libemu__ provides a decent detection ratio. There are a few cases where __libemu__ fails but for most usecases it is good enough.

__Yara__ provides signature-based malware identification and classification facility. Its __yara-python__ bindings in __flowinspect__ allows usage of existing/custom signature files on network streams.

Fuzzy string matching features have been added via the __fuzzywuzzy__ module. A default match threshold of 75 is used which can be overridden through cli.

Inspection could be requested for any of the CTS/STC/ANY directions and their combinations. Inspection buffers are populated as network traffic arrives and as such CTS matches (CTS or ANY) happen first. If more than one mode of inspection is requested, flows are inspected in the following order: regex, fuzzy, libemu, and finally yara. For TCP, if any of these inspection mode succeeds, the next in oder are skipped and the flow is not tracked any further.

Inspection could also be disabled completely if required via the linemode option. This mode is really helpful when combined with a suitable outmode to have a look at network communication as it is happening over wire. If no inspection method is provided via cli, linemode is the default fallback.

For TCP, the first pattern to match on a flow will be the last time it will be tested. For UDP, matches happen on a per-packet basis and as such for a flow, subsequent packets will be tested even after a match has already been found.

Match scope could be limited through BPF expressions, Snort-like offset-depth content modifiers or via packets/streams inspection limit flags. Matched flows could be killed if need be. Flows could also be logged to files in addition to being dumped on stdout. A few useful output modes (quite, meta, hex, print, raw) help with further analysis.


HELP:
-----
```sh
        ______              _                            __
       / __/ /___ _      __(_)___  _________  ___  _____/ /_
      / /_/ / __ \ | /| / / / __ \/ ___/ __ \/ _ \/ ___/ __/
     / __/ / /_/ / |/ |/ / / / / (__  ) /_/ /  __/ /__/ /_
    /_/ /_/\____/|__/|__/_/_/ /_/____/ .___/\___/\___/\__/
                                    /_/
    
flowinspect.py v0.2 - A tool for network traffic inspection
Ankur Tyagi (7h3rAm) @ Juniper Networks Security Research Group

usage: flowinspect.py [-h] (-p --pcap | -d --device) [-c --cregex]
                      [-s --sregex] [-a --aregex] [-i] [-m] [-G --cfuzz]
                      [-H --sfuzz] [-I --afuzz] [-r fuzzminthreshold]
                      [-C --cdfa] [-S --sdfa] [-A --adfa] [-l] [-X --dfaexpr]
                      [-g [graphdir]] [-P --cyararules] [-Q --syararules]
                      [-R --ayararules] [-M] [-y] [-O --offset] [-D --depth]
                      [-T --maxinspstreams] [-U --maxinsppackets]
                      [-t --maxdispstreams] [-u --maxdisppackets]
                      [-b --maxdispbytes] [-w [logdir]]
                      [-o {quite,meta,hex,print,raw}] [-f --bpf] [-v] [-V]
                      [-k] [-n] [-L]

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
  -k                    kill matching TCP stream
  -n                    confirm before initializing NIDS
  -L                    enable linemode (disables inspection)
```


EXAMPLES:
---------
Look at HTTP sessions:
```sh
./flowinspect.py -d eth0 -c "^(GET|POST|HEAD|PUT).*" -f "tcp and port 80" -o print
```


Quickly scan for Blackhole Exploit Kit infections (enable multiline match and restrict display to max 64B):
```sh
./flowinspect.py -d eth0 -c "/forum/links/(column|news)\.php\?\w+=(\d\w:?)+" -mb64
```


Inspect HTTP streams for Metasploit ie_cgenericelement_uaf exploit (CVE-2013-1347):
```sh
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


Scan for SIP INVITE messages using fuzzy string matching (_inite_ as the query string and min. match threshold of 50%):
```sh
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


Scan for presence of shellcode in a network stream (currently on ANY direction only):
```sh
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


Use a Yara signature to look for UPX packed binaries on STC direction:
```sh
./flowinspect.py -p e03a7f89a6cbc45144aafac2779c7b6d.pcap -R upx.yara

[MATCH] (00000156/00000001) [TCP#00000001] 111.110.77.53:54159 - 79.115.117.66:80 matches rule: 'UPX' from ../rulesets/yararules/upx.yara
[MATCH] (00000156/00000001) [TCP#00000001] match @ STC[185362:185401] - 39B | packet[156] - packet[156]
00000000:  ff d5 8d 87 1f 02 00 00 80 20 7f 80 60 28 7f 58   |......... ..`(.X|
00000010:  50 54 50 53 57 ff d5 58 61 8d 44 24 80 6a 00 39   |PTPSW..Xa.D$.j.9|
00000020:  c4 75 fa 83 ec 80 e9                              |.u.....|

[U] Processed: 0 | Matches: 0 | Shortest: 0B (#0) | Longest: 0B (#0)
[T] Processed: 1 | Matches: 1 | Shortest: 39B (#1) | Longest: 39B (#1)
```


INSTALLATION:
-------------
Make sure you have a working Python installation. The only other hard-dependency is __pynids__. For the four inspection modes, you need respective python modules to be installed correctly. Reach out if you need help setting up pynids or for any other queries.


STATUS:
-------
A few [issues](https://github.com/7h3rAm/flowinspect/blob/master/issues) have been found through some basic testing I did during initial development. They are being worked upon. Please feel free to use __flowinspect__ and let me know if you find any others. There's a [todo](https://github.com/7h3rAm/flowinspect/blob/develop/todo) list as well that you can use if you would like to contribute.

