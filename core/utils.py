# flowinspect misc. utilities

from globals import configopts, ippacketsdict
import sys, os, pickle, collections, json, struct, binascii, random, re, time, datetime, inspect


# get current timestamp
def getcurtime():
    return datetime.datetime.now()


# get current formatted timestamp
def gettimestamp():
    return "%s %s" % (datetime.datetime.now().strftime("%d-%b-%Y %H:%M:%S.%f"), time.tzname[0])


# print message with debug level and function/module name
def doprint(msg, level='INFO', back=0):
    frame = sys._getframe(back + 1)
    filename = os.path.basename(frame.f_code.co_filename)
    lineno = frame.f_lineno
    funcname = frame.f_code.co_name
    print "[%s] [%s] %s: %s" % (gettimestamp(), funcname, level, msg)


# print info messages
def doinfo(msg):
    doprint(msg, 'INFO', back=1)


# print debug messages
def dodebug(msg):
    doprint(msg, 'DEBUG', back=1)


# print warning messages
def dowarn(msg):
    doprint(msg, 'WARN', back=1)


# print error messages
def doerror(msg):
    doprint(msg, 'ERROR', back=1)


# when stdout has to be mute'd
class NullDevice():
    def write(self, s): pass


# generate bpf from a tcp/udp flow
def generate_bpf(proto, aip, aport, directionflag, bip, bport):
    l3protostr = "ip"

    if proto == "TCP":
        l4protostr = "tcp"
        if directionflag == "<":
            aip, bip = bip, aip
            aport, bport = bport, aport
    elif proto == "UDP":
        l4protostr = "udp"

    return "(%s.src == %s and %s.srcport == %s) and (%s.dst == %s and %s.dstport == %s)" % (l3protostr, aip, l4protostr, aport, l3protostr, bip, l4protostr, bport)


# prepare a list of packets to be written to flow-named pcap
def writepackets():
    pktlist = []

    for key in ippacketsdict.keys():
        if ippacketsdict[key]['matched']:
            packets = 0
            del pktlist[:]
            ((src, sport), (dst, dport)) = key
            pcapfile = '%s-%08d-%s.%s-%s.%s.pcap' % (ippacketsdict[key]['proto'], ippacketsdict[key]['id'], src, sport, dst, dport)
            for subkey in ippacketsdict[key].keys():
                if subkey not in ['proto', 'id', 'matched', 'matchedid']:
                    pktlist.append(ippacketsdict[key][subkey])
                    packets += 1
            pcapwriter(pcapfile, pktlist)
            if configopts['verbose'] and configopts['verboselevel'] >= 1:
                print '[DEBUG] writepackets - Wrote %d packets to %s' % (packets, pcapfile)
            del ippacketsdict[key]


# write some packet data to a pcap file
def pcapwriter(filename, pktlist):
    pcap_endian = '='
    pcap_magic = 0xA1B2C3D4
    pcap_version_major = 2
    pcap_version_minor = 4
    pcap_thiszone = 0
    pcap_sigfigs = 0
    pcap_snaplen = 65535
    pcap_network = 1
    pcap_header = struct.pack(
        pcap_endian + 'IHHIIII',
        pcap_magic,
        pcap_version_major,
        pcap_version_minor,
        pcap_thiszone,
        pcap_sigfigs,
        pcap_snaplen,
        pcap_network)

    pcap_ts_sec = 0x50F551DD
    pcap_ts_usec = 0x0008BD2E
    pcap_incl_len = 0
    pcap_orig_len = 0

    ethernet = ('00 0b 00 0b 00 0b'
                  '00 0a 00 0a 00 0a'
                  '08 00')
    eth_header = binascii.a2b_hex(''.join(ethernet.split()))

    fo = open(filename, 'wb')
    fo.write(pcap_header)

    for pkt in pktlist:
        pcap_ts_usec += random.randint(1000, 3000)
        pcap_incl_len = len(pkt) + 14
        pcap_orig_len = len(pkt) + 14
        pkt_header = struct.pack(pcap_endian + 'IIII',
                    pcap_ts_sec,
                    pcap_ts_usec,
                    pcap_incl_len,
                    pcap_orig_len)
        fo.write(pkt_header)
        fo.write(eth_header)
        fo.write(pkt)


# write some data to a file
def writetofile(filename, data):
    try:
        if not os.path.isdir(configopts['logdir']): os.makedirs(configopts['logdir'])
    except OSError, oserr: print '[-] writetofile: %s' % oserr

    try:
        if configopts['linemode']: file = open(filename, 'ab+')
        else: file = open(filename, 'wb+')
        file.write(data)
    except IOError, io: print '[-] writetofile - %s' % io


# sort and print a dict
def printdict(dictdata):
    sd = collections.OrderedDict(sorted(dictdata.items()))
    print(json.dumps(sd, indent=4))


# get regex pattern from compiled object
def getregexpattern(regexobj):
    if configopts['regexengine'] == 're':
        import re

    dumps = pickle.dumps(regexobj)
    regexpattern = re.search("\n\(S'(.*)'\n", dumps).group(1)
    if re.findall(r'\\x[0-9a-f]{2}', regexpattern):
        regexpattern = re.sub(r'(\\x)([0-9a-f]{2})', r'x\2', regexpattern)

    return regexpattern


# raw bytes to hexdump filter
def hexdump(data, color, length=16, sep='.'):
    lines = []
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    for c in xrange(0, len(data), length):
        chars = data[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printablechars = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars])
        lines.append("%08x:  %-*s  |%s|\n" % (c, length*3, hex, printablechars))

    if configopts['colored']:
        try:
            from termcolor import colored
        except ImportError, ex:
            configopts['colored'] = False

    if color and configopts['colored']:
        if color == configopts['ctsoutcolor']:
            print colored(''.join(lines), configopts['ctsoutcolor'], attrs=configopts['ctsoutcolorattrs'])
        elif color == configopts['stcoutcolor']:
            print colored(''.join(lines), configopts['stcoutcolor'], attrs=configopts['stcoutcolorattrs'])
    else:
        print ''.join(lines),


# ascii printable filter for raw bytes
def printable(data, color):
    if configopts['colored']:
        try:
            from termcolor import colored
        except ImportError, ex:
            configopts['colored'] = False

    if color and configopts['colored']:
        if color == configopts['ctsoutcolor']:
            print colored(''.join([ch for ch in data if ord(ch) > 31 and ord(ch) < 126
                                   or ord(ch) == 9
                                   or ord(ch) == 10
                                   or ord(ch) == 13
                                   or ord(ch) == 32]), configopts['ctsoutcolor'], attrs=configopts['ctsoutcolorattrs'])
        elif color == configopts['stcoutcolor']:
            print colored(''.join([ch for ch in data if ord(ch) > 31 and ord(ch) < 126
                                   or ord(ch) == 9
                                   or ord(ch) == 10
                                   or ord(ch) == 13
                                   or ord(ch) == 32]), configopts['stcoutcolor'], attrs=configopts['stcoutcolorattrs'])
    else:
        print ''.join([ch for ch in data if ord(ch) > 31 and ord(ch) < 126
                        or ord(ch) == 9
                        or ord(ch) == 10
                        or ord(ch) == 13
                        or ord(ch) == 32])
