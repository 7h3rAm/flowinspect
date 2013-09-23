# nids callback handler for ip packets
# collects ip payload if pcap write is requested

import datetime, nids
from globals import configopts, openudpflows, matchstats
from inspector import inspect
from utils import getregexpattern, hexdump, printable

import sys, socket
from struct import unpack


ipprotodict = {
    'icmp': 1,
    'igmp': 2,
    'tcp': 6,
    'igrp': 9,
    'udp': 17,
    'esp': 50,
    'ah': 51
}

UDPHDRLEN = 8

def handleip(pkt):
    iphdr = unpack('!BBHHHBBH4s4s', pkt[:20])
    ipversion = iphdr[0] >> 4
    ipihl = iphdr[0] & 0xF
    ipihl *= 4
    iptos = iphdr[1]
    iptotallen = iphdr[2]
    ipid = iphdr[3]
    ipttl = iphdr[5]
    ipproto = iphdr[6]
    ipsrc = socket.inet_ntoa(iphdr[8])
    ipdst = socket.inet_ntoa(iphdr[9])

    if ipproto == ipprotodict['tcp']:
        tcphdr = unpack('!HHLLBBHHH', pkt[ipihl:ipihl+20])
        tcpsport = tcphdr[0]
        tcpdport = tcphdr[1]
        tcpseq = tcphdr[2]
        tcpack = tcphdr[3]
        tcpoffset = tcphdr[4] >> 4
        tcphl = tcpoffset * 4
        tcpflags = tcphdr[5]
        tcpwindow = tcphdr[6]
        tcpchksum = tcphdr[7]
        tcpurgptr = tcphdr[8]

        data = pkt[ipihl+tcphl:]

        tcpflagsstr = []
        if tcpflags & 1 == 1: tcpflagsstr.append('F')
        if tcpflags & 2 == 2: tcpflagsstr.append('S')
        if tcpflags & 4 == 4: tcpflagsstr.append('R')
        if tcpflags & 8 == 8: tcpflagsstr.append('P')
        if tcpflags & 16 == 16: tcpflagsstr.append('A')
        if tcpflags & 32 == 32: tcpflagsstr.append('U')
        tcpflagsstr = "".join(tcpflagsstr)

        if configopts['verbose']:
            print '[DEBUG] handleip - %s:%s > %s:%s TCP [ flags: %s | seq: %d | ack: %d | win: %d | len: %dB ]' % (
                    ipsrc,
                    tcpsport,
                    ipdst,
                    tcpdport,
                    tcpflagsstr,
                    tcpseq,
                    tcpack,
                    tcpwindow,
                    len(data))

    elif ipproto == ipprotodict['udp']:
        udphdr = unpack('!HHHH', pkt[ipihl:ipihl+UDPHDRLEN])
        udpsport = udphdr[0]
        udpdport = udphdr[1]
        udplen = udphdr[2]

        data = pkt[ipihl+UDPHDRLEN:]

        if configopts['verbose']:
            print '[DEBUG] handleip - %s:%s > %s:%s UDP [ len: %dB ]' % (
                    ipsrc,
                    udpsport,
                    ipdst,
                    udpdport,
                    len(data))


