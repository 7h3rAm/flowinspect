# nids callback handler for ip packets
# collects ip payload if pcap write is requested
# also tracks tcp/udp flows (populates flow entry tables)

from globals import configopts, openudpflows, opentcpflows, matchstats, ippacketsdict
from utils import doinfo, dodebug, dowarn, doerror

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
    ipmetavars = configopts['ipmetavars']

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

        pktstats = ''
        fivetuple = ((ipsrc, tcpsport), (ipdst, tcpdport))
        revfivetuple = ((ipdst, tcpdport), (ipsrc, tcpsport))

        if configopts['writepcap']:
            if fivetuple in ippacketsdict.keys() and ippacketsdict[fivetuple]['proto'] == 'TCP':
                key = len(ippacketsdict[fivetuple].keys()) - ipmetavars
                ippacketsdict[fivetuple][key] = pkt
                pktstats = 'pktid: %d | ' % (len(ippacketsdict[fivetuple]) - ipmetavars)

            elif revfivetuple in ippacketsdict.keys() and ippacketsdict[revfivetuple]['proto'] == 'TCP':
                key = len(ippacketsdict[revfivetuple].keys()) - ipmetavars
                ippacketsdict[revfivetuple][key] = pkt
                pktstats = 'pktid: %d | ' % (len(ippacketsdict[revfivetuple]) - ipmetavars)

            elif tcpflagsstr == 'S':
                ippacketsdict[fivetuple] = {    'proto': 'TCP',
                                                'id': 0,
                                                'matched':False,
                                                'matchedid': 0,
                                                0: pkt
                                            }
                pktstats = 'pktid: %d | ' % (len(ippacketsdict[fivetuple]) - ipmetavars)

            else:
                return

        if configopts['writepcapfast']:
            if fivetuple in ippacketsdict.keys() and ippacketsdict[fivetuple]['proto'] == 'TCP':
                if not ippacketsdict[fivetuple]['matched']:
                    key = len(ippacketsdict[fivetuple].keys()) - ipmetavars
                    ippacketsdict[fivetuple][key] = pkt
                    pktstats = 'pktid: %d | ' % (len(ippacketsdict[fivetuple]) - ipmetavars)
                else:
                    if (len(ippacketsdict[fivetuple]) - ipmetavars) == (ippacketsdict[fivetuple]['matchedid'] + configopts['pcappacketct']):
                        if configopts['verbose'] and configopts['verboselevel'] >= 2:
                            dodebug('Post match packet collection complete for %s:%s - %s:%s { matchpacket: %d, postpackets: +%d }' % (
                                    ipsrc,
                                    tcpsport,
                                    ipdst,
                                    tcpdport,
                                    ippacketsdict[fivetuple]['matchedid'],
                                    configopts['pcappacketct']))

                        writepackets()
                    else:
                        key = len(ippacketsdict[fivetuple].keys()) - ipmetavars
                        ippacketsdict[fivetuple][key] = pkt
                        pktstats = 'pktid: %d | ' % (len(ippacketsdict[fivetuple]) - ipmetavars)

            elif revfivetuple in ippacketsdict.keys() and ippacketsdict[revfivetuple]['proto'] == 'TCP':
                if not ippacketsdict[revfivetuple]['matched']:
                    key = len(ippacketsdict[revfivetuple].keys()) - ipmetavars
                    ippacketsdict[revfivetuple][key] = pkt
                    pktstats = 'pktid: %d | ' % (len(ippacketsdict[revfivetuple]) - ipmetavars)
                else:
                    if (len(ippacketsdict[revfivetuple]) - ipmetavars) == (ippacketsdict[revfivetuple]['matchedid'] + configopts['pcappacketct']):
                        if configopts['verbose'] and configopts['verboselevel'] >= 2:
                            dodebug('Post match packet collection complete for %s:%s - %s:%s { matchpacket: %d, postpackets: +%d }' % (
                                    ipsrc,
                                    tcpsport,
                                    ipdst,
                                    tcpdport,
                                    ippacketsdict[revfivetuple]['matchedid'],
                                    configopts['pcappacketct']))

                        writepackets()
                    else:
                        key = len(ippacketsdict[revfivetuple].keys()) - ipmetavars
                        ippacketsdict[revfivetuple][key] = pkt
                        pktstats = 'pktid: %d | ' % (len(ippacketsdict[revfivetuple]) - ipmetavars)

            elif tcpflagsstr == 'S':
                ippacketsdict[fivetuple] = {    'proto': 'TCP',
                                                'id': 0,
                                                'matched':False,
                                                'matchedid': 0,
                                                0: pkt
                                            }
                pktstats = 'pktid: %d | ' % (len(ippacketsdict[fivetuple]) - ipmetavars)

            else:
                return

        # if this is a new tcp stream, add it to the opentcpflows table
        addrkey = ((ipsrc, tcpsport), (ipdst, tcpdport))
        tmpaddrkey = ((ipdst, tcpdport), (ipsrc, tcpsport))

        if tcpflagsstr == 'S' and addrkey not in opentcpflows:
            configopts['ipflowsct'] += 1
            configopts['streamct'] += 1
            opentcpflows.update({addrkey:{
                                            'ipct': configopts['ipflowsct'],
                                            'id': configopts['streamct'],
                                            'totdatasize': 0,
                                            'insppackets': 0,
                                            'multimatchskipoffset': 0,
                                            'ctspacketlendict': {},
                                            'stcpacketlendict': {},
                                        }
                                })

        count = len(data)
        if addrkey in opentcpflows:
            # this tcp/ip packet is travelling from CTS direction
            opentcpflows[addrkey]['insppackets'] += 1
            opentcpflows[addrkey]['ctspacketlendict'].update({ opentcpflows[addrkey]['insppackets']:count })
            key = addrkey
        elif tmpaddrkey in opentcpflows:
            # this tcp/ip packet is travelling from STC direction
            opentcpflows[tmpaddrkey]['insppackets'] += 1
            opentcpflows[tmpaddrkey]['stcpacketlendict'].update({ opentcpflows[tmpaddrkey]['insppackets']:count })
            key = tmpaddrkey
        else:
            # this ip flow is untracked, let's not care about it
            key = None

        if configopts['verbose'] and configopts['verboselevel'] >= 2 and key in opentcpflows:
            dodebug('[IP#%d.TCP#%d] %s:%s %s %s:%s { %sflags: %s, seq: %d, ack: %d, win: %d, len: %dB }' % (
                    opentcpflows[key]['ipct'],
                    opentcpflows[key]['id'],
                    ipsrc,
                    tcpsport,
                    configopts['ctsdirectionflag'],
                    ipdst,
                    tcpdport,
                    pktstats,
                    tcpflagsstr,
                    tcpseq,
                    tcpack,
                    tcpwindow,
                    len(data)))

    elif ipproto == ipprotodict['udp']:
        udphdr = unpack('!HHHH', pkt[ipihl:ipihl+UDPHDRLEN])
        udpsport = udphdr[0]
        udpdport = udphdr[1]
        udplen = udphdr[2]

        data = pkt[ipihl+UDPHDRLEN:]

        pktstats = ''
        fivetuple = ((ipsrc, udpsport), (ipdst, udpdport))
        revfivetuple = ((ipdst, udpdport), (ipsrc, udpsport))

        if configopts['writepcap']:
            if fivetuple in ippacketsdict.keys() and ippacketsdict[fivetuple]['proto'] == 'UDP':
                key = len(ippacketsdict[fivetuple].keys()) - ipmetavars
                ippacketsdict[fivetuple][key] = pkt
                pktstats = 'pktid: %d | ' % (len(ippacketsdict[fivetuple]) - ipmetavars)

            elif revfivetuple in ippacketsdict.keys() and ippacketsdict[revfivetuple]['proto'] == 'UDP':
                key = len(ippacketsdict[revfivetuple].keys()) - ipmetavars
                ippacketsdict[revfivetuple][key] = pkt
                pktstats = 'pktid: %d | ' % (len(ippacketsdict[revfivetuple]) - ipmetavars)

            else:
                ippacketsdict[fivetuple] = {    'proto': 'UDP',
                                                'id': 0,
                                                'matched':False,
                                                'matchedid': 0,
                                                0: pkt
                                            }
                pktstats = 'pktid: %d | ' % (len(ippacketsdict[fivetuple]) - ipmetavars)

        if configopts['writepcapfast']:
            if fivetuple in ippacketsdict.keys() and ippacketsdict[fivetuple]['proto'] == 'UDP':
                if not ippacketsdict[fivetuple]['matched']:
                    key = len(ippacketsdict[fivetuple].keys()) - ipmetavars
                    ippacketsdict[fivetuple][key] = pkt
                    pktstats = 'pktid: %d | ' % (len(ippacketsdict[fivetuple]) - ipmetavars)
                else:
                    if (len(ippacketsdict[fivetuple]) - ipmetavars) == (ippacketsdict[fivetuple]['matchedid'] + configopts['pcappacketct']):
                        if configopts['verbose'] and configopts['verboselevel'] >= 2:
                            dodebug('Post match packet collection complete for %s:%s - %s:%s { matchpacket: %d, postpackets: +%d }' % (
                                    ipsrc,
                                    udpsport,
                                    ipdst,
                                    udpdport,
                                    ippacketsdict[fivetuple]['matchedid'],
                                    configopts['pcappacketct']))

                        writepackets()
                    else:
                        key = len(ippacketsdict[fivetuple].keys()) - ipmetavars
                        ippacketsdict[fivetuple][key] = pkt
                        pktstats = 'pktid: %d | ' % (len(ippacketsdict[fivetuple]) - ipmetavars)

            elif revfivetuple in ippacketsdict.keys() and ippacketsdict[revfivetuple]['proto'] == 'UDP':
                if not ippacketsdict[revfivetuple]['matched']:
                    key = len(ippacketsdict[revfivetuple].keys()) - ipmetavars
                    ippacketsdict[revfivetuple][key] = pkt
                    pktstats = 'pktid: %d | ' % (len(ippacketsdict[revfivetuple]) - ipmetavars)
                else:
                    if (len(ippacketsdict[revfivetuple]) - ipmetavars) == (ippacketsdict[revfivetuple]['matchedid'] + configopts['pcappacketct']):
                        if configopts['verbose'] and configopts['verboselevel'] >= 2:
                            dodebug('Post match packet collection complete for %s:%s - %s:%s { matchpacket: %d, postpackets: +%d }' % (
                                    ipsrc,
                                    udpsport,
                                    ipdst,
                                    udpdport,
                                    ippacketsdict[revfivetuple]['matchedid'],
                                    configopts['pcappacketct']))

                        writepackets()
                    else:
                        key = len(ippacketsdict[revfivetuple].keys()) - ipmetavars
                        ippacketsdict[revfivetuple][key] = pkt
                        pktstats = 'pktid: %d | ' % (len(ippacketsdict[revfivetuple]) - ipmetavars)

            else:
                ippacketsdict[fivetuple] = {    'proto': 'UDP',
                                                'id': 0,
                                                'matched':False,
                                                'matchedid': 0,
                                                0: pkt
                                            }
                pktstats = 'pktid: %d | ' % (len(ippacketsdict[fivetuple]) - ipmetavars)


        keya = "%s:%s" % (ipsrc, udpsport)
        keyb = "%s:%s" % (ipdst, udpdport)
        if udpdport <= 1024 and udpsport >= 1024:
            key = keya
            keydst = keyb
        else:
            key = keyb
            keydst = keya

        if key not in openudpflows:
            configopts['ipflowsct'] += 1
            configopts['packetct'] += 1
            openudpflows.update({ key:{
                                            'ipct': configopts['ipflowsct'],
                                            'id':configopts['packetct'],
                                            'keydst':keydst,
                                            'matches':0,
                                            'ctsdatasize':0,
                                            'stcdatasize':0,
                                            'totdatasize':0,
                                        }
                                    })

        if configopts['verbose'] and configopts['verboselevel'] >= 2 and key in openudpflows:
            dodebug('[IP#%d.UDP#%d] %s %s %s [%dB]' % (
                        openudpflows[key]['ipct'],
                        openudpflows[key]['id'],
                        key,
                        configopts['ctsdirectionflag'],
                        keydst,
                        len(data)))
