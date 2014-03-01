# flowinspect tcp flow handler
# tracks sessions, identifies direction, populates data buffers, calls inspect, and calls show tcpmatches

import datetime, collections, nids
from globals import configopts, opentcpflows, matchstats, ippacketsdict
from inspector import inspect
from utils import generate_bpf, getregexpattern, hexdump, printable, writetofile, writepackets, donorm, doinfo, dodebug, dowarn, doerror, dumpasm


try:
    from termcolor import colored
except ImportError, ex:
    configopts['colored'] = False


def handletcp(tcp):
    id = 0
    showmatch = False
    addrkey = tcp.addr
    ((src, sport), (dst, dport)) = tcp.addr

    if not configopts['linemode']:
        if configopts['tcpdone']:
            if configopts['udpdone']:
                if configopts['verbose'] and configopts['verboselevel'] >= 1:
                    if addrkey in opentcpflows: id = opentcpflows[addrkey]['id']
                    doinfo('[IP#%d.TCP#%d] Done inspecting max packets (%d) and max streams (%d), preparing for exit' % (
                            opentcpflows[addrkey]['ipct'],
                            opentcpflows[addrkey]['id'],
                            configopts['maxinsppackets'],
                            configopts['maxinspstreams']))
                exitwithstats()
            else:
                if configopts['verbose'] and configopts['verboselevel'] >= 1:
                    if addrkey in opentcpflows: id = opentcpflows[addrkey]['id']
                    doinfo('[IP#%d.TCP#%d] Ignoring stream %s:%s %s %s:%s { insptcppacketct: %d == maxinspstreams: %d }' % (
                            opentcpflows[addrkey]['ipct'],
                            opentcpflows[addrkey]['id'],
                            src,
                            sport,
                            dst,
                            dport,
                            configopts['insptcppacketct'],
                            configopts['maxinspstreams']))
            return

    regexes = []
    fuzzpatterns = []
    yararuleobjects = []
    timestamp = datetime.datetime.fromtimestamp(nids.get_pkt_ts()).strftime('%H:%M:%S | %Y/%m/%d')
    endstates = [ nids.NIDS_CLOSE, nids.NIDS_TIMED_OUT, nids.NIDS_RESET ]

    inspectcts = False
    inspectstc = False
    if len(configopts['ctsregexes']) > 0 or len(configopts['ctsfuzzpatterns']) > 0 or len(configopts['ctsyararules']) > 0:
        inspectcts = True
    if len(configopts['stcregexes']) > 0 or len(configopts['stcfuzzpatterns']) > 0 or len(configopts['stcyararules']) > 0:
        inspectstc = True

    if tcp.nids_state == nids.NIDS_JUST_EST:
        if addrkey not in opentcpflows:
            tcp.server.collect = 0
            tcp.client.collect = 0
            if configopts['verbose']  and configopts['verboselevel'] >= 1:
                doinfo('[IP#%d.TCP#%d] %s:%s - %s:%s remains untracked { IP tracking missed this flow }' % (
                        opentcpflows[addrkey]['ipct'],
                        opentcpflows[addrkey]['id'],
                        src,
                        sport,
                        dst,
                        dport))
        else:
            configopts['insptcpstreamct'] += 1

            if configopts['verbose']  and configopts['verboselevel'] >= 1:
                doinfo('[IP#%d.TCP#%d] %s:%s - %s:%s [NEW] { TRACKED: %d }' % (
                        opentcpflows[addrkey]['ipct'],
                        opentcpflows[addrkey]['id'],
                        src,
                        sport,
                        dst,
                        dport,
                        len(opentcpflows)))

        if configopts['linemode'] or 'shellcode' in configopts['inspectionmodes']:
            tcp.server.collect = 1
            tcp.client.collect = 1
            if configopts['verbose'] and configopts['verboselevel'] >= 1:
                doinfo('[IP#%d.TCP#%d] Enabled both CTS and STC data collection for %s:%s - %s:%s' % (
                        opentcpflows[addrkey]['ipct'],
                        opentcpflows[addrkey]['id'],
                        src,
                        sport,
                        dst,
                        dport))
        else:
            if inspectcts or 'shellcode' in configopts['inspectionmodes']:
                tcp.server.collect = 1
                if configopts['verbose'] and configopts['verboselevel'] >= 1:
                    doinfo('[IP#%d.TCP#%d] Enabled CTS data collection for %s:%s - %s:%s' % (
                        opentcpflows[addrkey]['ipct'],
                        opentcpflows[addrkey]['id'],
                        src,
                        sport,
                        dst,
                        dport))
            if inspectstc or 'shellcode' in configopts['inspectionmodes']:
                tcp.client.collect = 1
                if configopts['verbose'] and configopts['verboselevel'] >= 1:
                    doinfo('[IP#%d.TCP#%d] Enabled STC data collection for %s:%s - %s:%s' % (
                        opentcpflows[addrkey]['ipct'],
                        opentcpflows[addrkey]['id'],
                        src,
                        sport,
                        dst,
                        dport))

    if tcp.nids_state == nids.NIDS_DATA:
        tcp.discard(0)

        configopts['insptcppacketct'] += 1

        if tcp.server.count_new > 0:
            direction = configopts['ctsdirectionstring']
            directionflag = configopts['ctsdirectionflag']
            count = tcp.server.count
            newcount = tcp.server.count_new
            start = tcp.server.count - tcp.server.count_new
            end = tcp.server.count
            opentcpflows[addrkey]['totdatasize'] += tcp.server.count_new

            if configopts['offset'] > 0 and configopts['offset'] < count:
                offset = configopts['offset']
            else:
                offset = 0

            if configopts['depth'] > 0 and configopts['depth'] <= (count - offset):
                depth = configopts['depth'] + offset
            else:
                depth = count

            offset += opentcpflows[addrkey]['multimatchskipoffset']
            configopts['inspoffset'] = offset

            inspdata = tcp.server.data[offset:depth]
            inspdatalen = len(inspdata)

            if 'regex' in configopts['inspectionmodes']:
                for regex in configopts['ctsregexes'].keys():
                    regexes.append(regex)

            if 'fuzzy' in configopts['inspectionmodes']:
                for fuzzpattern in configopts['ctsfuzzpatterns']:
                    fuzzpatterns.append(fuzzpattern)

            if 'yara' in configopts['inspectionmodes']:
                for yararuleobj in configopts['ctsyararules']:
                    yararuleobjects.append(yararuleobj)

        if tcp.client.count_new > 0:
            direction = configopts['stcdirectionstring']
            directionflag = configopts['stcdirectionflag']
            count = tcp.client.count
            newcount = tcp.client.count_new
            start = tcp.client.count - tcp.client.count_new
            end = tcp.client.count
            opentcpflows[addrkey]['totdatasize'] += tcp.client.count_new

            if configopts['offset'] > 0 and configopts['offset'] < count:
                offset = configopts['offset']
            else:
                offset = 0

            offset += opentcpflows[addrkey]['multimatchskipoffset']
            configopts['inspoffset'] = offset

            if configopts['depth'] > 0 and configopts['depth'] < (count - offset):
                depth = offset + configopts['depth']
            else:
                depth = count

            inspdata = tcp.client.data[offset:depth]
            inspdatalen = len(inspdata)

            if 'regex' in configopts['inspectionmodes']:
                for regex in configopts['stcregexes'].keys():
                    regexes.append(regex)

            if 'fuzzy' in configopts['inspectionmodes']:
                for fuzzpattern in configopts['stcfuzzpatterns']:
                    fuzzpatterns.append(fuzzpattern)

            if 'yara' in configopts['inspectionmodes']:
                for yararuleobj in configopts['stcyararules']:
                    yararuleobjects.append(yararuleobj)

        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            doinfo('[IP#%d.TCP#%d] %s:%s %s %s:%s [%dB] { CTS: %d, STC: %d, TOT: %d }' % (
                    opentcpflows[addrkey]['ipct'],
                    opentcpflows[addrkey]['id'],
                    src,
                    sport,
                    directionflag,
                    dst,
                    dport,
                    newcount,
                    tcp.server.count,
                    tcp.client.count,
                    opentcpflows[addrkey]['totdatasize']))

        if configopts['linemode']:
            matchstats['addr'] = addrkey
            matchstats['start'] = start
            matchstats['end'] = end
            matchstats['matchsize'] = matchstats['end'] - matchstats['start']
            matchstats['direction'] = direction
            matchstats['directionflag'] = directionflag
            donorm('[IP#%d.TCP#%d] Skipping inspection as linemode is enabled.' % (opentcpflows[addrkey]['ipct'], opentcpflows[addrkey]['id']))
            showtcpmatches(inspdata[matchstats['start']:matchstats['end']])
            if configopts['writepcap']:
                markmatchedippackets(addrkey)
            return

        if configopts['maxinspstreams'] != 0 and configopts['insptcppacketct'] >= configopts['maxinspstreams']:
            configopts['tcpdone'] = True

        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            doinfo('[IP#%d.TCP#%d] Initiating inspection on %s[%d:%d] - %dB' % (
                    opentcpflows[addrkey]['ipct'],
                    opentcpflows[addrkey]['id'],
                    direction,
                    offset,
                    depth,
                    inspdatalen))

        matched = inspect('TCP', inspdata, inspdatalen, regexes, fuzzpatterns, yararuleobjects, addrkey, direction, directionflag)

        if matched:
            if configopts['killtcp']: tcp.kill

            if configopts['writepcap']:
                markmatchedippackets(addrkey)

            elif configopts['writepcapfast']:
                if addrkey in ippacketsdict.keys() and ippacketsdict[addrkey]['proto'] == 'TCP':
                    ippacketsdict[addrkey]['matched'] = True
                    ippacketsdict[addrkey]['id'] = opentcpflows[addrkey]['id']
                    ippacketsdict[addrkey]['matchedid'] = len(ippacketsdict[addrkey].keys()) - configopts['ipmetavars']

                else:
                    ((sip, sp), (dip, dp)) = addrkey
                    newaddrkey = ((dip, dp), (sip, sp))
                    if newaddrkey in ippacketsdict.keys() and ippacketsdict[newaddrkey]['proto'] == 'TCP':
                        ippacketsdict[newaddrkey]['matched'] = True
                        ippacketsdict[newaddrkey]['id'] = opentcpflows[newaddrkey]['id']
                        ippacketsdict[newaddrkey]['matchedid'] = len(ippacketsdict[newaddrkey].keys()) - configopts['ipmetavars']

            if direction == configopts['ctsdirectionstring']:
                matchstats['direction'] = configopts['ctsdirectionstring']
                matchstats['directionflag'] = configopts['ctsdirectionflag']
            elif direction == 'STC':
                matchstats['direction'] = configopts['stcdirectionstring']
                matchstats['directionflag'] = configopts['stcdirectionflag']

            if configopts['tcpmatches'] == 0:
                configopts['shortestmatch']['stream'] = matchstats['matchsize']
                configopts['shortestmatch']['streamid'] = opentcpflows[addrkey]['id']
                configopts['longestmatch']['stream'] = matchstats['matchsize']
                configopts['longestmatch']['streamid'] = opentcpflows[addrkey]['id']
            else:
                if matchstats['matchsize'] <= configopts['shortestmatch']['stream']:
                    configopts['shortestmatch']['stream'] = matchstats['matchsize']
                    configopts['shortestmatch']['streamid'] = opentcpflows[addrkey]['id']

                if matchstats['matchsize'] >= configopts['longestmatch']['stream']:
                    configopts['longestmatch']['stream'] = matchstats['matchsize']
                    configopts['longestmatch']['streamid'] = opentcpflows[addrkey]['id']

            configopts['tcpmatches'] += 1
            matchstats['addr'] = addrkey
            showtcpmatches(inspdata[matchstats['start']:matchstats['end']])

            if not configopts['tcpmultimatch']:
                tcp.server.collect = 0
                tcp.client.collect = 0
                if configopts['verbose'] and configopts['verboselevel'] >= 1:
                    doinfo('[IP#%d.TCP#%d] %s:%s - %s:%s not being tracked any further { tcpmultimatch: %s }' % (
                            opentcpflows[addrkey]['ipct'],
                            opentcpflows[addrkey]['id'],
                            src,
                            sport,
                            dst,
                            dport,
                            configopts['tcpmultimatch']))
                del opentcpflows[addrkey]
            else:
                if direction == configopts['ctsdirectionstring']:
                    opentcpflows[addrkey]['ctspacketlendict'].clear()
                elif direction == configopts['stcdirectionstring']:
                    opentcpflows[addrkey]['stcpacketlendict'].clear()

                opentcpflows[addrkey]['multimatchskipoffset'] += matchstats['end']

                if configopts['verbose'] and configopts['verboselevel'] >= 1:
                    doinfo('[IP#%d.TCP#%d] Marked %dB to be skipped for further %s inspection' % (
                            opentcpflows[addrkey]['ipct'],
                            opentcpflows[addrkey]['id'],
                            opentcpflows[addrkey]['multimatchskipoffset'],
                            direction))

        else:
            opentcpflows[addrkey]['previnspbufsize'] = inspdatalen

    if tcp.nids_state in endstates:
        if addrkey in opentcpflows:
            ipct = opentcpflows[addrkey]['ipct']
            id = opentcpflows[addrkey]['id']
            del opentcpflows[addrkey]
            if configopts['verbose'] and configopts['verboselevel'] >= 1:
                if tcp.nids_state == nids.NIDS_CLOSE: state = 'FIN'
                elif tcp.nids_state == nids.NIDS_TIMED_OUT: state = 'TIMED_OUT'
                elif tcp.nids_state == nids.NIDS_RESET: state = 'RST'
                else: state = 'UNKNOWN'
                doinfo('[IP#%d.TCP#%d] %s:%s - %s:%s [%s] { TRACKED: %d }' % (
                        ipct,
                        id,
                        src,
                        sport,
                        dst,
                        dport,
                        state,
                        len(opentcpflows)))


def showtcpmatches(data):
    proto = 'TCP'

    if configopts['maxdispbytes'] > 0: maxdispbytes = configopts['maxdispbytes']
    else: maxdispbytes = len(data)

    ((src, sport), (dst, dport)) = matchstats['addr']
    filename = '%s/%s-%08d-%s.%s-%s.%s-%s' % (configopts['logdir'], proto, opentcpflows[matchstats['addr']]['id'], src, sport, dst, dport, matchstats['direction'])

    if configopts['writelogs']:
        writetofile(filename, data)

        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            doinfo('[IP#%d.TCP#%d] Wrote %dB to %s' % (
                    opentcpflows[matchstats['addr']]['ipct'],
                    opentcpflows[matchstats['addr']]['id'],
                    matchstats['matchsize'],
                    filename))

    if 'quite' in configopts['outmodes']:
        if matchstats['detectiontype'] == 'regex':
            pattern = getregexpattern(matchstats['regex'])
        elif matchstats['detectiontype'] == 'fuzzy':
            if matchstats['direction'] == 'CTS':
                pattern = configopts['ctsfuzzpatterns']
            else:
                pattern = configopts['stcfuzzpaterns']
        else:
            pattern = None

        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            doinfo('[IP#%d.TCP#%d] %s:%s %s %s:%s matches \'%s\' @ [%d:%d] - %dB' % (
                        opentcpflows[matchstats['addr']]['ipct'],
                        opentcpflows[matchstats['addr']]['id'],
                        src,
                        sport,
                        matchstats['directionflag'],
                        dst,
                        dport,
                        pattern,
                        matchstats['start'],
                        matchstats['end'],
                        matchstats['matchsize']))
        return

    if configopts['maxdispstreams'] != 0 and configopts['dispstreamct'] >= configopts['maxdispstreams']:
        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            doinfo('Skipping outmode parsing { dispstreamct: %d == maxdispstreams: %d }' % (
                    configopts['dispstreamct'],
                    configopts['maxdispstreams']))
        return

    direction = matchstats['direction']
    startpacket = 0
    endpacket = 0
    if 'meta' in configopts['outmodes']:
        if configopts['invertmatch']:
            invertstatus = " (invert)"
        else:
            invertstatus = ""

        id = opentcpflows[matchstats['addr']]['id']

        if matchstats['direction'] == 'CTS':
            packetlendict = opentcpflows[matchstats['addr']]['ctspacketlendict']
        else:
            packetlendict = opentcpflows[matchstats['addr']]['stcpacketlendict']

        direction = matchstats['direction']
        directionflag = matchstats['directionflag']
        start = matchstats['start']
        end = matchstats['end']
        matchsize = matchstats['matchsize']

        totalcount = 0
        startpacket = 0
        endpacket = 0
        if len(packetlendict) == 1:
            startpacket = packetlendict.keys()[0]
            endpacket = startpacket
        else:
            for (pktid, pktlen) in collections.OrderedDict(sorted(packetlendict.items())).items():
                totalcount += pktlen

                if start <= totalcount and startpacket == 0 and pktlen != 0:
                    startpacket = pktid

                if end <= totalcount:
                    endpacket = pktid

                if configopts['verbose'] and configopts['verboselevel'] >= 5:
                    dodebug('(%06d:%06d) start:%d <= totalcount:%06d | end:%d <= totalcount:%06d ... %s|%-5s\t' % (
                                pktid, pktlen, start, totalcount, end, totalcount, (start <= totalcount), (end <= totalcount)))

                if endpacket != 0:
                    if configopts['verbose'] and configopts['verboselevel'] >= 5:
                        dodebug('startpacket: %d - endpacket: %d' % (startpacket, endpacket))
                    break

            if startpacket > endpacket:
                startpacket, endpacket = endpacket, startpacket

        if matchstats['detectiontype'] == 'regex':
            if direction == configopts['ctsdirectionstring']:
                regexpattern = configopts['ctsregexes'][matchstats['regex']]['regexpattern']
            elif direction == configopts['stcdirectionstring']:
                regexpattern = configopts['stcregexes'][matchstats['regex']]['regexpattern']

            metastr = 'matches regex%s: \'%s\'' % (invertstatus, regexpattern)

        elif matchstats['detectiontype'] == 'fuzzy':
            metastr = 'matches \'%s\' %s%s' % (matchstats['fuzzpattern'], matchstats['fuzzmatchdetails'], invertstatus)

        elif matchstats['detectiontype'] == 'shellcode':
            metastr = 'contains shellcode [Offset: %d]%s' % (matchstats['shellcodeoffset'], invertstatus)

        elif matchstats['detectiontype'] == 'yara':
            metastr = 'matches rule: \'%s\' from %s' % (matchstats['yararulename'], matchstats['yararulefilepath'])

        else:
            metastr = ''

        if not configopts['linemode']:
            packetstats = ' | packet[%d] - packet[%d]' % (startpacket, endpacket)
        else:
            packetstats = ''

        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            bpfstr = generate_bpf("TCP", src, sport, directionflag, dst, dport)
            doinfo('[IP#%d.TCP#%d] BPF: %s' % (opentcpflows[matchstats['addr']]['ipct'], opentcpflows[matchstats['addr']]['id'], bpfstr))

        print '[MATCH] (%08d/%08d) [IP#%d.TCP#%d] %s:%s %s %s:%s %s' % (
                configopts['insptcppacketct'],
                configopts['tcpmatches'],
                opentcpflows[matchstats['addr']]['ipct'],
                opentcpflows[matchstats['addr']]['id'],
                src,
                sport,
                directionflag,
                dst,
                dport,
                metastr)

        print '[MATCH] (%08d/%08d) [IP#%d.TCP#%d] match @ %s[%d:%d] (%dB%s)' % (
                configopts['insptcppacketct'],
                configopts['tcpmatches'],
                opentcpflows[matchstats['addr']]['ipct'],
                opentcpflows[matchstats['addr']]['id'],
                direction,
                start + configopts['inspoffset'],
                end + configopts['inspoffset'],
                matchsize,
                packetstats)

    if 'print' in configopts['outmodes']:
        if configopts['colored']:
            if direction == configopts['ctsdirectionstring']:
                printable(data[:maxdispbytes], configopts['ctsoutcolor'])
            elif direction == configopts['stcdirectionstring']:
                printable(data[:maxdispbytes], configopts['stcoutcolor'])
        else:
            printable(data[:maxdispbytes], None)

    if 'raw' in configopts['outmodes']:
        if configopts['colored']:
            print colored(data[:maxdispbytes])
        else:
            print data[:maxdispbytes]

    if 'hex' in configopts['outmodes']:
        if configopts['colored']:
            if direction == configopts['ctsdirectionstring']:
                hexdump(data[:maxdispbytes], configopts['ctsoutcolor'])
            elif direction == configopts['stcdirectionstring']:
                hexdump(data[:maxdispbytes], configopts['stcoutcolor'])
        else:
            hexdump(data[:maxdispbytes], None)

    if configopts['asm4shellcode']:
        print
        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            doinfo('[IP#%d.TCP#%d] Generating disassembled output for %dB of detected shellcode' % (
                        opentcpflows[matchstats['addr']]['ipct'],
                        opentcpflows[matchstats['addr']]['id'],
                        len(data)))
        dumpasm(data)

    configopts['dispstreamct'] += 1

    if not configopts['colored']:
        print


def markmatchedippackets(addrkey):
    ((src, sport), (dst, dport)) = addrkey
    ((sip, sp), (dip, dp)) = addrkey
    newaddrkey = ((dip, dp), (sip, sp))

    if addrkey in ippacketsdict.keys() and ippacketsdict[addrkey]['proto'] == 'TCP':
        ippacketsdict[addrkey]['matched'] = True
        ippacketsdict[addrkey]['id'] = opentcpflows[addrkey]['id']
        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            doinfo('[IP#%d.TCP#%d] Flow %s:%s - %s:%s marked to be written to a pcap' % (
                    opentcpflows[matchstats['addr']]['ipct'],
                    opentcpflows[matchstats['addr']]['id'],
                    src,
                    sport,
                    dst,
                    dport))

    elif newaddrkey in ippacketsdict.keys() and ippacketsdict[newaddrkey]['proto'] == 'TCP':
        ippacketsdict[newaddrkey]['matched'] = True
        ippacketsdict[newaddrkey]['id'] = opentcpflows[addrkey]['id']
        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            doinfo('[IP#%d.TCP#%d] Flow %s:%s - %s:%s marked to be written to a pcap' % (
                    opentcpflows[matchstats['addr']]['ipct'],
                    opentcpflows[matchstats['addr']]['id'],
                    src,
                    sport,
                    dst,
                    dport))

    elif not configopts['linemode']:
        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            doinfo('[IP#%d.TCP#%d] Flow %s:%s - %s:%s not found in ippacketsdict, something\'s wrong' % (
                    opentcpflows[matchstats['addr']]['ipct'],
                    opentcpflows[matchstats['addr']]['id'],
                    src,
                    sport,
                    dst,
                    dport))
