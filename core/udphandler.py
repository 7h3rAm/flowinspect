# flowinspect udp flow handler
# tracks sessions, identifies direction, populates data buffers, calls inspect, and calls show udpmatches

import datetime, nids
from globals import configopts, openudpflows, matchstats, ippacketsdict
from inspector import inspect
from utils import generate_bpf, getregexpattern, hexdump, printable, writetofile, doinfo, dodebug, dowarn, doerror


try:
    from termcolor import colored
except ImportError, ex:
    configopts['colored'] = False


def handleudp(addr, payload, pkt):
    showmatch = False
    addrkey = addr
    ((src, sport), (dst, dport)) = addr
    count = len(payload)
    start = 0
    end = count
    data = payload

    if len(configopts['ctsregexes']) > 0 or len(configopts['ctsfuzzpatterns']) > 0 or len(configopts['ctsyararules']) > 0:
        inspectcts = True
    else:
        inspectcts = False

    if len(configopts['stcregexes']) > 0 or len(configopts['stcfuzzpatterns']) > 0 or len(configopts['stcyararules']) > 0:
        inspectstc = True
    else:
        inspectstc = False

    keya = "%s:%s" % (src, sport)
    keyb = "%s:%s" % (dst, dport)
    key = None
    if keya in openudpflows:
        key = "%s:%s" % (src, sport)
        keydst = "%s:%s" % (dst, dport)
        direction = configopts['ctsdirectionstring']
        directionflag = configopts['ctsdirectionflag']
    elif keyb in openudpflows:
        key = "%s:%s" % (dst, dport)
        keydst = "%s:%s" % (src, sport)
        direction = configopts['stcdirectionstring']
        directionflag = configopts['stcdirectionflag']

    if key in openudpflows and openudpflows[key]['keydst'] == keydst:
        openudpflows[key]['totdatasize'] += count
    else:
        if configopts['verbose'] and configopts['verboselevel'] >= 3:
            dodebug('[IP#%d.UDP#%d] %s:%s - %s:%s remains untracked { IP tracking missed this flow }' % (
                        openudpflows[key]['ipct'],
                        openudpflows[key]['id'],
                        src,
                        sport,
                        dst,
                        dport))

    regexes = []
    fuzzpatterns = []
    yararuleobjects = []
    timestamp = datetime.datetime.fromtimestamp(nids.get_pkt_ts()).strftime('%H:%M:%S | %Y/%m/%d')

    if direction == configopts['ctsdirectionstring']:
        openudpflows[key]['ctsdatasize'] += count
        if 'regex' in configopts['inspectionmodes']:
            for regex in configopts['ctsregexes']:
                regexes.append(regex)

        if 'fuzzy' in configopts['inspectionmodes']:
            for fuzzpattern in configopts['ctsfuzzpatterns']:
                fuzzpatterns.append(fuzzpattern)

        if 'yara' in configopts['inspectionmodes']:
            for yararuleobj in configopts['ctsyararules']:
                yararuleobjects.append(yararuleobj)

    elif direction == configopts['stcdirectionstring']:
        openudpflows[key]['stcdatasize'] += count
        if 'regex' in configopts['inspectionmodes']:
            for regex in configopts['stcregexes']:
                regexes.append(regex)

        if 'fuzzy' in configopts['inspectionmodes']:
            for fuzzpattern in configopts['stcfuzzpatterns']:
                fuzzpatterns.append(fuzzpattern)

        if 'yara' in configopts['inspectionmodes']:
            for yararuleobj in configopts['stcyararules']:
                yararuleobjects.append(yararuleobj)

    if configopts['verbose'] and configopts['verboselevel'] >= 3:
        dodebug('[IP#%d.UDP#%d] %s %s %s [%dB] { TRACKED: %d } { CTS: %dB, STC: %dB, TOT: %dB }' % (
                openudpflows[key]['ipct'],
                openudpflows[key]['id'],
                key,
                directionflag,
                keydst,
                count,
                len(openudpflows),
                openudpflows[key]['ctsdatasize'],
                openudpflows[key]['stcdatasize'],
                openudpflows[key]['totdatasize']))

    if not configopts['linemode']:
        if configopts['udpdone']:
            if configopts['tcpdone']:
                if configopts['verbose'] and configopts['verboselevel'] >= 3:
                    dodebug('Done inspecting max packets (%d) and max streams (%d), \
                            preparing for exit' % (
                            configopts['maxinsppackets'],
                            configopts['maxinspstreams']))
                exitwithstats()
            else:
                if configopts['verbose'] and configopts['verboselevel'] >= 3:
                    dodebug('Ignoring packet %s:%s %s %s:%s { inspudppacketct: %d == maxinsppackets: %d }' % (
                            src,
                            sport,
                            dst,
                            dport,
                            configopts['inspudppacketct'],
                            configopts['maxinsppackets']))
            return

    configopts['inspudppacketct'] += 1

    if configopts['linemode']:
        matchstats['addr'] = addrkey
        matchstats['start'] = start
        matchstats['end'] = end
        matchstats['matchsize'] = matchstats['end'] - matchstats['start']
        matchstats['direction'] = direction
        matchstats['directionflag'] = directionflag
        if configopts['verbose'] and configopts['verboselevel'] >= 3:
            dodebug('[IP#%d.UDP#%d] Skipping inspection as linemode is enabled.' % (
                        openudpflows[key]['ipct'],
                        openudpflows[key]['id'],
                        configopts['packetct']))
        showudpmatches(data[matchstats['start']:matchstats['end']])

        if configopts['writepcap']:
            markmatchedippackets(addrkey)
        return

    if configopts['maxinsppackets'] != 0 and configopts['inspudppacketct'] >= configopts['maxinsppackets']:
        configopts['udpdone'] = True

    if configopts['offset'] > 0 and configopts['offset'] < count:
        offset = configopts['offset']
    else:
        offset = 0

    if configopts['depth'] > 0 and configopts['depth'] <= (count - offset):
        depth = configopts['depth'] + offset
    else:
        depth = count

    inspdata = data[offset:depth]
    inspdatalen = len(inspdata)

    if configopts['verbose'] and configopts['verboselevel'] >= 3:
        dodebug('[IP#%d.UDP#%d] Initiating inspection on %s[%d:%d] - %dB' % (
                openudpflows[key]['ipct'],
                openudpflows[key]['id'],
                direction,
                offset,
                depth,
                inspdatalen))

    matched = inspect('UDP', inspdata, inspdatalen, regexes, fuzzpatterns, yararuleobjects, addrkey, direction, directionflag)

    if matched:
        openudpflows[key]['matches'] += 1

        if configopts['writepcap']:
            markmatchedippackets(addrkey)

        if configopts['writepcapfast']:
            if addrkey in ippacketsdict.keys() and ippacketsdict[addrkey]['proto'] == 'UDP':
                ippacketsdict[addrkey]['matched'] = True
                ippacketsdict[addrkey]['id'] = configopts['packetct']
                ippacketsdict[addrkey]['matchedid'] = len(ippacketsdict[addrkey].keys()) - configopts['ipmetavars']

            else:
                ((sip, sp), (dip, dp)) = addrkey
                newaddrkey = ((dip, dp), (sip, sp))
                if newaddrkey in ippacketsdict.keys() and ippacketsdict[newaddrkey]['proto'] == 'UDP':
                    ippacketsdict[newaddrkey]['matched'] = True
                    ippacketsdict[newaddrkey]['id'] = configopts['packetct']
                    ippacketsdict[newaddrkey]['matchedid'] = len(ippacketsdict[newaddrkey].keys()) - configopts['ipmetavars']

        matchstats['start'] += offset
        matchstats['end'] += offset

        matchstats['direction'] = direction
        matchstats['directionflag'] = directionflag

        if configopts['udpmatches'] == 0:
            configopts['shortestmatch']['packet'] = matchstats['matchsize']
            configopts['shortestmatch']['packetid'] = configopts['packetct']
            configopts['longestmatch']['packet'] = matchstats['matchsize']
            configopts['longestmatch']['packetid'] = configopts['packetct']
        else:
            if matchstats['matchsize'] <= configopts['shortestmatch']['packet']:
                configopts['shortestmatch']['packet'] = matchstats['matchsize']
                configopts['shortestmatch']['packetid'] = configopts['packetct']

            if matchstats['matchsize'] >= configopts['longestmatch']['packet']:
                configopts['longestmatch']['packet'] = matchstats['matchsize']
                configopts['longestmatch']['packetid'] = configopts['packetct']

        configopts['udpmatches'] += 1

        matchstats['addr'] = addrkey
        showudpmatches(data[matchstats['start']:matchstats['end']])
        del openudpflows[key]


def showudpmatches(data):
    proto = 'UDP'

    ((src, sport), (dst, dport)) = matchstats['addr']

    key = "%s:%s" % (src, sport)
    if key not in openudpflows:
        key = "%s:%s" % (dst, dport)

    if configopts['maxdispbytes'] > 0: maxdispbytes = configopts['maxdispbytes']
    else: maxdispbytes = len(data)

    filename = '%s/%s-%08d-%s.%s-%s.%s-%s' % (configopts['logdir'], proto, configopts['packetct'], src, sport, dst, dport, matchstats['direction'])

    if configopts['writelogs']:
        writetofile(filename, data)

        if configopts['verbose'] and configopts['verboselevel'] >= 3:
            dodebug('[IP#%d.UDP#%d] Wrote %dB to %s/%s-%08d.%s.%s.%s.%s' % (
                    openudpflows[key]['ipct'],
                    openudpflows[key]['id'],
                    matchstats['matchsize'],
                    configopts['logdir'],
                    proto,
                    configopts['packetct'],
                    src,
                    sport,
                    dst,
                    dport))

    if 'quite' in configopts['outmodes']:
        if configopts['verbose'] and configopts['verboselevel'] >= 3:
            dodebug('[IP#%d.UDP#%d] %s:%s %s %s:%s matches \'%s\' @ [%d:%d] - %dB' % (
                    openudpflows[key]['ipct'],
                    openudpflows[key]['id'],
                    src,
                    sport,
                    matchstats['directionflag'],
                    dst,
                    dport,
                    getregexpattern(matchstats['regex']),
                    matchstats['start'],
                    matchstats['end'],
                    matchstats['matchsize']))
        return

    if configopts['maxdisppackets'] != 0 and configopts['disppacketct'] >= configopts['maxdisppackets']:
        if configopts['verbose'] and configopts['verboselevel'] >= 3:
            dodebug('Skipping outmode parsing { disppacketct: %d == maxdisppackets: %d }' % (
                    configopts['disppacketct'],
                    configopts['maxdisppackets']))
        return

    direction = matchstats['direction']
    directionflag = matchstats['directionflag']
    if 'meta' in configopts['outmodes']:
        if configopts['invertmatch']:
            invertstatus = " (invert)"
        else:
            invertstatus = ""

        start = matchstats['start']
        end = matchstats['end']
        matchsize = matchstats['matchsize']

        if matchstats['detectiontype'] == 'regex':
            metastr = 'matches regex%s: \'%s\'' % (invertstatus, getregexpattern(matchstats['regex']))

        elif matchstats['detectiontype'] == 'shellcode':
            metastr = 'contains shellcode [Offset: %d]%s' % (matchstats['shellcodeoffset'], invertstatus)

        elif matchstats['detectiontype'] == 'yara':
            metastr = 'matches rule: \'%s\' from %s' % (matchstats['yararulename'], matchstats['yararulefilepath'])

        else:
            metastr = ''

        if configopts['verbose'] and configopts['verboselevel'] >= 3:
             bpfstr = generate_bpf("UDP", src, sport, directionflag, dst, dport)
             dodebug('[IP#%d.UDP#%d] BPF: %s' % (
                openudpflows[key]['ipct'],
                openudpflows[key]['id'],
                bpfstr))

        print '[MATCH] (%08d/%08d) [IP#%d.UDP#%d] %s:%s %s %s:%s %s' % (
                configopts['inspudppacketct'],
                configopts['udpmatches'],
                openudpflows[key]['ipct'],
                openudpflows[key]['id'],
                src,
                sport,
                directionflag,
                dst,
                dport,
                metastr)

        print '[MATCH] (%08d/%08d) [IP#%d.UDP#%d] match @ %s[%d:%d] (%dB)' % (
                configopts['inspudppacketct'],
                configopts['udpmatches'],
                openudpflows[key]['ipct'],
                openudpflows[key]['id'],
                direction,
                start,
                end,
                matchsize)

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

    configopts['dispstreamct'] += 1

    if not configopts['colored']:
        print


def markmatchedippackets(addrkey):
    ((src, sport), (dst, dport)) = addrkey
    ((sip, sp), (dip, dp)) = addrkey
    newaddrkey = ((dip, dp), (sip, sp))

    if addrkey in ippacketsdict.keys() and ippacketsdict[addrkey]['proto'] == 'UDP':
        ippacketsdict[addrkey]['matched'] = True
        ippacketsdict[addrkey]['id'] = configopts['packetct']
        if configopts['verbose'] and configopts['verboselevel'] >= 3:
            dodebug('[IP#%d.UDP#%d] Flow %s:%s - %s:%s marked to be written to a pcap' % (
                            openudpflows[key]['ipct'],
                            openudpflows[key]['id'],
                            src,
                            sport,
                            dst,
                            dport))

    elif newaddrkey in ippacketsdict.keys() and ippacketsdict[newaddrkey]['proto'] == 'UDP':
        ippacketsdict[newaddrkey]['matched'] = True
        ippacketsdict[newaddrkey]['id'] = configopts['packetct']
        if configopts['verbose'] and configopts['verboselevel'] >= 3:
            dodebug('[IP#%d.UDP#%d] Flow %s:%s - %s:%s marked to be written to a pcap' % (
                            openudpflows[key]['ipct'],
                            openudpflows[key]['id'],
                            src,
                            sport,
                            dst,
                            dport))

    elif configopts['verbose'] and configopts['verboselevel'] >= 3:
        dodebug('[IP#%d.UDP#%d] Flow %s:%s - %s:%s not found in ippacketsdict, something\'s wrong' % (
                            openudpflows[key]['ipct'],
                            openudpflows[key]['id'],
                            src,
                            sport,
                            dst,
                            dport))
