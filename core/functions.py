# flowinspect specific functions commonly used by modules

from globals import configopts, opentcpflows, openudpflows, ippacketsdict
from tcphandler import handletcp
from udphandler import handleudp
from iphandler import handleip
from utils import getcurtime, printdict, writepackets, doinfo, dodebug, dowarn, doerror

import sys


def doexit():
    configopts['endtime'] = getcurtime()
    configopts['totalruntime'] = configopts['endtime'] - configopts['starttime']

    print
    doinfo('Session completed in %s. Exiting.' % (configopts['totalruntime']))

    if configopts['udpmatches'] > 0 or configopts['tcpmatches'] > 0: sys.exit(0)
    else: sys.exit(1)


def dumpmatchstats():
    if len(opentcpflows) > 0 or len(openudpflows) > 0:
        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            print
            dumpopenstreams()

    if len(ippacketsdict) > 0:
        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            dumpippacketsdict()
            print
        writepackets()

    if configopts['verbose'] and configopts['verboselevel'] >= 3:
        print

    if 'quite' in configopts['outmodes']:
        print

    doinfo('UDP Stats: { Processed: %d, Matched: %d } { Shortest: %dB (#%d), Longest: %dB (#%d) }' % (
                configopts['inspudppacketct'],
                configopts['udpmatches'],
                configopts['shortestmatch']['packet'],
                configopts['shortestmatch']['packetid'],
                configopts['longestmatch']['packet'],
                configopts['longestmatch']['packetid']))

    doinfo('TCP Stats: { Processed: %d, Matches: %d } { Shortest: %dB (#%d), Longest: %dB (#%d) }' % (
                configopts['insptcpstreamct'],
                configopts['tcpmatches'],
                configopts['shortestmatch']['stream'],
                configopts['shortestmatch']['streamid'],
                configopts['longestmatch']['stream'],
                configopts['longestmatch']['streamid']))


def dumpopenstreams():
    if len(openudpflows) > 0:
        doinfo('Dumping open/tracked UDP streams: %d' % len(openudpflows))

        for (key, value) in openudpflows.items():
            id = value['id']
            keydst = value['keydst']
            matches = value['matches']
            ctsdatasize = value['ctsdatasize']
            stcdatasize = value['stcdatasize']
            totdatasize = value['totdatasize']
            doinfo('[%08d] %s - %s { CTS: %dB, STC: %dB, TOT: %dB } { matches: %d }' % (
                    id,
                    key,
                    keydst,
                    ctsdatasize,
                    stcdatasize,
                    totdatasize,
                    matches),
                    'DEBUG')

    if len(opentcpflows) > 0:
        print
        doinfo('Dumping open/tracked TCP streams: %d' % (len(opentcpflows)))

        for (key, value) in opentcpflows.items():
            id = value['id']
            ((src, sport), (dst, dport)) = key

            ctsdatasize = 0
            for size in value['ctspacketlendict'].values():
                ctsdatasize += size

            stcdatasize = 0
            for size in value['stcpacketlendict'].values():
                stcdatasize += size

            totdatasize = ctsdatasize + stcdatasize
            doinfo('[%08d] %s:%s - %s:%s { CTS: %dB, STC: %dB, TOT: %dB }' % (
                    id,
                    src,
                    sport,
                    dst,
                    dport,
                    ctsdatasize,
                    stcdatasize,
                    totdatasize))


def dumpippacketsdict():
    print
    doinfo('Dumping IP packets dictionary: %d' % len(ippacketsdict.keys()))
    for key in ippacketsdict.keys():
        ((src, sport), (dst, dport)) = key
        doinfo('[%s#%08d] %s:%s - %s:%s { Packets: %d, Matched: %s}' % (
            ippacketsdict[key]['proto'],
            ippacketsdict[key]['id'],
            src,
            sport,
            dst,
            dport,
            len(ippacketsdict[key].keys()) - configopts['ipmetavars'],
            ippacketsdict[key]['matched']))


def dumpargstats(configopts):
    if configopts['pcap']:
        print '%-30s' % 'Input pcap:', ; print '[ %s ]' % (configopts['pcap'])
    elif configopts['device']:
        print '%-30s' % 'Listening device:', ;print '[ %s ]' % (configopts['device']),
        if configopts['killtcp']: print '[ w/ killtcp ]'
        else: print

    print '%-30s' % 'Inspection Modes:', ;print '[',
    for mode in configopts['inspectionmodes']:
        if mode == 'regex': print 'regex (%s)' % (configopts['regexengine']),
        if mode == 'fuzzy': print 'fuzzy (%s)' % (configopts['fuzzengine']),
        if mode == 'shellcode': print 'shellcode (%s) | memory: %dK' % (configopts['shellcodeengine'], configopts['emuprofileoutsize']),
    print ']'

    if 'regex' in configopts['inspectionmodes']:
        print '%-30s' % 'CTS regex:', ; print '[ %d |' % (len(configopts['ctsregexes'])),
        for c in configopts['ctsregexes']:
            print '%s' % configopts['ctsregexes'][c]['regexpattern'],
        print ']'

        print '%-30s' % 'STC regex:', ; print '[ %d |' % (len(configopts['stcregexes'])),
        for s in configopts['stcregexes']:
            print '%s' % configopts['stcregexes'][s]['regexpattern'],
        print ']'

        print '%-30s' % 'RE stats:', ; print '[ Flags: %d (' % (configopts['reflags']),
        if configopts['igncase']: print 'ignorecase',
        if configopts['multiline']: print 'multiline',
        print ') ]'

    if 'fuzzy' in configopts['inspectionmodes']:
        print '%-30s' % 'CTS fuzz patterns:', ; print '[ %d |' % (len(configopts['ctsfuzzpatterns'])),
        for c in configopts['ctsfuzzpatterns']:
            print '%s' % (c),
        print ']'

        print '%-30s' % 'STC fuzz patterns:', ; print '[ %d |' % (len(configopts['stcfuzzpatterns'])),
        for s in configopts['stcfuzzpatterns']:
            print '%s' % (s),
        print ']'

    if 'yara' in configopts['inspectionmodes']:
        print '%-30s' % 'CTS yara rules:', ; print '[ %d |' % (len(configopts['ctsyararules'])),
        for c in configopts['ctsyararules']:
            print '%s' % (c),
        print ']'

        print '%-30s' % 'STC yara rules:', ; print '[ %d |' % (len(configopts['stcyararules'])),
        for s in configopts['stcyararules']:
            print '%s' % (s),
        print ']'

    print '%-30s' % 'Inspection limits:',
    print '[ Streams: %d | Packets: %d | Offset: %d | Depth: %d ]' % (
            configopts['maxinspstreams'],
            configopts['maxinsppackets'],
            configopts['offset'],
            configopts['depth'])

    print '%-30s' % 'Display limits:',
    print '[ Streams: %d | Packets: %d | Bytes: %d ]' % (
            configopts['maxdispstreams'],
            configopts['maxdisppackets'],
            configopts['maxdispbytes'])

    print '%-30s' % 'Output modes:', ; print '[',
    if 'quite' in configopts['outmodes']:
        print 'quite',
        if configopts['writelogs']: print 'write: %s' % (configopts['logdir']),
        if configopts['writepcap']: print 'pcap: all packets'
        if configopts['writepcapfast']: print 'pcap: matched' + '%d packets' % (configopts['pcappacketct'])
    else:
        if 'meta' in configopts['outmodes']: print 'meta',
        if 'hex' in configopts['outmodes']: print 'hex',
        if 'print' in configopts['outmodes']: print 'print',
        if 'raw' in configopts['outmodes']: print 'raw',
        if configopts['writelogs']: print 'write: %s' % (configopts['logdir']),
        if configopts['writepcap']: print 'pcap: all packets',
        if configopts['writepcapfast']: print 'pcap: matched' + '%d packets' % (configopts['pcappacketct']),
    print ']'

    print '%-30s' % 'Misc options:',
    print '[ BPF: %s | invertmatch: %s | killtcp: %s | verbose: %s (%d) | linemode: %s | multimatch: %s ]' % (
            configopts['bpf'],
            configopts['invertmatch'],
            configopts['killtcp'],
            configopts['verbose'],
            configopts['verboselevel'],
            configopts['linemode'],
            configopts['tcpmultimatch'])

    try:
        print
        print "Press any key to continue...",
        input()
    except: pass
