# flowinspect inspector - 4 modes of inspection
# regex: import re2 or re, match over rcvd data, populate match stats
# fuzzy: import fuzzywuzzy, match over rcvd data, populate match stats
# yara: import python-yara, match over rcvd data, populate match stats
# shellcode: import libemu, match over rcvd data, populate match stats

import sys, nids
from globals import configopts, opentcpflows, openudpflows, matchstats
from utils import printdict, hexdump, doinfo, dodebug, dowarn, doerror


def inspect(proto, data, datalen, regexes, fuzzpatterns, yararuleobjects, addrkey, direction, directionflag):
    if configopts['regexengine'] == 're':
        import re
    if configopts['fuzzengine']:
        from fuzzywuzzy import fuzz
    if configopts['yaraengine']:
        import yara
    if configopts['shellcodeengine']:
        import pylibemu as emu

    skip = False
    matched = False

    ((src, sport), (dst, dport)) = addrkey

    if proto == 'TCP':
        id = opentcpflows[addrkey]['id']
    elif proto == 'UDP':
        for key in openudpflows.keys():
            skey = '%s:%s' % (src, sport)
            dkey = '%s:%s' % (dst, dport)
            if skey == key:
                id = openudpflows[key]['id']
                addrkey = skey
            elif dkey == key:
                id = openudpflows[key]['id']
                addrkey = dkey

    if configopts['verbose'] and configopts['verboselevel'] >= 2:
        dodebug('[%s#%08d] Received %dB for inspection from %s:%s %s %s:%s' % (
                proto,
                id,
                datalen,
                src,
                sport,
                directionflag,
                dst,
                dport))

    if 'regex' in configopts['inspectionmodes']:
        for regex in regexes:
            matchstats['match'] = regex.search(data)

            if direction == configopts['ctsdirectionstring']:
                regexpattern = configopts['ctsregexes'][regex]['regexpattern']
            elif direction == configopts['stcdirectionstring']:
                regexpattern = configopts['stcregexes'][regex]['regexpattern']

            if matchstats['match'] and not configopts['invertmatch']:
                matchstats['detectiontype'] = 'regex'
                matchstats['regex'] = regex
                matchstats['start'] = matchstats['match'].start()
                matchstats['end'] = matchstats['match'].end()
                matchstats['matchsize'] = matchstats['end'] - matchstats['start']
                if configopts['verbose'] and configopts['verboselevel'] >= 2:
                    dodebug('[%s#%08d] %s:%s %s %s:%s matches regex: \'%s\'' % (
                            proto,
                            id,
                            src,
                            sport,
                            directionflag,
                            dst,
                            dport,
                            regexpattern))
                return True

            if not matchstats['match'] and configopts['invertmatch']:
                matchstats['detectiontype'] = 'regex'
                matchstats['regex'] = regex
                matchstats['start'] = 0
                matchstats['end'] = datalen
                matchstats['matchsize'] = matchstats['end'] - matchstats['start']
                if configopts['verbose'] and configopts['verboselevel'] >= 2:
                    dodebug('[%s#%08d] %s:%s %s %s:%s matches regex (invert): \'%s\'' % (
                            proto,
                            id,
                            src,
                            sport,
                            directionflag,
                            dst,
                            dport,
                            regexpattern))
                return True

            if configopts['verbose'] and configopts['verboselevel'] >= 2:
                if configopts['invertmatch']:
                    invertstatus = " (invert)"
                else:
                    invertstatus = ""

                dodebug('[%s#%08d] %s:%s %s %s:%s did not match regex%s: \'%s\'' % (
                        proto,
                        id,
                        src,
                        sport,
                        directionflag,
                        dst,
                        dport,
                        invertstatus,
                        regexpattern))

    if 'fuzzy' in configopts['inspectionmodes']:
        for pattern in fuzzpatterns:
            partialratio = fuzz.partial_ratio(data, pattern)

            if partialratio >= configopts['fuzzminthreshold']:
                if not configopts['invertmatch']:
                    matched = True
                    matchstr = 'matches'
                    matchreason = '>='
                else:
                    matched = False
                    matchstr = 'doesnot match'
                    matchreason = '|'
            else:
                if configopts['invertmatch']:
                    matched = True
                    matchstr = 'matches'
                    matchreason = '|'
                else:
                    matched = False
                    matchstr = 'doesnot match'
                    matchreason = '<'

            if configopts['verbose'] and configopts['verboselevel'] >= 2:
                dodebug('[%s#%08d] %s:%s %s %s:%s %s \'%s\' (ratio: %d %s threshold: %d)' % (
                        proto,
                        id,
                        src,
                        sport,
                        directionflag,
                        dst,
                        dport,
                        matchstr,
                        pattern,
                        partialratio,
                        matchreason,
                        configopts['fuzzminthreshold']))

            if matched:
                matchstats['detectiontype'] = 'fuzzy'
                matchstats['fuzzpattern'] = pattern
                matchstats['start'] = 0
                matchstats['end'] = datalen
                matchstats['matchsize'] = matchstats['end'] - matchstats['start']
                return True

    if 'shellcode' in configopts['inspectionmodes']:
        emulator = emu.Emulator(configopts['emuprofileoutsize'])
        offset = emulator.shellcode_getpc_test(data)
        if offset < 0: offset = 0
        emulator.prepare(data, offset)
        emulator.test()

        matched = False
        invert = False
        invertstatus = ""

        if emulator.emu_profile_output:
            # shellcode found!
            if configopts['invertmatch']:
                matched = True
                invert = False
                invertstatus = ""
            else:
                matched = True
                invert = False
                invertstatus = ""
        else:
            # shellcode not found!
            if configopts['invertmatch']:
                matched = True
                invert = True
                invertstatus = " (invert)"
            else:
                matched = False
                invert = False
                invertstatus = ""

        if matched:
            emulator.free()
            matchstats['detectiontype'] = 'shellcode'
            matchstats['shellcodeoffset'] = offset
            matchstats['start'] = offset
            matchstats['end'] = datalen
            matchstats['matchsize'] = matchstats['end'] - matchstats['start']
            if configopts['verbose'] and configopts['verboselevel'] >= 2:
                dodebug('[%s#%08d] %s:%s %s %s:%s contains shellcode%s' % (
                        proto,
                        id,
                        src,
                        sport,
                        directionflag,
                        dst,
                        dport,
                        invertstatus))

            if configopts['emuprofile'] and not invert:
                filename = '%s-%08d-%s.%s-%s.%s-%s.emuprofile' % (
                            proto,
                            id,
                            src,
                            sport,
                            dst,
                            dport,
                            direction)

                data = emulator.emu_profile_output.decode('utf8')

                if emulator.emu_profile_truncated and configopts['verbose'] and configopts['verboselevel'] >= 2:
                    dodebug('[%s#%08d] Skipping emulator profile output generation as its truncated' % (proto, id))
                else:
                    fo = open(filename, 'w')
                    fo.write(data)
                    fo.close()
                    if configopts['verbose'] and configopts['verboselevel'] >= 2:
                        dodebug('[%s#%08d] Wrote %d byte emulator profile output to %s' % (proto, id, len(data), filename))

            return True

        if configopts['verbose'] and configopts['verboselevel'] >= 2:
            dodebug('[%s#%08d] %s:%s %s %s:%s doesnot contain shellcode%s' % (
                            proto,
                            id,
                            src,
                            sport,
                            directionflag,
                            dst,
                            dport,
                            invertstatus))

    if 'yara' in configopts['inspectionmodes']:
       for ruleobj in yararuleobjects:
            matchstats['start'] = -1
            matchstats['end'] = -1
            matchstats['yararulenamespace'] = None
            matchstats['yararulename'] = None
            matchstats['yararulemeta'] = None

            matches = ruleobj.match(data=data, callback=yaramatchcallback)

            if matches:
                if not configopts['invertmatch']: matched = True
                else: matched = False
            else:
                if configopts['invertmatch']: matched = True
                else: matched = False

            if matched:
                matchstats['detectiontype'] = 'yara'

                for rule in configopts['ctsyararules']:
                    if rule == ruleobj: matchstats['yararulefilepath'] = configopts['ctsyararules'][rule]['filepath']
                for rule in configopts['stcyararules']:
                    if rule == ruleobj: matchstats['yararulefilepath'] = configopts['stcyararules'][rule]['filepath']

                if matchstats['start'] == -1 and matchstats['end'] == -1:
                    matchstats['start'] = 0
                    matchstats['end'] = len(data)

                matchstats['matchsize'] = matchstats['end'] - matchstats['start']
                return True

    return False


def yaramatchcallback(data):
    matchstats['yararulenamespace'] = data['namespace']
    matchstats['yararulename'] = data['rule']
    matchstats['yararulemeta'] = data['meta']
    for (start, var, matchstr) in data['strings']:
        matchstats['start'] = start
        matchstats['end'] = start + len(matchstr)

    configopts['yaracallbackretval']

