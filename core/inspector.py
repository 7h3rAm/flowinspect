# flowinspect inspector - 4 modes of inspection
# regex: import re2 or re, match over rcvd data, populate match stats
# fuzzy: import fuzzywuzzy, match over rcvd data, populate match stats
# yara: import python-yara, match over rcvd data, populate match stats
# shellcode: import libemu, match over rcvd data, populate match stats

import nids
from globals import configopts, opentcpflows, openudpflows, matchstats, dfapartialmatches
from utils import printdict, hexdump


def inspect(proto, data, datalen, regexes, fuzzpatterns, yararuleobjects, addrkey, direction, directionflag):
    if configopts['regexengine'] == 're2':
        import re2 as re
    else:
        import re
    if configopts['fuzzengine']: from fuzzywuzzy import fuzz
    if configopts['yaraengine']: import yara
    if configopts['shellcodeengine']: import pylibemu as emu
    if configopts['dfaengine']:
        from pydfa.pydfa import Rexp
        from pydfa.graph import FA

    skip = False
    matched = False
    configopts['dfapartialmatch'] = False
    configopts['dfafinalmatch'] = False

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

    if configopts['verbose']:
        print '[DEBUG] inspect - [%s#%08d] Received %dB for inspection from %s:%s %s %s:%s' % (
                proto,
                id,
                datalen,
                src,
                sport,
                directionflag,
                dst,
                dport)

    if 'regex' in configopts['inspectionmodes']:
        for regex in regexes:
            matchstats['match'] = regex.search(data)

            if direction == configopts['ctsdirectionstring']:
                regexpattern = configopts['ctsregexes'][regex]['regexpattern']
            elif direction == configopts['stcdirectionstring']:
                regexpattern = configopts['stcregexes'][regex]['regexpattern']

            if matchstats['match']:
                matchstats['detectiontype'] = 'regex'
                matchstats['regex'] = regex
                matchstats['start'] = matchstats['match'].start()
                matchstats['end'] = matchstats['match'].end()
                matchstats['matchsize'] = matchstats['end'] - matchstats['start']
                if configopts['verbose']:
                    print '[DEBUG] inspect - [%s#%08d] %s:%s %s %s:%s matches regex: \'%s\'' % (
                            proto,
                            id,
                            src,
                            sport,
                            directionflag,
                            dst,
                            dport,
                            regexpattern)

                return True
            else:
                if configopts['invertmatch']:
                    matchstats['detectiontype'] = 'regex'
                    matchstats['regex'] = regex
                    matchstats['start'] = 0
                    matchstats['end'] = datalen
                    matchstats['matchsize'] = matchstats['end'] - matchstats['start']
                    return True

            if configopts['verbose']:
                print '[DEBUG] inspect - [%s#%08d] %s:%s %s %s:%s did not match regex: \'%s\'' % (
                        proto,
                        id,
                        src,
                        sport,
                        directionflag,
                        dst,
                        dport,
                        regexpattern)

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

            if configopts['verbose']:
                print '[DEBUG] inspect - [%s#%08d] %s:%s %s %s:%s %s \'%s\' (ratio: %d %s threshold: %d)' % (
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
                        configopts['fuzzminthreshold'])

            if matched:
                matchstats['detectiontype'] = 'fuzzy'
                matchstats['fuzzpattern'] = pattern
                matchstats['start'] = 0
                matchstats['end'] = datalen
                matchstats['matchsize'] = matchstats['end'] - matchstats['start']
                return True

    dfas = {}
    if 'dfa' in configopts['inspectionmodes']:
        if direction == 'CTS': dfas = configopts['ctsdfas']
        if direction == 'STC': dfas = configopts['stcdfas']

        for dfaobject in dfas.keys():
            if direction == 'CTS':
                memberid = configopts['ctsdfas'][dfaobject]['memberid']
                dfapattern = configopts['ctsdfas'][dfaobject]['dfapattern']
                dfas = configopts['ctsdfas']

                if proto == 'TCP':
                    if dfaobject in opentcpflows[addrkey]['ctsmatcheddfastats'] and opentcpflows[addrkey]['ctsmatcheddfastats'][dfaobject]['truthvalue']:
                        #skip = True
                        memberid = opentcpflows[addrkey]['ctsmatcheddfastats'][dfaobject]['memberid']
                elif proto == 'UDP':
                    if dfaobject in openudpflows[addrkey]['ctsmatcheddfastats'] and openudpflows[addrkey]['ctsmatcheddfastats'][dfaobject]['truthvalue']:
                        #skip = True
                        memberid = openudpflows[addrkey]['ctsmatcheddfastats'][dfaobject]['memberid']

            if direction == 'STC':
                memberid = configopts['stcdfas'][dfaobject]['memberid']
                dfapattern = configopts['stcdfas'][dfaobject]['dfapattern']
                dfas = configopts['stcdfas']

                if proto == 'TCP':
                    if dfaobject in opentcpflows[addrkey]['stcmatcheddfastats'] and opentcpflows[addrkey]['stcmatcheddfastats'][dfaobject]['truthvalue']:
                        #skip = True
                        memberid = opentcpflows[addrkey]['stcmatcheddfastats'][dfaobject]['memberid']
                elif proto == 'UDP':
                    if dfaobject in openudpflows[addrkey]['stcmatcheddfastats'] and openudpflows[addrkey]['stcmatcheddfastats'][dfaobject]['truthvalue']:
                        #skip = True
                        memberid = openudpflows[addrkey]['stcmatcheddfastats'][dfaobject]['memberid']

            if skip:
                if configopts['verbose']:
                    print '[DEBUG] inspect - [%s#%08d] %s:%s %s %s:%s already matched %s' % (
                            proto,
                            id,
                            src,
                            sport,
                            dst,
                            dport,
                            memberid)
                continue

            matched = False

            retncode = dfaobject.match(data)
            dfaobject.reset_dfa()

            if retncode == 1 and not configopts['invertmatch']: matched = True
            elif retncode == 0 and configopts['invertmatch']: matched = True

            dfaexpression = configopts['dfaexpression']

            if matched:
                configopts['dfapartialmatch'] = True

                matchstats['detectiontype'] = 'dfa'
                matchstats['dfaobj'] = dfaobject
                matchstats['dfapattern'] = dfapattern
                matchstats['dfastatecount'] = dfaobject.nQ
                matchstats['start'] = 0
                matchstats['end'] = datalen
                matchstats['matchsize'] = matchstats['end'] - matchstats['start']

                if proto == 'TCP':
                    if direction == 'CTS':
                        opentcpflows[addrkey]['ctsmatcheddfastats'].update({
                                                        dfaobject: {
                                                                'dfaobject': dfaobject,
                                                                'dfapattern': dfapattern,
                                                                'memberid': memberid,
                                                                'truthvalue': 'True'
                                                            }
                                                    })

                    if direction == 'STC':
                        opentcpflows[addrkey]['stcmatcheddfastats'].update({
                                                        dfaobject: {
                                                                'dfaobject': dfaobject,
                                                                'dfapattern': dfapattern,
                                                                'memberid': memberid,
                                                                'truthvalue': 'True'
                                                            }
                                                    })

                elif proto == 'UDP':
                    if direction == 'CTS':
                        openudpflows[addrkey]['ctsmatcheddfastats'].update({
                                                                                dfaobject: {
                                                                                                'dfaobject': dfaobject,
                                                                                                'dfapattern': dfapattern,
                                                                                                'memberid': memberid,
                                                                                                'truthvalue': 'True'
                                                                                            }
                                                                            })

                    if direction == 'STC':
                        openudpflows[addrkey]['stcmatcheddfastats'].update({
                                                                                dfaobject: {
                                                                                                'dfaobject': dfaobject,
                                                                                                'dfapattern': dfapattern,
                                                                                                'memberid': memberid,
                                                                                                'truthvalue': 'True'
                                                                                            }
                                                                            })


                if configopts['verbose']:
                    print '[DEBUG] inspect - [%s#%08d] %s:%s %s %s:%s matches %s: \'%s\'' % (
                            proto,
                            id,
                            src,
                            sport,
                            directionflag,
                            dst,
                            dport,
                            memberid,
                            dfapattern)

                exprdict = {}
                if proto == 'TCP':
                    for key in opentcpflows[addrkey]['ctsmatcheddfastats'].keys():
                        if key in opentcpflows[addrkey]['ctsmatcheddfastats']:
                            exprdict[opentcpflows[addrkey]['ctsmatcheddfastats'][key]['memberid']] = opentcpflows[addrkey]['ctsmatcheddfastats'][key]['truthvalue']
                        if key in opentcpflows[addrkey]['stcmatcheddfastats']:
                            exprdict[opentcpflows[addrkey]['stcmatcheddfastats'][key]['memberid']] = opentcpflows[addrkey]['stcmatcheddfastats'][key]['truthvalue']

                    for key in opentcpflows[addrkey]['stcmatcheddfastats'].keys():
                        if key in opentcpflows[addrkey]['ctsmatcheddfastats']:
                            exprdict[opentcpflows[addrkey]['ctsmatcheddfastats'][key]['memberid']] = opentcpflows[addrkey]['ctsmatcheddfastats'][key]['truthvalue']
                        if key in opentcpflows[addrkey]['stcmatcheddfastats']:
                            exprdict[opentcpflows[addrkey]['stcmatcheddfastats'][key]['memberid']] = opentcpflows[addrkey]['stcmatcheddfastats'][key]['truthvalue']

                if proto == 'UDP':
                    for key in openudpflows[addrkey]['ctsmatcheddfastats'].keys():
                        if key in openudpflows[addrkey]['ctsmatcheddfastats']:
                            exprdict[openudpflows[addrkey]['ctsmatcheddfastats'][key]['memberid']] = openudpflows[addrkey]['ctsmatcheddfastats'][key]['truthvalue']
                        if key in openudpflows[addrkey]['stcmatcheddfastats']:
                            exprdict[openudpflows[addrkey]['stcmatcheddfastats'][key]['memberid']] = openudpflows[addrkey]['stcmatcheddfastats'][key]['truthvalue']

                    for key in openudpflows[addrkey]['stcmatcheddfastats'].keys():
                        if key in openudpflows[addrkey]['ctsmatcheddfastats']:
                            exprdict[openudpflows[addrkey]['ctsmatcheddfastats'][key]['memberid']] = openudpflows[addrkey]['ctsmatcheddfastats'][key]['truthvalue']
                        if key in openudpflows[addrkey]['stcmatcheddfastats']:
                            exprdict[openudpflows[addrkey]['stcmatcheddfastats'][key]['memberid']] = openudpflows[addrkey]['stcmatcheddfastats'][key]['truthvalue']

                exprlist = []
                for token in configopts['dfaexpression'].split(' '):
                    if '(' in token and ')' in token:
                        token = token.replace('(', '')
                        token = token.replace(')', '')
                        exprlist.append('(')
                        exprlist.append(token)
                        exprlist.append(')')
                    elif '(' in token and token != '(':
                        exprlist.append('(')
                        exprlist.append(token.replace('(', ''))
                    elif ')' in token and token != ')':
                        exprlist.append(token.replace(')', ''))
                        exprlist.append(')')
                    elif token != '':
                        exprlist.append(token)

                configopts['dfaexpression'] = ' '.join(exprlist)

                exprboolean = []
                for token in exprlist:
                    if token == 'and': exprboolean.append(token)
                    elif token == 'or': exprboolean.append(token)
                    elif token == '(': exprboolean.append(token)
                    elif token == ')': exprboolean.append(token)
                    elif token in exprdict.keys(): exprboolean.append(exprdict[token])
                    else: exprboolean.append('False')

                evalboolean = ' '.join(exprboolean)

                configopts['dfafinalmatch'] = eval(evalboolean)

                if configopts['verbose']:
                    print '[DEBUG] inspect - [%s#%08d] %s:%s %s %s:%s (\'%s\' ==> \'%s\' ==> \'%s\')' % (
                            proto,
                            id,
                            src,
                            sport,
                            directionflag,
                            dst,
                            dport,
                            dfaexpression,
                            evalboolean,
                            configopts['dfafinalmatch'])

                graphexpression = dfapattern
                graphstatecount = dfaobject.nQ
                graphflow = '[%s#%08d] %s:%s %s %s:%s match @ %s[%d:%d] - %dB' % (
                            proto,
                            id,
                            src,
                            sport,
                            directionflag,
                            dst,
                            dport,
                            direction,
                            0,
                            datalen,
                            datalen)

                graphtitle = 'Expression: \'%s\' | State Count: %d\nFlow: %s' % (graphexpression, graphstatecount, graphflow)

                if configopts['dfapartialmatch']:
                    configopts['dfapartialmatchmember'] = memberid
                    dfapartialmatches = {
                                    memberid: {
                                            'addr': addrkey,
                                            'dfaobject': dfaobject,
                                            'dfapattern': dfapattern,
                                            'dfastatecount': dfaobject.nQ,
                                            'start': 0,
                                            'end': datalen,
                                            'matchsize': datalen,
                                            'direction': direction,
                                            'directionflag': None
                                        }
                                }

                    if proto == 'TCP':
                        if direction == 'CTS':
                            dfapartialmatches[memberid]['directionflag'] = '>'
                            opentcpflows[addrkey]['ctspacketlendict'].update({ opentcpflows[addrkey]['insppackets']: datalen })
                        elif direction == 'STC':
                            dfapartialmatches[memberid]['directionflag'] = '<'
                            opentcpflows[addrkey]['stcpacketlendict'].update({ opentcpflows[addrkey]['insppackets']: datalen })
                        #showtcpmatches(data)
                    if proto == 'UDP':
                        if direction == 'CTS':
                            dfapartialmatches[memberid]['directionflag'] = '>'
                        elif direction == 'STC':
                            dfapartialmatches[memberid]['directionflag'] = '<'
                        #showudpmatches(data)

                    if configopts['graph']:
                        graphdfatransitions(graphtitle, '%s-%08d-%s.%s-%s.%s-%s' % (proto, id, src, sport, dst, dport, memberid), dfaobject)

                if configopts['dfafinalmatch']:
                    configopts['dfapartialmatch'] = False
                    matchstats['dfaexpression'] = configopts['dfaexpression']

                    if configopts['graph']:
                        graphdfatransitions(graphtitle, '%s-%08d-%s.%s-%s.%s-%s' % (proto, id, src, sport, dst, dport, memberid), dfaobject)

                    return configopts['dfafinalmatch']

            elif configopts['verbose']:
                finalmatch = False
                print '[DEBUG] inspect - [%s#%08d] %s:%s %s %s:%s did not match %s: \'%s\'' % (
                        proto,
                        id,
                        src,
                        sport,
                directionflag,
                        dst,
                        dport,
                        memberid,
                        dfapattern)

    if 'shellcode' in configopts['inspectionmodes']:
        emulator = emu.Emulator(configopts['emuprofileoutsize'])
        offset = emulator.shellcode_getpc_test(data)
        if offset < 0: offset = 0
        emulator.prepare(data, offset)

        if not emulator.test() and emulator.emu_profile_output:
            emulator.free()
            matchstats['detectiontype'] = 'shellcode'
            matchstats['shellcodeoffset'] = offset
            matchstats['start'] = offset
            matchstats['end'] = datalen
            matchstats['matchsize'] = matchstats['end'] - matchstats['start']
            if configopts['verbose']:
                print '[DEBUG] inspect - [%s#%08d] %s:%s %s %s:%s contains shellcode' % (
                        proto,
                        id,
                        src,
                        sport,
                        directionflag,
                        dst,
                        dport)

            if configopts['emuprofile']:
                filename = '%s-%08d-%s.%s-%s.%s-%s.emuprofile' % (
                            proto,
                            id,
                            src,
                            sport,
                            dst,
                            dport,
                            direction)

                data = emulator.emu_profile_output.decode('utf8')

                if emulator.emu_profile_truncated and configopts['verbose']:
                    print '[DEBUG] inspect - [%s#%08d] Skipping emulator profile output generation as its truncated' % (proto, id)
                else:
                    fo = open(filename, 'w')
                    fo.write(data)
                    fo.close()
                    if configopts['verbose']:
                        print '[DEBUG] inspect - [%s#%08d] Wrote %d byte emulator profile output to %s' % (proto, id, len(data), filename)

            return True

        elif configopts['verbose']: print '[DEBUG] inspect - [%s#%08d] %s:%s %s %s:%s doesnot contain shellcode' % (
                            proto,
                            id,
                            src,
                            sport,
                            directionflag,
                            dst,
                            dport)

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
    global matchstats

    matchstats['yararulenamespace'] = data['namespace']
    matchstats['yararulename'] = data['rule']
    matchstats['yararulemeta'] = data['meta']
    for (start, var, matchstr) in data['strings']:
        matchstats['start'] = start
        matchstats['end'] = start + len(matchstr)

    yara.CALLBACK_ABORT


def graphdfatransitions(graphtitle, filename, dfaobject):
    global configopts

    if configopts['graph']:
        class NullDevice():
            def write(self, s): pass

        extension = 'png'
        graphfilename = '%s.%s' % (filename, extension)
        automata = FA(dfaobject)
        automata.draw_graph(graphtitle, 1, 0)
        stdstdout = sys.stdout
        sys.stdout = NullDevice()
        automata.save_graph(graphfilename)
        sys.stdout = sys.__stdout__

        if configopts['graphdir'] != '.':
            if not os.path.exists(configopts['graphdir']):
                os.makedirs(configopts['graphdir'])
            else:
                if os.path.exists(os.path.join(configopts['graphdir'], graphfilename)):
                    os.remove(os.path.join(configopts['graphdir'], graphfilename))

            shutil.move(graphfilename, configopts['graphdir'])

