#!/usr/bin/env python2

__author__  = 'Ankur Tyagi (7h3rAm)'
__email__   = '7h3rAm [at] gmail [dot] com'
__version__ = '0.2'
__license__ = 'CC BY-NC-SA 3.0 (http://creativecommons.org/licenses/by-nc-sa/3.0/)'
__status__  = 'Development'


import os, sys, shutil, argparse

# adding custom modules path to system search paths list
# for Python to be able to import flowinspect's core modules
# inspired from Chopshop: https://github.com/MITRECND/chopshop/blob/master/chopshop
# and this SO answer: http://stackoverflow.com/questions/4383571/importing-files-from-different-folder-in-python
FLOWINSPECTROOTDIR = os.path.realpath(os.path.dirname(sys.argv[0]))
sys.path.insert(0, '%s/%s' % (FLOWINSPECTROOTDIR, 'core'))

from globals import configopts, opentcpflows, openudpflows, ippacketsdict
from functions import dumpargsstats, exitwithstats
from tcphandler import handletcp
from udphandler import handleudp
from iphandler import handleip
from utils import NullDevice

sys.dont_write_bytecode = True


try:
    import nids
except ImportError, ex:
    print '[-] Import failed: %s' % ex
    print '[-] Cannot proceed. Exiting.'
    print
    sys.exit(1)


def main():
    banner = '''\
        ______              _                            __
       / __/ /___ _      __(_)___  _________  ___  _____/ /_
      / /_/ / __ \ | /| / / / __ \/ ___/ __ \/ _ \/ ___/ __/
     / __/ / /_/ / |/ |/ / / / / (__  ) /_/ /  __/ /__/ /_
    /_/ /_/\____/|__/|__/_/_/ /_/____/ .___/\___/\___/\__/
                                    /_/
    '''

    sys.stdout = sys.__stdout__
    print '%s' % (banner)
    print '          %s - %s' % (configopts['name'], configopts['desc'])
    print '          %s' % configopts['author']
    print

    import re
    configopts['regexengine'] = 're'

    parser = argparse.ArgumentParser()

    inputgroup = parser.add_mutually_exclusive_group(required=True)
    inputgroup.add_argument(
                                    '-p',
                                    metavar='--pcap',
                                    dest='pcap',
                                    default='',
                                    action='store',
                                    help='input pcap file')
    inputgroup.add_argument(
                                    '-d',
                                    metavar='--device',
                                    dest='device',
                                    default='lo',
                                    action='store',
                                    help='listening device')

    regex_direction_flags = parser.add_argument_group('RegEx per Direction')
    regex_direction_flags.add_argument(
                                    '-c',
                                    metavar='--cregex',
                                    dest='cres',
                                    default=[],
                                    action='append',
                                    required=False,
                                    help='regex to match against CTS data')
    regex_direction_flags.add_argument(
                                    '-s',
                                    metavar='--sregex',
                                    dest='sres',
                                    default=[],
                                    action='append',
                                    required=False,
                                    help='regex to match against STC data')
    regex_direction_flags.add_argument(
                                    '-a',
                                    metavar='--aregex',
                                    dest='ares',
                                    default=[],
                                    action='append',
                                    required=False,
                                    help='regex to match against ANY data')

    regex_options = parser.add_argument_group('RegEx Options')
    regex_options.add_argument(
                                    '-i',
                                    dest='igncase',
                                    default=False,
                                    action='store_true',
                                    required=False,
                                    help='ignore case')
    regex_options.add_argument(
                                    '-m',
                                    dest='multiline',
                                    default=True,
                                    action='store_false',
                                    required=False,
                                    help='disable multiline match')

    fuzzy_direction_flags = parser.add_argument_group('Fuzzy Patterns per Direction')
    fuzzy_direction_flags.add_argument(
                                    '-G',
                                    metavar='--cfuzz',
                                    dest='cfuzz',
                                    default=[],
                                    action='append',
                                    required=False,
                                    help='string to fuzzy match against CTS data')
    fuzzy_direction_flags.add_argument(
                                    '-H',
                                    metavar='--sfuzz',
                                    dest='sfuzz',
                                    default=[],
                                    action='append',
                                    required=False,
                                    help='string to fuzzy match against STC data')
    fuzzy_direction_flags.add_argument(
                                    '-I',
                                    metavar='--afuzz',
                                    dest='afuzz',
                                    default=[],
                                    action='append',
                                    required=False,
                                    help='string to fuzzy match against ANY data')
    fuzzy_options = parser.add_argument_group('Fuzzy Options')
    fuzzy_options.add_argument(
                                    '-r',
                                    metavar='fuzzminthreshold',
                                    dest='fuzzminthreshold',
                                    type=int,
                                    default=75,
                                    action='store',
                                    required=False,
                                    help='threshold for fuzzy match (1-100) - default 75')

    yara_direction_flags = parser.add_argument_group('Yara Rules per Direction')
    yara_direction_flags.add_argument(
                                    '-P',
                                    metavar='--cyararules',
                                    dest='cyararules',
                                    default=[],
                                    action='append',
                                    required=False,
                                    help='Yara rules to match on CTS data')
    yara_direction_flags.add_argument(
                                    '-Q',
                                    metavar='--syararules',
                                    dest='syararules',
                                    default=[],
                                    action='append',
                                    required=False,
                                    help='Yara rules to match on STC data')
    yara_direction_flags.add_argument(
                                    '-R',
                                    metavar='--ayararules',
                                    dest='ayararules',
                                    default=[],
                                    action='append',
                                    required=False,
                                    help='Yara rules to match on ANY data')

    shellcode_options = parser.add_argument_group('Shellcode Detection')
    shellcode_options.add_argument(
                                    '-M',
                                    dest='shellcode',
                                    default=False,
                                    action='store_true',
                                    required=False,
                                    help='enable shellcode detection')
    shellcode_options.add_argument(
                                    '-y',
                                    dest='emuprofile',
                                    default=False,
                                    action='store_true',
                                    required=False,
                                    help='generate emulator profile for detected shellcode')
    shellcode_options.add_argument(
                                    '-Y',
                                    metavar='--emuprofileoutsize',
                                    dest='emuprofileoutsize',
                                    default=0,
                                    action='store',
                                    required=False,
                                    help='emulator profile memory size (default 1024K | max: 10240K)')

    content_modifiers = parser.add_argument_group('Content Modifiers')
    content_modifiers.add_argument(
                                    '-O',
                                    metavar='--offset',
                                    dest='offset',
                                    default=0,
                                    action='store',
                                    required=False,
                                    help='bytes to skip before matching')
    content_modifiers.add_argument(
                                    '-D',
                                    metavar='--depth',
                                    dest='depth',
                                    default=0,
                                    action='store',
                                    required=False,
                                    help='bytes to look at while matching (starting from offset)')

    inspection_limits = parser.add_argument_group('Inspection Limits')
    inspection_limits.add_argument(
                                    '-T',
                                    metavar='--maxinspstreams',
                                    dest='maxinspstreams',
                                    default=0,
                                    action='store',
                                    type=int,
                                    required=False,
                                    help='max streams to inspect')
    inspection_limits.add_argument(
                                    '-U',
                                    metavar='--maxinsppackets',
                                    dest='maxinsppackets',
                                    default=0,
                                    action='store',
                                    type=int,
                                    required=False,
                                    help='max packets to inspect')

    display_limits = parser.add_argument_group('Display Limits')
    display_limits.add_argument(
                                    '-t',
                                    metavar='--maxdispstreams',
                                    dest='maxdispstreams',
                                    default=0,
                                    action='store',
                                    type=int,
                                    required=False,
                                    help='max streams to display')
    display_limits.add_argument(
                                    '-u',
                                    metavar='--maxdisppackets',
                                    dest='maxdisppackets',
                                    default=0,
                                    action='store',
                                    type=int,
                                    required=False,
                                    help='max packets to display')
    display_limits.add_argument(
                                    '-b',
                                    metavar='--maxdispbytes',
                                    dest='maxdispbytes',
                                    default=0,
                                    action='store',
                                    type=int,
                                    required=False,
                                    help='max bytes to display')

    output_options = parser.add_argument_group('Output Options')
    output_options.add_argument(
                                    '-w',
                                    metavar='logdir',
                                    dest='writebytes',
                                    default='',
                                    action='store',
                                    required=False,
                                    nargs='?',
                                    help='write matching packets/streams')
    output_options.add_argument(
                                    '-o',
                                    dest='outmodes',
                                    choices=('quite', 'meta', 'hex', 'print', 'raw'),
                                    action='append',
                                    default=[],
                                    required=False,
                                    help='match output modes')

    misc_options = parser.add_argument_group('Misc. Options')
    misc_options.add_argument(
                                    '-f',
                                    metavar='--bpf',
                                    dest='bpf',
                                    default='',
                                    action='store',
                                    required=False,
                                    help='BPF expression')
    misc_options.add_argument(
                                    '-v',
                                    dest='invmatch',
                                    default=False,
                                    action='store_true',
                                    required=False,
                                    help='invert match')
    misc_options.add_argument(
                                    '-V',
                                    dest='verbose',
                                    default=0,
                                    action='count',
                                    required=False,
                                    help='verbose output')
    misc_options.add_argument(
                                    '-e',
                                    dest='colored',
                                    default=False,
                                    action='store_true',
                                    required=False,
                                    help='highlight CTS/STC matches')
    misc_options.add_argument(
                                    '-k',
                                    dest='killtcp',
                                    default=False,
                                    action='store_true',
                                    required=False,
                                    help='kill matching TCP stream')
    misc_options.add_argument(
                                    '-j',
                                    dest='tcpmultimatch',
                                    default=False,
                                    action='store_true',
                                    required=False,
                                    help='enable TCP multi match mode')

    pcapwrite = parser.add_mutually_exclusive_group(required=False)
    pcapwrite.add_argument(
                                    '-z',
                                    dest='writepcapfast',
                                    default=False,
                                    action='store_true',
                                    help='write matching flows to pcap w/ %d post match packets' % (configopts['pcappacketct']))
    pcapwrite.add_argument(
                                    '-Z',
                                    dest='writepcap',
                                    default=False,
                                    action='store_true',
                                    help='write matching flows to pcap w/ all post match packets')

    misc_options.add_argument(
                                    '-q',
                                    metavar='pcappacketct',
                                    dest='pcappacketct',
                                    default=configopts['pcappacketct'],
                                    action='store',
                                    help='# of post match packets to write to pcap')

    misc_options.add_argument(
                                    '-n',
                                    dest='confirm',
                                    default=False,
                                    action='store_true',
                                    required=False,
                                    help='confirm before initializing NIDS')
    misc_options.add_argument(
                                    '-L',
                                    dest='linemode',
                                    default=False,
                                    action='store_true',
                                    required=False,
                                    help='enable linemode (disables inspection)')

    args = parser.parse_args()
    sys.stdout = NullDevice()

    if args.pcap:
        configopts['pcap'] = args.pcap
        nids.param('filename', configopts['pcap'])
        configopts['livemode'] = False
    elif args.device:
        configopts['device'] = args.device
        nids.param('device', configopts['device'])
        configopts['livemode'] = True

    if args.igncase:
        configopts['igncase'] = True
        configopts['reflags'] |= re.IGNORECASE

    if args.invmatch:
        configopts['invertmatch'] = True

    if args.multiline:
        configopts['multiline'] = True
        configopts['reflags'] |= re.MULTILINE
        configopts['reflags'] |= re.DOTALL

    if args.tcpmultimatch:
        configopts['tcpmultimatch'] = True

    if configopts['regexengine']:
        if args.cres:
            if 'regex' not in configopts['inspectionmodes']:
                configopts['inspectionmodes'].append('regex')
            for c in args.cres:
                configopts['ctsregexes'][re.compile(c, configopts['reflags'])] = { 'regexpattern': c }

        if args.sres:
            if 'regex' not in configopts['inspectionmodes']:
                configopts['inspectionmodes'].append('regex')
            for s in args.sres:
                configopts['stcregexes'][re.compile(s, configopts['reflags'])] = { 'regexpattern': s }

        if args.ares:
            if 'regex' not in configopts['inspectionmodes']:
                configopts['inspectionmodes'].append('regex')
            for a in args.ares:
                configopts['ctsregexes'][re.compile(a, configopts['reflags'])] = { 'regexpattern': a }
                configopts['stcregexes'][re.compile(a, configopts['reflags'])] = { 'regexpattern': a }

    if args.cfuzz or args.sfuzz or args.afuzz:
        try:
            from fuzzywuzzy import fuzz
            configopts['fuzzengine'] = 'fuzzywuzzy'
        except ImportError, ex:
            configopts['fuzzengine'] = None

    if configopts['fuzzengine']:
        if args.cfuzz:
            if 'fuzzy' not in configopts['inspectionmodes']: configopts['inspectionmodes'].append('fuzzy')
            for c in args.cfuzz:
                configopts['ctsfuzzpatterns'].append(c)

        if args.sfuzz:
            if 'fuzzy' not in configopts['inspectionmodes']: configopts['inspectionmodes'].append('fuzzy')
            for s in args.sfuzz:
                configopts['stcfuzzpatterns'].append(s)

        if args.afuzz:
            if 'fuzzy' not in configopts['inspectionmodes']: configopts['inspectionmodes'].append('fuzzy')
            for a in args.afuzz:
                configopts['ctsfuzzpatterns'].append(a)
                configopts['stcfuzzpatterns'].append(a)

    if args.fuzzminthreshold >= 1 and args.fuzzminthreshold <= 100:
        configopts['fuzzminthreshold'] = args.fuzzminthreshold

    if args.cyararules or args.syararules or args.ayararules:
        try:
            import yara
            configopts['yaraengine'] = 'pyyara'
        except ImportError, ex:
            configopts['yaraengine'] = None

    if configopts['yaraengine']:
        configopts['yaracallbackretval'] = yara.CALLBACK_ABORT

        if args.cyararules:
            if 'yara' not in configopts['inspectionmodes']: configopts['inspectionmodes'].append('yara')
            for c in args.cyararules:
                if os.path.isfile(c): configopts['ctsyararules'][yara.compile(c)] = { 'filepath': c }

        if args.syararules:
            if 'yara' not in configopts['inspectionmodes']: configopts['inspectionmodes'].append('yara')
            for s in args.syararules:
                if os.path.isfile(s): configopts['stcyararules'][yara.compile(s)] = { 'filepath': s }

        if args.ayararules:
            if 'yara' not in configopts['inspectionmodes']: configopts['inspectionmodes'].append('yara')
            for a in args.ayararules:
                if os.path.isfile(a):
                    configopts['ctsyararules'][yara.compile(a)] = { 'filepath': a }
                    configopts['stcyararules'][yara.compile(a)] = { 'filepath': a }

    if args.offset:
        configopts['offset'] = int(args.offset)

    if args.depth:
        configopts['depth'] = int(args.depth)

    if args.maxinsppackets:
        configopts['maxinsppackets'] = int(args.maxinsppackets)

    if args.maxinspstreams:
        configopts['maxinspstreams'] = int(args.maxinspstreams)

    if args.maxdisppackets:
        configopts['maxdisppackets'] = int(args.maxdisppackets)

    if args.maxdispstreams:
        configopts['maxdispstreams'] = int(args.maxdispstreams)

    if args.maxdispbytes:
        configopts['maxdispbytes'] = int(args.maxdispbytes)

    if args.writebytes != '':
        configopts['writelogs'] = True
        if args.writebytes != None:
            configopts['logdir'] = args.writebytes
        else:
            configopts['logdir'] = '.'

    if not args.outmodes:
        configopts['outmodes'].append('meta')
        configopts['outmodes'].append('hex')
    else:
        if 'quite' in args.outmodes: configopts['outmodes'].append('quite')
        if 'meta' in args.outmodes: configopts['outmodes'].append('meta')
        if 'hex' in args.outmodes: configopts['outmodes'].append('hex')
        if 'print' in args.outmodes: configopts['outmodes'].append('print')
        if 'raw' in args.outmodes: configopts['outmodes'].append('raw')

    try:
        import pylibemu as emu
        configopts['shellcodeengine'] = 'pylibemu'
    except ImportError, ex:
        configopts['shellcodeengine'] = None

    if configopts['shellcodeengine']:
        if args.shellcode:
            configopts['inspectionmodes'].append('shellcode')

    if args.emuprofile:
        configopts['emuprofile'] = True

    if int(args.emuprofileoutsize) > 0 and int(args.emuprofileoutsize) <= 10240:
        configopts['emuprofileoutsize'] = int(args.emuprofileoutsize)

    if args.bpf:
        configopts['bpf'] = args.bpf
        nids.param('pcap_filter', configopts['bpf'])

    if args.killtcp:
        if configopts['livemode']: configopts['killtcp'] = True

    if args.writepcap:
        configopts['writepcap'] = True

    if args.writepcapfast:
        configopts['writepcapfast'] = True

    if int(args.pcappacketct) >= 0:
        configopts['pcappacketct'] = int(args.pcappacketct)

    if args.colored:
        try:
            from termcolor import colored
            configopts['colored'] = True
        except ImportError, ex:
            print '[!] Import failed: %s' % (ex)
            configopts['colored'] = False

    if args.verbose:
        configopts['verbose'] = True
        configopts['verboselevel'] = args.verbose
        if configopts['verboselevel'] > 4:
            configopts['verboselevel'] = 4

    if args.linemode:
        configopts['linemode'] = True

    sys.stdout = sys.__stdout__

    if not configopts['inspectionmodes'] and not configopts['linemode']:
        configopts['linemode'] = True
        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            print '[DEBUG] Inspection disabled as no mode selected/available'
            print '[DEBUG] Fallback - linemode enabled'
            print

    if configopts['writepcapfast'] and configopts['linemode']:
        configopts['writepcapfast'] = False
        configopts['writepcap'] = True
        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            print '[DEBUG] Fast pcap writing is incompatible with linemode. Using slow pcap writing as fallback.'

    if configopts['writepcapfast'] and configopts['tcpmultimatch']:
        configopts['writepcapfast'] = False
        configopts['writepcap'] = True
        if configopts['verbose'] and configopts['verboselevel'] >= 1:
            print '[DEBUG] Fast pcap writing is incompatible with multimatch. Using slow pcap writing as fallback.'

    if configopts['linemode']:
        configopts['offset'] = 0
        configopts['depth'] = 0
        del configopts['inspectionmodes'][:]
        configopts['invertmatch'] = False
        configopts['killtcp'] = False
        configopts['livemode'] = False

    if configopts['verbose'] and configopts['verboselevel'] >= 1:
        dumpargsstats(configopts)

    try:
        nids.chksum_ctl([('0.0.0.0/0', False)])
        nids.param('scan_num_hosts', 0)

        nids.init()
        nids.register_ip(handleip)
        nids.register_udp(handleudp)
        nids.register_tcp(handletcp)

        if args.confirm:
            print '[+] Callback handlers registered. Press any key to continue...',
            try: input()
            except: pass
        else:
            print '[+] Callback handlers registered'

        print '[+] NIDS initialized, waiting for events...' ; print
        try: nids.run()
        except KeyboardInterrupt: exitwithstats()

    except nids.error, nx:
        print
        print '[-] NIDS error: %s' % nx
        print
        sys.exit(1)
#    except Exception, ex:
#        print
#        print '[-] Exception: %s' % ex
#        print
#        sys.exit(1)

    exitwithstats()

if __name__ == '__main__':
    main()
