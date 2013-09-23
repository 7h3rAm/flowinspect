# globals 


dfapartialmatches = {}
openudpflows = {}
opentcpflows = {}

matchstats = {
	'addr':None,

	'regex':None,

	'dfaobject':None,
	'dfapattern':None,
	'dfastatecount':0,
	'dfaexpression':None,

	'start':0,
	'end':0,
	'matchsize':0,

	'direction':None,
	'directionflag':None,

	'detectiontype':None,

	'shellcodeoffset':0
}

configopts = {
    'author': 'Ankur Tyagi (7h3rAm [at] gmail [dot] com)',

    'bpf': None,

    'ctsdfas': {},
    'ctsdirectionflag': '>',
    'ctsdirectionstring': 'CTS',
    'ctsfuzzpatterns': [],
    'ctsregexes': {},
    'ctsyararules': {},

    'depth': 0,
    'desc': 'A network inspection tool',
    'device': None,
    'dfaengine': None,
    'dfaexprmembers': [],
    'dfafinalmatch': False,
    'dfalist': [],
    'dfapartialmatch': False,
    'disppacketct': 0,
    'dispstreamct': 0,

    'emuprofile': False,

    'fuzzengine': None,
    'fuzzminthreshold': 75,

    'graphdir': '.',
    'graph': False,

    'igncase': False,
    'inspectionmodes': [],
    'insptcppacketct': 0,
    'insptcpstreamct': 0,
    'inspudppacketct': 0,
    'invertmatch': False,

    'killtcp': False,

    'linemode': False,
    'livemode': False,
    'logdir': '.',
    'longestmatch': { 'packet': 0, 'packetid': 0, 'stream': 0, 'streamid': 0 },

    'maxdispbytes': 0,
    'maxdisppackets': 0,
    'maxdispstreams': 0,
    'maxinsppackets': 0,
    'maxinspstreams': 0,
    'multiline': False,
    'name': 'flowinspect',

    'offset': 0,
    'outmodes': [],

    'packetct': 0,

    'reflags': 0,
    'regexengine': None,
    'regexlist': [],

    'shellcodeengine': None,
    'shortestmatch': { 'packet': 0, 'packetid': 0, 'stream': 0, 'streamid': 0 },
    'stcdfas': {},
    'stcdirectionflag': '<',
    'stcdirectionstring': 'STC',
    'stcfuzzpatterns': [],
    'stcregexes': {},
    'stcyararules': {},
    'streamct': 0,

    'tcpdone': False,
    'tcpmatches': 0,
    'udpdone': False,
    'udpmatches': 0,
    'useoroperator': False,

    'verbose': None,
    'version': 0.2,

    'writelogs': False,

    'yaraengine': None
}

