#!/usr/bin/env python

__author__	= 'Ankur Tyagi (7h3rAm)'
__email__ 	= '7h3rAm [at] gmail [dot] com'
__version__ = '0.2'
__license__ = 'CC-BY-SA 3.0'
__status__ 	= 'Development'


import os, sys, argparse, datetime

reengine = 're2'
if reengine == 're2':
	try: import re2 as re
	except ImportError, ex:
		reengine = 're'
		print '[!] Import failed: %s' % ex

if reengine == 're':
		try: import re
		except ImportError, ex: print '[!] Import failed: %s' % ex


try: import nids
except ImportError, ex:
	print '[-] Import failed: %s' % ex
	print '[-] Cannot proceed. Exiting.'
	sys.exit(1)

sys.dont_write_bytecode = True
from utils import *


configopts = {
			'name':os.path.basename(sys.argv[0]),
			'version':'0.2',
			'desc':'A tool for network traffic inspection',
			'author':'Ankur Tyagi (7h3rAm) @ Juniper Networks Security Research Group',

			'pcap':'',
			'device':'',
			'livemode':False,

			'ctsregexes':[],
			'stcregexes':[],

			'offset':0,
			'depth':0,

			'packetct':0,
			'streamct':0,

			'insppacketct':0,
			'inspstreamct':0,

			'disppacketct':0,
			'dispstreamct':0,

			'maxinsppackets':0,
			'maxinspstreams':0,
			'maxdisppackets':0,
			'maxdispstreams':0,
			'maxdispbytes':0,

			'packetmatches':0,
			'streammatches':0,

			'shortestmatch':{ 'packet':0, 'packetid':0, 'stream':0, 'streamid':0 },
			'longestmatch':{ 'packet':0, 'packetid':0, 'stream':0, 'streamid':0 },

			'udpdone':False,
			'tcpdone':False,

			'reflags':0,
			'igncase':False,
			'multiline':False,

			'bpf':'',
			'invertmatch':False,
			'killtcp':False,
			'verbose':False,
			'outmodes':[],
			'logdir':'',
			'writelogs':False,
			'linemode':False,

			}

matchstats = {
			'addr':'',
			'regex':None,
			'start':0,
			'end':0,
			'matchsize':0,
			'direction':'',
			'directionflag':''
			}

openstreams = {}


def handleudp(addr, payload, pkt):
	global configopts

	showmatch = False
	addrkey = addr
	((src, sport), (dst, dport)) = addrkey

	if not configopts['linemode']:
		if configopts['udpdone']:
			if configopts['tcpdone']:
				if configopts['verbose']:
					print "[DEBUG] handleudp - Done inspecting max packets (%d) and max streams (%d), \
							preparing for exit" % (
							configopts['maxinsppackets'],
							configopts['maxinspstreams'])
				exitwithstats()
			else:
				if configopts['verbose']:
					print "[DEBUG] handleudp - Ignoring packet %s:%s - %s:%s (insppacketct: %d == maxinsppackets: %d)" % (
							src,
							sport,
							dst,
							dport,
							configopts['insppacketct'],
							configopts['maxinsppackets'])
			return

	regexes = []
	timestamp = datetime.datetime.fromtimestamp(nids.get_pkt_ts()).strftime('%H:%M:%S | %Y/%m/%d')

	configopts['packetct'] += 1

	if configopts['verbose']:
		print "[DEBUG] handleudp - [UDP#%08d] %s:%s - %s:%s (%dB)" % (
				configopts['packetct'],
				src,
				sport,
				dst,
				dport,
				len(payload))

	direction = 'ANY'
	directionflag = '>'
	count = len(payload)
	start = 0
	end = count
	data = payload

	for regex in configopts['ctsregexes']:
		regexes.append(regex)

	for regex in configopts['stcregexes']:
		regexes.append(regex)

	configopts['insppacketct'] += 1

	if configopts['linemode']:
		matchstats['addr'] = addrkey
		matchstats['regex'] = re.compile('.*')
		matchstats['start'] = start
		matchstats['end'] = end
		matchstats['matchsize'] = matchstats['end'] - matchstats['start']
		matchstats['direction'] = direction
		matchstats['directionflag'] = directionflag
		if configopts['verbose']: print "[DEBUG] handleudp - [UDP#%08d] Skipping inspection as linemode is enabled." % (
											configopts['packetct'])
		showudpmatches(data[matchstats['start']:matchstats['end']])
		return

	if configopts['maxinsppackets'] != 0 and configopts['insppacketct'] >= configopts['maxinsppackets']:
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

	if configopts['verbose']:
		print "[DEBUG] handleudp - [UDP#%08d] Initiating inspection on %s[%d:%d] - %dB (RegEx #:%d)" % (
				configopts['packetct'],
				direction,
				offset,
				depth,
				inspdatalen,
				len(regexes))

	matched = inspect('UDP', configopts['packetct'], inspdata, inspdatalen, regexes, addrkey)

	if not matched and configopts['invertmatch']:
		showmatch = True

	if matched and not configopts['invertmatch']:
		showmatch = True

	if showmatch:
		matchstats['start'] += offset
		matchstats['end'] += offset

		matchstats['direction'] = direction
		matchstats['directionflag'] = directionflag

		if configopts['packetmatches'] == 0:
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

		configopts['packetmatches'] += 1

		matchstats['addr'] = addrkey
		showudpmatches(data[matchstats['start']:matchstats['end']])


def showudpmatches(data):
	global configopts, matchstats

	((src, sport), (dst, dport)) = matchstats['addr']

	if configopts['maxdispbytes'] > 0: maxdispbytes = configopts['maxdispbytes']
	else: maxdispbytes = len(data)

	if configopts['writelogs']:
		proto = "UDP"
		writetofile(proto, configopts['packetct'], src, sport, dst, dport, data)

		if configopts['verbose']:
			print '[DEBUG] showudpmatches - [UDP#%08d] Wrote %dB to %s/%s-%08d.%s.%s.%s.%s' % (
					configopts['packetct'],
					matchstats['matchsize'],
					configopts['logdir'],
					proto,
					configopts['packetct'],
					src,
					sport,
					dst,
					dport)

	if 'quite' in configopts['outmodes']:
		if configopts['verbose']:
			print "[DEBUG] showudpmatches - [UDP#%08d] %s:%s %s %s:%s matches \'%s\' @ [%d:%d] - %dB" % (
					configopts['packetct'],
					src,
					sport,
					matchstats['directionflag'],
					dst,
					dport,
					getregexpattern(matchstats['regex']),
					matchstats['start'],
					matchstats['end'],
					matchstats['matchsize'])
		return

	if configopts['maxdisppackets'] != 0 and configopts['disppacketct'] >= configopts['maxdisppackets']:
		if configopts['verbose']:
			print '[DEBUG] showudpmatches - Skipping outmode parsing (disppacketct: %d == maxdisppackets: %d)' % (
					configopts['disppacketct'],
					configopts['maxdisppackets'])
		return

	if 'meta' in configopts['outmodes']:
		print "[MATCH] (%08d/%08d) [UDP#%08d] %s:%s %s %s:%s matches \'%s\' @ [%d:%d] - %dB" % (
				configopts['insppacketct'],
				configopts['packetmatches'],
				configopts['packetct'],
				src,
				sport,
				matchstats['directionflag'],
				dst,
				dport,
				getregexpattern(matchstats['regex']),
				matchstats['start'],
				matchstats['end'],
				matchstats['matchsize'])
	if 'print' in configopts['outmodes']: printable(data[:maxdispbytes])
	if 'raw' in configopts['outmodes']: print data[:maxdispbytes]
	if 'hex' in configopts['outmodes']: hexdump(data[:maxdispbytes])

	configopts['disppacketct'] += 1


def inspect(proto, id, data, datalen, regexes, addr):
	global configopts, matchstats

	((src, sport), (dst, dport)) = addr

	if configopts['verbose']:
		print "[DEBUG] inspect - [%s#%08d] Received %dB for inspection from %s:%s - %s:%s against %d regex pattern(s)" % (
				proto,
				id,
				datalen,
				src,
				sport,
				dst,
				dport,
				len(regexes))

	for regex in regexes:
		matchstats['match'] = regex.search(data)
		if matchstats['match']:
			matchstats['regex'] = regex
			matchstats['start'] = matchstats['match'].start()
			matchstats['end'] = matchstats['match'].end()
			matchstats['matchsize'] = matchstats['end'] - matchstats['start']
			if configopts['verbose']:
				print "[DEBUG] inspect - [%s#%08d] %s:%s - %s:%s matches \'%s\'" % (
						proto,
						id,
						src,
						sport,
						dst,
						dport,
						getregexpattern(regex))
			return True
		else:
			if configopts['invertmatch']:
				matchstats['regex'] = regex
				matchstats['start'] = 0
				matchstats['end'] = len(data)
				matchstats['matchsize'] = matchstats['end'] - matchstats['start']
				return False

			if configopts['verbose']:
				print "[DEBUG] inspect - [%s#%08d] - Stream %s:%s - %s:%s did not match \'%s\'" % (
						proto,
						id,
						src,
						sport,
						dst,
						dport,
						getregexpattern(regex))

	return False


def handletcp(tcp):
	global configopts, openstreams

	id = 0
	showmatch = False
	addrkey = tcp.addr
	((src, sport), (dst, dport)) = tcp.addr

	if not configopts['linemode']:
		if configopts['tcpdone']:
			if configopts['udpdone']:
				if configopts['verbose']:
					if addrkey in openstreams: id = openstreams[addrkey]['id']
					print "[DEBUG] handletcp - [TCP#%08d] Done inspecting max packets (%d) and max streams (%d), \
							preparing for exit" % (
							id,
							configopts['maxinsppackets'],
							configopts['maxinspstreams'])
				exitwithstats()
			else:
				if configopts['verbose']:
					if addrkey in openstreams: id = openstreams[addrkey]['id']
					print "[DEBUG] handletcp - [TCP#%08d] Ignoring stream %s:%s - %s:%s (inspstreamct: %d == maxinspstreams: %d)" % (
							id,
							src,
							sport,
							dst,
							dport,
							configopts['inspstreamct'],
							configopts['maxinspstreams'])
			return

	regexes = []
	timestamp = datetime.datetime.fromtimestamp(nids.get_pkt_ts()).strftime('%H:%M:%S | %Y/%m/%d')
	endstates = [ nids.NIDS_CLOSE, nids.NIDS_TIMED_OUT, nids.NIDS_RESET ]

	if tcp.nids_state == nids.NIDS_JUST_EST:
		if addrkey not in openstreams:
			configopts['streamct'] += 1

			openstreams.update({addrkey:{
											'id':configopts['streamct'],
											'totdatasize':0,
										}
								})

			if configopts['verbose']:
				print "[DEBUG] handletcp - [TCP#%08d] %s:%s - %s:%s [SYN] (TRACKED: %d)" % (
						openstreams[addrkey]['id'],
						src,
						sport,
						dst,
						dport,
						len(openstreams))

		if configopts['linemode']:
			tcp.server.collect = 1
			tcp.client.collect = 1
			if configopts['verbose']:
				print "[DEBUG] handletcp - [TCP#%08d] Enabled both CTS and STC data collection for %s:%s - %s:%s (linemode)" % (
						openstreams[addrkey]['id'],
						src,
						sport,
						dst,
						dport)
		else:
			if len(configopts['ctsregexes']) > 0:
				tcp.server.collect = 1
				if configopts['verbose']:
					print "[DEBUG] handletcp - [TCP#%08d] Enabled CTS data collection for %s:%s - %s:%s" % (
						openstreams[addrkey]['id'],
						src,
						sport,
						dst,
						dport)
			if len(configopts['stcregexes']) > 0:
				tcp.client.collect = 1
				if configopts['verbose']:
					print "[DEBUG] handletcp - [TCP#%08d] Enabled STC data collection for %s:%s - %s:%s" % (
						openstreams[addrkey]['id'],
						src,
						sport,
						dst,
						dport)

	if tcp.nids_state == nids.NIDS_DATA:
		tcp.discard(0)

		if tcp.server.count_new > 0:
			direction = 'CTS'
			directionflag = '>'
			count = tcp.server.count
			newcount = tcp.server.count_new
			start = tcp.server.count - tcp.server.count_new
			end = tcp.server.count
			data = tcp.server.data[:tcp.server.count]
			openstreams[addrkey]['totdatasize'] += tcp.server.count_new
			for regex in configopts['ctsregexes']:
				regexes.append(regex)

		if tcp.client.count_new > 0:
			direction = 'STC'
			directionflag = '<'
			count = tcp.client.count
			newcount = tcp.client.count_new
			start = tcp.client.count - tcp.client.count_new
			end = tcp.client.count
			data = tcp.client.data[:tcp.client.count]
			openstreams[addrkey]['totdatasize'] += tcp.client.count_new
			for regex in configopts['stcregexes']:
				regexes.append(regex)

		if configopts['verbose']:
			print "[DEBUG] handletcp - [TCP#%08d] %s:%s %s %s:%s [%dB] (CTS: %d | STC: %d | TOT: %d)" % (
					openstreams[addrkey]['id'],
					src,
					sport,
					directionflag,
					dst,
					dport,
					newcount,
					tcp.server.count,
					tcp.client.count,
					openstreams[addrkey]['totdatasize'])

		configopts['inspstreamct'] += 1

		if configopts['linemode']:
			matchstats['addr'] = addrkey
			matchstats['regex'] = re.compile('.*')
			matchstats['start'] = start
			matchstats['end'] = end
			matchstats['matchsize'] = matchstats['end'] - matchstats['start']
			matchstats['direction'] = direction
			matchstats['directionflag'] = directionflag
			if configopts['verbose']: print "[DEBUG] handletcp - [TCP#%08d] Skipping inspection as linemode is enabled." % (
												openstreams[addrkey]['id'])
			showtcpmatches(data[matchstats['start']:matchstats['end']])
			return

		if configopts['maxinspstreams'] != 0 and configopts['inspstreamct'] >= configopts['maxinspstreams']:
			configopts['tcpdone'] = True

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

		if configopts['verbose']:
			print "[DEBUG] handletcp - [TCP#%08d] Initiating inspection on %s[%d:%d] - %dB (RegEx #:%d)" % (
					openstreams[addrkey]['id'],
					direction,
					offset,
					depth,
					inspdatalen,
					len(regexes))

		matched = inspect('TCP', openstreams[addrkey]['id'], inspdata, inspdatalen, regexes, addrkey)

		if not matched and configopts['invertmatch']:
			showmatch = True

		if matched and not configopts['invertmatch']:
			showmatch = True

		if showmatch:
			if configopts['killtcp']: tcp.kill

			matchstats['start'] += offset
			matchstats['end'] += offset

			matchstats['direction'] = direction
			matchstats['directionflag'] = directionflag

			if configopts['streammatches'] == 0:
				configopts['shortestmatch']['stream'] = matchstats['matchsize']
				configopts['shortestmatch']['streamid'] = openstreams[addrkey]['id']
				configopts['longestmatch']['stream'] = matchstats['matchsize']
				configopts['longestmatch']['streamid'] = openstreams[addrkey]['id']
			else:
				if matchstats['matchsize'] <= configopts['shortestmatch']['stream']:
					configopts['shortestmatch']['stream'] = matchstats['matchsize']
					configopts['shortestmatch']['streamid'] = openstreams[addrkey]['id']

				if matchstats['matchsize'] >= configopts['longestmatch']['stream']:
					configopts['longestmatch']['stream'] = matchstats['matchsize']
					configopts['longestmatch']['streamid'] = openstreams[addrkey]['id']

			tcp.server.collect = 0
			tcp.client.collect = 0
			configopts['streammatches'] += 1

			matchstats['addr'] = addrkey
			showtcpmatches(data[matchstats['start']:matchstats['end']])
			del openstreams[addrkey]

	if tcp.nids_state in endstates:
		if addrkey in openstreams:
			id = openstreams[addrkey]['id']
			del openstreams[addrkey]
			if configopts['verbose']:
				if tcp.nids_state == nids.NIDS_CLOSE: state = "FIN"
				elif tcp.nids_state == nids.NIDS_TIMED_OUT: state = "TIMED_OUT"
				elif tcp.nids_state == nids.NIDS_RESET: state = "RST"
				else: state = "UNKNOWN"
				print "[DEBUG] handletcp - [TCP#%08d] %s:%s - %s:%s [%s] (TRACKED: %d)" % (
						id,
						src,
						sport,
						dst,
						dport,
						state,
						len(openstreams))


def showtcpmatches(data):
	global configopts, openstreams, matchstats

	((src, sport), (dst, dport)) = matchstats['addr']

	if configopts['maxdispbytes'] > 0: maxdispbytes = configopts['maxdispbytes']
	else: maxdispbytes = len(data)

	if configopts['writelogs']:
		proto = "TCP"
		writetofile(proto, openstreams[matchstats['addr']]['id'], src, sport, dst, dport, data)

		if configopts['verbose']:
			print '[DEBUG] showtcpmatches - [TCP#%08d] Wrote %dB to %s/%s-%08d.%s.%s.%s.%s' % (
					openstreams[matchstats['addr']]['id'],
					matchstats['matchsize'],
					configopts['logdir'],
					proto,
					openstreams[matchstats['addr']]['id'],
					src,
					sport,
					dst,
					dport)

	if 'quite' in configopts['outmodes']:
		if configopts['verbose']:
			print "[DEBUG] showtcpmatches - [TCP#%08d] %s:%s %s %s:%s matches \'%s\' @ [%d:%d] - %dB" % (
					openstreams[matchstats['addr']]['id'],
					src,
					sport,
					matchstats['directionflag'],
					dst,
					dport,
					getregexpattern(matchstats['regex']),
					matchstats['start'],
					matchstats['end'],
					matchstats['matchsize'])
		return

	if configopts['maxdispstreams'] != 0 and configopts['dispstreamct'] >= configopts['maxdispstreams']:
		if configopts['verbose']:
			print '[DEBUG] showtcpmatches - Skipping outmode parsing (dispstreamct: %d == maxdispstreams: %d)' % (
					configopts['dispstreamct'],
					configopts['maxdispstreams'])
		return

	if 'meta' in configopts['outmodes']:
		print "[MATCH] (%08d/%08d) [TCP#%08d] %s:%s %s %s:%s matches \'%s\' @ [%d:%d] - %dB" % (
				configopts['inspstreamct'],
				configopts['streammatches'],
				openstreams[matchstats['addr']]['id'],
				src,
				sport,
				matchstats['directionflag'],
				dst,
				dport,
				getregexpattern(matchstats['regex']),
				matchstats['start'],
				matchstats['end'],
				matchstats['matchsize'])
	if 'print' in configopts['outmodes']: printable(data[:maxdispbytes])
	if 'raw' in configopts['outmodes']: print data[:maxdispbytes]
	if 'hex' in configopts['outmodes']: hexdump(data[:maxdispbytes])

	configopts['dispstreamct'] += 1


def writetofile(proto, id, src, sport, dst, dport, data):
	global configopts, openstreams

	try:
		if not os.path.isdir(configopts['logdir']): os.makedirs(configopts['logdir'])
	except OSError, oserr: print '[ERROR] %s' % oserr

	filename = '%s/%s-%08d-%s.%s-%s.%s' % (configopts['logdir'], proto, id, src, sport, dst, dport)

	try:
		if configopts['linemode']: file = open(filename, 'ab+')
		else: file = open(filename, 'wb+')
		file.write(data)
	except IOError, io: print '[Error] %s' % io


def exitwithstats():
	global configopts, openstreams

	if configopts['verbose'] and len(openstreams) > 0:
		dumpopenstreams()

	print
	if configopts['packetct'] >= 0:
		print '[U] Processed: %d | Matches: %d | Shortest: %dB (#%d) | Longest: %dB (#%d)' % (
				configopts['insppacketct'],
				configopts['packetmatches'],
				configopts['shortestmatch']['packet'],
				configopts['shortestmatch']['packetid'],
				configopts['longestmatch']['packet'],
				configopts['longestmatch']['packetid'])

	if configopts['streamct'] >= 0:
		print '[T] Processed: %d | Matches: %d | Shortest: %dB (#%d) | Longest: %dB (#%d)' % (
				configopts['inspstreamct'],
				configopts['streammatches'],
				configopts['shortestmatch']['stream'],
				configopts['shortestmatch']['streamid'],
				configopts['longestmatch']['stream'],
				configopts['longestmatch']['streamid'])

	print '[+] Flowsrch session complete. Exiting.'
	sys.exit(0)


def dumpopenstreams():
	global openstreams

	print
	print "[DEBUG] Dumping open/tracked streams: %d" % (len(openstreams))

	for (key, value) in openstreams.items():
		((src, sport), (dst, dport)) = key
		id = value['id']
		datasize = value['totdatasize']
		print "[DEBUG] [%08d] %s:%s - %s:%s [%dB]" % (id, src, sport, dst, dport, datasize)


def handleip(pkt):
	timestamp = nids.get_pkt_ts()


def dumpargsstats(configopts):
	print '%-30s' % '[DEBUG] Input pcap:', ; print '[ \'%s\' ]' % (configopts['pcap'])
	print '%-30s' % '[DEBUG] Listening device:', ;print '[ \'%s\' ]' % (configopts['device']),
	if configopts['killtcp']:
		print '[ w/ \'killtcp\' ]'
	else:
		print

	print '%-30s' % '[DEBUG] CTS regex:', ; print '[ %d |' % (len(configopts['ctsregexes'])),
	for c in configopts['ctsregexes']:
		print '\'%s\'' % getregexpattern(c),
	print ']'

	print '%-30s' % '[DEBUG] STC regex:', ; print '[ %d |' % (len(configopts['stcregexes'])),
	for s in configopts['stcregexes']:
		print '\'%s\'' % getregexpattern(s),
	print ']'

	print '%-30s' % '[DEBUG] RE stats:', ; print '[ Engine: \'%s\' | Flags: %d - (' % (reengine, configopts['reflags']),
	if configopts['igncase']: print "ignorecase",
	if configopts['multiline']: print "multiline",
	print ") ]"

	print '%-30s' % '[DEBUG] Inspection limits:',
	print '[ Streams: %d | Packets: %d | Offset: %d | Depth: %d ]' % (
			configopts['maxinspstreams'],
			configopts['maxinsppackets'],
			configopts['offset'],
			configopts['depth'])

	print '%-30s' % '[DEBUG] Display limits:',
	print '[ Streams: %d | Packets: %d | Bytes: %d ]' % (
			configopts['maxdispstreams'],
			configopts['maxdisppackets'],
			configopts['maxdispbytes'])

	print '%-30s' % '[DEBUG] Output modes:', ; print '[',
	if 'quite' in configopts['outmodes']:
		print '\'quite\'',
		if configopts['writelogs']:
			print '\'write: %s\'' % (configopts['logdir']),
	else:
		if 'meta' in configopts['outmodes']: print '\'meta\'',
		if 'hex' in configopts['outmodes']: print '\'hex\'',
		if 'print' in configopts['outmodes']: print '\'print\'',
		if 'raw' in configopts['outmodes']: print '\'raw\'',
		if configopts['writelogs']: print '\'write: %s\'' % (configopts['logdir']),
	print ']'

	print '%-30s' % '[DEBUG] Misc options:',
	print '[ BPF: \'%s\' | invertmatch: %s | killtcp: %s | verbose: %s | linemode: %s ]' % (
			configopts['bpf'],
			configopts['invertmatch'],
			configopts['killtcp'],
			configopts['verbose'],
			configopts['linemode'])
	print


def main():
	global configopts

	banner = """\
	    ______              _                            __ 
	   / __/ /___ _      __(_)___  _________  ___  _____/ /_
	  / /_/ / __ \ | /| / / / __ \/ ___/ __ \/ _ \/ ___/ __/
	 / __/ / /_/ / |/ |/ / / / / (__  ) /_/ /  __/ /__/ /_  
	/_/ /_/\____/|__/|__/_/_/ /_/____/ .___/\___/\___/\__/  
	                                /_/                     
	"""
	print '%s' % (banner)

	print '%s v%s - %s' % (configopts['name'], configopts['version'], configopts['desc'])
	print '%s' % configopts['author']
	print

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

	direction_flags = parser.add_argument_group('direction_flags')
	direction_flags.add_argument(
									'-c',
									metavar='--cregex',
									dest='cres',
									default=[],
									action='append',
									required=False,
									help='regex to match against client stream')
	direction_flags.add_argument(
									'-s',
									metavar='--sregex',
									dest='sres',
									default=[],
									action='append',
									required=False,
									help='regex to match against server stream')
	direction_flags.add_argument(
									'-a',
									metavar='--aregex',
									dest='ares',
									default=[],
									action='append',
									required=False,
									help='regex to match against any stream')

	regex_flags = parser.add_argument_group('regex_flags')
	regex_flags.add_argument(
									'-i',
									dest='igncase',
									default=False,
									action='store_true',
									required=False,
									help='ignore case')
	regex_flags.add_argument(
									'-m',
									dest='multiline',
									default=False,
									action='store_true',
									required=False,
									help='multiline match')

	content_modifiers = parser.add_argument_group('content_modifiers')
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

	inspection_limits = parser.add_argument_group('inspection_limits')
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

	display_limits = parser.add_argument_group('display_limits')
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

	out_options = parser.add_argument_group('out_options')
	out_options.add_argument(
									'-w',
									metavar='logdir',
									dest='writebytes',
									default='',
									action='store',
									required=False,
									nargs='?',
									help='write matching packets/streams')
	out_options.add_argument(
									'-o',
									dest='outmode',
									choices=('quite', 'meta', 'hex', 'print', 'raw'),
									action='append',
									default=[],
									required=False,
									help='match output mode')

	misc_options = parser.add_argument_group('misc_options')
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
									'-k',
									dest='killtcp',
									default=False,
									action='store_true',
									required=False,
									help='kill matching TCP stream')
	misc_options.add_argument(
									'-V',
									dest='verbose',
									default=False,
									action='store_true',
									required=False,
									help='verbose output')
	misc_options.add_argument(
									'-L',
									dest='linemode',
									default=False,
									action='store_true',
									required=False,
									help='enable linemode (disables inspection)')

	args = parser.parse_args()

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

	if args.cres:
		for c in args.cres:
			configopts['ctsregexes'].append(re.compile(c, configopts['reflags']))

	if args.sres:
		for s in args.sres:
			configopts['stcregexes'].append(re.compile(s, configopts['reflags']))

	if args.ares:
		for a in args.ares:
			configopts['ctsregexes'].append(re.compile(a, configopts['reflags']))
			configopts['stcregexes'].append(re.compile(a, configopts['reflags']))

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

	if not args.outmode:
		configopts['outmodes'].append('meta')
		configopts['outmodes'].append('hex')
	else:
		for mode in args.outmode:
			if mode == 'quite': configopts['outmodes'].append('quite')
			elif mode == 'meta': configopts['outmodes'].append('meta')
			elif mode == 'hex': configopts['outmodes'].append('hex')
			elif mode == 'print': configopts['outmodes'].append('print')
			elif mode == 'raw': configopts['outmodes'].append('raw')

	if args.bpf:
		configopts['bpf'] = args.bpf
		nids.param('pcap_filter', configopts['bpf'])				

	if args.killtcp:
		if configopts['livemode']: configopts['killtcp'] = True

	if args.verbose:
		configopts['verbose'] = True

	if args.linemode:
		configopts['linemode'] = True

	if not configopts['ctsregexes'] and not configopts['stcregexes'] and not configopts['linemode']:
		configopts['linemode'] = True
		if configopts['verbose']:
			print "[DEBUG] Inspection requires direction flags, none found!"
			print "[DEBUG] Fallback - linemode enabled"
			print


	if configopts['verbose']:
		dumpargsstats(configopts)

	try:
		nids.chksum_ctl([('0.0.0.0/0', False)])
		nids.param('scan_num_hosts', 0)

		nids.init()							
		nids.register_ip(handleip)
		nids.register_udp(handleudp)
		nids.register_tcp(handletcp)

		print '[+] Callback handlers registered. Press any key to continue...',
		try: input()
		except: pass

		print '[+] NIDS initialized, waiting for events...' ; print
		try: nids.run()
		except KeyboardInterrupt: exitwithstats()

	except nids.error, nx:
		print
		print '[-] NIDS error: %s' % nx
		sys.exit(1)
#	except Exception, ex:
#		print
#		print '[-] Exception: %s' % ex
#		sys.exit(1)

	exitwithstats()								

if __name__ == '__main__':
	main()

