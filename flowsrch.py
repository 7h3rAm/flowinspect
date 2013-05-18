#!/usr/bin/env python2 

import os, sys, argparse, re

# try importing NIDS; exit on error
try:
	import nids
except ImportError, ex:
	print "[-] Import failed: %s" % (ex)
	sys.exit(1)

# globals
version = "0.1"									# flowsrch version
reflags = 0									# regex match flags
matched = 0									# generic matched flag
openstreams = []								# list of open streams
udpdone = tcpdone = 0								# max packet/stream inspection flags
packetct = streamct = 0								# packet/stream counters
udpmatches = tcpmatches = 0							# udp/tcp match counters
maxinsppackets = maxinspstreams = maxinspbytes = 0				# max inspection counters
maxdisppackets = maxdispstreams = maxdispbytes = 0				# max display counters
shortestmatch = {'u':0, 't':0, 'U':0, 'T':0}					# shortest display/inspection match counters
longestmatch = {'u':0, 't':0, 'U':0, 'T':0}					# longest display/inspection match counters
flags = {'d':0, 'p':1, 'R':0, 'D':1, 'v':0, 'C':1, 'S':1, 'k':0, 'w':0}		# cmdline args dictionary

def hexdump(src, length=16, sep='.'):
	FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
	lines = []
	for c in xrange(0, len(src), length):
		chars = src[c:c+length]
		hex = ' '.join(["%02x" % ord(x) for x in chars])
		if len(hex) > 24:
			hex = "%s %s" % (hex[:24], hex[24:])
		printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars])
		lines.append("%08x:  %-*s  |%s|\n" % (c, length*3, hex, printable))
	print ''.join(lines)

# udp callback handler
def handleudp(addrs, payload, pkt):
	global udpregex, packetct, maxinsppackets, maxinspbytes, udpmatches, udpdone, tcpdone, matched
        finalpayload = timestamp = 0
	matched = 0

	if maxinsppackets != 0 and packetct >= maxinsppackets:			# if max packet inspection count is non-zero
 		udpdone = 1							# and we have reached that limit
		donetcpudp()							# set flag and return
		return

        packetct += 1								# increment packet counter
	timestamp = nids.get_pkt_ts()

	if maxinspbytes != 0:							# if max inspection depth is non-zero
		finalpayload = payload[:maxinspbytes]				# extract depth bytes from payload
	else:
		finalpayload = payload						# else extract all bytes from payload

	for match in udpregex.finditer(finalpayload):				# match regex and generate iterable match object
		matched = 1
		if not flags['v']:						# if invert match is not requested (direct match)
			start = match.start()					# find starting offset of matched bytes
			end = match.end()					# find ending offset of matched bytes
			udpmatches += 1						# increment udp match counter
			showudpmatch(timestamp, addrs, finalpayload, start, end)

	if not matched and flags['v']:						# packet did not match and invert match is requested
		start = 0							# point to the start of the payload
		end = len(finalpayload)						# should dump all of teh payload coz we don't have match offsets
		udpmatches += 1							# increment udp match counter
		showudpmatch(timestamp, addrs, finalpayload, start, end)

# show udp packet details and match stats
def showudpmatch(timestamp, addrs, payload, start, end):
	global packetct, maxinsppackets, maxinspbytes, udpmatches, maxdisppackets, shortestmatch, longestmatch
	((src,sport), (dst,dport)) = addrs

	count = end - start
	if count == 0:								# if matched payload is of size 0 (regex returns 0 bytes matches for some expressions)
		udpmatches -= 1							# don't track such matches
		return								# and return

	if maxdisppackets != 0 and udpmatches > maxdisppackets:			# if user requested packet matches have been dumped
		udpdone = 1							# mark completion of udp packets inspection
		donetcpudp()							# check if max stream and packet inspection limits have been exhausted
		return								# if above fails, return anyways

	if udpmatches == 1:							# if its the first udp match, track it as the 
		shortestmatch['u'] = count					# shortest and
		shortestmatch['U'] = udpmatches
		longestmatch['u'] = count					# longest match
		longestmatch['U'] = udpmatches

	if shortestmatch['u'] > count:						# if a shorter match if found
		shortestmatch['u'] = count					# track it as the new shortest match
		shortestmatch['U'] = udpmatches

	if longestmatch['u'] < count:						# if a new longest match is found
		longestmatch['u'] = count					# track it as the new longest match
		longestmatch['U'] = udpmatches

	if maxdispbytes == 0 or count <= maxdispbytes:				# tune display limits
		end = end
	else:
		end = start+maxdispbytes

	print
	print "[U] (%d/%d/%d) %s: %s:%s > %s:%s" % (udpmatches, packetct, maxinsppackets, str(timestamp), src, sport, dst, dport),
	print "(matched @ [%d:%d] - %dB)" % (start, end, count)
	hexdump(payload[start:end])

# tcp callback handler
def handletcp(tcp):
	global tcpregex, streamct, maxinspstreams, maxinspbytes, tcpmatches, tcpdone, udpdone, matched, openstreams
	matched = 0
	data = finalpayload = timestamp = ""

	if maxinspstreams != 0 and streamct > maxinspstreams:	# if max stream inspection count is non-zero
		tcpdone = 1							# and we have reached that limit
		donetcpudp()							# set flag and return
		return 

	endstates = (nids.NIDS_CLOSE, nids.NIDS_TIMED_OUT, nids.NIDS_RESET)	# possible stream termination states

	if tcp.nids_state == nids.NIDS_JUST_EST:				# if a new stream is available
		if flags['C']:							# and CTS stream has to be inspected
			tcp.server.collect = 1					# mark it for data collection
		if flags['S']:							# and STC stream has to be inspected
			tcp.client.collect = 1					# mark it for data collection

		if tcp.addr not in openstreams:					# if not already tracking (nids will take care of it, but still good to have a precheck)
			openstreams.append(tcp.addr)				# start tracking this stream
			streamct += 1						# increment stream counter

	elif tcp.nids_state == nids.NIDS_DATA:                                  # if a stream has data
		tcp.discard(0)			                                # discard first 0 bytes; collect entire payload

	elif tcp.nids_state in endstates:                                       # if a stream is closed, reset, or timed out, invoke match process
		timestamp = nids.get_pkt_ts()					# read timestamp

		if flags['C'] and flags['S']:					# if both CTS and STC inspection requested
			data = tcp.server.data + tcp.client.data		# extract both toserver and toclient data
		elif flags['C']:						# if just CTS inspection is requested
			data = tcp.server.data					# extract just toserver side data
		elif flags['S']:						# if just STC inspection is requested
			data = tcp.client.data					# extract just toclient side data

		if maxinspbytes != 0:						# if max inspection depth is non-zero
			finalpayload = data[:maxinspbytes]			# extract depth bytes from data
		else:
			finalpayload = data					# else extract all bytes from data

		for match in tcpregex.finditer(finalpayload):			# match regex and generate an iterable match object
			matched = 1
			if not flags['v']:
	 			start = match.start()				# find starting offset of matched bytes
				end = match.end()				# find ending offset of matched bytes
				tcpmatches += 1					# increment tcp match counter
				showtcpmatch(timestamp, tcp.addr, finalpayload, start, end)

		if matched and tcp.addr in openstreams:				# found a match for a tracked stream? (right to do this outside of above matches loop)
			openstreams.remove(tcp.addr)				# stop tracking any further
			if flags['k']:
				tcp.kill					# terminate matched stream if requested

		if not matched and flags['v']:					# stream did not match and invert match is requested
			start = 0						# point to the start of payload
			end = len(finalpayload)					# should dump all of the payload coz we don't have match offsets
			tcpmatches += 1						# increment tcp match counter
			showtcpmatch(timestamp, tcp.addr, finalpayload, start, end)
			if tcp.addr in openstreams:				# are we tracking this stream?
				openstreams.remove(tcp.addr)			# stop tracking any further
				if flags['k']:
					tcp.kill				# terminate matched stream if requested

	else:
		print >>sys.stderr, "[!] Unknown NIDS state: %s" % (tcp.nids_state)

# show tcp stream details and match stats
def showtcpmatch(timestamp, addrs, payload, start, end):
	global streamct, maxinspstreams, maxinspbytes, tcpmatches, maxdispstreams
	((src,sport), (dst,dport)) = addrs

	count = end - start
	if count == 0:								# if matched payload is of size 0 (regex returns 0 byte matches for some expressions)
		tcpmatches -= 1							# don't track such matches
		return								# and return

	if maxdispstreams != 0 and tcpmatches > maxdispstreams:			# if user requested streams have been dumped
		tcpdone = 1							# mark completion of tcp streams inspection
		donetcpudp()							# check if max stream and packet inspection limits have been exhausted
		return								# if above fails, return anyways

	if tcpmatches == 1:							# if its the first tcp match, track it as the
		shortestmatch['t'] = count					# shortest and
		shortestmatch['T'] = tcpmatches
		longestmatch['t'] = count					# longest match
		longestmatch['T'] = tcpmatches

	if shortestmatch['t'] > count:						# if a shorter match is found
		shortestmatch['t'] = count					# track it as the new shortest match
		shortestmatch['T'] = tcpmatches

	if longestmatch['t'] < count:						# if a longer match is found
		longestmatch['t'] = count					# track it as the new longest match
		longestmatch['T'] = tcpmatches

	if maxdispbytes == 0 or count <= maxdispbytes:				# tune display limits
		end = end
	else:
		end = start+maxdispbytes

	print
	print "[T] (%d/%d/%d) %s: %s:%s > %s:%s" % (tcpmatches, streamct, maxinspstreams, str(timestamp), src, sport, dst, dport),
	print "(matched @ [%d:%d] - %dB)" % (start, end, count)
	hexdump(payload[start:end])

# done parsing max packets/streams
def donetcpudp():
	global udpdone, tcpdone

	if tcpdone and udpdone:							# if we're done isnpecting max streams and packets
		exitwithstats()							# display stats and exit

# ip callback handler
def handleip(pkt):
	timestamp = nids.get_pkt_ts()

# keyboard interrupt handler / exit stats display routine
def exitwithstats():
	global packetct, udpmatches, streamct, tcpmatches, shortestmatch, longestmatch, openstreams

	print
	if packetct >= 0:
		print "[U] Processed: %d | Matches: %d | Shortest: %dB (#%d) | Longest: %dB (#%d)" % \
		(packetct, udpmatches, shortestmatch['u'], shortestmatch['U'], longestmatch['u'], longestmatch['U'])

	if streamct >= 0:
		print "[T] Processed: %d | Matches: %d | Shortest: %dB (#%d) | Longest: %dB (#%d)" % \
		(streamct, tcpmatches, shortestmatch['t'], shortestmatch['T'], longestmatch['t'], longestmatch['T'])

	if len(openstreams) > 0:
		print "[!] Skipped streams: %d (tcp.state did not match endstates)" % len(openstreams)

	print "[+] Flowsrch session complete. Exiting."
	sys.exit(0)

# main routine
def main():
	global version, reflags, udpregex, tcpregex, openstreams, maxinsppackets, maxinspstreams, maxinspbytes, maxdisppackets, maxdispstreams, maxdispbytes, packetct, streamct, flags

	parser = argparse.ArgumentParser()

	inputgroup = parser.add_mutually_exclusive_group(required=True)
	inputgroup.add_argument('-d', metavar="--device", dest="device", default="lo", action="store", help="listening device")
	inputgroup.add_argument('-p', metavar="--pcap", dest="pcap", default="", action="store", help="input pcap file")

	srchgroup = parser.add_mutually_exclusive_group(required=True)
	srchgroup.add_argument('-R', metavar="--regex", dest="regex", default="", action="store", help="regex pattern to search")
	srchgroup.add_argument('-D', metavar="--dfa", dest="dfa", default="", action="store", help="dfa pattern to search (WIP)")

	parser.add_argument('-f', metavar="--filter", dest="filter", default="", action="store", required=False, help="BPF expression")

	dirgroup = parser.add_mutually_exclusive_group(required=False)
	dirgroup.add_argument('-C', dest="cts", default=False, action="store_true", required=False, help="match client stream only")
	dirgroup.add_argument('-S', dest="stc", default=False, action="store_true", required=False, help="match server stream only")

	parser.add_argument('-i', dest="igncase", default=False, action="store_true", required=False, help="ignore case")
	parser.add_argument('-v', dest="invmatch", default=False, action="store_true", required=False, help="invert match")
	parser.add_argument('-m', dest="multiline", default=False, action="store_true", required=False, help="multiline match")

	parser.add_argument('-T', metavar="--maxinspstreams", dest="maxinspstreams", default=0, action="store", required=False, help="max streams to inspect")
	parser.add_argument('-U', metavar="--maxinsppackets", dest="maxinsppackets", default=0, action="store", required=False, help="max packets to inspect")
	parser.add_argument('-B', metavar="--maxinspbytes", dest="maxinspbytes", default=0, action="store", required=False, help="max bytes to inspect")

	parser.add_argument('-t', metavar="--maxdispstreams", dest="maxdispstreams", default=0, action="store", required=False, help="max streams to display")
	parser.add_argument('-u', metavar="--maxdisppackets", dest="maxdisppackets", default=0, action="store", required=False, help="max packets to display")
	parser.add_argument('-b', metavar="--maxdispbytes", dest="maxdispbytes", default=0, action="store", required=False, help="max bytes to display")

	parser.add_argument('-k', dest="killtcp", default=False, action="store_true", required=False, help="kill matching TCP stream")

	parser.add_argument('-V', action='version', version='%(prog)s 0.1')

	args = parser.parse_args()

	print "%s v%s - Search Packets/Flows using DFA/RegEx" % (os.path.basename(sys.argv[0]), version)
	print "Juniper Networks - Security Research Group"
	print

	nids.chksum_ctl([('0.0.0.0/0', False)])					# disable checksum verification
	nids.param("scan_num_hosts", 0)						# disable port scan detection

	if args.pcap != "":
		flags['p'] = 1							# enable pcap inspection
		flags['d'] = 0							# disable live device inspection
		nids.param("filename", args.pcap)				# set NIDS filename parameter with input pcap
		print "[+] Input pcap: \"%s\"" % (args.pcap)
	elif args.device != "":
		flags['d'] = 1							# enable live device inspection
		flags['p'] = 0							# disable pcap inspection
		nids.param("device", args.device)				# set NIDS device parameter with device name
		print "[+] Listening device: \"%s\"" % (args.device)

	if args.filter != "":
		nids.param("pcap_filter", args.filter)				# set NIDS filter parameter with input BPF expression
		print "[+] Applied BPF expression: \"%s\"" % (args.filter)

	if args.regex != "":
		flags['R'] = 1							# enable regex based inspection
		flags['D'] = 0							# disable DFA based inspection
		print "[+] Enabled RegEx match for pattern: \"%s\"" % (args.regex)
	elif args.dfa != "":
		flags['D'] = 1							# enable DFA based inspection
		flags['R'] = 0							# disable regex based inspection
		print "[+] Enabled DFA match for pattern: \"%s\"" % (args.dfa)

	if args.igncase == True:
		reflags |= re.IGNORECASE					# enable case insensitive regex match flag
		print "[+] Enabled case insensitive match"

	if args.invmatch == True:
		flags['v'] = 1							# enable invert match inspection
		print "[+] Enabled invert match"

	if args.multiline == True:
		reflags |= re.MULTILINE						# enable multiline regex match flag
		reflags |= re.DOTALL						# enable dotall regex match flag (dot matches newline)
		print "[+] Enabled multiline match (dot will now match newline as well)"

	if args.cts == True:
		flags['C'] = 1							# enable CTS inspection
		flags['S'] = 0							# disable STC inspection
		print "[+] Enabled inspection on CTS stream only"
	elif args.stc == True:
		flags['S'] = 1							# enable STC inspection
		flags['C'] = 0							# enable CTS inspection
		print "[+] Enabled inspection on STC stream only"
	else:
		flags['C'] = 1							# default, enable both CTS
		flags['S'] = 1							# and STC inspection
		print "[+] Enabled inspection on both CTS-STC streams"

	if args.killtcp == True:
		if flags['p']:
			print "[!] Cannot enable \"killtcp\" while reading pcaps"
		elif flags['d']:
			flags['k'] = 1
			print "[+] Enabled \"killtcp\" for matched stream"

	if args.maxinspstreams:							# if max stream inspection limit is provided,
		maxinspstreams = int(args.maxinspstreams)			# enable limit
	else:
		maxinspstreams = 0						# else keep limit uncapped

	if args.maxinsppackets:							# if max packet inspection limit is provided,
		maxinsppackets = int(args.maxinsppackets)			# enable limit
	else:
		maxinsppackets = 0						# else keep limit uncapped

	if args.maxinspbytes:							# if max inspection depth is provided,
		maxinspbytes = int(args.maxinspbytes)				# enable depth
	else:
		maxinspbytes = 0						# else keep limit uncapped
	print "[+] Max inspection limits: [ Streams (-T): %d | Packets (-U): %d | Bytes (-B): %d ]" % (maxinspstreams, maxinsppackets, maxinspbytes)

	if args.maxdispstreams:							# if max stream display limit is provided,
		maxdispstreams = int(args.maxdispstreams)			# enable limit
	else:
		maxdispstreams = 0						# else keep limit uncapped

	if args.maxdisppackets:							# if max packet display limit is provided,
		maxdisppackets = int(args.maxdisppackets)			# enable limit
	else:
		maxdisppackets = 0						# else keep limit uncapped

	if args.maxdispbytes:							# if max display depth is provided,
		maxdispbytes = int(args.maxdispbytes)				# enable depth
	else:
		maxdispbytes = 0						# else keep limit uncapped
	print "[+] Max display limits: [ Streams (-t): %d | Packets (-u): %d | Bytes (-b): %d ]" % (maxdispstreams, maxdisppackets, maxdispbytes)

	try:
		if flags['R']:
			tcpregex = re.compile(args.regex, reflags)		# compile and generate a regex object for tcp matches
			if args.multiline == False:
				reflags |= re.MULTILINE				# enable multiline regex match for udp by default
				reflags |= re.DOTALL
			udpregex = re.compile(args.regex, reflags)		# compile and generate a regex object for udp matches
		elif flags['D']:
			print "[!] DFA matching logic has not been implemented (yet). Please use regex patterns instead."
			print "[-] Failed to initialize DFA search. Exiting."
			sys.exit(1)

		nids.init()							# initialize NIDS
		nids.register_ip(handleip)					# register ip callback handler
		nids.register_udp(handleudp)					# register udp callback handler
		nids.register_tcp(handletcp)					# register tcp callback handler
		print "[+] UDP/TCP/IP callback handlers registered"

		print "[+] Ready, press any key to continue...",
		try: input()
		except: pass

		print "[+] NIDS initialized, waiting for events..."
		try:
			nids.run()						# invoke NIDS handler
		except KeyboardInterrupt:
			exitwithstats()

	except nids.error, nx:
		print
		print "[-] NIDS error: %s" % nx
		sys.exit(1)
	except Exception, ex:
		print
		print "[-] Exception: %s" % ex
		sys.exit(1)

	exitwithstats()

if __name__ == "__main__":
	main()

