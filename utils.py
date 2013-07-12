#!/usr/bin/env python2

import re, pickle

# get regex pattern from compiled object
def getregexpattern(regexobj):
	dumps = pickle.dumps(regexobj)
	return re.search("\n\(S'(.*)'\n", dumps).group(1)


# raw bytes to hexdump filter
def hexdump(data, length=16, sep='.'):
	lines = []
	FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
	for c in xrange(0, len(data), length):
		chars = data[c:c+length]
		hex = ' '.join(["%02x" % ord(x) for x in chars])
		printablechars = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars])
		lines.append("%08x:  %-*s  |%s|\n" % (c, length*3, hex, printablechars))
	print ''.join(lines)


# ascii printable filter for raw bytes
def printable(data):
	print ''.join([ch for ch in data if ord(ch) > 31 and ord(ch) < 126
					or ord(ch) == 9
					or ord(ch) == 10
					or ord(ch) == 13
					or ord(ch) == 32])


