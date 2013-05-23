#!/usr/bin/env python2

import re, pickle

# get regex pattern from compiled object
def getregexpattern(regexobj):
    dumps = pickle.dumps(regexobj)
    return re.search("\n\(S'(.*)'\n", dumps).group(1)

# raw bytes to hexdump filter
def hexdump(src, length=16, sep='.'):
        lines = []
        FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
        for c in xrange(0, len(src), length):
                chars = src[c:c+length]
                hex = ' '.join(["%02x" % ord(x) for x in chars])
                if len(hex) > 24:
                        hex = "%s %s" % (hex[:24], hex[24:])
                printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars])
                lines.append("%08x:  %-*s  |%s|\n" % (c, length*3, hex, printable))
        print ''.join(lines)

# ascii printable filter for raw bytes
def printable(src):
        print ''.join([ch for ch in src if ord(ch) > 31 and ord(ch) < 126 or ord(ch) == 9 or ord(ch) == 10 or ord(ch) == 13 or ord(ch) == 20])
        print

