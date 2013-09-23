# flowinspect misc. utilities

from globals import configopts

if configopts['regexengine'] == 're2':
    import re2
else:
    import re

import pickle, collections, json


# when stdout has to be mute'd
class NullDevice():
    def write(self, s): pass


# sort and print a dict
def printdict(dictdata):
    sd = collections.OrderedDict(sorted(dictdata.items()))
    print(json.dumps(sd, indent=4))

# get regex pattern from compiled object
def getregexpattern(regexobj):
    dumps = pickle.dumps(regexobj)
    regexpattern = re.search("\n\(S'(.*)'\n", dumps).group(1)
    if re.findall(r'\\x[0-9a-f]{2}', regexpattern):
        regexpattern = re2.sub(r'(\\x)([0-9a-f]{2})', r'x\2', regexpattern)

    return regexpattern

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


