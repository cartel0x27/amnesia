#!/usr/bin/python2.5

from optparse import OptionParser
from getpass import getpass
parser = OptionParser()
parser.add_option("-t", "--transpose", nargs=2, dest="trans")
parser.add_option("-d", "--delete-key", nargs=1, dest="delete",help="delete superblock index")
parser.add_option("-a", "--add-key", nargs=0, dest="add", help="add superblock by key")
parser.add_option("-s", "--set-working", nargs=1, dest="setworking", help="set working superblock")


(options, args) = parser.parse_args()
f = open(".amnesiacmd", "w")


if options.trans != None:
    try:
        p, k = options.trans    
        print "transposing %s to key %s"%(p, k)
        f.write("TRANSPOSE %s %s")%(p,k)
    except:
        pass
elif options.delete != None:
    print "deleting keyindex %s"%options.delete
    f.write("DELSUPERBLOCK %s ."%options.delete)
elif options.add != None:
    k = getpass(prompt="enter key:")
    print "adding key [not echoed]"
    f.write("ADDSUPERBLOCK %s ."%k)
elif options.setworking != None:
    print "setting working superblock to index %s"%options.setworking
    f.write("SETWORKINGSUPERBLOCK %s ."%options.setworking)
else:
    print "no valid opts"

try:
    f.close()
except IOError:
    pass